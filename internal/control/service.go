// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package control

import (
	"context"
	"errors"
	"time"

	"github.com/PharosVPN/node/internal/awg"
	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/node/internal/netpolicy"
	"github.com/PharosVPN/node/internal/xray"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// service implements the NodeControl gRPC service.
//
// GetStatus reports the node's AmneziaWG identity (coxswain refuses to provision
// devices until it has it — DESIGN §3) and the AmneziaWG service health.
// PushConfig, AddPeer, RemovePeer, ListPeers manage the AmneziaWG peer set
// (B2) and the XRay/REALITY VLESS client set (B3). GetMetrics reports counters
// (B4) — totals from the conf+live join plus cumulative handshakes_total /
// errors_total fed by the observer. WatchEvents streams the observer's live
// events (B5). SetNetworkConfig applies the node's forwarding / masquerade /
// isolation policy (decision 16). RestartService reloads a protocol's data
// plane in place.
type service struct {
	nodev1.UnimplementedNodeControlServer

	version   string
	started   time.Time
	awgNode   *awg.Node
	awgReg    *awg.Registry
	netPolicy *netpolicy.Applier
	xray      *xray.Runtime
}

// newService returns a NodeControl service implementation.
func newService(version string, awgNode *awg.Node, awgReg *awg.Registry, netPolicy *netpolicy.Applier, xrayRT *xray.Runtime) *service {
	return &service{
		version:   version,
		started:   time.Now(),
		awgNode:   awgNode,
		awgReg:    awgReg,
		netPolicy: netPolicy,
		xray:      xrayRT,
	}
}

// primary is the client-interface (awg0) data-plane manager. The current
// NodeControl RPCs operate on it; cascade inner-link interfaces in the registry
// are provisioned out of band (DESIGN §3) and not yet addressed per-RPC.
func (s *service) primary() *awg.Manager { return s.awgReg.Primary() }

// GetMetrics reports the data plane's current counters. AmneziaWG metrics
// come from the same conf+live correlation as ListPeers, with summed totals.
// handshakes_total / errors_total are reserved for the B5 polling observer
// that also feeds WatchEvents — they stay at zero in B4. XRay metrics land
// in B3.
func (s *service) GetMetrics(ctx context.Context, _ *nodev1.GetMetricsRequest) (*nodev1.GetMetricsResponse, error) {
	snap, err := s.primary().Metrics(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetMetrics: %v", err)
	}
	return &nodev1.GetMetricsResponse{
		Peers:           snap.Peers,
		TotalRxBytes:    snap.TotalRx,
		TotalTxBytes:    snap.TotalTx,
		HandshakesTotal: snap.Handshakes,
		ErrorsTotal:     snap.Errors,
	}, nil
}

// GetStatus reports the node's agent version, uptime, the AmneziaWG server
// identity, and per-protocol service health.
func (s *service) GetStatus(ctx context.Context, _ *nodev1.GetStatusRequest) (*nodev1.GetStatusResponse, error) {
	running, listening, peerCount, detail := s.primary().Status(ctx)
	newestHsAge, handshaking := s.primary().Liveness(ctx)
	services := []*nodev1.ServiceStatus{{
		Protocol:                  nodev1.Protocol_PROTOCOL_AMNEZIAWG,
		Running:                   running,
		Listening:                 listening,
		PeerCount:                 peerCount,
		Detail:                    detail,
		NewestHandshakeAgeSeconds: newestHsAge,
		HandshakingPeers:          handshaking,
	}}

	resp := &nodev1.GetStatusResponse{
		AgentVersion:  s.version,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		Services:      services,
		Amneziawg:     s.awgNode.Info(),
		// The revision the node has actually applied — coxswain diffs this
		// against its intended config_revision to catch a stale data plane.
		AppliedRevision: s.primary().AppliedRevision(),
	}

	// XRay/REALITY identity + health. The node always owns a REALITY keypair
	// (coxswain needs the public key to provision a matching client), even
	// before the service is configured up.
	if s.xray != nil {
		xRunning, xListening, xPeers, xDetail := s.xray.Status()
		resp.Services = append(resp.Services, &nodev1.ServiceStatus{
			Protocol:  nodev1.Protocol_PROTOCOL_XRAY_REALITY,
			Running:   xRunning,
			Listening: xListening,
			PeerCount: xPeers,
			Detail:    xDetail,
			// REALITY has no WireGuard-style handshake to age; not applicable.
			NewestHandshakeAgeSeconds: -1,
			HandshakingPeers:          0,
		})
		resp.Xray = s.xray.Info()
	}
	return resp, nil
}

// WatchEvents streams live data-plane events to coxswain: handshake up/down,
// peer connect/disconnect, observer errors. coxswain holds the stream open;
// this is what makes the admin UI live (DESIGN §7). The first events fire
// once the observer has its baseline (one poll cycle after Manager.Start),
// so a new stream on a quiet node may see no traffic until something
// changes — that's expected.
func (s *service) WatchEvents(_ *nodev1.WatchEventsRequest, stream nodev1.NodeControl_WatchEventsServer) error {
	events, cancel := s.primary().Subscribe()
	defer cancel()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				// Observer shut down (node is exiting); end the stream cleanly.
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// PushConfig replaces the data-plane peer set for one protocol.
//
// The wire encoding of req.config is fixed by the proto comment:
// PROTOCOL_AMNEZIAWG carries proto.Marshal of AmneziaWGConfig (decision: docs
// PR #11 / coxswain PR #28); PROTOCOL_XRAY_REALITY carries proto.Marshal of
// XRayRealityConfig (the VLESS client set + REALITY camouflage policy). The
// node-level secrets are deliberately not in either config — node owns them
// (awg-node.json / xray-node.json), and a request that somehow carries them
// would be ignored.
func (s *service) PushConfig(ctx context.Context, req *nodev1.PushConfigRequest) (*nodev1.PushConfigResponse, error) {
	switch req.GetProtocol() {
	case nodev1.Protocol_PROTOCOL_AMNEZIAWG:
		return s.pushAmneziaWG(ctx, req)
	case nodev1.Protocol_PROTOCOL_XRAY_REALITY:
		return s.pushXRay(ctx, req)
	default:
		return nil, status.Errorf(codes.Unimplemented,
			"PushConfig: protocol %s not yet implemented", req.GetProtocol())
	}
}

func (s *service) pushAmneziaWG(ctx context.Context, req *nodev1.PushConfigRequest) (*nodev1.PushConfigResponse, error) {
	var cfg nodev1.AmneziaWGConfig
	if err := proto.Unmarshal(req.GetConfig(), &cfg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"PushConfig: decode AmneziaWGConfig: %v", err)
	}

	peers := make([]awg.ConfPeer, 0, len(cfg.GetPeers()))
	for _, p := range cfg.GetPeers() {
		if p == nil || p.GetPublicKey() == "" {
			return nil, status.Error(codes.InvalidArgument,
				"PushConfig: peer missing public_key")
		}
		peers = append(peers, awg.ConfPeer{
			PublicKey:    p.GetPublicKey(),
			PresharedKey: p.GetPresharedKey(),
			AllowedIPs:   append([]string(nil), p.GetAllowedIps()...),
			Endpoint:     awg.FirstEndpoint(p.GetEndpoints()),
		})
	}

	applied, reloaded, err := s.primary().PushConfig(ctx, req.GetRevision(), peers)
	if err != nil {
		var stale awg.ErrStaleRevision
		if errors.As(err, &stale) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"PushConfig: %s", stale.Error())
		}
		return nil, status.Errorf(codes.Internal, "PushConfig: %v", err)
	}
	return &nodev1.PushConfigResponse{
		AppliedRevision: applied,
		Reloaded:        reloaded,
	}, nil
}

// pushXRay applies the full XRay/REALITY config: the VLESS client set plus the
// REALITY camouflage policy (decoy dest, accepted SNIs, shortIds, port). The
// node's REALITY keypair is its own identity and is not carried on the wire.
func (s *service) pushXRay(_ context.Context, req *nodev1.PushConfigRequest) (*nodev1.PushConfigResponse, error) {
	if s.xray == nil {
		return nil, status.Error(codes.Unimplemented, "PushConfig: XRay runtime not enabled on this node")
	}
	var cfg nodev1.XRayRealityConfig
	if err := proto.Unmarshal(req.GetConfig(), &cfg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"PushConfig: decode XRayRealityConfig: %v", err)
	}
	if cfg.GetPort() == 0 {
		return nil, status.Error(codes.InvalidArgument, "PushConfig: XRay port required")
	}
	clients := make([]xray.Client, 0, len(cfg.GetPeers()))
	for _, p := range cfg.GetPeers() {
		uuid := xrayClientID(p)
		if uuid == "" {
			return nil, status.Error(codes.InvalidArgument,
				"PushConfig: XRay peer missing id (VLESS UUID)")
		}
		clients = append(clients, xray.Client{UUID: uuid, Flow: p.GetFlow()})
	}
	applied, reloaded, err := s.xray.Apply(req.GetRevision(), xray.Config{
		Port:        cfg.GetPort(),
		Dest:        cfg.GetDest(),
		ServerNames: append([]string(nil), cfg.GetServerNames()...),
		ShortIDs:    append([]string(nil), cfg.GetShortIds()...),
		Clients:     clients,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "PushConfig: %v", err)
	}
	return &nodev1.PushConfigResponse{AppliedRevision: applied, Reloaded: reloaded}, nil
}

// xrayClientID returns the VLESS UUID for an XRay peer. coxswain carries the
// UUID in the peer's public_key field (peers.public_key holds the UUID for
// XRay, the WireGuard key for AmneziaWG); peer.id is coxswain's row id, not the
// UUID. RemovePeer likewise identifies an XRay client by public_key. id is only
// a fallback for a caller that put the UUID there.
func xrayClientID(p *nodev1.Peer) string {
	if pk := p.GetPublicKey(); pk != "" {
		return pk
	}
	return p.GetId()
}

// AddPeer adds one peer live. AmneziaWG adds a WireGuard peer; XRay/REALITY
// adds a VLESS client (its UUID + flow) and live-reloads the server.
func (s *service) AddPeer(ctx context.Context, req *nodev1.AddPeerRequest) (*nodev1.PeerResponse, error) {
	peer := req.GetPeer()
	if peer == nil {
		return nil, status.Error(codes.InvalidArgument, "AddPeer: missing peer")
	}
	switch peer.GetProtocol() {
	case nodev1.Protocol_PROTOCOL_AMNEZIAWG:
		applied, err := s.primary().AddPeer(ctx, peer)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "AddPeer: %v", err)
		}
		return &nodev1.PeerResponse{PeerId: peer.GetId(), Applied: applied}, nil
	case nodev1.Protocol_PROTOCOL_XRAY_REALITY:
		if s.xray == nil {
			return nil, status.Error(codes.Unimplemented, "AddPeer: XRay runtime not enabled on this node")
		}
		uuid := xrayClientID(peer)
		if uuid == "" {
			return nil, status.Error(codes.InvalidArgument, "AddPeer: XRay peer missing id (VLESS UUID)")
		}
		applied, err := s.xray.AddClient(xray.Client{UUID: uuid, Flow: peer.GetFlow()})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "AddPeer: %v", err)
		}
		return &nodev1.PeerResponse{PeerId: uuid, Applied: applied}, nil
	default:
		return nil, status.Errorf(codes.Unimplemented,
			"AddPeer: protocol %s not yet implemented", peer.GetProtocol())
	}
}

// RemovePeer revokes one peer live. For AmneziaWG public_key is the WireGuard
// key; for XRay/REALITY public_key carries the VLESS UUID to drop.
func (s *service) RemovePeer(ctx context.Context, req *nodev1.RemovePeerRequest) (*nodev1.PeerResponse, error) {
	switch req.GetProtocol() {
	case nodev1.Protocol_PROTOCOL_AMNEZIAWG:
		if req.GetPublicKey() == "" {
			return nil, status.Error(codes.InvalidArgument, "RemovePeer: missing public_key")
		}
		applied, err := s.primary().RemovePeer(ctx, req.GetPublicKey())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "RemovePeer: %v", err)
		}
		return &nodev1.PeerResponse{Applied: applied}, nil
	case nodev1.Protocol_PROTOCOL_XRAY_REALITY:
		if s.xray == nil {
			return nil, status.Error(codes.Unimplemented, "RemovePeer: XRay runtime not enabled on this node")
		}
		if req.GetPublicKey() == "" {
			return nil, status.Error(codes.InvalidArgument, "RemovePeer: missing public_key (VLESS UUID)")
		}
		applied, err := s.xray.RemoveClient(req.GetPublicKey())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "RemovePeer: %v", err)
		}
		return &nodev1.PeerResponse{Applied: applied}, nil
	default:
		return nil, status.Errorf(codes.Unimplemented,
			"RemovePeer: protocol %s not yet implemented", req.GetProtocol())
	}
}

// SetNetworkConfig applies the node's forwarding / masquerade / isolation
// policy (DESIGN §3, decision 16). coxswain sends the policy as three bools;
// node renders the canonical rule set, substitutes its own interface names, and
// applies it live (netfilter/sysctl only — established tunnels are not
// dropped). The policy is persisted so it is re-established on cold start.
func (s *service) SetNetworkConfig(ctx context.Context, req *nodev1.SetNetworkConfigRequest) (*nodev1.SetNetworkConfigResponse, error) {
	cfg := req.GetConfig()
	if cfg == nil {
		return nil, status.Error(codes.InvalidArgument, "SetNetworkConfig: missing config")
	}
	p := netpolicy.Policy{
		Forwarding: cfg.GetForwarding(),
		Masquerade: cfg.GetMasquerade(),
		Isolation:  cfg.GetIsolation(),
	}
	for _, t := range cfg.GetTransits() {
		p.Transits = append(p.Transits, netpolicy.TransitRoute{
			DeviceCIDR:     t.GetDeviceCidr(),
			InnerInterface: t.GetInnerInterface(),
			Mark:           t.GetMark(),
			Table:          t.GetTable(),
		})
	}
	if err := p.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "SetNetworkConfig: %v", err)
	}
	if err := s.netPolicy.Apply(ctx, p); err != nil {
		return nil, status.Errorf(codes.Internal, "SetNetworkConfig: %v", err)
	}
	return &nodev1.SetNetworkConfigResponse{Applied: true}, nil
}

// ConfigureInnerLink creates or updates a node→node inner AmneziaWG link on
// this entry node toward an exit (DESIGN §3, node cascade). The inner interface
// reuses this node's key but adopts the exit's listen port and obfuscation so
// the handshake matches; the single peer is the exit, which this node dials.
// Reconfiguring an existing link updates its peer set live (e.g. a new exit
// endpoint); changing the link's obfuscation or port needs RemoveInnerLink
// first.
func (s *service) ConfigureInnerLink(ctx context.Context, req *nodev1.ConfigureInnerLinkRequest) (*nodev1.ConfigureInnerLinkResponse, error) {
	cfg := req.GetConfig()
	if cfg == nil {
		return nil, status.Error(codes.InvalidArgument, "ConfigureInnerLink: missing config")
	}
	iface := cfg.GetInterface()
	if iface == "" {
		return nil, status.Error(codes.InvalidArgument, "ConfigureInnerLink: missing interface")
	}
	exit := cfg.GetExit()
	if exit == nil || exit.GetPublicKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "ConfigureInnerLink: missing exit public_key")
	}
	if len(exit.GetEndpoints()) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"ConfigureInnerLink: exit needs an endpoint — the entry dials it")
	}

	obf := awg.ObfuscationFromProto(cfg.GetPeerObfuscation())
	if err := obf.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "ConfigureInnerLink: exit obfuscation: %v", err)
	}
	spec := s.awgNode.InnerLinkSpec(uint16(cfg.GetListenPort()), uint16(cfg.GetMtu()), obf)

	m, err := s.awgReg.Ensure(iface, spec)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "ConfigureInnerLink: %v", err)
	}

	exitPeer := awg.ConfPeer{
		PublicKey:    exit.GetPublicKey(),
		PresharedKey: exit.GetPresharedKey(),
		AllowedIPs:   append([]string(nil), exit.GetAllowedIps()...),
		Endpoint:     awg.FirstEndpoint(exit.GetEndpoints()),
	}
	applied, reloaded, err := m.PushConfig(ctx, req.GetRevision(), []awg.ConfPeer{exitPeer})
	if err != nil {
		var stale awg.ErrStaleRevision
		if errors.As(err, &stale) {
			return nil, status.Errorf(codes.FailedPrecondition, "ConfigureInnerLink: %s", stale.Error())
		}
		return nil, status.Errorf(codes.Internal, "ConfigureInnerLink: %v", err)
	}
	return &nodev1.ConfigureInnerLinkResponse{AppliedRevision: applied, Reloaded: reloaded}, nil
}

// RemoveInnerLink tears down a previously configured inner link: the interface
// is brought down and its conf + revision removed. It is idempotent.
func (s *service) RemoveInnerLink(ctx context.Context, req *nodev1.RemoveInnerLinkRequest) (*nodev1.RemoveInnerLinkResponse, error) {
	iface := req.GetInterface()
	if iface == "" {
		return nil, status.Error(codes.InvalidArgument, "RemoveInnerLink: missing interface")
	}
	if err := s.awgReg.Remove(ctx, iface); err != nil {
		return nil, status.Errorf(codes.Internal, "RemoveInnerLink: %v", err)
	}
	return &nodev1.RemoveInnerLinkResponse{Removed: true}, nil
}

// ListPeers returns the configured peers for one protocol. AmneziaWG (also the
// default for PROTOCOL_UNSPECIFIED) joins the conf with live awg0 state; XRay
// returns the configured VLESS client set (REALITY exposes no per-client live
// state without the stats API, so those fields stay zero).
func (s *service) ListPeers(ctx context.Context, req *nodev1.ListPeersRequest) (*nodev1.ListPeersResponse, error) {
	switch req.GetProtocol() {
	case nodev1.Protocol_PROTOCOL_AMNEZIAWG, nodev1.Protocol_PROTOCOL_UNSPECIFIED:
		peers, err := s.primary().ListPeers(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "ListPeers: %v", err)
		}
		return &nodev1.ListPeersResponse{Peers: peers}, nil
	case nodev1.Protocol_PROTOCOL_XRAY_REALITY:
		if s.xray == nil {
			return nil, status.Error(codes.Unimplemented, "ListPeers: XRay runtime not enabled on this node")
		}
		clients := s.xray.Clients()
		states := make([]*nodev1.PeerState, 0, len(clients))
		for _, c := range clients {
			states = append(states, &nodev1.PeerState{
				Peer: &nodev1.Peer{
					Id:        c.UUID,
					PublicKey: c.UUID, // identity carried in both fields for matching
					Protocol:  nodev1.Protocol_PROTOCOL_XRAY_REALITY,
					Flow:      c.Flow,
				},
			})
		}
		return &nodev1.ListPeersResponse{Peers: states}, nil
	default:
		return nil, status.Errorf(codes.Unimplemented,
			"ListPeers: protocol %s not yet implemented", req.GetProtocol())
	}
}

// RestartService reloads a protocol's data plane in place. AmneziaWG
// re-applies the persisted interface conf (bringing it up if down, live-
// reloading it if up — no established tunnel is dropped); XRay/REALITY swaps
// in a fresh xray-core instance from the current config. It is the
// last-resort recovery action coxswain drives from the admin UI.
func (s *service) RestartService(ctx context.Context, req *nodev1.RestartServiceRequest) (*nodev1.RestartServiceResponse, error) {
	switch req.GetProtocol() {
	case nodev1.Protocol_PROTOCOL_AMNEZIAWG:
		if err := s.primary().Reconcile(ctx); err != nil {
			return nil, status.Errorf(codes.Internal, "RestartService: %v", err)
		}
		return &nodev1.RestartServiceResponse{Restarted: true}, nil
	case nodev1.Protocol_PROTOCOL_XRAY_REALITY:
		if s.xray == nil {
			return nil, status.Error(codes.Unimplemented, "RestartService: XRay runtime not enabled on this node")
		}
		if err := s.xray.Restart(); err != nil {
			return nil, status.Errorf(codes.Internal, "RestartService: %v", err)
		}
		return &nodev1.RestartServiceResponse{Restarted: true}, nil
	default:
		return nil, status.Errorf(codes.Unimplemented,
			"RestartService: protocol %s not yet implemented", req.GetProtocol())
	}
}
