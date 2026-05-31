// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package control

import (
	"context"
	"errors"
	"time"

	"github.com/PharosVPN/buoy/internal/awg"
	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
	"github.com/PharosVPN/buoy/internal/netpolicy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// service implements the NodeControl gRPC service.
//
// GetStatus reports the node's AmneziaWG identity (coxswain refuses to provision
// devices until it has it — DESIGN §3) and the AmneziaWG service health.
// PushConfig, AddPeer, RemovePeer, ListPeers manage the AmneziaWG peer set
// (B2). GetMetrics reports counters (B4) — totals from the conf+live join
// plus cumulative handshakes_total / errors_total fed by the observer.
// WatchEvents streams the observer's live events (B5). SetNetworkConfig applies
// the node's forwarding / masquerade / isolation policy (decision 16). XRay
// management lands in B3 — those calls return Unimplemented for now.
type service struct {
	buoyv1.UnimplementedNodeControlServer

	version    string
	started    time.Time
	awgNode    *awg.Node
	awgManager *awg.Manager
	netPolicy  *netpolicy.Applier
}

// newService returns a NodeControl service implementation.
func newService(version string, awgNode *awg.Node, awgManager *awg.Manager, netPolicy *netpolicy.Applier) *service {
	return &service{
		version:    version,
		started:    time.Now(),
		awgNode:    awgNode,
		awgManager: awgManager,
		netPolicy:  netPolicy,
	}
}

// GetMetrics reports the data plane's current counters. AmneziaWG metrics
// come from the same conf+live correlation as ListPeers, with summed totals.
// handshakes_total / errors_total are reserved for the B5 polling observer
// that also feeds WatchEvents — they stay at zero in B4. XRay metrics land
// in B3.
func (s *service) GetMetrics(ctx context.Context, _ *buoyv1.GetMetricsRequest) (*buoyv1.GetMetricsResponse, error) {
	snap, err := s.awgManager.Metrics(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetMetrics: %v", err)
	}
	return &buoyv1.GetMetricsResponse{
		Peers:           snap.Peers,
		TotalRxBytes:    snap.TotalRx,
		TotalTxBytes:    snap.TotalTx,
		HandshakesTotal: snap.Handshakes,
		ErrorsTotal:     snap.Errors,
	}, nil
}

// GetStatus reports the node's agent version, uptime, the AmneziaWG server
// identity, and per-protocol service health.
func (s *service) GetStatus(ctx context.Context, _ *buoyv1.GetStatusRequest) (*buoyv1.GetStatusResponse, error) {
	running, listening, peerCount, detail := s.awgManager.Status(ctx)
	return &buoyv1.GetStatusResponse{
		AgentVersion:  s.version,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		Services: []*buoyv1.ServiceStatus{{
			Protocol:  buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
			Running:   running,
			Listening: listening,
			PeerCount: peerCount,
			Detail:    detail,
		}},
		Amneziawg: s.awgNode.Info(),
	}, nil
}

// WatchEvents streams live data-plane events to coxswain: handshake up/down,
// peer connect/disconnect, observer errors. coxswain holds the stream open;
// this is what makes the admin UI live (DESIGN §7). The first events fire
// once the observer has its baseline (one poll cycle after Manager.Start),
// so a new stream on a quiet node may see no traffic until something
// changes — that's expected.
func (s *service) WatchEvents(_ *buoyv1.WatchEventsRequest, stream buoyv1.NodeControl_WatchEventsServer) error {
	events, cancel := s.awgManager.Subscribe()
	defer cancel()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				// Observer shut down (buoy is exiting); end the stream cleanly.
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
// PR #11 / coxswain PR #28). XRay's encoding lands in B3; other protocols are
// Unimplemented. The node-level obfuscation parameters are deliberately not
// in AmneziaWGConfig — buoy owns them (awg-node.json), and a request that
// somehow carries them would be ignored.
func (s *service) PushConfig(ctx context.Context, req *buoyv1.PushConfigRequest) (*buoyv1.PushConfigResponse, error) {
	if req.GetProtocol() != buoyv1.Protocol_PROTOCOL_AMNEZIAWG {
		return nil, status.Errorf(codes.Unimplemented,
			"PushConfig: protocol %s not yet implemented", req.GetProtocol())
	}

	var cfg buoyv1.AmneziaWGConfig
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
		})
	}

	applied, reloaded, err := s.awgManager.PushConfig(ctx, req.GetRevision(), peers)
	if err != nil {
		var stale awg.ErrStaleRevision
		if errors.As(err, &stale) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"PushConfig: %s", stale.Error())
		}
		return nil, status.Errorf(codes.Internal, "PushConfig: %v", err)
	}
	return &buoyv1.PushConfigResponse{
		AppliedRevision: applied,
		Reloaded:        reloaded,
	}, nil
}

// AddPeer adds one peer live. Only AmneziaWG is supported in B2; XRay
// returns Unimplemented (lands in B3).
func (s *service) AddPeer(ctx context.Context, req *buoyv1.AddPeerRequest) (*buoyv1.PeerResponse, error) {
	peer := req.GetPeer()
	if peer == nil {
		return nil, status.Error(codes.InvalidArgument, "AddPeer: missing peer")
	}
	if peer.GetProtocol() != buoyv1.Protocol_PROTOCOL_AMNEZIAWG {
		return nil, status.Errorf(codes.Unimplemented,
			"AddPeer: protocol %s not yet implemented", peer.GetProtocol())
	}
	applied, err := s.awgManager.AddPeer(ctx, peer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "AddPeer: %v", err)
	}
	return &buoyv1.PeerResponse{PeerId: peer.GetId(), Applied: applied}, nil
}

// RemovePeer revokes one peer live. Only AmneziaWG is supported in B2.
func (s *service) RemovePeer(ctx context.Context, req *buoyv1.RemovePeerRequest) (*buoyv1.PeerResponse, error) {
	if req.GetProtocol() != buoyv1.Protocol_PROTOCOL_AMNEZIAWG {
		return nil, status.Errorf(codes.Unimplemented,
			"RemovePeer: protocol %s not yet implemented", req.GetProtocol())
	}
	if req.GetPublicKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "RemovePeer: missing public_key")
	}
	applied, err := s.awgManager.RemovePeer(ctx, req.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "RemovePeer: %v", err)
	}
	return &buoyv1.PeerResponse{Applied: applied}, nil
}

// SetNetworkConfig applies the node's forwarding / masquerade / isolation
// policy (DESIGN §3, decision 16). coxswain sends the policy as three bools;
// buoy renders the canonical rule set, substitutes its own interface names, and
// applies it live (netfilter/sysctl only — established tunnels are not
// dropped). The policy is persisted so it is re-established on cold start.
func (s *service) SetNetworkConfig(ctx context.Context, req *buoyv1.SetNetworkConfigRequest) (*buoyv1.SetNetworkConfigResponse, error) {
	cfg := req.GetConfig()
	if cfg == nil {
		return nil, status.Error(codes.InvalidArgument, "SetNetworkConfig: missing config")
	}
	p := netpolicy.Policy{
		Forwarding: cfg.GetForwarding(),
		Masquerade: cfg.GetMasquerade(),
		Isolation:  cfg.GetIsolation(),
	}
	if err := p.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "SetNetworkConfig: %v", err)
	}
	if err := s.netPolicy.Apply(ctx, p); err != nil {
		return nil, status.Errorf(codes.Internal, "SetNetworkConfig: %v", err)
	}
	return &buoyv1.SetNetworkConfigResponse{Applied: true}, nil
}

// ListPeers returns configured peers joined with their live state on awg0.
// Filtering by XRay returns Unimplemented; PROTOCOL_UNSPECIFIED is treated
// as AmneziaWG-only until B3 lands XRay.
func (s *service) ListPeers(ctx context.Context, req *buoyv1.ListPeersRequest) (*buoyv1.ListPeersResponse, error) {
	switch req.GetProtocol() {
	case buoyv1.Protocol_PROTOCOL_AMNEZIAWG, buoyv1.Protocol_PROTOCOL_UNSPECIFIED:
	default:
		return nil, status.Errorf(codes.Unimplemented,
			"ListPeers: protocol %s not yet implemented", req.GetProtocol())
	}
	peers, err := s.awgManager.ListPeers(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ListPeers: %v", err)
	}
	return &buoyv1.ListPeersResponse{Peers: peers}, nil
}
