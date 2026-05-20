// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package control

import (
	"context"
	"testing"

	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// startTestServer spins up a NodeControl server backed by testOptions and
// returns a ready-to-use client.
func startTestServer(t *testing.T) buoyv1.NodeControlClient {
	t.Helper()
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.writeNodeFiles(t, dir)
	addr := freeAddr(t)

	srv, err := NewServer(testOptions(t, dir, addr))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	conn := dial(t, addr, ca.clientCreds(t))
	return buoyv1.NewNodeControlClient(conn)
}

// --- PushConfig -------------------------------------------------------------

func TestPushConfigRoundTrip(t *testing.T) {
	c := startTestServer(t)
	cfg := &buoyv1.AmneziaWGConfig{Peers: []*buoyv1.Peer{
		{Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG, PublicKey: "PUBA=", AllowedIps: []string{"10.0.0.2/32"}},
		{Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG, PublicKey: "PUBB=", PresharedKey: "PSK=", AllowedIps: []string{"10.0.0.3/32"}},
	}}
	body, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.PushConfig(context.Background(), &buoyv1.PushConfigRequest{
		Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
		Revision: 1,
		Config:   body,
	})
	if err != nil {
		t.Fatalf("PushConfig: %v", err)
	}
	if resp.GetAppliedRevision() != 1 || !resp.GetReloaded() {
		t.Errorf("response = %+v, want applied=1 reloaded=true", resp)
	}

	// ListPeers should now reflect both pushed peers — the conf is the
	// source of truth even when live state is empty.
	list, err := c.ListPeers(context.Background(), &buoyv1.ListPeersRequest{
		Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
	})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list.GetPeers()) != 2 {
		t.Errorf("peers = %d, want 2", len(list.GetPeers()))
	}
}

func TestPushConfigStaleRevision(t *testing.T) {
	c := startTestServer(t)
	body, _ := proto.Marshal(&buoyv1.AmneziaWGConfig{})

	if _, err := c.PushConfig(context.Background(), &buoyv1.PushConfigRequest{
		Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG, Revision: 5, Config: body,
	}); err != nil {
		t.Fatalf("first PushConfig: %v", err)
	}
	_, err := c.PushConfig(context.Background(), &buoyv1.PushConfigRequest{
		Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG, Revision: 3, Config: body,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale revision: got %v, want FailedPrecondition", err)
	}
}

func TestPushConfigUnknownProtocol(t *testing.T) {
	c := startTestServer(t)
	_, err := c.PushConfig(context.Background(), &buoyv1.PushConfigRequest{
		Protocol: buoyv1.Protocol_PROTOCOL_XRAY_REALITY,
	})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("XRay PushConfig: got %v, want Unimplemented", err)
	}
}

func TestPushConfigInvalidBytes(t *testing.T) {
	c := startTestServer(t)
	_, err := c.PushConfig(context.Background(), &buoyv1.PushConfigRequest{
		Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
		Revision: 1,
		Config:   []byte{0xff, 0xff, 0xff}, // garbage
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("malformed config: got %v, want InvalidArgument", err)
	}
}

// --- AddPeer / RemovePeer ---------------------------------------------------

func TestAddPeerRPC(t *testing.T) {
	c := startTestServer(t)
	resp, err := c.AddPeer(context.Background(), &buoyv1.AddPeerRequest{
		Peer: &buoyv1.Peer{
			Id:           "p1",
			Protocol:     buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
			PublicKey:    "PUB=",
			PresharedKey: "PSK=",
			AllowedIps:   []string{"10.0.0.2/32"},
		},
	})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if !resp.GetApplied() || resp.GetPeerId() != "p1" {
		t.Errorf("response = %+v, want applied=true peer_id=p1", resp)
	}
}

func TestAddPeerProtocolMismatchIsUnimplemented(t *testing.T) {
	c := startTestServer(t)
	_, err := c.AddPeer(context.Background(), &buoyv1.AddPeerRequest{
		Peer: &buoyv1.Peer{Protocol: buoyv1.Protocol_PROTOCOL_XRAY_REALITY, PublicKey: "u"},
	})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("XRay AddPeer: got %v, want Unimplemented", err)
	}
}

func TestAddPeerMissingPeerIsInvalidArgument(t *testing.T) {
	c := startTestServer(t)
	_, err := c.AddPeer(context.Background(), &buoyv1.AddPeerRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("AddPeer without peer: got %v, want InvalidArgument", err)
	}
}

func TestRemovePeerMissingPublicKey(t *testing.T) {
	c := startTestServer(t)
	_, err := c.RemovePeer(context.Background(), &buoyv1.RemovePeerRequest{
		Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("RemovePeer without key: got %v, want InvalidArgument", err)
	}
}

// --- GetStatus health -------------------------------------------------------

func TestGetStatusIncludesAmneziaWGService(t *testing.T) {
	c := startTestServer(t)
	resp, err := c.GetStatus(context.Background(), &buoyv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	var awg *buoyv1.ServiceStatus
	for _, svc := range resp.GetServices() {
		if svc.GetProtocol() == buoyv1.Protocol_PROTOCOL_AMNEZIAWG {
			awg = svc
		}
	}
	if awg == nil {
		t.Fatal("GetStatus missing PROTOCOL_AMNEZIAWG ServiceStatus")
	}
	// stubRuntime reports the interface as down — no PushConfig has run.
	if awg.GetRunning() || awg.GetListening() {
		t.Errorf("service status = %+v, want down (no apply yet)", awg)
	}
}
