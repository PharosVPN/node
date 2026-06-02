// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// startTestServer spins up a NodeControl server backed by testOptions and
// returns a ready-to-use client.
func startTestServer(t *testing.T) nodev1.NodeControlClient {
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
	return nodev1.NewNodeControlClient(conn)
}

// --- PushConfig -------------------------------------------------------------

func TestPushConfigRoundTrip(t *testing.T) {
	c := startTestServer(t)
	cfg := &nodev1.AmneziaWGConfig{Peers: []*nodev1.Peer{
		{Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG, PublicKey: "PUBA=", AllowedIps: []string{"10.0.0.2/32"}},
		{Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG, PublicKey: "PUBB=", PresharedKey: "PSK=", AllowedIps: []string{"10.0.0.3/32"}},
	}}
	body, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.PushConfig(context.Background(), &nodev1.PushConfigRequest{
		Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG,
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
	list, err := c.ListPeers(context.Background(), &nodev1.ListPeersRequest{
		Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG,
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
	body, _ := proto.Marshal(&nodev1.AmneziaWGConfig{})

	if _, err := c.PushConfig(context.Background(), &nodev1.PushConfigRequest{
		Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG, Revision: 5, Config: body,
	}); err != nil {
		t.Fatalf("first PushConfig: %v", err)
	}
	_, err := c.PushConfig(context.Background(), &nodev1.PushConfigRequest{
		Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG, Revision: 3, Config: body,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale revision: got %v, want FailedPrecondition", err)
	}
}

func TestPushConfigUnknownProtocol(t *testing.T) {
	c := startTestServer(t)
	_, err := c.PushConfig(context.Background(), &nodev1.PushConfigRequest{
		Protocol: nodev1.Protocol_PROTOCOL_XRAY_REALITY,
	})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("XRay PushConfig: got %v, want Unimplemented", err)
	}
}

func TestPushConfigInvalidBytes(t *testing.T) {
	c := startTestServer(t)
	_, err := c.PushConfig(context.Background(), &nodev1.PushConfigRequest{
		Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG,
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
	resp, err := c.AddPeer(context.Background(), &nodev1.AddPeerRequest{
		Peer: &nodev1.Peer{
			Id:           "p1",
			Protocol:     nodev1.Protocol_PROTOCOL_AMNEZIAWG,
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
	_, err := c.AddPeer(context.Background(), &nodev1.AddPeerRequest{
		Peer: &nodev1.Peer{Protocol: nodev1.Protocol_PROTOCOL_XRAY_REALITY, PublicKey: "u"},
	})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("XRay AddPeer: got %v, want Unimplemented", err)
	}
}

func TestAddPeerMissingPeerIsInvalidArgument(t *testing.T) {
	c := startTestServer(t)
	_, err := c.AddPeer(context.Background(), &nodev1.AddPeerRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("AddPeer without peer: got %v, want InvalidArgument", err)
	}
}

func TestRemovePeerMissingPublicKey(t *testing.T) {
	c := startTestServer(t)
	_, err := c.RemovePeer(context.Background(), &nodev1.RemovePeerRequest{
		Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("RemovePeer without key: got %v, want InvalidArgument", err)
	}
}

// --- GetMetrics -------------------------------------------------------------

func TestGetMetricsRPC(t *testing.T) {
	c := startTestServer(t)

	// Push two peers so the conf has something to correlate against. The
	// stub Runtime reports no live state, so per-peer counters stay zero —
	// the test asserts the response shape, not live byte totals (those are
	// covered by Manager-level tests with a richer fake).
	cfg := &nodev1.AmneziaWGConfig{Peers: []*nodev1.Peer{
		{Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG, PublicKey: "A=", AllowedIps: []string{"10.0.0.2/32"}},
		{Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG, PublicKey: "B=", AllowedIps: []string{"10.0.0.3/32"}},
	}}
	body, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushConfig(context.Background(), &nodev1.PushConfigRequest{
		Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG, Revision: 1, Config: body,
	}); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	resp, err := c.GetMetrics(context.Background(), &nodev1.GetMetricsRequest{})
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if len(resp.GetPeers()) != 2 {
		t.Errorf("peers = %d, want 2", len(resp.GetPeers()))
	}
	// handshakes_total / errors_total are reserved for B5's poller.
	if resp.GetHandshakesTotal() != 0 || resp.GetErrorsTotal() != 0 {
		t.Errorf("expected zero cumulative counters in B4: %+v", resp)
	}
}

// --- WatchEvents ------------------------------------------------------------

// TestWatchEventsClosesOnClientCancel proves the server-stream plumbing:
// the client opens WatchEvents, cancels its context, and the server-side
// stream returns cleanly without leaking the subscriber. Detailed event
// detection is covered under package awg.
func TestWatchEventsClosesOnClientCancel(t *testing.T) {
	c := startTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := c.WatchEvents(ctx, &nodev1.WatchEventsRequest{})
	if err != nil {
		t.Fatalf("WatchEvents: %v", err)
	}

	// Cancel the client side; Recv should return promptly with the
	// cancellation error.
	done := make(chan error, 1)
	go func() {
		_, recvErr := stream.Recv()
		done <- recvErr
	}()
	cancel()

	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled && !errors.Is(err, context.Canceled) {
			t.Errorf("Recv after cancel: got %v, want Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv did not return after client cancel")
	}
}

// --- GetStatus health -------------------------------------------------------

func TestGetStatusIncludesAmneziaWGService(t *testing.T) {
	c := startTestServer(t)
	resp, err := c.GetStatus(context.Background(), &nodev1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	var awg *nodev1.ServiceStatus
	for _, svc := range resp.GetServices() {
		if svc.GetProtocol() == nodev1.Protocol_PROTOCOL_AMNEZIAWG {
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
