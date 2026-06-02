// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
)

// TestLiveAmneziaWG drives the Manager against a real `awg`/`awg-quick`
// pipeline. It exercises the full coxswain→node data-plane handoff that B2 is
// the unblocker for: PushConfig brings the interface up; ListPeers shows the
// pushed peers; AddPeer mutates live state; RemovePeer reverts it.
//
// It skips cleanly when the prerequisites are absent — none of which are
// present in default CI:
//   - `awg` and `awg-quick` on PATH (install AmneziaWG)
//   - root privileges (creating a WireGuard interface needs CAP_NET_ADMIN)
//   - the AmneziaWG kernel module loaded or `amneziawg-go` userspace driver
//
// On a dev box with AmneziaWG installed: `sudo -E go test -run LiveAmneziaWG ./internal/awg/...`.
func TestLiveAmneziaWG(t *testing.T) {
	if _, err := exec.LookPath("awg"); err != nil {
		t.Skip("awg not on PATH — install AmneziaWG userspace to run this test")
	}
	if _, err := exec.LookPath("awg-quick"); err != nil {
		t.Skip("awg-quick not on PATH")
	}
	if os.Geteuid() != 0 {
		t.Skip("LiveAmneziaWG needs root (creating a WireGuard interface)")
	}

	// Use a collision-safe interface name so the test never touches a real
	// awg0 on a dev machine.
	const iface = "awg-nodeit"
	dir := t.TempDir()
	confPath := filepath.Join(dir, iface+".conf")
	node, err := Load(filepath.Join(dir, "awg-node.json"))
	if err != nil {
		t.Fatal(err)
	}
	rt := &ExecRuntime{Interface: iface}
	mgr, err := NewManager(ManagerOptions{
		Node:         node,
		Runtime:      rt,
		ConfPath:     confPath,
		RevisionPath: filepath.Join(dir, "awg-revision"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Guarantee teardown even if an assertion fails part-way through.
	t.Cleanup(func() {
		_ = exec.Command("awg-quick", "down", confPath).Run()
	})

	ctx := context.Background()
	peers := []ConfPeer{
		{PublicKey: keyA, AllowedIPs: []string{"10.66.66.2/32"}},
		{PublicKey: keyB, AllowedIPs: []string{"10.66.66.3/32"}},
	}
	if _, reloaded, err := mgr.PushConfig(ctx, 1, peers); err != nil || !reloaded {
		t.Fatalf("PushConfig: reloaded=%v err=%v", reloaded, err)
	}

	listed, err := mgr.ListPeers(ctx)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("ListPeers = %d peers, want 2", len(listed))
	}

	addReq := &nodev1.Peer{
		Protocol:   nodev1.Protocol_PROTOCOL_AMNEZIAWG,
		PublicKey:  keyC,
		AllowedIps: []string{"10.66.66.4/32"},
	}
	if applied, err := mgr.AddPeer(ctx, addReq); err != nil || !applied {
		t.Fatalf("AddPeer: applied=%v err=%v", applied, err)
	}
	if live, _ := rt.Show(ctx); len(live) != 3 {
		t.Errorf("`awg show` peers = %d, want 3", len(live))
	}

	if _, err := mgr.RemovePeer(ctx, keyA); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	listed, _ = mgr.ListPeers(ctx)
	if len(listed) != 2 {
		t.Errorf("ListPeers after remove = %d, want 2", len(listed))
	}
	for _, p := range listed {
		if p.GetPeer().GetPublicKey() == keyA {
			t.Errorf("removed peer %q is still listed", keyA)
		}
	}
}

// Test fixture keys — these are placeholder base64 blobs, never used as real
// WireGuard material. AmneziaWG accepts any 44-character base64 string as a
// public key for routing-table purposes (no handshake completes against
// them, but conf/show round-tripping works fine).
const (
	keyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	keyB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	keyC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
)
