// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package xray

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"testing"
)

// TestIdentityPersistAndReload checks the REALITY identity is generated once,
// persisted, and reloads to the same keypair — coxswain caches the public key,
// so it must be stable across restarts.
func TestIdentityPersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray-node.json")

	id, err := Load(path)
	if err != nil {
		t.Fatalf("Load (generate): %v", err)
	}
	priv, pub := id.PrivateKey(), id.PublicKey()

	// Keys must be valid base64url-encoded 32-byte Curve25519 values.
	for name, key := range map[string]string{"private": priv, "public": pub} {
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			t.Fatalf("%s key not base64url: %v", name, err)
		}
		if len(raw) != 32 {
			t.Fatalf("%s key is %d bytes, want 32", name, len(raw))
		}
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load (reload): %v", err)
	}
	if reloaded.PrivateKey() != priv || reloaded.PublicKey() != pub {
		t.Fatalf("identity changed across reload:\n  priv %s -> %s\n  pub  %s -> %s",
			priv, reloaded.PrivateKey(), pub, reloaded.PublicKey())
	}
	if reloaded.Info().GetPublicKey() != pub {
		t.Fatalf("Info public key %q, want %q", reloaded.Info().GetPublicKey(), pub)
	}
}

// TestRuntimeStartsRealityServer drives the full render → load → start path of
// the embedded xray-core: a VLESS+REALITY server actually binds a port. It also
// exercises live client add/remove and teardown (port 0). This is the in-repo
// equivalent of the embedding de-risk probe.
func TestRuntimeStartsRealityServer(t *testing.T) {
	id, err := Load(filepath.Join(t.TempDir(), "xray-node.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rt := NewRuntime(id, slog.New(slog.NewTextHandler(io.Discard, nil)))

	port := freePort(t)
	cfg := Config{
		Port:        uint32(port),
		Dest:        "www.microsoft.com:443",
		ServerNames: []string{"www.microsoft.com"},
		ShortIDs:    []string{""},
		Clients:     []Client{{UUID: "11111111-1111-1111-1111-111111111111", Flow: "xtls-rprx-vision"}},
	}

	applied, reloaded, err := rt.Apply(1, cfg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if applied != 1 || !reloaded {
		t.Fatalf("Apply = (%d, %v), want (1, true)", applied, reloaded)
	}
	running, listening, count, _ := rt.Status()
	if !running || !listening || count != 1 {
		t.Fatalf("Status = (running=%v, listening=%v, count=%d), want (true, true, 1)", running, listening, count)
	}
	// The REALITY server must actually be accepting TCP on the port.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial running REALITY server: %v", err)
	}
	_ = conn.Close()

	// Stale revision is rejected; an equal one is a no-op.
	if _, _, err := rt.Apply(0, cfg); err == nil {
		t.Fatal("Apply with stale revision 0 should fail")
	}

	// Live client add/remove reload the server.
	added, err := rt.AddClient(Client{UUID: "22222222-2222-2222-2222-222222222222"})
	if err != nil || !added {
		t.Fatalf("AddClient = (%v, %v), want (true, nil)", added, err)
	}
	if got := len(rt.Clients()); got != 2 {
		t.Fatalf("Clients = %d, want 2", got)
	}
	removed, err := rt.RemoveClient("22222222-2222-2222-2222-222222222222")
	if err != nil || !removed {
		t.Fatalf("RemoveClient = (%v, %v), want (true, nil)", removed, err)
	}
	if got := len(rt.Clients()); got != 1 {
		t.Fatalf("Clients after remove = %d, want 1", got)
	}

	// Port 0 tears the service down.
	if _, _, err := rt.Apply(2, Config{}); err != nil {
		t.Fatalf("Apply (teardown): %v", err)
	}
	if running, _, _, _ := rt.Status(); running {
		t.Fatal("Status running after teardown, want down")
	}
	rt.Stop()
}

// freePort returns a TCP port that was free at the moment of the call.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
