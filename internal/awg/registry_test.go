// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newIfaceManager builds a Manager for a named interface in dir, backed by a
// fresh fake runtime, with an explicit InterfaceSpec (the inner-link case).
func newIfaceManager(t *testing.T, dir, iface string, spec InterfaceSpec) (*Manager, *fakeRuntime) {
	t.Helper()
	rt := newFakeRuntime()
	m, err := NewManager(ManagerOptions{
		Interface:    iface,
		Spec:         &spec,
		Runtime:      rt,
		ConfPath:     filepath.Join(dir, iface+".conf"),
		RevisionPath: filepath.Join(dir, iface+"-revision"),
	})
	if err != nil {
		t.Fatalf("NewManager(%s): %v", iface, err)
	}
	return m, rt
}

func TestRegistryPrimaryAddGet(t *testing.T) {
	primary, _ := newTestManager(t) // awg0
	reg := NewRegistry(primary, nil)

	if reg.Primary() != primary {
		t.Fatal("Primary() did not return the seeded manager")
	}
	if m, ok := reg.Get("awg0"); !ok || m != primary {
		t.Fatal("Get(awg0) did not return the primary")
	}

	inner, _ := newIfaceManager(t, t.TempDir(), "awg1", InterfaceSpec{PrivateKey: "K=", ListenPort: 51820})
	if err := reg.Add(inner); err != nil {
		t.Fatalf("Add(awg1): %v", err)
	}
	if m, ok := reg.Get("awg1"); !ok || m != inner {
		t.Fatal("Get(awg1) did not return the inner manager")
	}
	if len(reg.All()) != 2 {
		t.Errorf("All() = %d managers, want 2", len(reg.All()))
	}
	// Adding the same interface again is rejected.
	if err := reg.Add(inner); err == nil {
		t.Error("Add of a duplicate interface should error")
	}
}

func TestRegistryEnsureCreatesViaFactory(t *testing.T) {
	primary, _ := newTestManager(t)
	dir := t.TempDir()
	calls := 0
	factory := func(iface string, spec InterfaceSpec) (*Manager, error) {
		calls++
		m, _ := newIfaceManager(t, dir, iface, spec)
		return m, nil
	}
	reg := NewRegistry(primary, factory)

	m1, err := reg.Ensure("awg1", InterfaceSpec{PrivateKey: "K=", ListenPort: 51820})
	if err != nil {
		t.Fatalf("Ensure(awg1): %v", err)
	}
	// A second Ensure for the same interface returns the existing manager
	// without invoking the factory again.
	m2, err := reg.Ensure("awg1", InterfaceSpec{PrivateKey: "K=", ListenPort: 51820})
	if err != nil {
		t.Fatalf("Ensure(awg1) again: %v", err)
	}
	if m1 != m2 || calls != 1 {
		t.Errorf("Ensure should be idempotent: same=%v calls=%d", m1 == m2, calls)
	}
	// Ensure on the primary name is rejected.
	if _, err := reg.Ensure("awg0", InterfaceSpec{}); err == nil {
		t.Error("Ensure on the primary interface must be rejected")
	}
	// With no factory, Ensure of a new interface errors.
	noFactory := NewRegistry(primary, nil)
	if _, err := noFactory.Ensure("awg2", InterfaceSpec{}); err == nil {
		t.Error("Ensure with no factory must error")
	}
}

func TestRegistryRemovePrimaryRejected(t *testing.T) {
	primary, _ := newTestManager(t)
	reg := NewRegistry(primary, nil)
	if err := reg.Remove(context.Background(), "awg0"); err == nil {
		t.Error("removing the primary interface must be rejected")
	}
	// Removing an unknown interface is a no-op, not an error.
	if err := reg.Remove(context.Background(), "awg9"); err != nil {
		t.Errorf("removing an unknown interface should be a no-op: %v", err)
	}
}

func TestRegistryRemoveTearsDownInterface(t *testing.T) {
	primary, _ := newTestManager(t)
	reg := NewRegistry(primary, nil)
	dir := t.TempDir()
	inner, rt := newIfaceManager(t, dir, "awg1", InterfaceSpec{PrivateKey: "K=", ListenPort: 51820})
	if err := reg.Add(inner); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Bring it up so there is a conf on disk to tear down.
	if _, _, err := inner.PushConfig(context.Background(), 1, []ConfPeer{
		{PublicKey: "EXIT=", AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: "198.51.100.9:443"},
	}); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}
	confPath := filepath.Join(dir, "awg1.conf")
	if _, err := os.Stat(confPath); err != nil {
		t.Fatalf("expected conf written: %v", err)
	}

	if err := reg.Remove(context.Background(), "awg1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if rt.callCount("Down") != 1 {
		t.Errorf("Remove must tear the interface down: Down calls = %d", rt.callCount("Down"))
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("Remove must delete the conf, stat err = %v", err)
	}
	if _, ok := reg.Get("awg1"); ok {
		t.Error("removed interface still registered")
	}
}

// TestInnerInterfaceRendersItsOwnSpec proves a cascade inner link uses its own
// [Interface] (the node key but the exit's port and obfuscation) and an
// endpoint peer — fully isolated from awg0's conf.
func TestInnerInterfaceRendersItsOwnSpec(t *testing.T) {
	dir := t.TempDir()
	spec := InterfaceSpec{
		PrivateKey:  "INNERNODEKEY=",
		ListenPort:  51820,
		MTU:         1380,
		Obfuscation: "Jc = 7\nH1 = 99999\n", // the exit node's obfuscation
	}
	inner, _ := newIfaceManager(t, dir, "awg1", spec)

	if _, _, err := inner.PushConfig(context.Background(), 1, []ConfPeer{
		{PublicKey: "EXIT=", AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: "198.51.100.9:443"},
	}); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "awg1.conf"))
	if err != nil {
		t.Fatalf("read awg1.conf: %v", err)
	}
	conf := string(raw)
	for _, want := range []string{
		"PrivateKey = INNERNODEKEY=",
		"ListenPort = 51820",
		"MTU = 1380",
		"Jc = 7",
		"Endpoint = 198.51.100.9:443",
		"AllowedIPs = 0.0.0.0/0",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("awg1.conf missing %q:\n%s", want, conf)
		}
	}
	// awg0.conf must not exist — the inner interface is fully separate.
	if _, err := os.Stat(filepath.Join(dir, "awg0.conf")); !os.IsNotExist(err) {
		t.Errorf("inner interface must not touch awg0.conf, stat err = %v", err)
	}
	if inner.Interface() != "awg1" {
		t.Errorf("Interface() = %q, want awg1", inner.Interface())
	}
}
