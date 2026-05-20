// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderRulesetResetsTable(t *testing.T) {
	// Every render begins with the idempotent table reset so a prior buoy
	// policy is unconditionally torn down before the new one lands.
	got := renderRuleset("awg0", Policy{})
	for _, want := range []string{
		"add table inet " + tableName,
		"delete table inet " + tableName,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset missing %q:\n%s", want, got)
		}
	}
}

func TestRenderRulesetForwardingOnlyEmitsNoRules(t *testing.T) {
	// Forwarding on, neither masquerade nor isolation: kernel's default
	// forward-accept is fine, so buoy installs no rules — only the reset.
	got := renderRuleset("awg0", Policy{Forwarding: true})
	if strings.Contains(got, "table inet "+tableName+" {") {
		t.Errorf("forwarding-only ruleset should not declare a table body:\n%s", got)
	}
}

func TestRenderRulesetMasqueradeOnly(t *testing.T) {
	got := renderRuleset("awg0", Policy{Forwarding: true, Masquerade: true})
	if !strings.Contains(got, "iifname \"awg0\" oifname != \"awg0\" masquerade") {
		t.Errorf("masquerade rule missing:\n%s", got)
	}
	if strings.Contains(got, "iifname \"awg0\" oifname \"awg0\" drop") {
		t.Errorf("isolation rule should not appear:\n%s", got)
	}
}

func TestRenderRulesetIsolationOnly(t *testing.T) {
	got := renderRuleset("awg0", Policy{Forwarding: true, Isolation: true})
	if !strings.Contains(got, "iifname \"awg0\" oifname \"awg0\" drop") {
		t.Errorf("isolation rule missing:\n%s", got)
	}
	if strings.Contains(got, "masquerade") {
		t.Errorf("masquerade rule should not appear:\n%s", got)
	}
}

func TestRenderRulesetBothRules(t *testing.T) {
	got := renderRuleset("awg0", Policy{Forwarding: true, Masquerade: true, Isolation: true})
	if !strings.Contains(got, "drop") || !strings.Contains(got, "masquerade") {
		t.Errorf("both rules should appear:\n%s", got)
	}
}

// TestNftApplierShellsOut exercises the full Apply path with a stub `nft`
// that records argv + stdin, plus tempdir overrides for the /proc/sys
// forwarding switches. Skipped on Windows where /bin/sh isn't around.
func TestNftApplierShellsOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-stub spy needs /bin/sh")
	}
	dir := t.TempDir()
	stdinCapture := filepath.Join(dir, "stdin")
	stub := filepath.Join(dir, "nft.sh")
	if err := os.WriteFile(stub,
		[]byte(fmt.Sprintf("#!/bin/sh\ncat > %q\n", stdinCapture)),
		0o755); err != nil {
		t.Fatal(err)
	}

	v4 := filepath.Join(dir, "ipv4-forward")
	v6 := filepath.Join(dir, "ipv6-forward")
	if err := os.WriteFile(v4, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v6, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &NftApplier{
		WGInterface:     "awg0",
		NftBin:          stub,
		IPv4ForwardPath: v4,
		IPv6ForwardPath: v6,
	}
	if err := a.Apply(context.Background(),
		Policy{Forwarding: true, Masquerade: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := os.ReadFile(stdinCapture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "masquerade") {
		t.Errorf("nft stdin missing masquerade rule:\n%s", got)
	}

	for _, path := range []string{v4, v6} {
		v, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(v)) != "1" {
			t.Errorf("%s = %q, want 1", path, v)
		}
	}
}

func TestNftApplierTurnsForwardingOff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-stub spy needs /bin/sh")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "nft.sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat >/dev/null\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	v4 := filepath.Join(dir, "ipv4-forward")
	v6 := filepath.Join(dir, "ipv6-forward")
	if err := os.WriteFile(v4, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v6, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &NftApplier{
		WGInterface:     "awg0",
		NftBin:          stub,
		IPv4ForwardPath: v4,
		IPv6ForwardPath: v6,
	}
	if err := a.Apply(context.Background(), Policy{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, path := range []string{v4, v6} {
		v, _ := os.ReadFile(path)
		if strings.TrimSpace(string(v)) != "0" {
			t.Errorf("%s = %q, want 0 after forwarding=false", path, v)
		}
	}
}
