// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

// TestRulesCanonical pins the exact canonical rule set. These strings are the
// cross-repo contract with coxswain/internal/netpolicy — if this test changes,
// coxswain's matching test must change identically, or buoy and coxswain will
// disagree on what a policy means.
func TestRulesCanonical(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   Rules
	}{
		{
			name:   "no forwarding yields no rules",
			policy: Policy{},
			want:   Rules{},
		},
		{
			name:   "forwarding only",
			policy: Policy{Forwarding: true},
			want: Rules{
				PreUp: []string{
					"sysctl -w net.ipv4.conf.all.forwarding=1",
					"sysctl -w net.ipv6.conf.all.forwarding=1",
				},
				PostUp: []string{
					"iptables -A FORWARD -i %i -j ACCEPT",
					"iptables -A FORWARD -o %i -j ACCEPT",
				},
				PostDown: []string{
					"iptables -D FORWARD -i %i -j ACCEPT",
					"iptables -D FORWARD -o %i -j ACCEPT",
				},
			},
		},
		{
			name:   "forwarding + masquerade",
			policy: Policy{Forwarding: true, Masquerade: true},
			want: Rules{
				PreUp: []string{
					"sysctl -w net.ipv4.conf.all.forwarding=1",
					"sysctl -w net.ipv6.conf.all.forwarding=1",
				},
				PostUp: []string{
					"iptables -A FORWARD -i %i -j ACCEPT",
					"iptables -A FORWARD -o %i -j ACCEPT",
					"iptables -t nat -A POSTROUTING -o %e -j MASQUERADE",
				},
				PostDown: []string{
					"iptables -D FORWARD -i %i -j ACCEPT",
					"iptables -D FORWARD -o %i -j ACCEPT",
					"iptables -t nat -D POSTROUTING -o %e -j MASQUERADE",
				},
			},
		},
		{
			name:   "forwarding + isolation places drop first",
			policy: Policy{Forwarding: true, Isolation: true},
			want: Rules{
				PreUp: []string{
					"sysctl -w net.ipv4.conf.all.forwarding=1",
					"sysctl -w net.ipv6.conf.all.forwarding=1",
				},
				PostUp: []string{
					"iptables -I FORWARD 1 -i %i -o %i -j DROP",
					"iptables -A FORWARD -i %i -j ACCEPT",
					"iptables -A FORWARD -o %i -j ACCEPT",
				},
				PostDown: []string{
					"iptables -D FORWARD -i %i -o %i -j DROP",
					"iptables -D FORWARD -i %i -j ACCEPT",
					"iptables -D FORWARD -o %i -j ACCEPT",
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy.Rules()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Rules() mismatch\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	if err := (Policy{Masquerade: true}).Validate(); !errors.Is(err, ErrMasqueradeNeedsForwarding) {
		t.Errorf("masquerade without forwarding: got %v", err)
	}
	if err := (Policy{Isolation: true}).Validate(); !errors.Is(err, ErrIsolationNeedsForwarding) {
		t.Errorf("isolation without forwarding: got %v", err)
	}
	if err := (Policy{Forwarding: true, Masquerade: true, Isolation: true}).Validate(); err != nil {
		t.Errorf("valid policy rejected: %v", err)
	}
	// Transit requires forwarding.
	tr := TransitRoute{DeviceCIDR: "10.8.0.5/32", InnerInterface: "awg1", Mark: 100, Table: 100}
	if err := (Policy{Transits: []TransitRoute{tr}}).Validate(); !errors.Is(err, ErrTransitNeedsForwarding) {
		t.Errorf("transit without forwarding: got %v", err)
	}
	// Incomplete transit is rejected.
	if err := (Policy{Forwarding: true, Transits: []TransitRoute{{DeviceCIDR: "10.8.0.5/32"}}}).Validate(); !errors.Is(err, ErrTransitIncomplete) {
		t.Errorf("incomplete transit: got %v", err)
	}
	if err := (Policy{Forwarding: true, Transits: []TransitRoute{tr}}).Validate(); err != nil {
		t.Errorf("valid transit policy rejected: %v", err)
	}
}

// TestTransitRulesCanonical pins the transit rule set — the cross-repo contract
// with coxswain's netpolicy transit rendering (DESIGN §3 transit mode).
func TestTransitRulesCanonical(t *testing.T) {
	p := Policy{
		Forwarding: true,
		Masquerade: true,
		Transits: []TransitRoute{
			{DeviceCIDR: "10.8.0.5/32", InnerInterface: "awg1", Mark: 100, Table: 100},
		},
	}
	r := p.Rules()
	wantUp := []string{
		"iptables -t mangle -A PREROUTING -i %i -s 10.8.0.5/32 -j MARK --set-mark 100",
		"ip rule add fwmark 100 lookup 100",
		"ip route add default dev awg1 table 100",
	}
	for _, w := range wantUp {
		if !containsLine(r.PostUp, w) {
			t.Errorf("PostUp missing %q\n got: %#v", w, r.PostUp)
		}
	}
	wantDown := []string{
		"ip route del default dev awg1 table 100",
		"ip rule del fwmark 100 lookup 100",
		"iptables -t mangle -D PREROUTING -i %i -s 10.8.0.5/32 -j MARK --set-mark 100",
	}
	for _, w := range wantDown {
		if !containsLine(r.PostDown, w) {
			t.Errorf("PostDown missing %q\n got: %#v", w, r.PostDown)
		}
	}

	// A transit node forwards returns asymmetrically (in on the inner interface,
	// route-back via egress), which rp_filter drops — so the cascade entry must
	// relax it while it carries transits, and restore it on teardown.
	if !containsLine(r.PreUp, "sysctl -w net.ipv4.conf.all.rp_filter=0") {
		t.Errorf("PreUp missing the rp_filter relax\n got: %#v", r.PreUp)
	}
	if !containsLine(r.PostDown, "sysctl -w net.ipv4.conf.all.rp_filter=2") {
		t.Errorf("PostDown missing the rp_filter restore\n got: %#v", r.PostDown)
	}
}

// TestNoTransitOmitsRpFilter guards that a plain forwarding node (no cascade)
// keeps reverse-path filtering — the relax is scoped to transit nodes only.
func TestNoTransitOmitsRpFilter(t *testing.T) {
	r := Policy{Forwarding: true, Masquerade: true}.Rules()
	if containsLine(r.PreUp, "sysctl -w net.ipv4.conf.all.rp_filter=0") {
		t.Errorf("non-transit node must not relax rp_filter\n got: %#v", r.PreUp)
	}
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// policyEqual compares two policies field-wise (Policy is no longer == due to
// the Transits slice; TransitRoute itself is comparable).
func policyEqual(a, b Policy) bool {
	if a.Forwarding != b.Forwarding || a.Masquerade != b.Masquerade || a.Isolation != b.Isolation {
		return false
	}
	if len(a.Transits) != len(b.Transits) {
		return false
	}
	for i := range a.Transits {
		if a.Transits[i] != b.Transits[i] {
			return false
		}
	}
	return true
}

func TestResolveSubstitutesTokens(t *testing.T) {
	rr := Policy{Forwarding: true, Masquerade: true}.resolve("awg0", "eth0")
	// The masquerade up-rule must carry the egress interface, not the token.
	wantUp := command{"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"}
	if got := rr.up[len(rr.up)-1]; !reflect.DeepEqual(got, wantUp) {
		t.Errorf("masquerade up: got %v want %v", got, wantUp)
	}
	// The forward accept must carry the wg interface.
	wantForward := command{"iptables", "-A", "FORWARD", "-i", "awg0", "-j", "ACCEPT"}
	if got := rr.up[2]; !reflect.DeepEqual(got, wantForward) {
		t.Errorf("forward accept: got %v want %v", got, wantForward)
	}
}

// fakeExec records every command and can be told to fail on a chosen one.
type fakeExec struct {
	runs     [][]string
	failOn   string // substring; if a command joins to contain it, Run errors
	missOnDel bool  // delete commands (-D) error, simulating "rule not present"
}

func (f *fakeExec) Run(_ context.Context, argv []string) error {
	joined := ""
	for _, a := range argv {
		joined += a + " "
	}
	f.runs = append(f.runs, append([]string(nil), argv...))
	if f.failOn != "" && contains(joined, f.failOn) {
		return errors.New("forced failure")
	}
	if f.missOnDel && containsArg(argv, "-D") {
		return errors.New("iptables: Bad rule (does a matching rule exist?)")
	}
	return nil
}

type fakeEgress struct{ iface string }

func (f fakeEgress) DefaultEgress(context.Context) (string, error) { return f.iface, nil }

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func containsArg(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

func newTestApplier(t *testing.T, ex Exec, eg EgressDetector) *Applier {
	t.Helper()
	a, err := New(Options{
		WGIface:   "awg0",
		Exec:      ex,
		Egress:    eg,
		StatePath: filepath.Join(t.TempDir(), "netpolicy.json"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestApplyInstallsRules(t *testing.T) {
	ex := &fakeExec{}
	a := newTestApplier(t, ex, fakeEgress{"eth0"})
	if err := a.Apply(context.Background(), Policy{Forwarding: true, Masquerade: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Expect: 2 sysctl + 2 forward-accept + 1 masquerade = 5 up commands.
	if len(ex.runs) != 5 {
		t.Fatalf("want 5 commands, got %d: %v", len(ex.runs), ex.runs)
	}
	if got := a.Policy(); !policyEqual(got, Policy{Forwarding: true, Masquerade: true}) {
		t.Errorf("Policy() = %+v", got)
	}
}

func TestApplyInstallsTransitRoute(t *testing.T) {
	ex := &fakeExec{}
	a := newTestApplier(t, ex, fakeEgress{"eth0"})
	p := Policy{Forwarding: true, Masquerade: true, Transits: []TransitRoute{
		{DeviceCIDR: "10.8.0.5/32", InnerInterface: "awg1", Mark: 100, Table: 100},
	}}
	if err := a.Apply(context.Background(), p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sawRoute, sawRule, sawMark := false, false, false
	for _, r := range ex.runs {
		switch {
		case containsArg(r, "route") && containsArg(r, "awg1"):
			sawRoute = true
		case containsArg(r, "rule") && containsArg(r, "fwmark"):
			sawRule = true
		case containsArg(r, "PREROUTING") && containsArg(r, "MARK"):
			sawMark = true
		}
	}
	if !sawRoute || !sawRule || !sawMark {
		t.Errorf("transit apply incomplete: route=%v rule=%v mark=%v\nruns: %v", sawRoute, sawRule, sawMark, ex.runs)
	}
}

func TestApplyRevertsPreviousFirst(t *testing.T) {
	ex := &fakeExec{}
	a := newTestApplier(t, ex, fakeEgress{"eth0"})
	ctx := context.Background()
	if err := a.Apply(ctx, Policy{Forwarding: true, Masquerade: true}); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	ex.runs = nil
	// Re-apply a narrower policy: the masquerade teardown from the first
	// policy must run before the new rules install.
	if err := a.Apply(ctx, Policy{Forwarding: true}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	sawMasqDelete := false
	for _, r := range ex.runs {
		if containsArg(r, "MASQUERADE") && containsArg(r, "-D") {
			sawMasqDelete = true
		}
	}
	if !sawMasqDelete {
		t.Errorf("expected masquerade teardown on policy change, runs: %v", ex.runs)
	}
}

func TestApplyRollsBackOnFailure(t *testing.T) {
	// Fail when installing the masquerade rule; the forward-accept rules
	// already applied must be torn back down.
	ex := &fakeExec{failOn: "MASQUERADE"}
	a := newTestApplier(t, ex, fakeEgress{"eth0"})
	err := a.Apply(context.Background(), Policy{Forwarding: true, Masquerade: true})
	if err == nil {
		t.Fatal("expected Apply to fail")
	}
	// Nothing should be recorded as the applied policy.
	if got := a.Policy(); !policyEqual(got, Policy{}) {
		t.Errorf("policy should be unset after failed apply, got %+v", got)
	}
	// Rollback should have issued delete commands.
	sawDelete := false
	for _, r := range ex.runs {
		if containsArg(r, "-D") {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Errorf("expected rollback deletes after failure, runs: %v", ex.runs)
	}
}

func TestReapplyAfterRestart(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "netpolicy.json")
	ctx := context.Background()

	// First process applies a policy and persists it.
	a1, err := New(Options{WGIface: "awg0", Exec: &fakeExec{}, Egress: fakeEgress{"eth0"}, StatePath: statePath})
	if err != nil {
		t.Fatalf("New a1: %v", err)
	}
	if err := a1.Apply(ctx, Policy{Forwarding: true, Masquerade: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Second process (restart): loads state, Reapply re-establishes the policy.
	ex2 := &fakeExec{missOnDel: true} // post-reboot: old rules gone, deletes miss
	a2, err := New(Options{WGIface: "awg0", Exec: ex2, Egress: fakeEgress{"eth0"}, StatePath: statePath})
	if err != nil {
		t.Fatalf("New a2: %v", err)
	}
	if got := a2.Policy(); !policyEqual(got, Policy{Forwarding: true, Masquerade: true}) {
		t.Fatalf("loaded policy = %+v", got)
	}
	if err := a2.Reapply(ctx); err != nil {
		t.Fatalf("Reapply: %v", err)
	}
	// Reapply must (best-effort) revert then install: at least one MASQUERADE -A.
	sawMasqAdd := false
	for _, r := range ex2.runs {
		if containsArg(r, "MASQUERADE") && containsArg(r, "-A") {
			sawMasqAdd = true
		}
	}
	if !sawMasqAdd {
		t.Errorf("Reapply did not reinstall masquerade, runs: %v", ex2.runs)
	}
}

func TestReapplyNoStateIsNoop(t *testing.T) {
	ex := &fakeExec{}
	a := newTestApplier(t, ex, fakeEgress{"eth0"})
	if err := a.Reapply(context.Background()); err != nil {
		t.Fatalf("Reapply with no state: %v", err)
	}
	if len(ex.runs) != 0 {
		t.Errorf("Reapply with no state ran commands: %v", ex.runs)
	}
}

func TestParseEgressDev(t *testing.T) {
	out := "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"
	if got := parseEgressDev(out); got != "eth0" {
		t.Errorf("parseEgressDev = %q want eth0", got)
	}
	if got := parseEgressDev("unreachable default\n"); got != "" {
		t.Errorf("parseEgressDev with no dev = %q want empty", got)
	}
}
