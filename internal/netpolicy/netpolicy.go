// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package netpolicy renders and applies a node's traffic-handling policy —
// forwarding, masquerade, client isolation (DESIGN §3, decision 16).
//
// The canonical rule set is owned by coxswain
// (github.com/PharosVPN/coxswain/internal/netpolicy): coxswain previews it in the
// admin UI, buoy applies the identical set. The two renderers MUST stay
// byte-identical — both are pinned by tests against the same expected strings.
// coxswain sends only the policy (three bools over NetworkConfig); buoy renders
// the rule templates here and substitutes the node-local interface names for
// the %i (wg interface) and %e (autodetected egress) tokens before applying.
package netpolicy

import (
	"errors"
	"strings"
)

// Rule-template tokens. The applier substitutes the wg interface for ifaceToken
// and the node's autodetected egress interface for egressToken.
const (
	ifaceToken  = "%i"
	egressToken = "%e"
)

// ErrMasqueradeNeedsForwarding / ErrIsolationNeedsForwarding report an invalid
// policy: you cannot NAT or isolate traffic that is not forwarded.
var (
	ErrMasqueradeNeedsForwarding = errors.New("netpolicy: masquerade requires forwarding")
	ErrIsolationNeedsForwarding  = errors.New("netpolicy: isolation requires forwarding")
)

// Policy is a node's traffic-handling policy. It mirrors coxswain's
// netpolicy.Policy and the pharos.buoy.v1.NetworkConfig wire message.
type Policy struct {
	Forwarding bool
	Masquerade bool
	Isolation  bool
}

// Validate reports whether the policy is internally consistent. It matches
// coxswain's validation so a policy coxswain accepts, buoy also accepts.
func (p Policy) Validate() error {
	if p.Masquerade && !p.Forwarding {
		return ErrMasqueradeNeedsForwarding
	}
	if p.Isolation && !p.Forwarding {
		return ErrIsolationNeedsForwarding
	}
	return nil
}

// Rules is the wg-quick-style hook rule set a policy produces. The lines carry
// the %i / %e tokens; Resolve substitutes them.
type Rules struct {
	PreUp    []string
	PostUp   []string
	PostDown []string
}

// Rules renders the canonical rule set for the policy. This is a deliberate
// mirror of coxswain's netpolicy.Policy.Rules() — keep them identical.
func (p Policy) Rules() Rules {
	var r Rules
	if !p.Forwarding {
		return r // a node that forwards nothing needs no rules
	}

	r.PreUp = []string{
		"sysctl -w net.ipv4.conf.all.forwarding=1",
		"sysctl -w net.ipv6.conf.all.forwarding=1",
	}

	// Isolation drops client-to-client traffic; it must sit above the accepts.
	if p.Isolation {
		r.PostUp = append(r.PostUp,
			"iptables -I FORWARD 1 -i "+ifaceToken+" -o "+ifaceToken+" -j DROP")
		r.PostDown = append(r.PostDown,
			"iptables -D FORWARD -i "+ifaceToken+" -o "+ifaceToken+" -j DROP")
	}

	r.PostUp = append(r.PostUp,
		"iptables -A FORWARD -i "+ifaceToken+" -j ACCEPT",
		"iptables -A FORWARD -o "+ifaceToken+" -j ACCEPT")
	r.PostDown = append(r.PostDown,
		"iptables -D FORWARD -i "+ifaceToken+" -j ACCEPT",
		"iptables -D FORWARD -o "+ifaceToken+" -j ACCEPT")

	if p.Masquerade {
		r.PostUp = append(r.PostUp,
			"iptables -t nat -A POSTROUTING -o "+egressToken+" -j MASQUERADE")
		r.PostDown = append(r.PostDown,
			"iptables -t nat -D POSTROUTING -o "+egressToken+" -j MASQUERADE")
	}
	return r
}

// command is one resolved rule, split into argv. argv[0] is the binary. Because
// the only substituted values are interface names (never spaces, never client
// input), splitting the canonical template on whitespace is safe — and the
// applier execs argv directly, never through a shell.
type command []string

// resolveLine substitutes the interface tokens in one template line and splits
// it into argv.
func resolveLine(line, wgIface, egress string) command {
	line = strings.ReplaceAll(line, ifaceToken, wgIface)
	line = strings.ReplaceAll(line, egressToken, egress)
	return strings.Fields(line)
}

// resolvedRules holds the policy's commands with all tokens substituted, ready
// to exec. up is run to establish the policy (PreUp then PostUp); down reverts
// it (PostDown). down is persisted so the applier can revert exactly what it
// added, even if the egress interface later changes.
type resolvedRules struct {
	up   []command
	down []command
}

// resolve substitutes the node's interface names into the policy's rule set.
func (p Policy) resolve(wgIface, egress string) resolvedRules {
	r := p.Rules()
	var rr resolvedRules
	for _, l := range r.PreUp {
		rr.up = append(rr.up, resolveLine(l, wgIface, egress))
	}
	for _, l := range r.PostUp {
		rr.up = append(rr.up, resolveLine(l, wgIface, egress))
	}
	for _, l := range r.PostDown {
		rr.down = append(rr.down, resolveLine(l, wgIface, egress))
	}
	return rr
}
