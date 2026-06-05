// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package netpolicy renders and applies a node's traffic-handling policy —
// forwarding, masquerade, client isolation (DESIGN §3, decision 16).
//
// The canonical rule set is owned by coxswain
// (github.com/PharosVPN/coxswain/internal/netpolicy): coxswain previews it in the
// admin UI, node applies the identical set. The two renderers MUST stay
// byte-identical — both are pinned by tests against the same expected strings.
// coxswain sends only the policy (three bools over NetworkConfig); node renders
// the rule templates here and substitutes the node-local interface names for
// the %i (wg interface) and %e (autodetected egress) tokens before applying.
package netpolicy

import (
	"errors"
	"strconv"
	"strings"
)

// Rule-template tokens. The applier substitutes the wg interface for ifaceToken
// and the node's autodetected egress interface for egressToken.
const (
	ifaceToken  = "%i"
	egressToken = "%e"
)

// ErrMasqueradeNeedsForwarding / ErrIsolationNeedsForwarding / ErrTransitNeedsForwarding
// report an invalid policy: you cannot NAT, isolate, or transit traffic that is
// not forwarded.
var (
	ErrMasqueradeNeedsForwarding = errors.New("netpolicy: masquerade requires forwarding")
	ErrIsolationNeedsForwarding  = errors.New("netpolicy: isolation requires forwarding")
	ErrTransitNeedsForwarding    = errors.New("netpolicy: transit routes require forwarding")
	ErrTransitIncomplete         = errors.New("netpolicy: transit route needs device_cidr, inner_interface, mark and table")
)

// TransitRoute policy-routes one cascaded device's tunnel traffic into an inner
// AmneziaWG interface toward its exit, instead of masquerading it to the public
// egress (DESIGN §3, the entry-node side of node cascade). Transited packets
// leave via the inner interface, so the egress masquerade rule never matches
// them — the exit node masquerades. coxswain computes the mark and table.
type TransitRoute struct {
	DeviceCIDR     string
	InnerInterface string
	Mark           uint32
	Table          uint32
}

// Policy is a node's traffic-handling policy. It mirrors coxswain's
// netpolicy.Policy and the pharos.node.v1.NetworkConfig wire message.
type Policy struct {
	Forwarding bool
	Masquerade bool
	Isolation  bool
	// Transits route specific devices into inner links (node cascade); empty on
	// a plain node.
	Transits []TransitRoute
}

// Validate reports whether the policy is internally consistent. It matches
// coxswain's validation so a policy coxswain accepts, node also accepts.
func (p Policy) Validate() error {
	if p.Masquerade && !p.Forwarding {
		return ErrMasqueradeNeedsForwarding
	}
	if p.Isolation && !p.Forwarding {
		return ErrIsolationNeedsForwarding
	}
	if len(p.Transits) > 0 && !p.Forwarding {
		return ErrTransitNeedsForwarding
	}
	for _, t := range p.Transits {
		if t.DeviceCIDR == "" || t.InnerInterface == "" || t.Mark == 0 || t.Table == 0 {
			return ErrTransitIncomplete
		}
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

	// Transit (node cascade): mark each cascaded device's packets, policy-route
	// the mark into the device's inner interface, and add a default route in
	// that table. Transited packets egress the inner interface, so they never
	// match the egress masquerade above — the exit node NATs them instead.
	//
	// A return from the exit arrives on the inner interface, but the route back
	// to its source (the public destination) is the egress interface — an
	// asymmetric path that reverse-path filtering drops, even in loose mode (2),
	// so the entry silently fails to forward returns to the client. The effective
	// value is max(conf.all, conf.<iface>): relaxing `all` ALONE is a no-op while
	// the receiving interface keeps the inherited default (2) — both must be 0.
	// Relax `default` so every wg interface inherits 0 when it is created (covers
	// the inner interface without racing its bring-up). Not restored on teardown:
	// resetting `all` to 2 would re-break any other transit still up. (Proven
	// live 2026-06: `all=0` alone left awg1 at 2 and the cascade black-holed.)
	if len(p.Transits) > 0 {
		r.PreUp = append(r.PreUp,
			"sysctl -w net.ipv4.conf.all.rp_filter=0",
			"sysctl -w net.ipv4.conf.default.rp_filter=0")
	}
	for _, t := range p.Transits {
		mark := strconv.FormatUint(uint64(t.Mark), 10)
		table := strconv.FormatUint(uint64(t.Table), 10)
		r.PostUp = append(r.PostUp,
			"iptables -t mangle -A PREROUTING -i "+ifaceToken+" -s "+t.DeviceCIDR+" -j MARK --set-mark "+mark,
			"ip rule add fwmark "+mark+" lookup "+table,
			// `replace` not `add`: a 2nd device binding the same path reuses this
			// per-path table+inner interface; `add` fails with "File exists".
			"ip route replace default dev "+t.InnerInterface+" table "+table)
		r.PostDown = append(r.PostDown,
			"ip route del default dev "+t.InnerInterface+" table "+table,
			"ip rule del fwmark "+mark+" lookup "+table,
			"iptables -t mangle -D PREROUTING -i "+ifaceToken+" -s "+t.DeviceCIDR+" -j MARK --set-mark "+mark)
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
