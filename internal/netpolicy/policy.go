// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package netpolicy applies a buoy node's traffic-handling policy:
// kernel IP forwarding, source NAT for forwarded traffic, and
// client-to-client isolation (DESIGN §3, decision 16). helm carries the
// policy over the wire as three booleans on NetworkConfig; buoy renders
// them into an nftables table + the /proc/sys forwarding switches.
//
// The package is independent of the AmneziaWG data plane — it only depends
// on knowing the WG interface name (default "awg0") so it can scope the
// nftables rules.
package netpolicy

import "fmt"

// DefaultWGInterface is the AmneziaWG interface name buoy scopes rules to.
const DefaultWGInterface = "awg0"

// Policy is the three-boolean network-handling policy helm pushes (DESIGN
// §3, decision 16). masquerade and isolation are only meaningful when
// forwarding is true.
type Policy struct {
	// Forwarding turns on kernel IP forwarding (ipv4 + ipv6). With it off,
	// the node accepts AmneziaWG handshakes but routes nothing onward.
	Forwarding bool
	// Masquerade source-NATs forwarded WG traffic to the node's egress
	// address — the "internet egress" posture.
	Masquerade bool
	// Isolation drops client-to-client forwarded traffic — peers can still
	// egress through the node but cannot reach each other.
	Isolation bool
}

// Validate rejects combinations the contract forbids (helm's
// netpolicy.Policy.Validate already enforces this on the helm side; buoy
// repeats the check defensively).
func (p Policy) Validate() error {
	if !p.Forwarding && (p.Masquerade || p.Isolation) {
		return fmt.Errorf("netpolicy: masquerade/isolation require forwarding=true (got %+v)", p)
	}
	return nil
}
