// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// tableName is the nftables table buoy owns. Keeping it in its own table
// (rather than mutating the system filter/nat tables) means a `delete table`
// is a clean, atomic teardown that touches nothing else on the host.
const tableName = "pharos_buoy"

// renderRuleset builds the nftables transaction script for a policy. The
// `add table; delete table; ...` opening is the standard idempotent reset:
// it works whether the table existed before or not, and the subsequent
// declarations live in a fresh table.
//
// When the policy needs no firewall rules — forwarding off, or forwarding
// on with neither masquerade nor isolation — the rendered script only
// removes any prior buoy table.
func renderRuleset(iface string, p Policy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", tableName)
	fmt.Fprintf(&b, "delete table inet %s\n", tableName)

	needsTable := p.Forwarding && (p.Masquerade || p.Isolation)
	if !needsTable {
		return b.String()
	}

	fmt.Fprintf(&b, "table inet %s {\n", tableName)
	if p.Isolation {
		b.WriteString("    chain forward {\n")
		b.WriteString("        type filter hook forward priority filter; policy accept;\n")
		fmt.Fprintf(&b, "        iifname \"%s\" oifname \"%s\" drop\n", iface, iface)
		b.WriteString("    }\n")
	}
	if p.Masquerade {
		b.WriteString("    chain postrouting {\n")
		b.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
		fmt.Fprintf(&b, "        iifname \"%s\" oifname != \"%s\" masquerade\n", iface, iface)
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// NftApplier applies a Policy to the running kernel via nftables and the
// /proc/sys forwarding switches. Test paths (NftBin, IPv4ForwardPath,
// IPv6ForwardPath) are overridable; production leaves them empty so the
// applier picks up the system `nft` and `/proc/sys/...`.
type NftApplier struct {
	// WGInterface scopes rules to the AmneziaWG interface; empty means
	// DefaultWGInterface.
	WGInterface string
	// NftBin overrides the `nft` binary lookup (tests use a stub).
	NftBin string
	// IPv4ForwardPath and IPv6ForwardPath override the procfs files
	// (tests redirect to a tempdir).
	IPv4ForwardPath string
	IPv6ForwardPath string
}

// NewNftApplier returns an NftApplier wired to the system defaults.
func NewNftApplier() *NftApplier {
	return &NftApplier{
		WGInterface:     DefaultWGInterface,
		IPv4ForwardPath: "/proc/sys/net/ipv4/ip_forward",
		IPv6ForwardPath: "/proc/sys/net/ipv6/conf/all/forwarding",
	}
}

func (a *NftApplier) iface() string {
	if a.WGInterface != "" {
		return a.WGInterface
	}
	return DefaultWGInterface
}

func (a *NftApplier) nft() string {
	if a.NftBin != "" {
		return a.NftBin
	}
	return "nft"
}

// Apply renders the ruleset for p, hands it to `nft -f -`, and writes the
// matching /proc/sys forwarding switches. Errors are surfaced verbatim;
// idempotency is the caller's concern.
func (a *NftApplier) Apply(ctx context.Context, p Policy) error {
	ruleset := renderRuleset(a.iface(), p)
	cmd := exec.CommandContext(ctx, a.nft(), "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("netpolicy: nft -f -: %w (stderr: %s)",
			err, strings.TrimSpace(stderr.String()))
	}

	if err := writeForward(a.IPv4ForwardPath, p.Forwarding); err != nil {
		return err
	}
	if err := writeForward(a.IPv6ForwardPath, p.Forwarding); err != nil {
		return err
	}
	return nil
}

// writeForward sets a /proc/sys/.../forwarding (or ip_forward) switch.
// Missing paths are tolerated only when explicitly empty — a real
// applier always has both paths set.
func writeForward(path string, enabled bool) error {
	if path == "" {
		return nil
	}
	v := []byte("0\n")
	if enabled {
		v = []byte("1\n")
	}
	if err := os.WriteFile(path, v, 0o644); err != nil {
		return fmt.Errorf("netpolicy: write %s: %w", path, err)
	}
	return nil
}
