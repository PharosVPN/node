// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// AmneziaWG data-plane defaults. The client interface (awg0) binds to UDP 443
// (DESIGN §3); MTU 1420 is the WireGuard default.
const (
	ListenPort uint16 = 443
	MTU        uint16 = 1420
)

// InterfaceSpec is the input for one wg interface's [Interface] block. The
// client interface (awg0) uses the node's own spec (key, port 443, the node's
// obfuscation). A cascade inner link reuses the node's key but carries the far
// (exit) node's listen port and obfuscation, so its handshake to that node
// matches (DESIGN §3). Obfuscation is the pre-rendered AmneziaWG lines.
type InterfaceSpec struct {
	PrivateKey  string
	ListenPort  uint16
	MTU         uint16
	Obfuscation string
	// Table sets awg-quick's `Table =` directive. Empty means the default
	// (awg-quick installs routes for each peer's AllowedIPs). A cascade inner
	// link sets it to "off": its exit peer has AllowedIPs 0.0.0.0/0, and we must
	// NOT let awg-quick install a default route through the inner interface —
	// that would hijack the node's own egress. The per-device transit rules
	// (mangle MARK + ip rule + ip route) route cascaded devices into it instead.
	Table string
}

// mtuOrDefault returns the spec MTU, or the package default when unset.
func (s InterfaceSpec) mtuOrDefault() uint16 {
	if s.MTU == 0 {
		return MTU
	}
	return s.MTU
}

// ConfPeer is one [Peer] section of awg0.conf, as buoy writes it.
//
// Endpoint is empty for client peers — clients dial the node, so the node never
// records where to reach them. It is set only for a node→node inner link, where
// this node dials the far node (DESIGN §3, node cascade): the entry node's
// inner-link peer carries the exit node's public AmneziaWG endpoint.
type ConfPeer struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   []string
	Endpoint     string
}

// renderConf produces a conf whose [Interface] block is sourced from spec
// (private key + listen port + obfuscation) and whose [Peer] blocks come from
// peers. Any obfuscation values arriving from coxswain in a PushConfig are
// ignored — buoy owns its obfuscation (DESIGN §3); spec is built on the node.
func renderConf(spec InterfaceSpec, peers []ConfPeer) string {
	var b strings.Builder
	b.WriteString("# Managed by buoy — edits will be overwritten.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", spec.PrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", spec.ListenPort)
	fmt.Fprintf(&b, "MTU = %d\n", spec.mtuOrDefault())
	if spec.Table != "" {
		fmt.Fprintf(&b, "Table = %s\n", spec.Table)
	}
	b.WriteString(spec.Obfuscation)

	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
	}
	return b.String()
}

// parseConfPeers extracts the [Peer] sections from awg0.conf data. The
// [Interface] section is ignored — buoy's source of truth for its own
// identity is awg-node.json, not the conf.
func parseConfPeers(data []byte) ([]ConfPeer, error) {
	var peers []ConfPeer
	var cur *ConfPeer
	flush := func() {
		if cur != nil {
			peers = append(peers, *cur)
			cur = nil
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			if strings.EqualFold(line, "[Peer]") {
				cur = &ConfPeer{}
			}
			continue
		}
		if cur == nil {
			// We're inside [Interface] or some other section; skip.
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("awg: conf line %d: missing '=': %q", lineNum, line)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch strings.ToLower(key) {
		case "publickey":
			cur.PublicKey = val
		case "presharedkey":
			cur.PresharedKey = val
		case "allowedips":
			cur.AllowedIPs = splitCSV(val)
		case "endpoint":
			cur.Endpoint = val
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("awg: read conf: %w", err)
	}
	return peers, nil
}

// splitCSV trims whitespace around each comma-separated entry, dropping empty
// fragments.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
