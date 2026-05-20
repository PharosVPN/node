// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// AmneziaWG data-plane defaults. The interface always binds to UDP 443
// (DESIGN §3); MTU 1420 is the WireGuard default.
const (
	ListenPort uint16 = 443
	MTU        uint16 = 1420
)

// ConfPeer is one [Peer] section of awg0.conf, as buoy writes it. buoy never
// sets Endpoint — clients dial the node, not the other way around.
type ConfPeer struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   []string
}

// renderConf produces an awg0.conf whose [Interface] block is sourced from
// the node's persisted identity (private key + obfuscation set) and whose
// [Peer] blocks come from peers. Any obfuscation values arriving from helm
// in a PushConfig are ignored — buoy owns its obfuscation (DESIGN §3).
func renderConf(n *Node, peers []ConfPeer) string {
	var b strings.Builder
	b.WriteString("# Managed by buoy — edits will be overwritten.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", n.PrivateKey())
	fmt.Fprintf(&b, "ListenPort = %d\n", ListenPort)
	fmt.Fprintf(&b, "MTU = %d\n", MTU)
	b.WriteString(n.RenderInterface())

	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
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
