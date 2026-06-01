// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderConfMatchesInterfaceAndPeers(t *testing.T) {
	node := mustLoadNode(t)
	peers := []ConfPeer{
		{PublicKey: "PEERA=", PresharedKey: "PSKA=", AllowedIPs: []string{"10.0.0.2/32"}},
		{PublicKey: "PEERB=", AllowedIPs: []string{"10.0.0.3/32", "fd00::3/128"}},
	}

	conf := renderConf(node.Spec(), peers)

	// [Interface] carries the node's private key, port, MTU and obfuscation.
	wantInterface := []string{
		"[Interface]",
		"PrivateKey = " + node.PrivateKey(),
		"ListenPort = 443",
		"MTU = 1420",
		"Jc = ", "H1 = ",
	}
	for _, want := range wantInterface {
		if !strings.Contains(conf, want) {
			t.Errorf("conf missing %q:\n%s", want, conf)
		}
	}

	// Two [Peer] blocks, no Endpoint line — clients dial in.
	if got := strings.Count(conf, "[Peer]"); got != 2 {
		t.Errorf("[Peer] blocks = %d, want 2", got)
	}
	if strings.Contains(conf, "Endpoint") {
		t.Errorf("conf must not write Endpoint lines:\n%s", conf)
	}
	// PSK only on the peer that has one.
	if !strings.Contains(conf, "PresharedKey = PSKA=") {
		t.Errorf("peer A's PSK missing from conf:\n%s", conf)
	}
	if strings.Count(conf, "PresharedKey =") != 1 {
		t.Errorf("PresharedKey occurrences = %d, want 1 (only peer A)",
			strings.Count(conf, "PresharedKey ="))
	}
	if !strings.Contains(conf, "AllowedIPs = 10.0.0.3/32, fd00::3/128") {
		t.Errorf("peer B's allowed-ips not joined:\n%s", conf)
	}
}

func TestParseConfPeersRoundTrip(t *testing.T) {
	node := mustLoadNode(t)
	original := []ConfPeer{
		{PublicKey: "A=", PresharedKey: "P=", AllowedIPs: []string{"10.0.0.2/32"}},
		{PublicKey: "B=", AllowedIPs: []string{"10.0.0.3/32"}},
	}

	parsed, err := parseConfPeers([]byte(renderConf(node.Spec(), original)))
	if err != nil {
		t.Fatalf("parseConfPeers: %v", err)
	}
	if len(parsed) != len(original) {
		t.Fatalf("parsed %d peers, want %d", len(parsed), len(original))
	}
	for i, want := range original {
		got := parsed[i]
		if got.PublicKey != want.PublicKey {
			t.Errorf("peer %d PublicKey = %q, want %q", i, got.PublicKey, want.PublicKey)
		}
		if got.PresharedKey != want.PresharedKey {
			t.Errorf("peer %d PSK mismatch", i)
		}
		if strings.Join(got.AllowedIPs, ",") != strings.Join(want.AllowedIPs, ",") {
			t.Errorf("peer %d AllowedIPs = %v, want %v", i, got.AllowedIPs, want.AllowedIPs)
		}
	}
}

// TestRenderConfInnerLinkEndpoint proves a node→node inner-link peer (the
// cascade primitive) carries its Endpoint through render and parse, while
// client peers in the same conf stay endpoint-free.
func TestRenderConfInnerLinkEndpoint(t *testing.T) {
	node := mustLoadNode(t)
	peers := []ConfPeer{
		{PublicKey: "CLIENT=", AllowedIPs: []string{"10.0.0.2/32"}},
		{PublicKey: "EXIT=", AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: "203.0.113.7:443"},
	}

	conf := renderConf(node.Spec(), peers)
	if !strings.Contains(conf, "Endpoint = 203.0.113.7:443") {
		t.Errorf("inner-link Endpoint missing from conf:\n%s", conf)
	}
	if strings.Count(conf, "Endpoint =") != 1 {
		t.Errorf("Endpoint lines = %d, want 1 (only the inner link)",
			strings.Count(conf, "Endpoint ="))
	}

	parsed, err := parseConfPeers([]byte(conf))
	if err != nil {
		t.Fatalf("parseConfPeers: %v", err)
	}
	var exit *ConfPeer
	for i := range parsed {
		if parsed[i].PublicKey == "EXIT=" {
			exit = &parsed[i]
		}
		if parsed[i].PublicKey == "CLIENT=" && parsed[i].Endpoint != "" {
			t.Errorf("client peer gained an endpoint: %q", parsed[i].Endpoint)
		}
	}
	if exit == nil || exit.Endpoint != "203.0.113.7:443" {
		t.Fatalf("inner-link endpoint did not round-trip: %+v", exit)
	}
}

// TestParseConfPeersIgnoresInterface guards the buoy invariant: the
// [Interface] section in awg0.conf is buoy-owned. coxswain-supplied obfuscation
// values, even if smuggled into a pushed conf, must not be readable as peers.
func TestParseConfPeersIgnoresInterface(t *testing.T) {
	conf := []byte("[Interface]\nPrivateKey = LEAK=\nJc = 9\n\n[Peer]\nPublicKey = X=\nAllowedIPs = 10.0.0.2/32\n")
	peers, err := parseConfPeers(conf)
	if err != nil {
		t.Fatalf("parseConfPeers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(peers))
	}
	if peers[0].PublicKey != "X=" {
		t.Errorf("peer key = %q, want X=", peers[0].PublicKey)
	}
}

func TestParseConfPeersRejectsBadLine(t *testing.T) {
	_, err := parseConfPeers([]byte("[Peer]\nPublicKey X\n"))
	if err == nil {
		t.Fatal("parseConfPeers on malformed line = nil error")
	}
}

func mustLoadNode(t *testing.T) *Node {
	t.Helper()
	node, err := Load(filepath.Join(t.TempDir(), "awg-node.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return node
}
