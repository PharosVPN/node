// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestParseShowDump exercises the dump-format reader with a realistic line.
func TestParseShowDump(t *testing.T) {
	// Line 1 is the interface; lines 2+ are peers (tab-separated).
	dump := "" +
		"PRIV\tPUB\t443\toff\n" +
		"PEERA=\t(none)\t198.51.100.23:51820\t10.0.0.2/32\t1747680000\t1024\t2048\toff\n" +
		"PEERB=\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\toff\n"

	peers, err := parseShowDump([]byte(dump))
	if err != nil {
		t.Fatalf("parseShowDump: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(peers))
	}
	if peers[0].PublicKey != "PEERA=" || peers[0].RxBytes != 1024 || peers[0].TxBytes != 2048 {
		t.Errorf("peer A = %+v", peers[0])
	}
	// The endpoint column (field 3) is parsed; a real IP:port is kept verbatim.
	if peers[0].Endpoint != "198.51.100.23:51820" {
		t.Errorf("peer A endpoint = %q, want 198.51.100.23:51820", peers[0].Endpoint)
	}
	if want := time.Unix(1747680000, 0).UTC(); !peers[0].LastHandshake.Equal(want) {
		t.Errorf("peer A handshake = %v, want %v", peers[0].LastHandshake, want)
	}
	// A peer that has never handshaken reports 0 — node returns zero time.
	if !peers[1].LastHandshake.IsZero() {
		t.Errorf("peer B handshake = %v, want zero (never)", peers[1].LastHandshake)
	}
	// "(none)" in the endpoint column normalises to the empty string, never a
	// literal — analytics must not see "(none)" as a source.
	if peers[1].Endpoint != "" {
		t.Errorf("peer B endpoint = %q, want \"\" (awg printed (none))", peers[1].Endpoint)
	}
}

// TestParseEndpoint covers the endpoint-column normalisation in isolation.
func TestParseEndpoint(t *testing.T) {
	cases := map[string]string{
		"198.51.100.23:51820": "198.51.100.23:51820",
		"[2001:db8::1]:443":   "[2001:db8::1]:443",
		"(none)":              "",
		"":                    "",
	}
	for in, want := range cases {
		if got := parseEndpoint(in); got != want {
			t.Errorf("parseEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseShowDumpEmpty(t *testing.T) {
	peers, err := parseShowDump([]byte("PRIV\tPUB\t443\toff\n"))
	if err != nil {
		t.Fatalf("parseShowDump: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("peers = %d, want 0", len(peers))
	}
}

func TestParseShowDumpRejectsMalformedLine(t *testing.T) {
	if _, err := parseShowDump([]byte("PRIV\tPUB\n2\t3\n")); err == nil {
		t.Fatal("parseShowDump on too-few fields = nil error")
	}
}

// TestAddPeerKeepsPSKOffArgv proves the security non-negotiable: the PSK is
// piped on stdin, never present in the command line that a process listing
// would expose. A shell stub stands in for awg; it captures both argv and
// stdin to disk and we assert on each.
func TestAddPeerKeepsPSKOffArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-stub spy needs /bin/sh")
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "argv")
	stdinFile := filepath.Join(dir, "stdin")
	stub := filepath.Join(dir, "awg.sh")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\ncat > %q\n", argsFile, stdinFile)
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	rt := &ExecRuntime{Interface: "awg0", AWGBin: stub}
	if err := rt.AddPeer(context.Background(), "PUB=", "SECRETPSK==", []string{"10.0.0.2/32"}, ""); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	argv, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(argv)), "\n")
	want := []string{"set", "awg0", "peer", "PUB=", "preshared-key", "/dev/stdin", "allowed-ips", "10.0.0.2/32"}
	if len(args) != len(want) {
		t.Fatalf("argv = %v, want %v", args, want)
	}
	for i, w := range want {
		if args[i] != w {
			t.Errorf("argv[%d] = %q, want %q", i, args[i], w)
		}
	}
	// The PSK must not appear in argv anywhere.
	for _, a := range args {
		if strings.Contains(a, "SECRETPSK") {
			t.Fatalf("PSK leaked into argv at %q — must be stdin-only", a)
		}
	}
	stdin, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stdin), "SECRETPSK==") {
		t.Errorf("PSK missing from stdin: %q", stdin)
	}
}

// TestRemovePeerArgv guards the remove command shape.
func TestRemovePeerArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-stub spy needs /bin/sh")
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "argv")
	stub := filepath.Join(dir, "awg.sh")
	if err := os.WriteFile(stub,
		[]byte(fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\n", argsFile)),
		0o755); err != nil {
		t.Fatal(err)
	}

	rt := &ExecRuntime{Interface: "awg0", AWGBin: stub}
	if err := rt.RemovePeer(context.Background(), "PUB="); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "set\nawg0\npeer\nPUB=\nremove"
	if got := strings.TrimSpace(string(raw)); got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestRedactOutputStripsPSK(t *testing.T) {
	in := []byte("ok\nsetting preshared key for PUB=\nallowed-ips 10.0.0.2/32\n")
	out := redactOutput(in)
	if strings.Contains(strings.ToLower(out), "preshared") {
		t.Errorf("redactOutput left a 'preshared' line in: %q", out)
	}
}
