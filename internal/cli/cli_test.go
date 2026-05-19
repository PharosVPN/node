// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run executes the buoy CLI with args, returning stdout and stderr separately —
// helm captures gen-csr's stdout over SSH, so the split matters.
func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&errOut)
	err = root.Execute()
	return out.String(), errOut.String(), err
}

func TestVersionCommand(t *testing.T) {
	stdout, _, err := run(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != version {
		t.Errorf("version stdout = %q, want %q", got, version)
	}
}

func TestGenCSRCommand(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, err := run(t, "gen-csr", "--config-dir", dir)
	if err != nil {
		t.Fatalf("gen-csr: %v", err)
	}
	if !strings.HasPrefix(stdout, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Errorf("gen-csr stdout is not a CSR PEM block:\n%s", stdout)
	}
	// Diagnostics must stay off stdout so helm captures only the CSR.
	if !strings.Contains(stderr, "node key") {
		t.Errorf("gen-csr stderr = %q, want a node-key diagnostic", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "node.key")); err != nil {
		t.Errorf("node.key not written: %v", err)
	}
}
