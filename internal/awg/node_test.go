// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadGeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awg-node.json")

	n, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n.PublicKey() == "" {
		t.Error("PublicKey is empty")
	}

	// The state file holds a private key — it must be owner-only.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != stateFileMode {
		t.Errorf("state file mode = %o, want %o", perm, stateFileMode)
	}
}

// TestLoadIsStable proves the identity survives a reload unchanged — helm
// caches it, so it must not drift across buoy restarts.
func TestLoadIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awg-node.json")

	first, err := Load(path)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}

	if first.PublicKey() != second.PublicKey() {
		t.Error("public key changed across reload")
	}
	if first.Obfuscation() != second.Obfuscation() {
		t.Errorf("obfuscation changed across reload:\n %+v\n %+v",
			first.Obfuscation(), second.Obfuscation())
	}
}

func TestLoadRejectsCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awg-node.json")
	if err := os.WriteFile(path, []byte("{not json"), stateFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load on corrupt state = nil error, want error")
	}
}

func TestLoadRejectsInvalidObfuscation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awg-node.json")
	// A well-formed key but an obfuscation set that violates Jmin <= Jmax.
	good, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.obfuscation.Jmin = bad.obfuscation.Jmax + 1
	if err := bad.persist(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load on invalid obfuscation = nil error, want error")
	}
}

func TestInfoMatchesNode(t *testing.T) {
	n, err := Load(filepath.Join(t.TempDir(), "awg-node.json"))
	if err != nil {
		t.Fatal(err)
	}
	info := n.Info()
	if info.GetPublicKey() != n.PublicKey() {
		t.Errorf("Info public key = %q, want %q", info.GetPublicKey(), n.PublicKey())
	}
	if info.GetObfuscation().GetJc() != n.Obfuscation().Jc {
		t.Errorf("Info Jc = %d, want %d", info.GetObfuscation().GetJc(), n.Obfuscation().Jc)
	}
}

func TestRenderInterface(t *testing.T) {
	n, err := Load(filepath.Join(t.TempDir(), "awg-node.json"))
	if err != nil {
		t.Fatal(err)
	}
	rendered := n.RenderInterface()
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
		if !strings.Contains(rendered, key+" = ") {
			t.Errorf("RenderInterface missing %q line:\n%s", key, rendered)
		}
	}
	// I1-I5 are empty, so they must not appear.
	if strings.Contains(rendered, "I1 = ") {
		t.Errorf("RenderInterface emitted an empty I1 line:\n%s", rendered)
	}
}
