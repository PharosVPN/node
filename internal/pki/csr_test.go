// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCSRCreatesKeyAndCSR(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node.key")

	res, err := GenerateCSR(keyPath)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if !res.KeyGenerated {
		t.Error("KeyGenerated = false, want true on first call")
	}

	// The private key is persisted with owner-only permissions.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != keyFileMode {
		t.Errorf("key mode = %o, want %o", perm, keyFileMode)
	}

	// The CSR is a valid, self-signed PKCS#10 request.
	block, _ := pem.Decode(res.CSRPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("CSRPEM is not a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != csrSubject.CommonName {
		t.Errorf("CSR CommonName = %q, want %q", csr.Subject.CommonName, csrSubject.CommonName)
	}
}

func TestGenerateCSRIsIdempotent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node.key")

	first, err := GenerateCSR(keyPath)
	if err != nil {
		t.Fatalf("first GenerateCSR: %v", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := GenerateCSR(keyPath)
	if err != nil {
		t.Fatalf("second GenerateCSR: %v", err)
	}
	if second.KeyGenerated {
		t.Error("KeyGenerated = true on second call, want false (key reused)")
	}

	// The key on disk is unchanged — the same key never gets orphaned.
	keyBytesAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyBytes) != string(keyBytesAfter) {
		t.Error("node key changed on second gen-csr")
	}
	if len(first.CSRPEM) == 0 || len(second.CSRPEM) == 0 {
		t.Error("empty CSR")
	}
}

func TestGenerateCSRRejectsBadKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(keyPath, []byte("not a key"), keyFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateCSR(keyPath); err == nil {
		t.Fatal("GenerateCSR with corrupt key = nil error, want error")
	}
}
