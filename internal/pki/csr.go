// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package pki handles node's node-side certificate material: it generates the
// node's mTLS keypair on the node and emits a certificate signing request.
//
// The node's private key is generated here and never leaves the node. coxswain
// signs the CSR with the Fleet CA and pushes back the certificate and trust
// anchor over SSH (DESIGN §5, decision 14).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// keyFileMode is restrictive: the node private key is readable only by its
// owner. It never leaves the node.
const keyFileMode = 0o600

// CSR subject identifies the request as a node node certificate. coxswain pins the
// node's reachable address as a SAN when it signs (see pki.SignNodeCSR in
// coxswain); the CSR itself carries only this subject.
var csrSubject = pkix.Name{
	CommonName:   "pharos-node-node",
	Organization: []string{"PharosVPN"},
}

// CSRResult is the outcome of GenerateCSR.
type CSRResult struct {
	// CSRPEM is the PEM-encoded PKCS#10 certificate request, for coxswain to sign.
	CSRPEM []byte
	// KeyGenerated reports whether a new private key was created. It is false
	// when an existing key at keyPath was reused.
	KeyGenerated bool
}

// GenerateCSR ensures a node private key exists at keyPath and returns a
// certificate signing request built from it.
//
// If keyPath already holds a key it is reused, making `node gen-csr`
// idempotent: re-running it after a failed onboarding emits a fresh CSR for the
// same key rather than orphaning the old one. The parent directory is created
// if missing.
func GenerateCSR(keyPath string) (CSRResult, error) {
	key, generated, err := loadOrCreateKey(keyPath)
	if err != nil {
		return CSRResult{}, err
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            csrSubject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return CSRResult{}, fmt.Errorf("pki: create CSR: %w", err)
	}
	return CSRResult{
		CSRPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		KeyGenerated: generated,
	}, nil
}

// loadOrCreateKey returns the node private key at keyPath, generating and
// persisting a new ECDSA P-256 key if none exists.
func loadOrCreateKey(keyPath string) (*ecdsa.PrivateKey, bool, error) {
	switch existing, err := os.ReadFile(keyPath); {
	case err == nil:
		key, err := parseECKey(existing)
		if err != nil {
			return nil, false, fmt.Errorf("pki: existing key %s: %w", keyPath, err)
		}
		return key, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("pki: read %s: %w", keyPath, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("pki: generate key: %w", err)
	}
	if err := writeKey(keyPath, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// writeKey persists key as a PKCS#8 PEM file with owner-only permissions.
func writeKey(keyPath string, key *ecdsa.PrivateKey) error {
	if dir := filepath.Dir(keyPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("pki: create %s: %w", dir, err)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("pki: marshal key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemBytes, keyFileMode); err != nil {
		return fmt.Errorf("pki: write %s: %w", keyPath, err)
	}
	return nil
}

// parseECKey decodes a PKCS#8 PEM-encoded ECDSA private key.
func parseECKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key (%T)", parsed)
	}
	return key, nil
}
