// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package xray runs the node's embedded XRay/REALITY data plane (DESIGN §3).
// The node owns its REALITY keypair (its identity, like the AmneziaWG one) and
// reports the public key so caravel can build a matching REALITY client; the
// controller pushes only the VLESS clients and the camouflage policy.
package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
	"golang.org/x/crypto/curve25519"
)

// stateFileMode is restrictive: the state file holds the node's REALITY private key.
const stateFileMode = 0o600

// Identity is the node's XRay/REALITY server identity: a Curve25519 keypair,
// generated once and persisted, so the values stay stable across restarts —
// coxswain caches the public key. Keys are base64url-encoded as XRay/REALITY
// tooling expects.
type Identity struct {
	priv []byte // 32-byte clamped Curve25519 private scalar
	pub  []byte // 32-byte Curve25519 public key
}

// state is the on-disk JSON form. The public key is derived on load.
type state struct {
	PrivateKey string `json:"private_key"` // base64url, REALITY format
}

// Load returns the node's REALITY identity from path, generating + persisting a
// fresh keypair on first run.
func Load(path string) (*Identity, error) {
	switch raw, err := os.ReadFile(path); {
	case err == nil:
		return loadState(raw)
	case errors.Is(err, os.ErrNotExist):
		return generate(path)
	default:
		return nil, fmt.Errorf("xray: read %s: %w", path, err)
	}
}

func loadState(raw []byte) (*Identity, error) {
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("xray: decode state: %w", err)
	}
	priv, err := base64.RawURLEncoding.DecodeString(s.PrivateKey)
	if err != nil || len(priv) != 32 {
		return nil, fmt.Errorf("xray: invalid private key in state")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("xray: derive public key: %w", err)
	}
	return &Identity{priv: priv, pub: pub}, nil
}

func generate(path string) (*Identity, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("xray: generate key: %w", err)
	}
	// Standard X25519 clamp (matches `xray x25519`).
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("xray: derive public key: %w", err)
	}
	id := &Identity{priv: priv, pub: pub}
	if err := id.persist(path); err != nil {
		return nil, err
	}
	return id, nil
}

func (i *Identity) persist(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("xray: create %s: %w", dir, err)
		}
	}
	raw, err := json.MarshalIndent(state{PrivateKey: i.PrivateKey()}, "", "  ")
	if err != nil {
		return fmt.Errorf("xray: encode state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, stateFileMode); err != nil {
		return fmt.Errorf("xray: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("xray: replace %s: %w", path, err)
	}
	return nil
}

// PrivateKey returns the REALITY private key, base64url-encoded (server config).
func (i *Identity) PrivateKey() string { return base64.RawURLEncoding.EncodeToString(i.priv) }

// PublicKey returns the REALITY public key, base64url-encoded (the client needs it).
func (i *Identity) PublicKey() string { return base64.RawURLEncoding.EncodeToString(i.pub) }

// Info is the node's REALITY identity for GetStatus.
func (i *Identity) Info() *nodev1.XRayRealityInfo {
	return &nodev1.XRayRealityInfo{PublicKey: i.PublicKey()}
}
