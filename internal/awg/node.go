// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
)

// stateFileMode is restrictive: the state file holds the node's AmneziaWG
// private key.
const stateFileMode = 0o600

// Node is a node node's AmneziaWG server identity: its WireGuard keypair and
// its obfuscation parameter set. It is generated once and persisted, so the
// values stay stable across node restarts and awg reloads — coxswain caches them.
type Node struct {
	priv        *ecdh.PrivateKey
	obfuscation Obfuscation
}

// state is the on-disk JSON form of a Node. The public key is derived from the
// private key on load, so it is not stored.
type state struct {
	PrivateKey  string      `json:"private_key"` // base64 WireGuard key
	Obfuscation Obfuscation `json:"obfuscation"`
}

// Load returns the node's AmneziaWG identity, reading it from path. If path
// does not exist, a new keypair and obfuscation set are generated and
// persisted there atomically — this is the node's first run. Subsequent calls
// return the same stable identity.
func Load(path string) (*Node, error) {
	switch raw, err := os.ReadFile(path); {
	case err == nil:
		return loadState(raw)
	case errors.Is(err, os.ErrNotExist):
		return generate(path)
	default:
		return nil, fmt.Errorf("awg: read %s: %w", path, err)
	}
}

// loadState reconstructs a Node from its persisted JSON form.
func loadState(raw []byte) (*Node, error) {
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("awg: decode state: %w", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(s.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("awg: decode private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("awg: invalid private key: %w", err)
	}
	if err := s.Obfuscation.Validate(); err != nil {
		return nil, fmt.Errorf("awg: persisted obfuscation invalid: %w", err)
	}
	return &Node{priv: priv, obfuscation: s.Obfuscation}, nil
}

// generate creates a fresh identity and persists it to path.
func generate(path string) (*Node, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("awg: generate keypair: %w", err)
	}
	obf, err := generateObfuscation()
	if err != nil {
		return nil, err
	}
	n := &Node{priv: priv, obfuscation: obf}
	if err := n.persist(path); err != nil {
		return nil, err
	}
	return n, nil
}

// persist writes the node identity to path atomically with owner-only
// permissions.
func (n *Node) persist(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("awg: create %s: %w", dir, err)
		}
	}
	raw, err := json.MarshalIndent(state{
		PrivateKey:  base64.StdEncoding.EncodeToString(n.priv.Bytes()),
		Obfuscation: n.obfuscation,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("awg: encode state: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, stateFileMode); err != nil {
		return fmt.Errorf("awg: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("awg: replace %s: %w", path, err)
	}
	return nil
}

// PublicKey returns the node's AmneziaWG server public key, base64-encoded as
// WireGuard tooling expects.
func (n *Node) PublicKey() string {
	return base64.StdEncoding.EncodeToString(n.priv.PublicKey().Bytes())
}

// PrivateKey returns the node's AmneziaWG server private key, base64-encoded.
// It is only consumed by the conf renderer that writes awg0.conf (0600); the
// value must never appear in a log line, an argv slot, or a gRPC response.
func (n *Node) PrivateKey() string {
	return base64.StdEncoding.EncodeToString(n.priv.Bytes())
}

// Obfuscation returns a copy of the node's obfuscation parameter set.
func (n *Node) Obfuscation() Obfuscation { return n.obfuscation }

// Info returns the node's AmneziaWG identity in wire form for GetStatus.
func (n *Node) Info() *nodev1.AmneziaWGInfo {
	return &nodev1.AmneziaWGInfo{
		PublicKey:   n.PublicKey(),
		Obfuscation: n.obfuscation.toProto(),
	}
}

// Spec returns the node's own [Interface] inputs for the client interface
// (awg0): its private key, the standard listen port and MTU, and its
// obfuscation lines.
func (n *Node) Spec() InterfaceSpec {
	return InterfaceSpec{
		PrivateKey:  n.PrivateKey(),
		ListenPort:  ListenPort,
		MTU:         MTU,
		Obfuscation: n.RenderInterface(),
	}
}

// InnerLinkSpec returns the [Interface] inputs for a cascade inner link toward
// an exit node (DESIGN §3): this node's own private key (so the exit identifies
// the entry), but the exit's listen port, the computed link MTU, and the exit's
// obfuscation set — so the entry's handshake to the exit matches. A zero
// listenPort or mtu falls back to the conf defaults.
func (n *Node) InnerLinkSpec(listenPort, mtu uint16, exitObf Obfuscation) InterfaceSpec {
	return InterfaceSpec{
		PrivateKey:  n.PrivateKey(),
		ListenPort:  listenPort,
		MTU:         mtu,
		Obfuscation: exitObf.Render(),
		// Table=off: do not let awg-quick install a default route for the inner
		// link's 0.0.0.0/0 exit peer; the entry's transit rules route cascaded
		// devices into it (DESIGN §3). Without this the node hijacks its own egress.
		Table: "off",
	}
}

// RenderInterface renders the node's obfuscation parameters as the [Interface]
// lines node writes to awg0.conf. The data-plane writer applies the conf so the
// served config matches exactly what GetStatus reports.
func (n *Node) RenderInterface() string {
	return n.obfuscation.Render()
}
