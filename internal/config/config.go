// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package config defines node's configuration model and its loader.
//
// node holds no database. Its configuration is the config directory coxswain
// populated over SSH during onboarding (DESIGN §5) — the node keypair and the
// trust anchors — plus a small set of tunables with safe defaults. An optional
// node.yaml inside the config directory and NODE_-prefixed environment
// variables may override those tunables; neither is required.
package config

import "path/filepath"

// On-node filenames within the config directory. coxswain's deploy package writes
// node.crt and ca.crt to these exact paths over SSH, and `node gen-csr` writes
// node.key — this is the coxswain↔node on-disk contract (see deploy.go).
const (
	// NodeKeyFile holds the node's mTLS private key. It is generated on the
	// node by `node gen-csr` and never leaves it.
	NodeKeyFile = "node.key"
	// NodeCertFile holds the node's signed leaf certificate followed by the
	// Fleet intermediate, so node can present a full chain.
	NodeCertFile = "node.crt"
	// CACertFile holds the root CA certificate — the trust anchor controller
	// client certificates must chain to.
	CACertFile = "ca.crt"
	// ConfigFile is the optional tunables file read from the config directory.
	ConfigFile = "node.yaml"
	// AWGStateFile holds the node's AmneziaWG server identity — its keypair
	// and obfuscation set. node generates it once and reuses it (DESIGN §3).
	AWGStateFile = "awg-node.json"
	// AWGRevisionFile persists the last applied PushConfig revision so the
	// optimistic-concurrency guard survives a restart.
	AWGRevisionFile = "awg-revision"
	// NetPolicyFile persists the last-applied network policy (forwarding /
	// masquerade / isolation) and the exact teardown commands for it, so the
	// node re-establishes its firewall state on cold start and can revert the
	// previous rules before applying a new policy. It carries no secrets.
	NetPolicyFile = "netpolicy.json"
)

// DefaultListenAddr is the TCP address the NodeControl server binds to. coxswain
// dials port 8444 on every node (DESIGN §2; coxswain deploy.ControlPort).
const DefaultListenAddr = ":8444"

// Config is node's full runtime configuration.
type Config struct {
	// Dir is the config directory passed via --config-dir. It is not read
	// from the config file itself.
	Dir string `koanf:"-" yaml:"-"`

	// Control configures the mTLS NodeControl gRPC server.
	Control ControlConfig `koanf:"control" yaml:"control"`
	// Log controls diagnostic logging.
	Log LogConfig `koanf:"log" yaml:"log"`
}

// ControlConfig configures the mTLS NodeControl gRPC server coxswain drives.
type ControlConfig struct {
	// ListenAddr is the TCP address the server binds to.
	ListenAddr string `koanf:"listen_addr" yaml:"listen_addr"`
}

// LogConfig controls diagnostic logging.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `koanf:"level" yaml:"level"`
}

// NodeKeyPath is the absolute path to the node's mTLS private key.
func (c Config) NodeKeyPath() string { return filepath.Join(c.Dir, NodeKeyFile) }

// NodeCertPath is the absolute path to the node's certificate chain.
func (c Config) NodeCertPath() string { return filepath.Join(c.Dir, NodeCertFile) }

// CACertPath is the absolute path to the root CA trust anchor.
func (c Config) CACertPath() string { return filepath.Join(c.Dir, CACertFile) }

// AWGStatePath is the absolute path to the node's AmneziaWG identity file.
func (c Config) AWGStatePath() string { return filepath.Join(c.Dir, AWGStateFile) }

// AWGRevisionPath is the absolute path to the last-applied PushConfig
// revision file.
func (c Config) AWGRevisionPath() string { return filepath.Join(c.Dir, AWGRevisionFile) }

// NetPolicyPath is the absolute path to the persisted network-policy state.
func (c Config) NetPolicyPath() string { return filepath.Join(c.Dir, NetPolicyFile) }

// defaults returns the universal configuration, so a node with no node.yaml
// still has a complete, valid Config.
func defaults() Config {
	return Config{
		Control: ControlConfig{ListenAddr: DefaultListenAddr},
		Log:     LogConfig{Level: "info"},
	}
}
