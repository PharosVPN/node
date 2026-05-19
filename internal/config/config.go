// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package config defines buoy's configuration model and its loader.
//
// buoy holds no database. Its configuration is the config directory helm
// populated over SSH during onboarding (DESIGN §5) — the node keypair and the
// trust anchors — plus a small set of tunables with safe defaults. An optional
// buoy.yaml inside the config directory and BUOY_-prefixed environment
// variables may override those tunables; neither is required.
package config

import "path/filepath"

// On-node filenames within the config directory. helm's deploy package writes
// node.crt and ca.crt to these exact paths over SSH, and `buoy gen-csr` writes
// node.key — this is the helm↔buoy on-disk contract (see deploy.go).
const (
	// NodeKeyFile holds the node's mTLS private key. It is generated on the
	// node by `buoy gen-csr` and never leaves it.
	NodeKeyFile = "node.key"
	// NodeCertFile holds the node's signed leaf certificate followed by the
	// Fleet intermediate, so buoy can present a full chain.
	NodeCertFile = "node.crt"
	// CACertFile holds the root CA certificate — the trust anchor controller
	// client certificates must chain to.
	CACertFile = "ca.crt"
	// ConfigFile is the optional tunables file read from the config directory.
	ConfigFile = "buoy.yaml"
	// AWGStateFile holds the node's AmneziaWG server identity — its keypair
	// and obfuscation set. buoy generates it once and reuses it (DESIGN §3).
	AWGStateFile = "awg-node.json"
)

// DefaultListenAddr is the TCP address the NodeControl server binds to. helm
// dials port 8444 on every node (DESIGN §2; helm deploy.ControlPort).
const DefaultListenAddr = ":8444"

// Config is buoy's full runtime configuration.
type Config struct {
	// Dir is the config directory passed via --config-dir. It is not read
	// from the config file itself.
	Dir string `koanf:"-" yaml:"-"`

	// Control configures the mTLS NodeControl gRPC server.
	Control ControlConfig `koanf:"control" yaml:"control"`
	// Log controls diagnostic logging.
	Log LogConfig `koanf:"log" yaml:"log"`
}

// ControlConfig configures the mTLS NodeControl gRPC server helm drives.
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

// defaults returns the universal configuration, so a node with no buoy.yaml
// still has a complete, valid Config.
func defaults() Config {
	return Config{
		Control: ControlConfig{ListenAddr: DefaultListenAddr},
		Log:     LogConfig{Level: "info"},
	}
}
