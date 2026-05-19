// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

// envPrefix scopes environment-variable overrides. A double underscore marks a
// nesting boundary, so BUOY_CONTROL__LISTEN_ADDR overrides control.listen_addr.
const envPrefix = "BUOY_"

// Load builds buoy's configuration for the given config directory. It layers,
// in order: universal defaults, an optional buoy.yaml inside dir, then
// BUOY_-prefixed environment overrides. The config file is optional — a node
// onboarded by helm has none, and that is the normal case.
func Load(dir string) (Config, error) {
	if dir == "" {
		return Config{}, errors.New("config: config directory must not be empty")
	}

	k := koanf.New(".")

	// Layer 1: universal defaults.
	if err := k.Load(structs.Provider(defaults(), "koanf"), nil); err != nil {
		return Config{}, fmt.Errorf("config: load defaults: %w", err)
	}

	// Layer 2: the optional on-disk tunables file.
	confPath := filepath.Join(dir, ConfigFile)
	if _, err := os.Stat(confPath); err == nil {
		if err := k.Load(file.Provider(confPath), yaml.Parser()); err != nil {
			return Config{}, fmt.Errorf("config: read %s: %w", confPath, err)
		}
	} else if !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("config: stat %s: %w", confPath, err)
	}

	// Layer 3: environment overrides.
	if err := k.Load(env.Provider(envPrefix, ".", envKey), nil); err != nil {
		return Config{}, fmt.Errorf("config: load environment: %w", err)
	}

	var c Config
	if err := k.Unmarshal("", &c); err != nil {
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}
	c.Dir = dir
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// envKey maps an environment variable name to a config key path.
func envKey(s string) string {
	s = strings.ToLower(strings.TrimPrefix(s, envPrefix))
	return strings.ReplaceAll(s, "__", ".")
}

// Validate checks invariants the type system cannot.
func (c Config) Validate() error {
	if c.Dir == "" {
		return errors.New("config: config directory must not be empty")
	}
	if c.Control.ListenAddr == "" {
		return errors.New("config: control.listen_addr must not be empty")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: invalid log level %q", c.Log.Level)
	}
	return nil
}
