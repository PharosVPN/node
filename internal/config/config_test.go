// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Control.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", c.Control.ListenAddr, DefaultListenAddr)
	}
	if c.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want info", c.Log.Level)
	}
	if c.Dir != dir {
		t.Errorf("Dir = %q, want %q", c.Dir, dir)
	}
}

func TestLoadFileOverride(t *testing.T) {
	dir := t.TempDir()
	body := "control:\n  listen_addr: \":9000\"\nlog:\n  level: debug\n"
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Control.ListenAddr != ":9000" {
		t.Errorf("ListenAddr = %q, want :9000", c.Control.ListenAddr)
	}
	if c.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", c.Log.Level)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BUOY_CONTROL__LISTEN_ADDR", ":7777")
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Control.ListenAddr != ":7777" {
		t.Errorf("ListenAddr = %q, want :7777", c.Control.ListenAddr)
	}
}

func TestLoadEmptyDir(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("Load(\"\") = nil error, want error")
	}
}

func TestLoadRejectsBadLogLevel(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ConfigFile),
		[]byte("log:\n  level: chatty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load with bad log level = nil error, want error")
	}
}

func TestPathHelpers(t *testing.T) {
	c := Config{Dir: "/etc/buoy"}
	if got := c.NodeKeyPath(); got != "/etc/buoy/node.key" {
		t.Errorf("NodeKeyPath = %q", got)
	}
	if got := c.NodeCertPath(); got != "/etc/buoy/node.crt" {
		t.Errorf("NodeCertPath = %q", got)
	}
	if got := c.CACertPath(); got != "/etc/buoy/ca.crt" {
		t.Errorf("CACertPath = %q", got)
	}
}
