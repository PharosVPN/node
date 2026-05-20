// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Runtime is the AmneziaWG data-plane shell-out surface. The real
// implementation invokes the `awg-quick` and `awg` binaries; tests substitute
// a fake. Sensitive material — node private key, peer PSKs — is passed via
// stdin or the on-disk conf file, never on argv or in the environment, and
// never logged.
type Runtime interface {
	// Up brings up awg0 from confPath if it is not already present
	// (`awg-quick up`). Calling Up when the interface already exists is an
	// error — callers use SyncConf to live-reload.
	Up(ctx context.Context, confPath string) error
	// SyncConf live-reloads awg0 from confPath without dropping established
	// tunnels: `awg-quick strip <conf> | awg syncconf awg0 /dev/stdin`.
	SyncConf(ctx context.Context, confPath string) error
	// AddPeer adds one peer live. presharedKey, when non-empty, is piped on
	// stdin — never on argv. allowedIPs are joined into one comma-separated
	// argument as `awg set` expects.
	AddPeer(ctx context.Context, publicKey, presharedKey string, allowedIPs []string) error
	// RemovePeer removes one peer live. Removing a peer that is not on the
	// interface is not an error.
	RemovePeer(ctx context.Context, publicKey string) error
	// Show returns awg0's live per-peer state (`awg show awg0 dump`).
	Show(ctx context.Context) ([]LivePeer, error)
	// Listening reports whether awg0 is up and bound.
	Listening(ctx context.Context) (bool, error)
}

// LivePeer is the runtime state of one peer on awg0.
type LivePeer struct {
	PublicKey     string
	LastHandshake time.Time // zero when the peer has never handshaken
	RxBytes       uint64
	TxBytes       uint64
}

// ExecRuntime is the production Runtime: it shells out to `awg` and
// `awg-quick`.
type ExecRuntime struct {
	// Interface is the AmneziaWG interface name. Defaults to "awg0".
	Interface string
	// AWGBin and AWGQuickBin override the binary lookup; empty means resolve
	// "awg" and "awg-quick" on PATH at call time. Tests inject stand-ins;
	// production leaves them empty.
	AWGBin      string
	AWGQuickBin string
}

// NewExecRuntime returns a Runtime that shells out to the system `awg` /
// `awg-quick`.
func NewExecRuntime() *ExecRuntime {
	return &ExecRuntime{Interface: "awg0"}
}

func (r *ExecRuntime) iface() string {
	if r.Interface == "" {
		return "awg0"
	}
	return r.Interface
}

func (r *ExecRuntime) awg() string {
	if r.AWGBin != "" {
		return r.AWGBin
	}
	return "awg"
}

func (r *ExecRuntime) awgQuick() string {
	if r.AWGQuickBin != "" {
		return r.AWGQuickBin
	}
	return "awg-quick"
}

// Up runs `awg-quick up <confPath>`. awg-quick derives the interface name
// from the conf basename.
func (r *ExecRuntime) Up(ctx context.Context, confPath string) error {
	cmd := exec.CommandContext(ctx, r.awgQuick(), "up", confPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("awg-quick up %s: %w (output: %s)",
			confPath, err, redactOutput(out))
	}
	return nil
}

// SyncConf live-reloads the interface: it strips awg-quick-only directives
// from confPath and feeds the result to `awg syncconf` over stdin.
func (r *ExecRuntime) SyncConf(ctx context.Context, confPath string) error {
	strip := exec.CommandContext(ctx, r.awgQuick(), "strip", confPath)
	stripped, err := strip.Output()
	if err != nil {
		return fmt.Errorf("awg-quick strip: %w", err)
	}

	sync := exec.CommandContext(ctx, r.awg(), "syncconf", r.iface(), "/dev/stdin")
	sync.Stdin = bytes.NewReader(stripped)
	if out, err := sync.CombinedOutput(); err != nil {
		return fmt.Errorf("awg syncconf %s: %w (output: %s)",
			r.iface(), err, redactOutput(out))
	}
	return nil
}

// AddPeer adds one peer live. The PSK, when present, is piped on stdin.
func (r *ExecRuntime) AddPeer(ctx context.Context, publicKey, presharedKey string, allowedIPs []string) error {
	if publicKey == "" {
		return errors.New("awg: AddPeer requires a public key")
	}
	args := []string{"set", r.iface(), "peer", publicKey}
	if presharedKey != "" {
		args = append(args, "preshared-key", "/dev/stdin")
	}
	args = append(args, "allowed-ips", strings.Join(allowedIPs, ","))

	cmd := exec.CommandContext(ctx, r.awg(), args...)
	if presharedKey != "" {
		cmd.Stdin = strings.NewReader(presharedKey + "\n")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("awg set peer %s: %w (output: %s)",
			redactPubkey(publicKey), err, redactOutput(out))
	}
	return nil
}

// RemovePeer removes one peer live.
func (r *ExecRuntime) RemovePeer(ctx context.Context, publicKey string) error {
	if publicKey == "" {
		return errors.New("awg: RemovePeer requires a public key")
	}
	cmd := exec.CommandContext(ctx, r.awg(), "set", r.iface(), "peer", publicKey, "remove")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("awg set peer remove %s: %w (output: %s)",
			redactPubkey(publicKey), err, redactOutput(out))
	}
	return nil
}

// Show parses `awg show <iface> dump`.
//
// Dump format (tab-separated):
//   - line 1: interface — private_key, public_key, listen_port, fwmark.
//   - line 2+: per-peer — public_key, preshared_key, endpoint, allowed_ips,
//     latest_handshake (unix seconds, 0 = never), rx_bytes, tx_bytes,
//     persistent_keepalive.
//
// The interface private key on line 1 is intentionally ignored; we read it
// only from awg-node.json.
func (r *ExecRuntime) Show(ctx context.Context) ([]LivePeer, error) {
	cmd := exec.CommandContext(ctx, r.awg(), "show", r.iface(), "dump")
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("awg show %s dump: %w", r.iface(), err)
	}
	return parseShowDump(raw)
}

// Listening reports whether awg0 exists — `awg show <iface>` succeeds only
// when the interface is up.
func (r *ExecRuntime) Listening(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, r.awg(), "show", r.iface())
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		return false, fmt.Errorf("awg show %s: %w", r.iface(), err)
	}
	return true, nil
}

// parseShowDump turns the tab-separated dump into LivePeer values, skipping
// the interface line.
func parseShowDump(raw []byte) ([]LivePeer, error) {
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) <= 1 {
		return nil, nil
	}
	peers := make([]LivePeer, 0, len(lines)-1)
	for i, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			return nil, fmt.Errorf("awg: dump line %d: want >=7 fields, got %d", i+2, len(fields))
		}
		hs, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("awg: dump line %d: handshake: %w", i+2, err)
		}
		rx, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("awg: dump line %d: rx: %w", i+2, err)
		}
		tx, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("awg: dump line %d: tx: %w", i+2, err)
		}
		p := LivePeer{
			PublicKey: fields[0],
			RxBytes:   rx,
			TxBytes:   tx,
		}
		if hs != 0 {
			p.LastHandshake = time.Unix(hs, 0).UTC()
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// redactPubkey returns the first eight characters of a base64 public key —
// enough to identify a peer in a log line without exposing the full key.
func redactPubkey(k string) string {
	if len(k) > 8 {
		return k[:8] + "…"
	}
	return k
}

// redactOutput sanitises a command's combined output before it lands in an
// error string. awg's diagnostic output does not normally include the PSK
// (which arrived only on stdin), but defence in depth: strip any line that
// looks like a key=value with `key` or `preshared`.
func redactOutput(out []byte) string {
	s := string(out)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		low := strings.ToLower(line)
		if strings.Contains(low, "preshared") || strings.Contains(low, "private key") {
			lines[i] = "<redacted>"
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
