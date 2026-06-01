// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// allowedBinaries are the only programs the system Exec will run. The argv is
// built entirely from buoy's own canonical templates (the wire carries only
// three policy bools), so nothing client-controlled reaches a command — this
// allowlist is defence in depth, guarding against a future templating bug.
var allowedBinaries = map[string]bool{
	"sysctl":   true,
	"iptables": true,
	"ip":       true,
}

// SystemExec runs resolved commands via os/exec. argv is executed directly,
// never through a shell, so there is no interpolation or injection surface.
type SystemExec struct{}

// Run executes argv[0] with argv[1:], rejecting any binary not on the
// allowlist.
func (SystemExec) Run(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("netpolicy: empty command")
	}
	if !allowedBinaries[argv[0]] {
		return fmt.Errorf("netpolicy: refusing to run disallowed binary %q", argv[0])
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w (output: %s)",
			strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SystemEgress detects the default-route interface via `ip route show default`.
type SystemEgress struct{}

// DefaultEgress returns the interface backing the default route, e.g. "eth0".
// It parses the `dev <iface>` token from `ip route show default`.
func (SystemEgress) DefaultEgress(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ip route show default: %w", err)
	}
	return parseEgressDev(string(out)), nil
}

// parseEgressDev pulls the interface name following "dev" from the first
// default route line. It returns "" when no device is found.
func parseEgressDev(routes string) string {
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}
