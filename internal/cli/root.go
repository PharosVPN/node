// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package cli wires up the buoy command-line interface — the three commands
// that form the helm↔buoy contract: gen-csr, run, and version (DESIGN §5,
// decision 14).
package cli

import "github.com/spf13/cobra"

// version is the buoy build version. Overridable at link time with
// -ldflags "-X github.com/PharosVPN/buoy/internal/cli.version=...".
var version = "0.1.0-dev"

// DefaultConfigDir is where helm places a node's mTLS material during SSH
// onboarding, and where buoy reads it from. helm's deploy package runs
// `buoy gen-csr` with no flags and `buoy run --config-dir /etc/buoy`.
const DefaultConfigDir = "/etc/buoy"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "buoy",
		Short: "PharosVPN VPN node agent",
		Long: "buoy — the PharosVPN VPN node agent.\n\n" +
			"buoy runs on every public VPN node. It serves the mTLS NodeControl\n" +
			"gRPC service that helm drives and applies only the configuration helm\n" +
			"pushes to it. buoy opens no connection to helm; helm dials in.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newGenCSRCmd(),
		newRunCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the buoy CLI.
func Execute() error {
	return newRootCmd().Execute()
}
