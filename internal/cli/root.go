// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package cli wires up the node command-line interface — the three commands
// that form the coxswain↔node contract: gen-csr, run, and version (DESIGN §5,
// decision 14).
package cli

import "github.com/spf13/cobra"

// version is the node build version. Overridable at link time with
// -ldflags "-X github.com/PharosVPN/node/internal/cli.version=...".
var version = "0.1.0-dev"

// DefaultConfigDir is where coxswain places a node's mTLS material during SSH
// onboarding, and where node reads it from. coxswain's deploy package runs
// `node gen-csr` with no flags and `node run --config-dir /etc/node`.
const DefaultConfigDir = "/etc/node"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "node",
		Short: "PharosVPN VPN node agent",
		Long: "node — the PharosVPN VPN node agent.\n\n" +
			"node runs on every public VPN node. It serves the mTLS NodeControl\n" +
			"gRPC service that coxswain drives and applies only the configuration coxswain\n" +
			"pushes to it. node opens no connection to coxswain; coxswain dials in.",
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

// Execute runs the node CLI.
func Execute() error {
	return newRootCmd().Execute()
}
