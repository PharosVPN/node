// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"path/filepath"

	"github.com/PharosVPN/node/internal/config"
	"github.com/PharosVPN/node/internal/pki"
	"github.com/spf13/cobra"
)

// newGenCSRCmd generates the node's mTLS keypair on the node and prints a
// PEM-encoded certificate signing request to stdout.
//
// This is the first step of SSH onboarding (DESIGN §5, decision 14): coxswain runs
// `node gen-csr` over SSH, captures the CSR from stdout, signs it with the
// Fleet CA, and pushes node.crt and ca.crt back. The node's private key is
// written to node.key and never leaves the node.
//
// Re-running gen-csr is idempotent — an existing key is reused.
func newGenCSRCmd() *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   "gen-csr",
		Short: "Generate the node keypair and print a CSR for coxswain to sign",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyPath := filepath.Join(configDir, config.NodeKeyFile)
			res, err := pki.GenerateCSR(keyPath)
			if err != nil {
				return err
			}

			// Diagnostics go to stderr; stdout carries only the CSR so coxswain
			// can capture it cleanly over SSH. A failed diagnostic write must
			// not fail gen-csr itself.
			if res.KeyGenerated {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "node: generated node key at %s\n", keyPath)
			} else {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "node: reusing existing node key at %s\n", keyPath)
			}
			_, err = cmd.OutOrStdout().Write(res.CSRPEM)
			return err
		},
	}
	cmd.Flags().StringVar(&configDir, "config-dir", DefaultConfigDir,
		"directory the node keypair is written to")
	return cmd
}
