// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Command buoy is the PharosVPN VPN node agent. It runs on every public VPN
// node, serves the mTLS NodeControl gRPC service coxswain drives, and applies only
// the configuration coxswain pushes to it (DESIGN §3).
package main

import (
	"fmt"
	"os"

	"github.com/PharosVPN/buoy/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "buoy: "+err.Error())
		os.Exit(1)
	}
}
