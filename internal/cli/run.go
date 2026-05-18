// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/PharosVPN/buoy/internal/config"
	"github.com/PharosVPN/buoy/internal/control"
	"github.com/spf13/cobra"
)

// newRunCmd runs the buoy agent: it serves the mTLS NodeControl gRPC service
// helm drives. helm installs this as the buoy.service systemd unit, invoked as
// `buoy run --config-dir /etc/buoy`.
func newRunCmd() *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the buoy agent (serve the mTLS NodeControl service)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configDir)
			if err != nil {
				return err
			}

			log := newLogger(cfg.Log.Level)
			log.Info("starting buoy agent",
				"version", version,
				"config_dir", cfg.Dir,
				"listen_addr", cfg.Control.ListenAddr)

			srv, err := control.NewServer(
				cfg.Control.ListenAddr,
				cfg.NodeCertPath(),
				cfg.NodeKeyPath(),
				cfg.CACertPath(),
				log,
			)
			if err != nil {
				return err
			}

			// Shut down gracefully on SIGINT/SIGTERM — systemd sends SIGTERM.
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			return srv.Serve(ctx)
		},
	}
	cmd.Flags().StringVar(&configDir, "config-dir", DefaultConfigDir,
		"directory holding node.key, node.crt, ca.crt and optional buoy.yaml")
	return cmd
}

// newLogger builds a slog logger writing to stderr at the configured level.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
