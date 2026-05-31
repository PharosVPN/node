// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/PharosVPN/buoy/internal/awg"
	"github.com/PharosVPN/buoy/internal/config"
	"github.com/PharosVPN/buoy/internal/control"
	"github.com/PharosVPN/buoy/internal/netpolicy"
	"github.com/spf13/cobra"
)

// newRunCmd runs the buoy agent: it serves the mTLS NodeControl gRPC service
// coxswain drives. coxswain installs this as the buoy.service systemd unit, invoked as
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

			// The node's AmneziaWG identity is generated on first run and
			// reused thereafter, so the obfuscation set coxswain caches stays
			// stable across restarts (DESIGN §3).
			awgNode, err := awg.Load(cfg.AWGStatePath())
			if err != nil {
				return err
			}
			log.Info("AmneziaWG node identity ready",
				"public_key", awgNode.PublicKey(),
				"state_file", cfg.AWGStatePath())

			awgManager, err := awg.NewManager(awg.ManagerOptions{
				Node:         awgNode,
				Runtime:      awg.NewExecRuntime(),
				ConfPath:     awg.DefaultConfPath,
				RevisionPath: cfg.AWGRevisionPath(),
				Log:          log,
			})
			if err != nil {
				return err
			}
			log.Info("AmneziaWG manager ready",
				"conf_path", awg.DefaultConfPath,
				"applied_revision", awgManager.AppliedRevision())

			// The network-policy applier owns the node's forwarding /
			// masquerade / isolation firewall state (decision 16).
			netPolicy, err := netpolicy.New(netpolicy.Options{
				WGIface:   "awg0",
				Exec:      netpolicy.SystemExec{},
				Egress:    netpolicy.SystemEgress{},
				StatePath: cfg.NetPolicyPath(),
				Log:       log,
			})
			if err != nil {
				return err
			}

			srv, err := control.NewServer(control.Options{
				ListenAddr:   cfg.Control.ListenAddr,
				NodeCertPath: cfg.NodeCertPath(),
				NodeKeyPath:  cfg.NodeKeyPath(),
				CACertPath:   cfg.CACertPath(),
				Version:      version,
				AWGNode:      awgNode,
				AWGManager:   awgManager,
				NetPolicy:    netPolicy,
				Log:          log,
			})
			if err != nil {
				return err
			}

			// Shut down gracefully on SIGINT/SIGTERM — systemd sends SIGTERM.
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Cold start: re-establish the persisted network policy and bring
			// the data plane up from the on-disk conf, so a rebooted node
			// restores its firewall and tunnels before serving — existing
			// peers keep working even if coxswain is unreachable (DESIGN §3).
			if err := netPolicy.Reapply(ctx); err != nil {
				return err
			}
			if err := awgManager.Reconcile(ctx); err != nil {
				return err
			}
			log.Info("cold-start reconcile complete",
				"network_policy", netPolicy.Policy(),
				"applied_revision", awgManager.AppliedRevision())

			// Start the polling observer that feeds WatchEvents and the
			// cumulative GetMetrics counters; it runs until ctx cancels.
			awgManager.Start(ctx)

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
