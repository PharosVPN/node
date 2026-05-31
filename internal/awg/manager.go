// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultConfPath is the AmneziaWG conf file buoy writes and `awg-quick` reads.
const DefaultConfPath = "/etc/amnezia/amneziawg/awg0.conf"

const (
	// confFileMode keeps the awg0.conf owner-only — it holds the node
	// private key and per-peer PSKs.
	confFileMode fs.FileMode = 0o600
	// revisionFileMode is the persisted last-applied PushConfig revision.
	// It carries no secrets.
	revisionFileMode fs.FileMode = 0o644
)

// ManagerOptions configures a Manager.
type ManagerOptions struct {
	// Node is the persisted AmneziaWG identity (keypair + obfuscation).
	Node *Node
	// Runtime is the awg/awg-quick driver; tests substitute a fake.
	Runtime Runtime
	// ConfPath is the awg0.conf path; empty means DefaultConfPath.
	ConfPath string
	// RevisionPath persists the last applied PushConfig revision across
	// restarts; required.
	RevisionPath string
	// ObserverInterval and ObserverStaleThreshold tune the polling
	// observer that feeds WatchEvents and the cumulative counters
	// (handshakes_total, errors_total) on GetMetrics. Zero values fall back
	// to package defaults.
	ObserverInterval       time.Duration
	ObserverStaleThreshold time.Duration
	// Log is the manager's logger; the observer inherits it.
	Log *slog.Logger
}

// Manager owns the AmneziaWG data plane: awg0's running state, awg0.conf, the
// last-applied PushConfig revision, and the polling observer that produces
// WatchEvents and accumulates GetMetrics counters. All mutations are
// serialised.
type Manager struct {
	node         *Node
	runtime      Runtime
	confPath     string
	revisionPath string
	observer     *Observer

	mu              sync.Mutex
	appliedRevision int64
}

// NewManager loads the last applied revision from disk and returns a Manager
// ready to serve. It does not bring the interface up; that happens on the
// first PushConfig.
func NewManager(opts ManagerOptions) (*Manager, error) {
	if opts.Node == nil {
		return nil, errors.New("awg: Manager needs a Node")
	}
	if opts.Runtime == nil {
		return nil, errors.New("awg: Manager needs a Runtime")
	}
	if opts.RevisionPath == "" {
		return nil, errors.New("awg: Manager needs a RevisionPath")
	}
	confPath := opts.ConfPath
	if confPath == "" {
		confPath = DefaultConfPath
	}
	m := &Manager{
		node:         opts.Node,
		runtime:      opts.Runtime,
		confPath:     confPath,
		revisionPath: opts.RevisionPath,
		observer: NewObserver(
			opts.Runtime,
			opts.ObserverInterval,
			opts.ObserverStaleThreshold,
			opts.Log,
		),
	}
	rev, err := readRevision(opts.RevisionPath)
	if err != nil {
		return nil, err
	}
	m.appliedRevision = rev
	return m, nil
}

// Reconcile brings the data plane up from the on-disk conf at startup, so a
// node that rebooted (or whose buoy process restarted) re-establishes its
// tunnels from persisted state without waiting for coxswain to push again —
// the controller-outage-survival guarantee (DESIGN §3). If no conf has been
// written yet (a fresh node), it is a no-op. It never changes the applied
// revision; it only mirrors the persisted conf onto the interface.
func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(m.confPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // fresh node — nothing persisted to bring up
		}
		return fmt.Errorf("awg: stat %s: %w", m.confPath, err)
	}
	// applyConf brings the interface up if it is down (the reboot case) or
	// live-reloads it if it is already up (a plain process restart) — neither
	// drops an established tunnel.
	return m.applyConf(ctx)
}

// Start launches the polling observer in the background; it runs until ctx
// cancels. Subscribers (WatchEvents streams) registered before Start get the
// first poll's events too, but the first poll itself establishes the
// baseline silently.
func (m *Manager) Start(ctx context.Context) {
	go m.observer.Run(ctx)
}

// Subscribe registers a WatchEvents consumer with the observer. The returned
// cancel must be called when the stream ends so the subscriber slot is
// released.
func (m *Manager) Subscribe() (<-chan *buoyv1.Event, func()) {
	return m.observer.Subscribe()
}

// AppliedRevision returns the last successfully applied PushConfig revision.
func (m *Manager) AppliedRevision() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appliedRevision
}

// PushConfig replaces the data plane's peer set, renders awg0.conf from the
// node's persisted identity + the given peers, and reloads the interface
// live. Stale revisions are rejected; an equal revision is treated as an
// idempotent replay (no rewrite, reloaded=false). The caller has already
// stripped any obfuscation values arriving in the request — buoy owns those.
func (m *Manager) PushConfig(ctx context.Context, revision int64, peers []ConfPeer) (appliedRev int64, reloaded bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if revision < m.appliedRevision {
		return m.appliedRevision, false, ErrStaleRevision{Got: revision, Applied: m.appliedRevision}
	}
	if revision == m.appliedRevision && m.appliedRevision > 0 {
		// Idempotent replay — the same config landed before.
		return m.appliedRevision, false, nil
	}

	if err := m.writeConf(peers); err != nil {
		return 0, false, err
	}
	if err := m.applyConf(ctx); err != nil {
		return 0, false, err
	}
	if err := writeRevision(m.revisionPath, revision); err != nil {
		return 0, false, err
	}
	m.appliedRevision = revision
	return revision, true, nil
}

// AddPeer inserts (or upserts) one peer into awg0.conf and adds it live. It
// is idempotent: adding a peer with the same public key replaces its
// allowed-ips and PSK with the new values.
func (m *Manager) AddPeer(ctx context.Context, p *buoyv1.Peer) (bool, error) {
	if p == nil || p.GetPublicKey() == "" {
		return false, errors.New("awg: AddPeer requires a Peer with a public key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	peers, err := m.readPeers()
	if err != nil {
		return false, err
	}
	cp := ConfPeer{
		PublicKey:    p.GetPublicKey(),
		PresharedKey: p.GetPresharedKey(),
		AllowedIPs:   append([]string(nil), p.GetAllowedIps()...),
	}
	peers = upsertPeer(peers, cp)
	if err := m.writeConf(peers); err != nil {
		return false, err
	}
	if err := m.runtime.AddPeer(ctx, cp.PublicKey, cp.PresharedKey, cp.AllowedIPs); err != nil {
		return false, err
	}
	return true, nil
}

// RemovePeer drops the peer from awg0.conf and from the live interface.
// Removing a peer that is not present is not an error.
func (m *Manager) RemovePeer(ctx context.Context, publicKey string) (bool, error) {
	if publicKey == "" {
		return false, errors.New("awg: RemovePeer requires a public key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	peers, err := m.readPeers()
	if err != nil {
		return false, err
	}
	filtered := make([]ConfPeer, 0, len(peers))
	for _, p := range peers {
		if p.PublicKey != publicKey {
			filtered = append(filtered, p)
		}
	}
	if err := m.writeConf(filtered); err != nil {
		return false, err
	}
	if err := m.runtime.RemovePeer(ctx, publicKey); err != nil {
		return false, err
	}
	return true, nil
}

// ListPeers correlates the configured peers (the conf is the source of
// truth) with their live state on awg0. Peers configured but not yet
// observed live appear with zero counters and an unset handshake.
func (m *Manager) ListPeers(ctx context.Context) ([]*buoyv1.PeerState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	confPeers, err := m.readPeers()
	if err != nil {
		return nil, err
	}

	live, _ := m.runtime.Show(ctx)
	byKey := make(map[string]LivePeer, len(live))
	for _, p := range live {
		byKey[p.PublicKey] = p
	}

	out := make([]*buoyv1.PeerState, 0, len(confPeers))
	for _, cp := range confPeers {
		ps := &buoyv1.PeerState{
			Peer: &buoyv1.Peer{
				Protocol:     buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
				PublicKey:    cp.PublicKey,
				PresharedKey: cp.PresharedKey,
				AllowedIps:   append([]string(nil), cp.AllowedIPs...),
			},
		}
		if lp, ok := byKey[cp.PublicKey]; ok {
			ps.RxBytes = lp.RxBytes
			ps.TxBytes = lp.TxBytes
			if !lp.LastHandshake.IsZero() {
				ps.LastHandshake = timestamppb.New(lp.LastHandshake)
			}
		}
		out = append(out, ps)
	}
	return out, nil
}

// MetricsSnapshot is the AmneziaWG data plane's current metrics snapshot.
type MetricsSnapshot struct {
	Peers   []*buoyv1.PeerState
	TotalRx uint64
	TotalTx uint64
	// Handshakes and Errors are cumulative counters maintained by the
	// observer (B5) — they only advance when the observer witnesses a
	// transition, matching Prometheus monotonic-counter semantics.
	Handshakes uint64
	Errors     uint64
}

// Metrics builds a metrics snapshot from the current conf+live correlation.
// Per-peer counters come from `awg show`; totals are sums over the live peer
// set. The cumulative counters come from the observer.
func (m *Manager) Metrics(ctx context.Context) (*MetricsSnapshot, error) {
	peers, err := m.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	snap := &MetricsSnapshot{
		Peers:      peers,
		Handshakes: m.observer.HandshakesTotal(),
		Errors:     m.observer.ErrorsTotal(),
	}
	for _, p := range peers {
		snap.TotalRx += p.GetRxBytes()
		snap.TotalTx += p.GetTxBytes()
	}
	return snap, nil
}

// Status reports the AmneziaWG service health.
func (m *Manager) Status(ctx context.Context) (running, listening bool, peerCount uint32, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	up, err := m.runtime.Listening(ctx)
	if err != nil {
		return false, false, 0, fmt.Sprintf("awg show failed: %v", err)
	}
	if !up {
		return false, false, 0, "awg0 not up"
	}
	live, err := m.runtime.Show(ctx)
	if err != nil {
		return true, true, 0, fmt.Sprintf("awg show dump failed: %v", err)
	}
	return true, true, uint32(len(live)), fmt.Sprintf("awg0 up, %d peers", len(live))
}

// --- internals --------------------------------------------------------------

// applyConf reloads awg0 from the on-disk conf. The first call brings the
// interface up; subsequent calls use SyncConf so established tunnels do not
// drop.
func (m *Manager) applyConf(ctx context.Context) error {
	up, err := m.runtime.Listening(ctx)
	if err != nil {
		return err
	}
	if !up {
		return m.runtime.Up(ctx, m.confPath)
	}
	return m.runtime.SyncConf(ctx, m.confPath)
}

// readPeers returns the [Peer] sections from awg0.conf, or an empty slice if
// the file does not yet exist.
func (m *Manager) readPeers() ([]ConfPeer, error) {
	raw, err := os.ReadFile(m.confPath)
	switch {
	case err == nil:
		return parseConfPeers(raw)
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	default:
		return nil, fmt.Errorf("awg: read %s: %w", m.confPath, err)
	}
}

// writeConf renders peers + the node's [Interface] block and persists the
// result to confPath atomically (temp + rename, 0600). The parent directory
// is created on demand.
func (m *Manager) writeConf(peers []ConfPeer) error {
	if dir := filepath.Dir(m.confPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("awg: create %s: %w", dir, err)
		}
	}
	body := renderConf(m.node, peers)
	tmp := m.confPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), confFileMode); err != nil {
		return fmt.Errorf("awg: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, m.confPath); err != nil {
		return fmt.Errorf("awg: replace %s: %w", m.confPath, err)
	}
	return nil
}

// upsertPeer replaces an existing peer with the same public key, otherwise
// appends.
func upsertPeer(peers []ConfPeer, p ConfPeer) []ConfPeer {
	for i := range peers {
		if peers[i].PublicKey == p.PublicKey {
			peers[i] = p
			return peers
		}
	}
	return append(peers, p)
}

func readRevision(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		return 0, nil
	default:
		return 0, fmt.Errorf("awg: read %s: %w", path, err)
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("awg: parse %s: %w", path, err)
	}
	return v, nil
}

func writeRevision(path string, rev int64) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("awg: create %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(rev, 10)+"\n"), revisionFileMode); err != nil {
		return fmt.Errorf("awg: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("awg: replace %s: %w", path, err)
	}
	return nil
}

// ErrStaleRevision is returned when PushConfig sees a revision below the last
// applied one. The service layer maps it to gRPC FailedPrecondition.
type ErrStaleRevision struct {
	Got, Applied int64
}

func (e ErrStaleRevision) Error() string {
	return fmt.Sprintf("awg: stale revision %d (last applied %d)", e.Got, e.Applied)
}
