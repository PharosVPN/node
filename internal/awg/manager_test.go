// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
)

// fakeRuntime is a Runtime that maintains synthetic live state. Up/SyncConf
// reload the live peer set from the on-disk conf, so a Manager driving it
// behaves like a real one driving awg0.
type fakeRuntime struct {
	mu sync.Mutex

	listening bool
	confPath  string
	live      map[string]LivePeer
	calls     []string
	showErr   error // injected; non-nil → Show returns this error
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{live: map[string]LivePeer{}}
}

func (r *fakeRuntime) Up(_ context.Context, confPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listening = true
	r.confPath = confPath
	r.calls = append(r.calls, "Up")
	return r.reloadLocked()
}

func (r *fakeRuntime) SyncConf(_ context.Context, confPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.confPath = confPath
	r.calls = append(r.calls, "SyncConf")
	return r.reloadLocked()
}

func (r *fakeRuntime) AddPeer(_ context.Context, publicKey, _ string, allowedIPs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "AddPeer:"+publicKey)
	// preserve any prior byte counters
	prev := r.live[publicKey]
	prev.PublicKey = publicKey
	_ = allowedIPs
	r.live[publicKey] = prev
	return nil
}

func (r *fakeRuntime) RemovePeer(_ context.Context, publicKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "RemovePeer:"+publicKey)
	delete(r.live, publicKey)
	return nil
}

func (r *fakeRuntime) Show(_ context.Context) ([]LivePeer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.showErr != nil {
		return nil, r.showErr
	}
	out := make([]LivePeer, 0, len(r.live))
	for _, p := range r.live {
		out = append(out, p)
	}
	return out, nil
}

// setListening flips the listening flag without going through Up.
func (r *fakeRuntime) setListening(up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listening = up
}

// setShowErr injects an error into the next Show calls.
func (r *fakeRuntime) setShowErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.showErr = err
}

func (r *fakeRuntime) Listening(_ context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listening, nil
}

// reloadLocked rebuilds live from the on-disk conf. Caller holds r.mu.
func (r *fakeRuntime) reloadLocked() error {
	raw, err := os.ReadFile(r.confPath)
	if err != nil {
		return err
	}
	peers, err := parseConfPeers(raw)
	if err != nil {
		return err
	}
	next := make(map[string]LivePeer, len(peers))
	for _, p := range peers {
		// preserve byte counters when a peer survives a reload
		prev := r.live[p.PublicKey]
		prev.PublicKey = p.PublicKey
		next[p.PublicKey] = prev
	}
	r.live = next
	return nil
}

// setLivePeer is a test hook for seeding handshake / byte counters.
func (r *fakeRuntime) setLivePeer(p LivePeer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live[p.PublicKey] = p
}

// callCount returns how many times a given method prefix was recorded.
func (r *fakeRuntime) callCount(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c == prefix || (len(c) > len(prefix) && c[:len(prefix)+1] == prefix+":") {
			n++
		}
	}
	return n
}

// --- test helpers -----------------------------------------------------------

func newTestManager(t *testing.T) (*Manager, *fakeRuntime) {
	t.Helper()
	dir := t.TempDir()
	node := mustLoadNode(t)
	rt := newFakeRuntime()
	mgr, err := NewManager(ManagerOptions{
		Node:         node,
		Runtime:      rt,
		ConfPath:     filepath.Join(dir, "awg0.conf"),
		RevisionPath: filepath.Join(dir, "awg-revision"),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr, rt
}

func peer(id, pubkey, psk string, ips ...string) *buoyv1.Peer {
	return &buoyv1.Peer{
		Id:           id,
		Protocol:     buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
		PublicKey:    pubkey,
		PresharedKey: psk,
		AllowedIps:   ips,
	}
}

// --- AddPeer / RemovePeer ---------------------------------------------------

func TestAddPeerWritesConfAndCallsRuntime(t *testing.T) {
	mgr, rt := newTestManager(t)
	applied, err := mgr.AddPeer(context.Background(), peer("p1", "PUBA=", "PSKA=", "10.0.0.2/32"))
	if err != nil || !applied {
		t.Fatalf("AddPeer: applied=%v err=%v", applied, err)
	}
	if rt.callCount("AddPeer") != 1 {
		t.Errorf("runtime.AddPeer calls = %d, want 1", rt.callCount("AddPeer"))
	}

	raw, err := os.ReadFile(mgr.confPath)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := parseConfPeers(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].PublicKey != "PUBA=" {
		t.Errorf("conf peers = %+v, want one PUBA=", peers)
	}
}

func TestAddPeerIsIdempotentAndUpserts(t *testing.T) {
	mgr, _ := newTestManager(t)
	ctx := context.Background()
	if _, err := mgr.AddPeer(ctx, peer("p1", "PUB=", "OLD=", "10.0.0.2/32")); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddPeer(ctx, peer("p1", "PUB=", "NEW=", "10.0.0.3/32")); err != nil {
		t.Fatal(err)
	}

	peers, err := mgr.ListPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers = %d, want 1 (upsert)", len(peers))
	}
	if peers[0].GetPeer().GetPresharedKey() != "NEW=" {
		t.Errorf("psk = %q, want NEW= (upsert replaced)", peers[0].GetPeer().GetPresharedKey())
	}
	if peers[0].GetPeer().GetAllowedIps()[0] != "10.0.0.3/32" {
		t.Errorf("allowed-ips not updated: %v", peers[0].GetPeer().GetAllowedIps())
	}
}

func TestRemovePeerIsIdempotent(t *testing.T) {
	mgr, rt := newTestManager(t)
	ctx := context.Background()
	if _, err := mgr.AddPeer(ctx, peer("p1", "PUB=", "", "10.0.0.2/32")); err != nil {
		t.Fatal(err)
	}
	if applied, err := mgr.RemovePeer(ctx, "PUB="); err != nil || !applied {
		t.Fatalf("first RemovePeer: applied=%v err=%v", applied, err)
	}
	// Second remove on a vanished peer must still succeed.
	if applied, err := mgr.RemovePeer(ctx, "PUB="); err != nil || !applied {
		t.Fatalf("second RemovePeer: applied=%v err=%v", applied, err)
	}
	if rt.callCount("RemovePeer") != 2 {
		t.Errorf("runtime.RemovePeer calls = %d, want 2", rt.callCount("RemovePeer"))
	}
}

// --- ListPeers --------------------------------------------------------------

func TestListPeersJoinsLiveState(t *testing.T) {
	mgr, rt := newTestManager(t)
	ctx := context.Background()
	if _, err := mgr.AddPeer(ctx, peer("p1", "PUBA=", "", "10.0.0.2/32")); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddPeer(ctx, peer("p2", "PUBB=", "", "10.0.0.3/32")); err != nil {
		t.Fatal(err)
	}
	// PUBA has handshaken and exchanged traffic; PUBB has not.
	rt.setLivePeer(LivePeer{PublicKey: "PUBA=", RxBytes: 1024, TxBytes: 2048})

	peers, err := mgr.ListPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(peers))
	}
	byKey := map[string]*buoyv1.PeerState{}
	for _, p := range peers {
		byKey[p.GetPeer().GetPublicKey()] = p
	}
	if got := byKey["PUBA="]; got == nil || got.GetRxBytes() != 1024 || got.GetTxBytes() != 2048 {
		t.Errorf("PUBA= live state lost: %+v", got)
	}
	if got := byKey["PUBB="]; got == nil || got.GetRxBytes() != 0 {
		t.Errorf("PUBB= should have zero counters: %+v", got)
	}
}

// --- PushConfig -------------------------------------------------------------

func TestPushConfigAppliesAndPersistsRevision(t *testing.T) {
	mgr, rt := newTestManager(t)
	ctx := context.Background()

	peers := []ConfPeer{
		{PublicKey: "PUBA=", AllowedIPs: []string{"10.0.0.2/32"}},
		{PublicKey: "PUBB=", AllowedIPs: []string{"10.0.0.3/32"}},
	}
	rev, reloaded, err := mgr.PushConfig(ctx, 1, peers)
	if err != nil || !reloaded || rev != 1 {
		t.Fatalf("PushConfig: rev=%d reloaded=%v err=%v", rev, reloaded, err)
	}
	if rt.callCount("Up") != 1 {
		t.Errorf("runtime.Up calls = %d, want 1 (first apply brings interface up)",
			rt.callCount("Up"))
	}

	// A second push (higher revision) live-reloads with SyncConf, not Up.
	if _, _, err := mgr.PushConfig(ctx, 2, peers); err != nil {
		t.Fatalf("second PushConfig: %v", err)
	}
	if rt.callCount("SyncConf") != 1 {
		t.Errorf("runtime.SyncConf calls = %d, want 1 (live reload)",
			rt.callCount("SyncConf"))
	}

	// Persisted across "restart".
	mgr2, err := NewManager(ManagerOptions{
		Node:         mgr.node,
		Runtime:      rt,
		ConfPath:     mgr.confPath,
		RevisionPath: mgr.revisionPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := mgr2.AppliedRevision(); got != 2 {
		t.Errorf("AppliedRevision after restart = %d, want 2", got)
	}
}

func TestPushConfigRejectsStaleRevision(t *testing.T) {
	mgr, _ := newTestManager(t)
	ctx := context.Background()
	if _, _, err := mgr.PushConfig(ctx, 5, nil); err != nil {
		t.Fatal(err)
	}
	_, _, err := mgr.PushConfig(ctx, 3, nil)
	var stale ErrStaleRevision
	if !errors.As(err, &stale) {
		t.Fatalf("got %v, want ErrStaleRevision", err)
	}
	if stale.Got != 3 || stale.Applied != 5 {
		t.Errorf("ErrStaleRevision = %+v, want {Got:3, Applied:5}", stale)
	}
}

func TestPushConfigEqualRevisionIsIdempotent(t *testing.T) {
	mgr, rt := newTestManager(t)
	ctx := context.Background()
	if _, _, err := mgr.PushConfig(ctx, 7, nil); err != nil {
		t.Fatal(err)
	}
	rev, reloaded, err := mgr.PushConfig(ctx, 7, nil)
	if err != nil {
		t.Fatalf("replay PushConfig: %v", err)
	}
	if reloaded {
		t.Error("equal revision must report reloaded=false")
	}
	if rev != 7 {
		t.Errorf("applied revision = %d, want 7", rev)
	}
	// The replay must not re-trigger Up or SyncConf.
	if got := rt.callCount("Up") + rt.callCount("SyncConf"); got != 1 {
		t.Errorf("apply calls after replay = %d, want 1 (no rewrite)", got)
	}
}

// --- Metrics ----------------------------------------------------------------

func TestMetricsSumsLiveBytes(t *testing.T) {
	mgr, rt := newTestManager(t)
	ctx := context.Background()
	if _, err := mgr.AddPeer(ctx, peer("p1", "PUBA=", "", "10.0.0.2/32")); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddPeer(ctx, peer("p2", "PUBB=", "", "10.0.0.3/32")); err != nil {
		t.Fatal(err)
	}
	rt.setLivePeer(LivePeer{PublicKey: "PUBA=", RxBytes: 100, TxBytes: 200})
	rt.setLivePeer(LivePeer{PublicKey: "PUBB=", RxBytes: 25, TxBytes: 75})

	snap, err := mgr.Metrics(ctx)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if len(snap.Peers) != 2 {
		t.Errorf("peers = %d, want 2", len(snap.Peers))
	}
	if snap.TotalRx != 125 || snap.TotalTx != 275 {
		t.Errorf("totals = rx %d / tx %d, want 125 / 275", snap.TotalRx, snap.TotalTx)
	}
	// handshakes_total / errors_total are placeholders until the B5 poller.
	if snap.Handshakes != 0 || snap.Errors != 0 {
		t.Errorf("expected zero cumulative counters in B4: %+v", snap)
	}
}

func TestMetricsZeroWhenInterfaceDown(t *testing.T) {
	mgr, _ := newTestManager(t)
	snap, err := mgr.Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if len(snap.Peers) != 0 || snap.TotalRx != 0 || snap.TotalTx != 0 {
		t.Errorf("metrics on down interface non-zero: %+v", snap)
	}
}

// --- Status ----------------------------------------------------------------

func TestStatusReportsDownThenUp(t *testing.T) {
	mgr, _ := newTestManager(t)
	ctx := context.Background()
	running, listening, _, _ := mgr.Status(ctx)
	if running || listening {
		t.Error("Status before any apply must report down")
	}
	if _, _, err := mgr.PushConfig(ctx, 1, []ConfPeer{
		{PublicKey: "PUB=", AllowedIPs: []string{"10.0.0.2/32"}},
	}); err != nil {
		t.Fatal(err)
	}
	running, listening, count, _ := mgr.Status(ctx)
	if !running || !listening {
		t.Error("Status after PushConfig must report up")
	}
	if count != 1 {
		t.Errorf("peer count = %d, want 1", count)
	}
}

// --- Reconcile (cold start) -------------------------------------------------

// TestReconcileBringsUpFromDisk proves a rebooted node re-establishes its
// tunnels from the persisted conf without a fresh PushConfig: a new Manager
// over an existing conf, with the interface down, brings it up.
func TestReconcileBringsUpFromDisk(t *testing.T) {
	dir := t.TempDir()
	node := mustLoadNode(t)
	confPath := filepath.Join(dir, "awg0.conf")
	revPath := filepath.Join(dir, "awg-revision")
	ctx := context.Background()

	// First process: push a config, which writes the conf and brings awg0 up.
	mgr1, err := NewManager(ManagerOptions{Node: node, Runtime: newFakeRuntime(), ConfPath: confPath, RevisionPath: revPath})
	if err != nil {
		t.Fatalf("NewManager 1: %v", err)
	}
	if _, _, err := mgr1.PushConfig(ctx, 1, []ConfPeer{
		{PublicKey: "PUB=", AllowedIPs: []string{"10.0.0.2/32"}},
	}); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	// Reboot: a fresh Manager over the same paths with a down interface.
	rt2 := newFakeRuntime() // listening defaults to false
	mgr2, err := NewManager(ManagerOptions{Node: node, Runtime: rt2, ConfPath: confPath, RevisionPath: revPath})
	if err != nil {
		t.Fatalf("NewManager 2: %v", err)
	}
	if err := mgr2.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rt2.callCount("Up") != 1 {
		t.Errorf("Reconcile must bring the interface up from disk: Up calls = %d, want 1", rt2.callCount("Up"))
	}
	// The persisted revision survives the restart.
	if mgr2.AppliedRevision() != 1 {
		t.Errorf("applied revision = %d, want 1 (persisted)", mgr2.AppliedRevision())
	}
}

// TestReconcileLiveReloadsWhenAlreadyUp proves a plain process restart (awg0
// still up) live-reloads rather than bouncing the interface.
func TestReconcileLiveReloadsWhenAlreadyUp(t *testing.T) {
	dir := t.TempDir()
	node := mustLoadNode(t)
	confPath := filepath.Join(dir, "awg0.conf")
	revPath := filepath.Join(dir, "awg-revision")
	ctx := context.Background()

	mgr1, err := NewManager(ManagerOptions{Node: node, Runtime: newFakeRuntime(), ConfPath: confPath, RevisionPath: revPath})
	if err != nil {
		t.Fatalf("NewManager 1: %v", err)
	}
	if _, _, err := mgr1.PushConfig(ctx, 1, []ConfPeer{{PublicKey: "PUB=", AllowedIPs: []string{"10.0.0.2/32"}}}); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	rt2 := newFakeRuntime()
	rt2.setListening(true) // interface still up across the restart
	mgr2, err := NewManager(ManagerOptions{Node: node, Runtime: rt2, ConfPath: confPath, RevisionPath: revPath})
	if err != nil {
		t.Fatalf("NewManager 2: %v", err)
	}
	if err := mgr2.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rt2.callCount("Up") != 0 {
		t.Errorf("Reconcile must not bounce a live interface: Up calls = %d, want 0", rt2.callCount("Up"))
	}
	if rt2.callCount("SyncConf") != 1 {
		t.Errorf("Reconcile on a live interface must SyncConf: calls = %d, want 1", rt2.callCount("SyncConf"))
	}
}

// TestReconcileNoConfIsNoop proves a fresh node (nothing persisted) does
// nothing on Reconcile.
func TestReconcileNoConfIsNoop(t *testing.T) {
	mgr, rt := newTestManager(t)
	if err := mgr.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile on fresh node: %v", err)
	}
	if got := rt.callCount("Up") + rt.callCount("SyncConf"); got != 0 {
		t.Errorf("Reconcile on fresh node ran %d apply calls, want 0", got)
	}
}
