// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
)

// newTestObserver builds an Observer wired to a fakeRuntime with deterministic
// time. Tests advance `now` between polls to simulate clock progression.
func newTestObserver(t *testing.T) (*Observer, *fakeRuntime, *time.Time) {
	t.Helper()
	rt := newFakeRuntime()
	rt.setListening(true)
	clock := time.Unix(1_700_000_000, 0).UTC()
	o := NewObserver(rt, time.Hour, 30*time.Second, nil)
	o.now = func() time.Time { return clock }
	return o, rt, &clock
}

// drain reads up to n events from ch with a small timeout per event,
// returning what it got. Unblocks tests when the observer emits fewer
// events than expected.
func drain(t *testing.T, ch <-chan *nodev1.Event, n int) []*nodev1.Event {
	t.Helper()
	out := make([]*nodev1.Event, 0, n)
	for i := 0; i < n; i++ {
		select {
		case ev := <-ch:
			out = append(out, ev)
		case <-time.After(time.Second):
			return out
		}
	}
	return out
}

// TestObserverBaselineSilent proves the first poll never emits events —
// admin UIs read current state via GetStatus + ListPeers, and a replay would
// double-count.
func TestObserverBaselineSilent(t *testing.T) {
	o, rt, _ := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "A=", LastHandshake: time.Unix(1_700_000_000, 0)})
	rt.setLivePeer(LivePeer{PublicKey: "B="})

	ch, cancel := o.Subscribe()
	defer cancel()
	o.Poll(context.Background())

	select {
	case ev := <-ch:
		t.Fatalf("baseline poll emitted %v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestObserverEmitsPeerConnected(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	// A peer present-but-idle (no handshake) is the baseline — it is not yet a
	// session. Connecting is the handshake transition.
	rt.setLivePeer(LivePeer{PublicKey: "NEW="})
	o.Poll(context.Background()) // baseline

	ch, cancel := o.Subscribe()
	defer cancel()

	// The peer completes its first handshake from a known endpoint — it now
	// has a live session, so we expect a HANDSHAKE_UP and a PEER_CONNECTED,
	// both carrying the source endpoint and the peer public key.
	*clock = (*clock).Add(10 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "NEW=", Endpoint: "203.0.113.7:51820", LastHandshake: *clock})
	o.Poll(context.Background())

	evs := drain(t, ch, 2)
	var connected *nodev1.Event
	for _, e := range evs {
		if e.GetType() == nodev1.EventType_EVENT_TYPE_PEER_CONNECTED {
			connected = e
		}
	}
	if connected == nil {
		t.Fatalf("events = %v, want a PEER_CONNECTED", evs)
	}
	if connected.GetPeerId() != "NEW=" {
		t.Errorf("peer_id = %q, want NEW=", connected.GetPeerId())
	}
	if connected.GetSourceEndpoint() != "203.0.113.7:51820" {
		t.Errorf("source_endpoint = %q, want 203.0.113.7:51820", connected.GetSourceEndpoint())
	}
}

func TestObserverEmitsPeerDisconnected(t *testing.T) {
	o, rt, _ := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "GONE="})
	o.Poll(context.Background()) // baseline with one peer

	ch, cancel := o.Subscribe()
	defer cancel()

	// Remove the peer between polls.
	rt.mu.Lock()
	delete(rt.live, "GONE=")
	rt.mu.Unlock()
	o.Poll(context.Background())

	evs := drain(t, ch, 1)
	if len(evs) != 1 || evs[0].GetType() != nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED {
		t.Fatalf("events = %v, want one PEER_DISCONNECTED", evs)
	}
}

func TestObserverEmitsHandshakeUpAndCounts(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "P="})
	o.Poll(context.Background()) // baseline: zero handshake

	ch, cancel := o.Subscribe()
	defer cancel()

	// A handshake completes — the first one. It emits a HANDSHAKE_UP and, since
	// the peer was idle until now, a PEER_CONNECTED (the session opens).
	*clock = (*clock).Add(10 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", LastHandshake: *clock})
	o.Poll(context.Background())

	if got := o.HandshakesTotal(); got != 1 {
		t.Errorf("HandshakesTotal = %d, want 1", got)
	}
	if !hasType(drain(t, ch, 2), nodev1.EventType_EVENT_TYPE_HANDSHAKE_UP) {
		t.Fatalf("first handshake did not emit HANDSHAKE_UP")
	}

	// A rekey advances last_handshake again — second HANDSHAKE_UP, counter 2.
	// The peer was already up, so no second PEER_CONNECTED.
	*clock = (*clock).Add(120 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", LastHandshake: *clock})
	o.Poll(context.Background())
	if got := o.HandshakesTotal(); got != 2 {
		t.Errorf("HandshakesTotal after rekey = %d, want 2", got)
	}
	rekey := drain(t, ch, 2)
	if !hasType(rekey, nodev1.EventType_EVENT_TYPE_HANDSHAKE_UP) {
		t.Errorf("rekey events = %v, want a HANDSHAKE_UP", rekey)
	}
	if hasType(rekey, nodev1.EventType_EVENT_TYPE_PEER_CONNECTED) {
		t.Errorf("rekey re-emitted PEER_CONNECTED: %v", rekey)
	}
}

// hasType reports whether any event in evs is of type t.
func hasType(evs []*nodev1.Event, t nodev1.EventType) bool {
	for _, e := range evs {
		if e.GetType() == t {
			return true
		}
	}
	return false
}

func TestObserverEmitsHandshakeDownOnceWhenStale(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	hs := time.Unix(1_700_000_000, 0)
	rt.setLivePeer(LivePeer{PublicKey: "P=", LastHandshake: hs})
	o.Poll(context.Background()) // baseline with handshake

	// A subsequent poll where the handshake has advanced — emits UP (and, as
	// the session opens, PEER_CONNECTED).
	ch, cancel := o.Subscribe()
	defer cancel()
	*clock = hs.Add(5 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", LastHandshake: *clock})
	o.Poll(context.Background())
	if !hasType(drain(t, ch, 2), nodev1.EventType_EVENT_TYPE_HANDSHAKE_UP) {
		t.Fatalf("priming poll did not emit HANDSHAKE_UP")
	}

	// Now the handshake ages past the stale threshold (30s) — a HANDSHAKE_DOWN
	// and a PEER_DISCONNECTED close the session.
	*clock = (*clock).Add(60 * time.Second)
	o.Poll(context.Background())
	stale := drain(t, ch, 2)
	if !hasType(stale, nodev1.EventType_EVENT_TYPE_HANDSHAKE_DOWN) {
		t.Fatalf("stale events = %v, want a HANDSHAKE_DOWN", stale)
	}
	if !hasType(stale, nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED) {
		t.Fatalf("stale events = %v, want a PEER_DISCONNECTED", stale)
	}

	// A second stale poll must not re-emit DOWN/DISCONNECTED.
	*clock = (*clock).Add(60 * time.Second)
	o.Poll(context.Background())
	select {
	case ev := <-ch:
		t.Fatalf("repeated stale poll re-emitted %v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestObserverErrorPath(t *testing.T) {
	o, rt, _ := newTestObserver(t)
	o.Poll(context.Background()) // baseline ok

	ch, cancel := o.Subscribe()
	defer cancel()

	rt.setShowErr(errors.New("show boom"))
	o.Poll(context.Background())

	if got := o.ErrorsTotal(); got != 1 {
		t.Errorf("ErrorsTotal = %d, want 1", got)
	}
	evs := drain(t, ch, 1)
	if len(evs) != 1 || evs[0].GetType() != nodev1.EventType_EVENT_TYPE_ERROR {
		t.Fatalf("events = %v, want ERROR", evs)
	}
}

// TestObserverIgnoresShowErrorWhenInterfaceDown proves node doesn't count
// "interface not up yet" against errors_total — that's the normal pre-push
// state, not a fault.
func TestObserverIgnoresShowErrorWhenInterfaceDown(t *testing.T) {
	o, rt, _ := newTestObserver(t)
	o.Poll(context.Background()) // baseline

	ch, cancel := o.Subscribe()
	defer cancel()

	rt.setListening(false)
	rt.setShowErr(errors.New("interface not up"))
	o.Poll(context.Background())

	if got := o.ErrorsTotal(); got != 0 {
		t.Errorf("ErrorsTotal = %d, want 0 (down isn't an error)", got)
	}
	select {
	case ev := <-ch:
		t.Errorf("emitted %v while interface was down", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestObserverSubscribeIsolated proves a slow subscriber doesn't block a
// fast one — the slow ch fills up and drops, the fast ch keeps receiving.
func TestObserverSubscribeIsolated(t *testing.T) {
	o, rt, _ := newTestObserver(t)
	o.Poll(context.Background())

	slow, slowCancel := o.Subscribe()
	defer slowCancel()
	fast, fastCancel := o.Subscribe()
	defer fastCancel()

	// Saturate the slow subscriber by emitting more than subscriberBuffer
	// events while draining fast on the fly.
	go func() {
		for range fast {
		}
	}()

	// One unique peer per call, each handshaking immediately — every iteration
	// emits a HANDSHAKE_UP (and PEER_CONNECTED). Push well past the buffer so
	// the slow subscriber must shed events.
	base := time.Unix(1_700_000_100, 0).UTC()
	for i := 0; i < subscriberBuffer*2; i++ {
		key := fmt.Sprintf("K%d=", i)
		rt.setLivePeer(LivePeer{PublicKey: key, LastHandshake: base.Add(time.Duration(i) * time.Second)})
		o.Poll(context.Background())
	}
	_ = slow // unread on purpose

	dropped := o.droppedEventsTotal()
	if dropped == 0 {
		t.Errorf("expected drops on the slow subscriber, got 0")
	}
	// The observer-wide counter (surfaced by Run's drop ticker + DroppedTotal)
	// must mirror the per-subscriber sum so silent loss is observable.
	if o.DroppedTotal() != dropped {
		t.Errorf("DroppedTotal() = %d, want %d (per-subscriber sum)", o.DroppedTotal(), dropped)
	}
}

// TestObserverEmitsShutdownDisconnects proves a graceful stop closes out live
// peers (LOW-14): every currently-connected peer gets a PEER_DISCONNECTED so
// coxswain does not leave the session dangling.
func TestObserverEmitsShutdownDisconnects(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "LIVE="})
	o.Poll(context.Background()) // baseline

	ch, cancel := o.Subscribe()
	defer cancel()

	// Bring the peer up so it is "connected" (upEmitted).
	*clock = (*clock).Add(10 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "LIVE=", Endpoint: "203.0.113.7:51820", LastHandshake: *clock})
	o.Poll(context.Background())
	// Drain the HANDSHAKE_UP + PEER_CONNECTED from coming up.
	drain(t, ch, 2)

	// Graceful shutdown should emit a PEER_DISCONNECTED for the live peer.
	o.emitShutdownDisconnects(*clock)
	evs := drain(t, ch, 1)
	if len(evs) != 1 || evs[0].GetType() != nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED {
		t.Fatalf("events = %v, want one PEER_DISCONNECTED on shutdown", evs)
	}
	if evs[0].GetPeerId() != "LIVE=" {
		t.Errorf("peer_id = %q, want LIVE=", evs[0].GetPeerId())
	}

	// Idempotent: a second call must not re-emit (upEmitted was cleared).
	o.emitShutdownDisconnects(*clock)
	select {
	case ev := <-ch:
		t.Fatalf("second shutdown emit produced %v, want none", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestObserverShutdownSkipsIdlePeer proves a present-but-not-connected peer
// (no handshake, never upEmitted) does not get a spurious shutdown disconnect.
func TestObserverShutdownSkipsIdlePeer(t *testing.T) {
	o, rt, _ := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "IDLE="})
	o.Poll(context.Background()) // baseline; peer present but never handshaked

	ch, cancel := o.Subscribe()
	defer cancel()

	o.emitShutdownDisconnects(o.now())
	select {
	case ev := <-ch:
		t.Fatalf("idle peer got a shutdown disconnect %v, want none", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestObserverSubscribeCancelClosesChannel proves the cancel func releases
// the slot and closes the channel exactly once — repeated cancels are safe.
func TestObserverSubscribeCancelClosesChannel(t *testing.T) {
	o, _, _ := newTestObserver(t)
	ch, cancel := o.Subscribe()

	cancel()
	if _, ok := <-ch; ok {
		t.Error("channel still open after cancel")
	}
	cancel() // must not panic
}

// findType returns the first event of type t in evs, or nil.
func findType(evs []*nodev1.Event, t nodev1.EventType) *nodev1.Event {
	for _, e := range evs {
		if e.GetType() == t {
			return e
		}
	}
	return nil
}

// TestObserverConnectDisconnectCarryCumulative proves the observer reports the
// peer's RAW CUMULATIVE awg counters on BOTH the connect and the disconnect that
// closes a stale session — NOT an in-observer delta. The controller pairs the
// two and computes the per-session delta. Here the connect carries cumulative C1
// (1000/2000) and the disconnect carries cumulative C2 (6000/11000).
func TestObserverConnectDisconnectCarryCumulative(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	// Baseline poll: peer already has lifetime traffic from a PRIOR session
	// (1000/2000 cumulative) but is idle (no handshake yet this run).
	const c1Rx, c1Tx = 1000, 2000
	rt.setLivePeer(LivePeer{PublicKey: "P=", RxBytes: c1Rx, TxBytes: c1Tx})
	o.Poll(context.Background())

	ch, cancel := o.Subscribe()
	defer cancel()

	// The session opens with a handshake; cumulative is still 1000/2000. The
	// PEER_CONNECTED must carry that RAW cumulative C1, not 0.
	*clock = (*clock).Add(10 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", Endpoint: "203.0.113.7:51820", LastHandshake: *clock, RxBytes: c1Rx, TxBytes: c1Tx})
	o.Poll(context.Background())
	connected := findType(drain(t, ch, 2), nodev1.EventType_EVENT_TYPE_PEER_CONNECTED)
	if connected == nil {
		t.Fatal("no PEER_CONNECTED")
	}
	if connected.GetRxBytes() != c1Rx || connected.GetTxBytes() != c1Tx {
		t.Errorf("connect carried rx=%d tx=%d, want cumulative %d/%d", connected.GetRxBytes(), connected.GetTxBytes(), c1Rx, c1Tx)
	}

	// During the session the peer transfers more; cumulative rises to 6000/11000.
	// The handshake goes stale and the session closes; the disconnect must report
	// the RAW cumulative C2 (6000/11000), not a delta.
	const c2Rx, c2Tx = 6000, 11000
	*clock = (*clock).Add(60 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", Endpoint: "203.0.113.7:51820", LastHandshake: (*clock).Add(-60 * time.Second), RxBytes: c2Rx, TxBytes: c2Tx})
	o.Poll(context.Background())
	disc := findType(drain(t, ch, 2), nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED)
	if disc == nil {
		t.Fatal("no PEER_DISCONNECTED")
	}
	if disc.GetRxBytes() != c2Rx || disc.GetTxBytes() != c2Tx {
		t.Errorf("disconnect carried rx=%d tx=%d, want cumulative %d/%d", disc.GetRxBytes(), disc.GetTxBytes(), c2Rx, c2Tx)
	}
}

// TestObserverRoamCarriesCumulative proves an endpoint roam emits a fresh
// PEER_CONNECTED (a real source-IP-change signal) carrying the CURRENT cumulative
// counters — the observer no longer keeps a byte baseline, so the controller is
// responsible for pairing connects with disconnects. The roam connect simply
// reports whatever the cumulative is at that instant.
func TestObserverRoamCarriesCumulative(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "P=", RxBytes: 0, TxBytes: 0})
	o.Poll(context.Background())

	ch, cancel := o.Subscribe()
	defer cancel()

	// Connect from endpoint A; cumulative 0/0.
	*clock = (*clock).Add(10 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", Endpoint: "203.0.113.7:51820", LastHandshake: *clock, RxBytes: 0, TxBytes: 0})
	o.Poll(context.Background())
	drain(t, ch, 2)

	// Roam: same peer, fresh handshake from a NEW endpoint, with ~21 MB already
	// cumulative. The roam emits a fresh PEER_CONNECTED carrying that cumulative.
	const roamRx, roamTx = 21_000_000, 1_000_000
	*clock = (*clock).Add(30 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", Endpoint: "198.51.100.9:33333", LastHandshake: *clock, RxBytes: roamRx, TxBytes: roamTx})
	o.Poll(context.Background())
	roamConn := findType(drain(t, ch, 2), nodev1.EventType_EVENT_TYPE_PEER_CONNECTED)
	if roamConn == nil {
		t.Fatal("roam did not emit a fresh PEER_CONNECTED")
	}
	if roamConn.GetSourceEndpoint() != "198.51.100.9:33333" {
		t.Errorf("roam connect source_endpoint = %q, want 198.51.100.9:33333", roamConn.GetSourceEndpoint())
	}
	if roamConn.GetRxBytes() != roamRx || roamConn.GetTxBytes() != roamTx {
		t.Errorf("roam connect carried rx=%d tx=%d, want cumulative %d/%d", roamConn.GetRxBytes(), roamConn.GetTxBytes(), roamRx, roamTx)
	}

	// Close the session by going stale; the disconnect carries the final cumulative.
	const finalRx, finalTx = 22_000_000, 1_100_000
	*clock = (*clock).Add(60 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", Endpoint: "198.51.100.9:33333", LastHandshake: (*clock).Add(-60 * time.Second), RxBytes: finalRx, TxBytes: finalTx})
	o.Poll(context.Background())
	disc := findType(drain(t, ch, 2), nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED)
	if disc == nil {
		t.Fatal("no PEER_DISCONNECTED after roam")
	}
	if disc.GetRxBytes() != finalRx || disc.GetTxBytes() != finalTx {
		t.Errorf("disconnect carried rx=%d tx=%d, want cumulative %d/%d",
			disc.GetRxBytes(), disc.GetTxBytes(), finalRx, finalTx)
	}
}

// TestObserverConfigRemovalCarriesCumulative proves a peer removed from the
// config (gone from the dump) closes its session carrying the LAST-SEEN
// cumulative counter.
func TestObserverConfigRemovalCarriesCumulative(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "P=", RxBytes: 100, TxBytes: 200})
	o.Poll(context.Background())

	ch, cancel := o.Subscribe()
	defer cancel()

	// Connect; cumulative 100/200.
	*clock = (*clock).Add(10 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", LastHandshake: *clock, RxBytes: 100, TxBytes: 200})
	o.Poll(context.Background())
	drain(t, ch, 2)

	// Poll once more so the observer records the last-seen cumulative (3100/4200)
	// while the peer is still up but not stale.
	const lastRx, lastTx = 3100, 4200
	*clock = (*clock).Add(5 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "P=", LastHandshake: (*clock).Add(-5 * time.Second), RxBytes: lastRx, TxBytes: lastTx})
	o.Poll(context.Background())

	// Remove the peer from the config entirely. The disconnect must report the
	// LAST-SEEN cumulative: 3100/4200.
	rt.mu.Lock()
	delete(rt.live, "P=")
	rt.mu.Unlock()
	*clock = (*clock).Add(5 * time.Second)
	o.Poll(context.Background())
	disc := findType(drain(t, ch, 1), nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED)
	if disc == nil {
		t.Fatal("no PEER_DISCONNECTED on config removal")
	}
	if disc.GetRxBytes() != lastRx || disc.GetTxBytes() != lastTx {
		t.Errorf("config-removal carried rx=%d tx=%d, want cumulative %d/%d", disc.GetRxBytes(), disc.GetTxBytes(), lastRx, lastTx)
	}
}

// TestObserverShutdownCarriesCumulative proves a graceful shutdown closes a live
// session carrying the LAST-SEEN cumulative counters.
func TestObserverShutdownCarriesCumulative(t *testing.T) {
	o, rt, clock := newTestObserver(t)
	rt.setLivePeer(LivePeer{PublicKey: "LIVE=", RxBytes: 500, TxBytes: 600})
	o.Poll(context.Background())

	ch, cancel := o.Subscribe()
	defer cancel()

	// Connect; cumulative 500/600.
	*clock = (*clock).Add(10 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "LIVE=", Endpoint: "203.0.113.7:51820", LastHandshake: *clock, RxBytes: 500, TxBytes: 600})
	o.Poll(context.Background())
	drain(t, ch, 2)

	// Transfer some traffic, observed by a poll (last-seen cumulative 8500/9600).
	const lastRx, lastTx = 8500, 9600
	*clock = (*clock).Add(5 * time.Second)
	rt.setLivePeer(LivePeer{PublicKey: "LIVE=", Endpoint: "203.0.113.7:51820", LastHandshake: (*clock).Add(-5 * time.Second), RxBytes: lastRx, TxBytes: lastTx})
	o.Poll(context.Background())

	// Graceful shutdown closes the session carrying the last-seen cumulative.
	o.emitShutdownDisconnects(*clock)
	disc := findType(drain(t, ch, 1), nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED)
	if disc == nil {
		t.Fatal("no PEER_DISCONNECTED on shutdown")
	}
	if disc.GetRxBytes() != lastRx || disc.GetTxBytes() != lastTx {
		t.Errorf("shutdown carried rx=%d tx=%d, want cumulative %d/%d", disc.GetRxBytes(), disc.GetTxBytes(), lastRx, lastTx)
	}
}

// droppedEventsTotal sums per-subscriber drop counters; test-only.
func (o *Observer) droppedEventsTotal() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	var n uint64
	for sub := range o.subscribers {
		n += sub.dropped.Load()
	}
	return n
}
