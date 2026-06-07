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
