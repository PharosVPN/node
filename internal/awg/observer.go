// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Observer defaults. Polling is cheap (one `awg show dump` per tick); 5s is
// brisk enough for an admin UI without flooding the bus.
const (
	DefaultObserverInterval       = 5 * time.Second
	DefaultObserverStaleThreshold = 180 * time.Second
)

// subscriberBuffer is the per-stream event buffer. A slow consumer that
// stays full longer than this many events behind loses the overflow rather
// than blocking the observer or freezing peer streams.
const subscriberBuffer = 256

// Observer polls the AmneziaWG runtime, diffs the snapshot against the
// previous one, and emits events to its subscribers. It is the single
// source of truth for the cumulative counters coxswain sees on GetMetrics
// (handshakes_total, errors_total) — the values only advance when this
// loop observes an actual transition.
type Observer struct {
	runtime  Runtime
	interval time.Duration
	stale    time.Duration
	log      *slog.Logger
	now      func() time.Time // injectable for deterministic tests

	mu          sync.Mutex
	prev        map[string]peerState // nil until first poll
	subscribers map[*subscriber]struct{}

	handshakes atomic.Uint64
	errors     atomic.Uint64
}

// peerState is the observer's memory of one peer between polls.
type peerState struct {
	lastHandshake time.Time
	endpoint      string
	// upEmitted is true if a HANDSHAKE_UP for the current handshake has been
	// emitted but no matching HANDSHAKE_DOWN has yet — prevents duplicate
	// stale-handshake events. It also marks a peer as currently "connected",
	// so a stale handshake emits a PEER_DISCONNECTED exactly once.
	upEmitted bool
}

type subscriber struct {
	ch      chan *nodev1.Event
	dropped atomic.Uint64
}

// NewObserver returns an Observer wired to rt. Call Run with the node
// lifetime context, or Poll once for unit-test determinism.
func NewObserver(rt Runtime, interval, stale time.Duration, log *slog.Logger) *Observer {
	if interval <= 0 {
		interval = DefaultObserverInterval
	}
	if stale <= 0 {
		stale = DefaultObserverStaleThreshold
	}
	if log == nil {
		log = slog.Default()
	}
	return &Observer{
		runtime:     rt,
		interval:    interval,
		stale:       stale,
		log:         log,
		now:         time.Now,
		subscribers: map[*subscriber]struct{}{},
	}
}

// HandshakesTotal is the cumulative count of completed AmneziaWG handshakes
// the observer has witnessed (initial and rekeys both count).
func (o *Observer) HandshakesTotal() uint64 { return o.handshakes.Load() }

// ErrorsTotal is the cumulative count of observer poll errors. It does not
// count transient "interface not up" — only failures while the interface
// was expected to be observable.
func (o *Observer) ErrorsTotal() uint64 { return o.errors.Load() }

// Subscribe registers a new event consumer. The returned cancel function
// unregisters and closes the channel; the caller must always invoke it
// (typically via defer) so a disconnected WatchEvents stream cannot leak.
func (o *Observer) Subscribe() (<-chan *nodev1.Event, func()) {
	sub := &subscriber{ch: make(chan *nodev1.Event, subscriberBuffer)}
	o.mu.Lock()
	o.subscribers[sub] = struct{}{}
	o.mu.Unlock()

	cancel := func() {
		o.mu.Lock()
		_, still := o.subscribers[sub]
		if still {
			delete(o.subscribers, sub)
		}
		o.mu.Unlock()
		if still {
			close(sub.ch)
		}
	}
	return sub.ch, cancel
}

// Run polls until ctx is cancelled. The first poll establishes the baseline
// silently — only subsequent transitions emit events.
func (o *Observer) Run(ctx context.Context) {
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	o.Poll(ctx)
	for {
		select {
		case <-ctx.Done():
			o.closeAllSubscribers()
			return
		case <-ticker.C:
			o.Poll(ctx)
		}
	}
}

// Poll runs one observation cycle. Tests call this directly with a
// time-injected Observer to avoid sleeping on a ticker.
func (o *Observer) Poll(ctx context.Context) {
	live, err := o.runtime.Show(ctx)
	if err != nil {
		// Interface-not-up isn't an error — node may be running before any
		// PushConfig. Only count and emit when we know we should be live.
		listening, _ := o.runtime.Listening(ctx)
		if !listening {
			return
		}
		o.errors.Add(1)
		o.broadcast(&nodev1.Event{
			At:       timestamppb.New(o.now()),
			Type:     nodev1.EventType_EVENT_TYPE_ERROR,
			Protocol: nodev1.Protocol_PROTOCOL_AMNEZIAWG,
			Message:  err.Error(),
		})
		return
	}
	cur := make(map[string]LivePeer, len(live))
	for _, p := range live {
		cur[p.PublicKey] = p
	}
	o.detect(o.now(), cur)
}

// detect diffs cur against the previous snapshot and emits events. The
// caller need not hold any lock; detect takes o.mu.
func (o *Observer) detect(now time.Time, cur map[string]LivePeer) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// First poll establishes baseline silently — admin UIs read current
	// state via GetStatus + ListPeers, not via a stream replay.
	if o.prev == nil {
		o.prev = make(map[string]peerState, len(cur))
		for pk, lp := range cur {
			o.prev[pk] = peerState{lastHandshake: lp.LastHandshake, endpoint: lp.Endpoint}
		}
		return
	}

	next := make(map[string]peerState, len(cur))
	for pk, lp := range cur {
		old, was := o.prev[pk]
		ps := peerState{lastHandshake: lp.LastHandshake, endpoint: lp.Endpoint, upEmitted: old.upEmitted}

		freshHandshake := lp.LastHandshake.After(old.lastHandshake) && !lp.LastHandshake.IsZero()
		if freshHandshake {
			// Fresh handshake — initial or rekey. Both count.
			o.handshakes.Add(1)
			o.emitLocked(&nodev1.Event{
				At:             timestamppb.New(now),
				Type:           nodev1.EventType_EVENT_TYPE_HANDSHAKE_UP,
				Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PeerId:         pk,
				SourceEndpoint: lp.Endpoint,
			})
		}

		// A peer "connects" the moment it transitions into a live handshake
		// (was idle/new, now handshaking) or when its source endpoint changes
		// while already up (the client roamed to a new IP:port). Both are real
		// session boundaries the history must record; emit on the TRANSITION
		// only, never on every poll.
		endpointChanged := was && ps.upEmitted && lp.Endpoint != "" && lp.Endpoint != old.endpoint
		if (freshHandshake && !old.upEmitted) || endpointChanged {
			ps.upEmitted = true
			o.emitLocked(&nodev1.Event{
				At:             timestamppb.New(now),
				Type:           nodev1.EventType_EVENT_TYPE_PEER_CONNECTED,
				Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PeerId:         pk,
				SourceEndpoint: lp.Endpoint,
			})
		} else if freshHandshake {
			ps.upEmitted = true
		}

		// A peer "disconnects" when a previously-live handshake ages past the
		// stale threshold. Emit a HANDSHAKE_DOWN and a PEER_DISCONNECTED so the
		// session is closed in the history.
		if ps.upEmitted && !freshHandshake && !lp.LastHandshake.IsZero() && now.Sub(lp.LastHandshake) > o.stale {
			ps.upEmitted = false
			o.emitLocked(&nodev1.Event{
				At:             timestamppb.New(now),
				Type:           nodev1.EventType_EVENT_TYPE_HANDSHAKE_DOWN,
				Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PeerId:         pk,
				SourceEndpoint: lp.Endpoint,
			})
			o.emitLocked(&nodev1.Event{
				At:             timestamppb.New(now),
				Type:           nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED,
				Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PeerId:         pk,
				SourceEndpoint: lp.Endpoint,
			})
		}

		next[pk] = ps
	}

	// A peer removed from the config (no longer in the dump) disconnects too.
	for pk, old := range o.prev {
		if _, still := cur[pk]; !still {
			o.emitLocked(&nodev1.Event{
				At:             timestamppb.New(now),
				Type:           nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED,
				Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PeerId:         pk,
				SourceEndpoint: old.endpoint,
			})
		}
	}

	o.prev = next
}

// broadcast emits one event to all subscribers. Useful for synchronous
// emission outside detect (e.g., poll errors).
func (o *Observer) broadcast(ev *nodev1.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.emitLocked(ev)
}

// emitLocked fans an event out to every subscriber. A subscriber that is
// already at buffer capacity loses the event — better than blocking the
// observer loop or back-pressuring other peers' streams. Drops are
// counted per-subscriber and logged at the cancel point.
func (o *Observer) emitLocked(ev *nodev1.Event) {
	for sub := range o.subscribers {
		select {
		case sub.ch <- ev:
		default:
			sub.dropped.Add(1)
		}
	}
}

// closeAllSubscribers releases every subscriber when Run exits. WatchEvents
// streams return cleanly on a closed channel.
func (o *Observer) closeAllSubscribers() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for sub := range o.subscribers {
		close(sub.ch)
	}
	o.subscribers = map[*subscriber]struct{}{}
}
