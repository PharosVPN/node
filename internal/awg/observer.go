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

// dropReportInterval is how often Run checks whether the cumulative dropped
// count advanced and, if so, logs it. A slow WatchEvents consumer sheds events
// silently otherwise; this surfaces the loss at a bounded, rate-limited cadence.
const dropReportInterval = 60 * time.Second

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
	// dropped is the cumulative count of events shed because some subscriber's
	// buffer was full (summed across all subscribers, all time). It mirrors the
	// per-subscriber counters but is observer-wide so Run can surface silent loss.
	dropped atomic.Uint64
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
	// rxLast and txLast are the most recent CUMULATIVE awg byte counters seen
	// for this peer. The observer reports these raw cumulative counters on every
	// PEER_CONNECTED and PEER_DISCONNECTED — the controller pairs connect→
	// disconnect and computes the per-session delta. A peer that vanishes from
	// the dump (config-removed) or a graceful shutdown has no fresh dump line,
	// so its disconnect carries this last-seen cumulative.
	rxLast uint64
	txLast uint64
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

// DroppedTotal is the cumulative count of events shed because a subscriber's
// buffer was full. A non-zero, growing value means a WatchEvents consumer is
// too slow and is losing live events.
func (o *Observer) DroppedTotal() uint64 { return o.dropped.Load() }

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
	// Surface silent event loss: a slow WatchEvents consumer's full buffer sheds
	// events (counted in o.dropped) without blocking the observer, so without
	// this the loss is invisible. Log only the delta, rate-limited to its ticker.
	dropTicker := time.NewTicker(dropReportInterval)
	defer dropTicker.Stop()
	var lastDropped uint64
	o.Poll(ctx)
	for {
		select {
		case <-ctx.Done():
			// On a GRACEFUL shutdown, emit a disconnect for every still-live peer
			// so coxswain closes those sessions instead of leaving them dangling
			// (LOW-14). A crash emits nothing — the controller's stream-drop
			// close-out is the backstop for that — but a clean stop is courteous.
			o.emitShutdownDisconnects(o.now())
			o.closeAllSubscribers()
			return
		case <-dropTicker.C:
			if d := o.dropped.Load(); d > lastDropped {
				o.log.Warn("observer: dropped events (slow WatchEvents consumer)",
					"dropped_total", d, "dropped_since_last", d-lastDropped)
				lastDropped = d
			}
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
			o.prev[pk] = peerState{
				lastHandshake: lp.LastHandshake,
				endpoint:      lp.Endpoint,
				rxLast:        lp.RxBytes,
				txLast:        lp.TxBytes,
			}
		}
		return
	}

	next := make(map[string]peerState, len(cur))
	for pk, lp := range cur {
		old, was := o.prev[pk]
		// Refresh the last-seen cumulative to this poll's reading so a later
		// config-removed/shutdown disconnect has a current counter to report.
		ps := peerState{
			lastHandshake: lp.LastHandshake,
			endpoint:      lp.Endpoint,
			upEmitted:     old.upEmitted,
			rxLast:        lp.RxBytes,
			txLast:        lp.TxBytes,
		}

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
		// only, never on every poll. The connect carries the peer's RAW
		// CUMULATIVE awg counters at this instant — the controller pairs this
		// connect with the matching disconnect and computes the session delta.
		endpointChanged := was && ps.upEmitted && lp.Endpoint != "" && lp.Endpoint != old.endpoint
		if (freshHandshake && !old.upEmitted) || endpointChanged {
			ps.upEmitted = true
			o.emitLocked(&nodev1.Event{
				At:             timestamppb.New(now),
				Type:           nodev1.EventType_EVENT_TYPE_PEER_CONNECTED,
				Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PeerId:         pk,
				SourceEndpoint: lp.Endpoint,
				RxBytes:        int64(lp.RxBytes),
				TxBytes:        int64(lp.TxBytes),
			})
		} else if freshHandshake {
			ps.upEmitted = true
		}

		// A peer "disconnects" when a previously-live handshake ages past the
		// stale threshold. Emit a HANDSHAKE_DOWN and a PEER_DISCONNECTED so the
		// session is closed in the history. The disconnect carries the peer's RAW
		// CUMULATIVE awg counters at this instant; the controller subtracts the
		// cumulative it remembered at the matching connect to get the session delta.
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
				RxBytes:        int64(lp.RxBytes),
				TxBytes:        int64(lp.TxBytes),
			})
		}

		next[pk] = ps
	}

	// A peer removed from the config (no longer in the dump) disconnects too. It
	// has no fresh dump line, so it carries the last cumulative counter we saw
	// for it — the controller deltas that against the connect it remembered.
	for pk, old := range o.prev {
		if _, still := cur[pk]; !still {
			ev := &nodev1.Event{
				At:             timestamppb.New(now),
				Type:           nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED,
				Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PeerId:         pk,
				SourceEndpoint: old.endpoint,
			}
			// Only a peer that had an open session reports its cumulative; one
			// that never connected has a zero last counter anyway.
			if old.upEmitted {
				ev.RxBytes = int64(old.rxLast)
				ev.TxBytes = int64(old.txLast)
			}
			o.emitLocked(ev)
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
// observer loop or back-pressuring other peers' streams. Drops are counted
// per-subscriber and observer-wide; Run's drop ticker surfaces the latter.
func (o *Observer) emitLocked(ev *nodev1.Event) {
	for sub := range o.subscribers {
		select {
		case sub.ch <- ev:
		default:
			sub.dropped.Add(1)
			o.dropped.Add(1)
		}
	}
}

// emitShutdownDisconnects emits a PEER_DISCONNECTED for every peer the observer
// currently considers connected (upEmitted), so a graceful node stop closes out
// live sessions instead of leaving them open in coxswain's history (LOW-14). It
// flips upEmitted off so a re-poll after this would not double-report. Best
// effort: a subscriber that has already drained may miss these (the controller's
// stream-drop close-out covers that case).
func (o *Observer) emitShutdownDisconnects(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.prev == nil {
		return
	}
	for pk, ps := range o.prev {
		if !ps.upEmitted {
			continue
		}
		o.emitLocked(&nodev1.Event{
			At:             timestamppb.New(now),
			Type:           nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED,
			Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
			PeerId:         pk,
			SourceEndpoint: ps.endpoint,
			Message:        "node-shutdown",
			// Report the last cumulative counters we polled (a graceful stop has
			// no fresh dump); the controller deltas against the remembered connect.
			RxBytes: int64(ps.rxLast),
			TxBytes: int64(ps.txLast),
		})
		ps.upEmitted = false
		o.prev[pk] = ps
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
