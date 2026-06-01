// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// stateFileMode keeps the persisted policy owner-readable; it carries no
// secrets, only the policy bools and the teardown argv.
const stateFileMode fs.FileMode = 0o644

// Exec runs one resolved firewall/sysctl command. The production implementation
// shells out (no shell interpolation — argv is passed directly); tests fake it.
type Exec interface {
	// Run executes argv[0] with argv[1:]. It returns an error on a non-zero
	// exit so the applier can distinguish establish failures (fatal) from
	// teardown misses (tolerated).
	Run(ctx context.Context, argv []string) error
}

// EgressDetector reports the node's default-route (egress) interface, the
// value substituted for the %e token in the masquerade rule.
type EgressDetector interface {
	DefaultEgress(ctx context.Context) (string, error)
}

// state is the on-disk record of the currently applied policy: the policy
// itself (for reporting / reapply) plus the exact teardown commands that revert
// it. Persisting the resolved teardown — rather than re-deriving it — means a
// later egress change cannot strand a masquerade rule we can no longer match.
type state struct {
	Policy Policy    `json:"policy"`
	Down   []command `json:"down"`
}

// Applier owns the node's live network policy. It serialises Apply/Reapply,
// reverts the previously applied rules before installing a new set, and
// persists the teardown so the node converges to a single copy of its rules
// across both a plain restart (rules still live) and a reboot (rules gone).
type Applier struct {
	wgIface   string
	exec      Exec
	egress    EgressDetector
	statePath string
	log       *slog.Logger

	mu      sync.Mutex
	applied *state
}

// Options configures an Applier.
type Options struct {
	// WGIface is the wg interface the %i token resolves to (e.g. "awg0").
	WGIface string
	// Exec runs the resolved commands; required.
	Exec Exec
	// Egress detects the %e egress interface; required.
	Egress EgressDetector
	// StatePath persists the applied policy + teardown across restarts;
	// required.
	StatePath string
	// Log receives applier diagnostics.
	Log *slog.Logger
}

// New returns an Applier with its persisted state loaded (if any). It does not
// touch the firewall; call Reapply once at startup to re-establish the policy.
func New(opts Options) (*Applier, error) {
	if opts.Exec == nil {
		return nil, errors.New("netpolicy: Applier needs an Exec")
	}
	if opts.Egress == nil {
		return nil, errors.New("netpolicy: Applier needs an EgressDetector")
	}
	if opts.StatePath == "" {
		return nil, errors.New("netpolicy: Applier needs a StatePath")
	}
	wgIface := opts.WGIface
	if wgIface == "" {
		wgIface = "awg0"
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	a := &Applier{
		wgIface:   wgIface,
		exec:      opts.Exec,
		egress:    opts.Egress,
		statePath: opts.StatePath,
		log:       log,
	}
	st, err := readState(opts.StatePath)
	if err != nil {
		return nil, err
	}
	a.applied = st
	return a, nil
}

// Policy returns the last successfully applied policy (zero value if none).
func (a *Applier) Policy() Policy {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applied == nil {
		return Policy{}
	}
	return a.applied.Policy
}

// Apply reverts the previously applied policy, then installs p. It is the
// SetNetworkConfig entry point. Applying is live: it touches netfilter/sysctl
// only, never the wg interface, so established tunnels are not dropped. A
// failure to install rolls back the partially applied set and returns the
// error; the persisted state is updated only on full success.
func (a *Applier) Apply(ctx context.Context, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.apply(ctx, p)
}

// Reapply re-establishes the persisted policy at startup. After a reboot the
// rules are gone and the teardown is a no-op; after a plain restart the rules
// are still live and the teardown clears them first — either way the node ends
// with exactly one copy. With no persisted policy it does nothing.
func (a *Applier) Reapply(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applied == nil {
		return nil
	}
	return a.apply(ctx, a.applied.Policy)
}

// apply does the work under the held lock: revert what is live, resolve and
// install p, persist the new teardown.
func (a *Applier) apply(ctx context.Context, p Policy) error {
	// 1. Revert whatever we last installed. Teardown misses are expected
	//    (e.g. after a reboot the rules no longer exist) and tolerated.
	if a.applied != nil {
		for _, c := range a.applied.Down {
			if err := a.exec.Run(ctx, c); err != nil {
				a.log.Debug("netpolicy: teardown command missed (tolerated)",
					"argv", c, "err", err)
			}
		}
	}

	// 2. Resolve the new policy against this node's interfaces. The egress
	//    interface is only needed when masquerade is on.
	egress := ""
	if p.Masquerade {
		e, err := a.egress.DefaultEgress(ctx)
		if err != nil {
			return fmt.Errorf("netpolicy: detect egress interface: %w", err)
		}
		if e == "" {
			return errors.New("netpolicy: no default-route egress interface found")
		}
		egress = e
	}
	rr := p.resolve(a.wgIface, egress)

	// 3. Install. On failure, roll back the commands run so far (best effort)
	//    so we never leave a half-applied policy live.
	for i, c := range rr.up {
		if err := a.exec.Run(ctx, c); err != nil {
			a.rollback(ctx, rr.down)
			return fmt.Errorf("netpolicy: apply %v (step %d/%d): %w", c, i+1, len(rr.up), err)
		}
	}

	// 4. Persist the policy + its exact teardown for the next Apply/Reapply.
	st := &state{Policy: p, Down: rr.down}
	if err := writeState(a.statePath, st); err != nil {
		// Rules are live but unpersisted: roll back so disk and kernel agree.
		a.rollback(ctx, rr.down)
		return fmt.Errorf("netpolicy: persist state: %w", err)
	}
	a.applied = st
	return nil
}

// rollback runs teardown commands best-effort (used to undo a partial apply).
func (a *Applier) rollback(ctx context.Context, down []command) {
	for _, c := range down {
		if err := a.exec.Run(ctx, c); err != nil {
			a.log.Debug("netpolicy: rollback command missed (tolerated)",
				"argv", c, "err", err)
		}
	}
}

func readState(path string) (*state, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	default:
		return nil, fmt.Errorf("netpolicy: read %s: %w", path, err)
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("netpolicy: parse %s: %w", path, err)
	}
	return &st, nil
}

func writeState(path string, st *state) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("netpolicy: create %s: %w", dir, err)
		}
	}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("netpolicy: encode state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, stateFileMode); err != nil {
		return fmt.Errorf("netpolicy: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("netpolicy: replace %s: %w", path, err)
	}
	return nil
}
