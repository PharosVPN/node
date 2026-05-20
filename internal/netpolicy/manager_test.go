// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// fakeApplier records every Apply call and can return an injected error.
type fakeApplier struct {
	mu      sync.Mutex
	calls   []Policy
	failErr error
}

func (f *fakeApplier) Apply(_ context.Context, p Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return f.failErr
	}
	f.calls = append(f.calls, p)
	return nil
}

func (f *fakeApplier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestManagerAppliesFirstCall(t *testing.T) {
	f := &fakeApplier{}
	m := NewManager(f)
	applied, err := m.Apply(context.Background(), Policy{Forwarding: true, Masquerade: true})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !applied {
		t.Error("first Apply should return applied=true")
	}
	if f.callCount() != 1 {
		t.Errorf("applier calls = %d, want 1", f.callCount())
	}
}

func TestManagerIdempotentReplay(t *testing.T) {
	f := &fakeApplier{}
	m := NewManager(f)
	p := Policy{Forwarding: true, Isolation: true}
	if _, err := m.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	applied, err := m.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Error("identical second Apply should return applied=false")
	}
	if f.callCount() != 1 {
		t.Errorf("applier calls = %d, want 1 (replay must not re-apply)", f.callCount())
	}
}

func TestManagerReAppliesOnChange(t *testing.T) {
	f := &fakeApplier{}
	m := NewManager(f)
	if _, err := m.Apply(context.Background(), Policy{Forwarding: true}); err != nil {
		t.Fatal(err)
	}
	if applied, err := m.Apply(context.Background(),
		Policy{Forwarding: true, Masquerade: true}); err != nil || !applied {
		t.Fatalf("apply changed policy: applied=%v err=%v", applied, err)
	}
	if f.callCount() != 2 {
		t.Errorf("applier calls = %d, want 2 (changed policy re-applies)", f.callCount())
	}
}

func TestManagerRejectsInvalidBeforeApplier(t *testing.T) {
	f := &fakeApplier{}
	m := NewManager(f)
	_, err := m.Apply(context.Background(), Policy{Masquerade: true}) // forwarding=false invalid
	if err == nil {
		t.Fatal("Apply with invalid policy = nil error")
	}
	if f.callCount() != 0 {
		t.Errorf("applier called %d times; must not run for invalid policy", f.callCount())
	}
}

// TestManagerDoesNotRecordOnFailure proves a failed Apply leaves the
// last-applied state untouched — the next call with the same policy must
// still try, since the previous attempt didn't land.
func TestManagerDoesNotRecordOnFailure(t *testing.T) {
	f := &fakeApplier{failErr: errors.New("nft boom")}
	m := NewManager(f)
	p := Policy{Forwarding: true}
	if _, err := m.Apply(context.Background(), p); err == nil {
		t.Fatal("Apply with failing applier = nil error")
	}
	if m.LastApplied() != nil {
		t.Error("LastApplied should be nil after a failed Apply")
	}

	// With the failure cleared, the same policy now applies — proving the
	// failed attempt didn't poison the idempotency cache.
	f.failErr = nil
	applied, err := m.Apply(context.Background(), p)
	if err != nil || !applied {
		t.Fatalf("retry Apply: applied=%v err=%v", applied, err)
	}
}
