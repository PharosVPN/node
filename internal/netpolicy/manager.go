// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import (
	"context"
	"sync"
)

// Applier installs a Policy on the host. Tests substitute a fake; the
// production wiring uses *NftApplier.
type Applier interface {
	Apply(ctx context.Context, p Policy) error
}

// Manager owns the last-applied Policy and serves idempotent Apply calls.
// A call that matches the most recent applied policy returns applied=false
// without re-running the firewall transaction; anything else applies and
// records the new policy. The state lives only in memory, so a buoy
// restart re-applies on the next call (which is correct — nftables rules
// are not durable across reboots either).
type Manager struct {
	applier Applier

	mu   sync.Mutex
	last *Policy
}

// NewManager wraps an Applier.
func NewManager(a Applier) *Manager {
	return &Manager{applier: a}
}

// Apply installs p if it differs from the last applied policy.
// It returns (true, nil) when the call took effect, (false, nil) on an
// idempotent replay, or (false, err) on a validation or applier error.
func (m *Manager) Apply(ctx context.Context, p Policy) (bool, error) {
	if err := p.Validate(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last != nil && *m.last == p {
		return false, nil
	}
	if err := m.applier.Apply(ctx, p); err != nil {
		return false, err
	}
	clone := p
	m.last = &clone
	return true, nil
}

// LastApplied returns a copy of the most-recently-applied policy, or nil
// if no policy has been applied since process start.
func (m *Manager) LastApplied() *Policy {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return nil
	}
	clone := *m.last
	return &clone
}
