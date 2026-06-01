// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import (
	"context"
	"fmt"
	"sync"
)

// ManagerFactory builds a Manager for a named inner interface with the given
// [Interface] spec. Production wires it to an ExecRuntime for that interface
// plus the on-disk conf/revision paths; tests inject a fake-runtime factory.
type ManagerFactory func(iface string, spec InterfaceSpec) (*Manager, error)

// Registry owns the node's managed AmneziaWG interfaces. The client interface
// (Primary, awg0) is created at startup and serves end-user tunnels. Cascade
// inner links (DESIGN §3) are added on demand when the controller provisions a
// node→node edge and removed when it is torn down. It is safe for concurrent
// use; each Manager remains independently locked.
type Registry struct {
	primaryName string
	factory     ManagerFactory

	mu       sync.Mutex
	managers map[string]*Manager
}

// NewRegistry returns a Registry seeded with the primary client-interface
// Manager (whose Interface() name becomes the primary). factory builds inner
// links on demand for Ensure; it may be nil when no inner links are created
// (Ensure then errors).
func NewRegistry(primary *Manager, factory ManagerFactory) *Registry {
	return &Registry{
		primaryName: primary.Interface(),
		factory:     factory,
		managers:    map[string]*Manager{primary.Interface(): primary},
	}
}

// Ensure returns the Manager for an inner interface, building it via the
// factory if absent. On an existing interface the spec is not re-applied — the
// caller updates the peer set / endpoint through the returned Manager's
// PushConfig; a changed obfuscation or listen port needs Remove then Ensure.
func (r *Registry) Ensure(iface string, spec InterfaceSpec) (*Manager, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if iface == r.primaryName {
		return nil, fmt.Errorf("awg: %q is the client interface, not an inner link", iface)
	}
	if m, ok := r.managers[iface]; ok {
		return m, nil
	}
	if r.factory == nil {
		return nil, fmt.Errorf("awg: registry cannot create inner interface %q (no factory)", iface)
	}
	m, err := r.factory(iface, spec)
	if err != nil {
		return nil, err
	}
	r.managers[iface] = m
	return m, nil
}

// Primary returns the client-interface Manager (awg0).
func (r *Registry) Primary() *Manager {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.managers[r.primaryName]
}

// Get returns the Manager for iface, if registered.
func (r *Registry) Get(iface string) (*Manager, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.managers[iface]
	return m, ok
}

// Add registers a Manager for a new interface. It errors if one is already
// registered for that name — callers Get an existing one, or Remove then Add to
// replace it.
func (r *Registry) Add(m *Manager) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := m.Interface()
	if _, exists := r.managers[name]; exists {
		return fmt.Errorf("awg: interface %q already registered", name)
	}
	r.managers[name] = m
	return nil
}

// Remove tears the interface down and unregisters it. Removing the primary is
// rejected; removing an unknown interface is a no-op.
func (r *Registry) Remove(ctx context.Context, iface string) error {
	if iface == r.primaryName {
		return fmt.Errorf("awg: refusing to remove the primary interface %q", iface)
	}
	r.mu.Lock()
	m, ok := r.managers[iface]
	if ok {
		delete(r.managers, iface)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	return m.Down(ctx)
}

// All returns every registered Manager. Order is unspecified.
func (r *Registry) All() []*Manager {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Manager, 0, len(r.managers))
	for _, m := range r.managers {
		out = append(out, m)
	}
	return out
}
