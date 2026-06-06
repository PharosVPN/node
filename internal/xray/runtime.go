// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package xray

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// distro/all registers every protocol/transport (VLESS, REALITY, freedom, …)
	// so a JSON config can reference them. Pulls the full xray-core; the binary
	// stays a single static build (CGO_ENABLED=0).
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Client is one VLESS client (an end-user device) the node accepts.
type Client struct {
	UUID string
	Flow string // e.g. "xtls-rprx-vision"; empty = no flow
}

// Config is the REALITY server policy coxswain pushes (the keypair is the node's
// own Identity, not here). Port 0 means "not configured" — the runtime stays down.
type Config struct {
	Port        uint32
	Dest        string   // REALITY decoy, host:port
	ServerNames []string // accepted SNIs (must include the decoy host)
	ShortIDs    []string // allowed REALITY shortIds ("" allows none)
	Clients     []Client
}

// Runtime runs an embedded xray-core VLESS+REALITY server and reloads it on
// config or client changes (a full instance swap — matches PushConfig's
// full-replace semantics).
type Runtime struct {
	id  *Identity
	log *slog.Logger

	mu   sync.Mutex
	inst *core.Instance
	cfg  Config
	rev  int64
}

// NewRuntime returns an XRay runtime bound to the node's REALITY identity. It
// starts down; coxswain brings it up with PushConfig.
func NewRuntime(id *Identity, log *slog.Logger) *Runtime {
	if log == nil {
		log = slog.Default()
	}
	return &Runtime{id: id, log: log}
}

// Apply installs the full config + client set (PushConfig). A revision older
// than the applied one is rejected; an equal one is a no-op.
func (r *Runtime) Apply(rev int64, cfg Config) (applied int64, reloaded bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rev < r.rev {
		return r.rev, false, fmt.Errorf("xray: stale revision %d (applied %d)", rev, r.rev)
	}
	if rev == r.rev && r.inst != nil {
		return r.rev, false, nil
	}
	prev := r.cfg
	r.cfg = cfg
	if err := r.rebuild(); err != nil {
		r.cfg = prev // roll back the intended config on failure
		return r.rev, false, err
	}
	r.rev = rev
	return rev, true, nil
}

// AddClient adds one VLESS client live and reloads.
func (r *Runtime) AddClient(c Client) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.cfg.Clients {
		if e.UUID == c.UUID {
			return false, nil // already present
		}
	}
	r.cfg.Clients = append(r.cfg.Clients, c)
	if err := r.rebuild(); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveClient removes one VLESS client live and reloads.
func (r *Runtime) RemoveClient(uuid string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.cfg.Clients[:0:0]
	removed := false
	for _, e := range r.cfg.Clients {
		if e.UUID == uuid {
			removed = true
			continue
		}
		out = append(out, e)
	}
	if !removed {
		return false, nil
	}
	r.cfg.Clients = out
	if err := r.rebuild(); err != nil {
		return false, err
	}
	return true, nil
}

// Clients returns a copy of the current VLESS client set.
func (r *Runtime) Clients() []Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Client(nil), r.cfg.Clients...)
}

// Status reports the XRay service health for GetStatus.
func (r *Runtime) Status() (running, listening bool, count uint32, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	up := r.inst != nil
	if r.cfg.Port == 0 {
		return false, false, 0, "not configured"
	}
	return up, up, uint32(len(r.cfg.Clients)), fmt.Sprintf("REALITY :%d", r.cfg.Port)
}

// Info returns the node's REALITY identity (its public key) for GetStatus.
func (r *Runtime) Info() *nodev1.XRayRealityInfo { return r.id.Info() }

// Restart re-applies the current config (a fresh instance) — the last-resort
// RestartService for XRay.
func (r *Runtime) Restart() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rebuild()
}

// Stop shuts the instance down.
func (r *Runtime) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inst != nil {
		_ = r.inst.Close()
		r.inst = nil
	}
}

// rebuild renders the xray JSON from the identity + current config, builds a new
// instance (validating the config while the old one still serves), then swaps:
// close old, start new. With Port 0 it tears the instance down. Caller holds mu.
func (r *Runtime) rebuild() error {
	if r.cfg.Port == 0 {
		if r.inst != nil {
			_ = r.inst.Close()
			r.inst = nil
		}
		return nil
	}
	raw, err := r.renderJSON()
	if err != nil {
		return err
	}
	coreCfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("xray: load config: %w", err)
	}
	next, err := core.New(coreCfg) // validate before disturbing the running one
	if err != nil {
		return fmt.Errorf("xray: build instance: %w", err)
	}
	if r.inst != nil {
		_ = r.inst.Close()
		r.inst = nil
	}
	if err := next.Start(); err != nil {
		return fmt.Errorf("xray: start instance: %w", err)
	}
	r.inst = next
	r.log.Info("xray REALITY server (re)started", "port", r.cfg.Port, "clients", len(r.cfg.Clients))
	return nil
}

func (r *Runtime) renderJSON() ([]byte, error) {
	clients := make([]jsonClient, 0, len(r.cfg.Clients))
	for _, c := range r.cfg.Clients {
		clients = append(clients, jsonClient{ID: c.UUID, Flow: c.Flow})
	}
	cfg := jsonConfig{
		Inbounds: []jsonInbound{{
			Port:     r.cfg.Port,
			Protocol: "vless",
			Settings: jsonVLESS{Clients: clients, Decryption: "none"},
			StreamSettings: jsonStream{
				Network:  "tcp",
				Security: "reality",
				Reality: jsonReality{
					Dest:        r.cfg.Dest,
					ServerNames: r.cfg.ServerNames,
					PrivateKey:  r.id.PrivateKey(),
					ShortIDs:    r.cfg.ShortIDs,
				},
			},
		}},
		Outbounds: []jsonOutbound{{Protocol: "freedom"}},
	}
	return json.Marshal(cfg)
}

// xray JSON config (the subset the node uses).
type jsonConfig struct {
	Inbounds  []jsonInbound  `json:"inbounds"`
	Outbounds []jsonOutbound `json:"outbounds"`
}
type jsonInbound struct {
	Port           uint32     `json:"port"`
	Protocol       string     `json:"protocol"`
	Settings       jsonVLESS  `json:"settings"`
	StreamSettings jsonStream `json:"streamSettings"`
}
type jsonVLESS struct {
	Clients    []jsonClient `json:"clients"`
	Decryption string       `json:"decryption"`
}
type jsonClient struct {
	ID   string `json:"id"`
	Flow string `json:"flow,omitempty"`
}
type jsonStream struct {
	Network  string      `json:"network"`
	Security string      `json:"security"`
	Reality  jsonReality `json:"realitySettings"`
}
type jsonReality struct {
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}
type jsonOutbound struct {
	Protocol string `json:"protocol"`
}
