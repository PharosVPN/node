// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package control

import (
	"context"
	"time"

	"github.com/PharosVPN/buoy/internal/awg"
	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
)

// service implements the NodeControl gRPC service.
//
// GetStatus is implemented so helm can read the node's AmneziaWG identity and
// obfuscation set — helm refuses to provision devices onto a node until it has
// them (DESIGN §3). The remaining data-plane RPCs are wired but unimplemented;
// they land in later milestones (B2: AmneziaWG, B3: XRay, B4: metrics,
// B5: WatchEvents). The embedded UnimplementedNodeControlServer supplies them
// and keeps the type forward-compatible.
type service struct {
	buoyv1.UnimplementedNodeControlServer

	version string
	started time.Time
	awgNode *awg.Node
}

// newService returns a NodeControl service implementation.
func newService(version string, awgNode *awg.Node) *service {
	return &service{
		version: version,
		started: time.Now(),
		awgNode: awgNode,
	}
}

// GetStatus reports the node's agent version, uptime, and AmneziaWG server
// identity. The identity is stable across restarts (see package awg), so helm
// can cache it and hand the obfuscation set to every client of the node.
func (s *service) GetStatus(_ context.Context, _ *buoyv1.GetStatusRequest) (*buoyv1.GetStatusResponse, error) {
	return &buoyv1.GetStatusResponse{
		AgentVersion:  s.version,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		Amneziawg:     s.awgNode.Info(),
	}, nil
}
