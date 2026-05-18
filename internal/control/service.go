// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package control

import buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"

// service implements the NodeControl gRPC service.
//
// Milestone B1 ships the skeleton: every RPC is wired but unimplemented.
// Embedding UnimplementedNodeControlServer makes each method return
// codes.Unimplemented and keeps the type forward-compatible as RPCs are added
// to the proto. The data-plane RPCs land in later milestones (B2: AmneziaWG,
// B3: XRay, B4: status/metrics, B5: WatchEvents).
type service struct {
	buoyv1.UnimplementedNodeControlServer
}

// newService returns a NodeControl service implementation.
func newService() *service {
	return &service{}
}
