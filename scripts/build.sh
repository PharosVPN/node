#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build node — a fully static, single binary (no dynamic linking, ever):
#   CGO_ENABLED=0 forces pure-Go net (netgo) + os/user (osusergo) too, so there
#   is no libc dependency. Version is injected from VERSION at link time.
#   scripts/build.sh [output-path]   (GOOS/GOARCH from env for cross-builds)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(tr -d '[:space:]' < VERSION)"
CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo \
  -ldflags "-X github.com/PharosVPN/node/internal/cli.version=$VERSION" \
  -o "${1:-bin/node}" ./cmd/node
echo "built node $VERSION (static) -> ${1:-bin/node}"
