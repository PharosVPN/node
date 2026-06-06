#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build node with the version from VERSION injected at link time.
#   scripts/build.sh [output-path]
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(tr -d '[:space:]' < VERSION)"
go build -ldflags "-X github.com/PharosVPN/node/internal/cli.version=$VERSION" -o "${1:-bin/node}" ./cmd/node
echo "built node $VERSION -> ${1:-bin/node}"
