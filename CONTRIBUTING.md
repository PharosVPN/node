# Contributing to buoy

Thanks for helping build PharosVPN. Before you start, read
[`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md) — the
platform's single source of truth — and this repo's [BUILD.md](BUILD.md).

## Developer Certificate of Origin (DCO)

PharosVPN takes contributions under the
[Developer Certificate of Origin](https://developercertificate.org/). There is
**no CLA** — there is no plan to relicense.

Every commit must be signed off, certifying you wrote the change or have the
right to submit it under the project's licence:

```
git commit -s
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer. The name
and email must be real and match your `git config user.name` / `user.email`.

## Workflow

- Branch from `main`; never commit straight to `main`. Open a PR.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `perf:`, `refactor:`, `test:`, `chore:`).
- If the design is silent or contradictory on something you need, stop and
  raise it — do not invent a contract. Update `docs/DESIGN.md` in the same PR.

## Wire contracts

`buoy` implements protobuf contracts `helm` owns. `proto/` holds a vendored
copy of `docs/proto/`; generated Go lives in `internal/gen/` and is committed.
Never edit the generated code or the vendored proto in place — change the
canonical schema in `docs/proto/`, re-vendor, and run `buf generate`. See
[`proto/README.md`](proto/README.md).

## Quality bar

Before opening a PR, make sure:

```
gofmt -l .        # no output
go vet ./...      # clean
go test -race ./... # green
golangci-lint run # clean
```

Add unit tests for logic and integration tests for anything crossing mTLS.
Never commit secrets — not even in test fixtures. Node private keys are
generated on the node and must never appear in this repo.

## Licence

buoy is licensed **AGPL-3.0-or-later**. Every source file carries the SPDX
header:

```
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors
```
