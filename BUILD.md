# buoy — Build Brief (subagent)

**Read first, in order:** `docs/BUILD.md` → `docs/DESIGN.md` (read decision 14
carefully) → this file.
This is a delegated subproject. If the design is silent on a contract you need,
stop and raise it — do not invent one.

---

## What you are building

`buoy` is the VPN node agent — a single static Go binary that runs on each
public VPN node. It is the *server* side of the control channel; `helm` (the
controller) is the *client* that dials in. `buoy` opens no connection to `helm`.

## Behaviour

### Onboarding & lifecycle — SSH-driven (DESIGN §5, decision 14)

There is **no enrollment-mode listener and no bootstrap token.** `helm` installs
and updates the `buoy` agent over SSH, then runs it as the `buoy.service`
systemd unit. SSH is a *deployment* channel only — every operational
instruction is gRPC.

`buoy` exposes three CLI commands — this is the `helm`↔`buoy` contract, and
`helm`'s `internal/deploy` package already calls them:

- **`buoy gen-csr`** — generate the node's mTLS keypair locally under
  `/etc/buoy/` (the private key is written to `/etc/buoy/node.key` and **never
  leaves the node**) and print a PEM-encoded CSR to stdout. `helm` captures the
  CSR over SSH, signs it with the Fleet CA, and pushes back `/etc/buoy/node.crt`
  (leaf + Fleet intermediate) and `/etc/buoy/ca.crt` (root trust anchor).
  Re-running it is idempotent — an existing key is reused.
- **`buoy run --config-dir /etc/buoy`** — the agent. Serve the `NodeControl`
  gRPC service on TCP **port 8444** over mTLS, presenting `node.crt`/`node.key`
  and requiring client certificates that chain to `ca.crt`. Non-mTLS
  connections are dropped at the TLS handshake — no banner, no 401.
- **`buoy version`** — print the agent version to stdout (`helm` records it
  after install/update).

### Normal mode

Once running, the control port accepts only mTLS connections whose client cert
chains to `ca.crt`. Anything else is dropped at the TLS handshake.

### Control service (gRPC over mTLS) — `helm` calls these

The contract is `docs/proto/pharos/buoy/v1/control.proto` — the `NodeControl`
service, owned by `helm`. RPCs are **unified across data-plane protocols**: each
request carries a `Protocol` enum field (`PROTOCOL_AMNEZIAWG`,
`PROTOCOL_XRAY_REALITY`) rather than the service offering per-protocol RPCs.
Implement the server against the proto; do not fork it.

- `GetStatus` — node + per-protocol service health (running, listening, peer
  count).
- `GetMetrics` — counters for metrics sampling: per-peer rx/tx bytes, totals,
  handshakes, errors.
- `PushConfig` — replace one protocol's data-plane config and reload it.
- `AddPeer` — add one peer live, no restart.
- `RemovePeer` — revoke one peer live.
- `ListPeers` — configured peers and their runtime state (handshakes, byte
  counters).
- `RestartService` — last-resort restart of one protocol's service.
- `WatchEvents` — **server-stream**: handshake up/down, peer connect/disconnect,
  errors. `helm` holds this open; this is what makes the admin UI live.

### Data plane

Manages `awg-quick@awg0` (UDP 443) and `xray.service` (TCP 443). Peer
add/remove must be **live** (no tunnel drop for other peers). Disk-full on a
config write → return a typed error; the running data plane keeps last-known-good.

## Reuse

`buoy`'s control channel is a **plain mTLS gRPC server** — `helm` dials it
directly (the node is public). It does **not** need the reverse-tunnel code;
that belongs to `beacon`. You may lift the **mTLS setup / CA-verification**
helpers from the `sultix` project — and if you do, obey the rebrand rule in
`docs/BUILD.md` §4 (strip every `sultix`/`mc*`/`x-sultix-*` identifier).

## Milestones

| # | Output |
|---|---|
| B1 | Repo skeleton, config loader, the `gen-csr`/`run`/`version` commands, mTLS `NodeControl` gRPC server skeleton (RPCs return `Unimplemented`) |
| B2 | AmneziaWG management: `PushConfig`, `AddPeer`/`RemovePeer`, `ListPeers` |
| B3 | XRay management: `PushConfig`, `AddPeer`/`RemovePeer`, `ListPeers` |
| B4 | `GetStatus` + `GetMetrics` |
| B5 | `WatchEvents` server-stream |
| B6 | Cold-start-from-disk + cloud-init packaging (static binary) |

## Non-negotiables

- `buoy` never dials `helm`. It only accepts.
- No config touches disk unless it arrived over a validated mTLS connection
  (the SSH-pushed `node.crt`/`ca.crt`/`node.key` are the onboarding exception).
- No state beyond what `helm` pushed + AWG/XRay runtime state. No database.
- Survives controller outage: existing tunnels keep serving.

## Depends on

The `buoy` control + event-stream protos, owned by `helm`, in `docs/proto/`.
A copy is vendored into this repo's `proto/`; generated Go is committed under
`internal/gen/`. Build against them; do not fork them. See `proto/README.md`.
