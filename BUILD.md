# node — Build Brief (subagent)

**Read first, in order:** `docs/BUILD.md` → `docs/DESIGN.md` (read decision 14
carefully) → this file.
This is a delegated subproject. If the design is silent on a contract you need,
stop and raise it — do not invent one.

---

## What you are building

`node` is the VPN node agent — a single static Go binary that runs on each
public VPN node. It is the *server* side of the control channel; `coxswain` (the
controller) is the *client* that dials in. `node` opens no connection to `coxswain`.

## Behaviour

### Onboarding & lifecycle — SSH-driven (DESIGN §5, decision 14)

There is **no enrollment-mode listener and no bootstrap token.** `coxswain` installs
and updates the `node` agent over SSH, then runs it as the `node.service`
systemd unit. SSH is a *deployment* channel only — every operational
instruction is gRPC.

`node` exposes three CLI commands — this is the `coxswain`↔`node` contract, and
`coxswain`'s `internal/deploy` package already calls them:

- **`node gen-csr`** — generate the node's mTLS keypair locally under
  `/etc/node/` (the private key is written to `/etc/node/node.key` and **never
  leaves the node**) and print a PEM-encoded CSR to stdout. `coxswain` captures the
  CSR over SSH, signs it with the Fleet CA, and pushes back `/etc/node/node.crt`
  (leaf + Fleet intermediate) and `/etc/node/ca.crt` (root trust anchor).
  Re-running it is idempotent — an existing key is reused.
- **`node run --config-dir /etc/node`** — the agent. Serve the `NodeControl`
  gRPC service on TCP **port 8444** over mTLS, presenting `node.crt`/`node.key`
  and requiring client certificates that chain to `ca.crt`. Non-mTLS
  connections are dropped at the TLS handshake — no banner, no 401.
- **`node version`** — print the agent version to stdout (`coxswain` records it
  after install/update).

### Normal mode

Once running, the control port accepts only mTLS connections whose client cert
chains to `ca.crt`. Anything else is dropped at the TLS handshake.

### Control service (gRPC over mTLS) — `coxswain` calls these

The contract is `docs/proto/pharos/node/v1/control.proto` — the `NodeControl`
service, owned by `coxswain`. RPCs are **unified across data-plane protocols**: each
request carries a `Protocol` enum field (`PROTOCOL_AMNEZIAWG`,
`PROTOCOL_XRAY_REALITY`) rather than the service offering per-protocol RPCs.
Implement the server against the proto; do not fork it.

- `GetStatus` — node + per-protocol service health (running, listening, peer
  count), plus the node's **AmneziaWG identity** (`amneziawg`): server public
  key and obfuscation set — see *AmneziaWG obfuscation* below.
- `GetMetrics` — counters for metrics sampling: per-peer rx/tx bytes, totals,
  handshakes, errors.
- `PushConfig` — replace one protocol's data-plane config and reload it.
- `AddPeer` — add one peer live, no restart.
- `RemovePeer` — revoke one peer live.
- `ListPeers` — configured peers and their runtime state (handshakes, byte
  counters).
- `RestartService` — last-resort restart of one protocol's service.
- `WatchEvents` — **server-stream**: handshake up/down, peer connect/disconnect,
  errors. `coxswain` holds this open; this is what makes the admin UI live.

### AmneziaWG obfuscation

`control.proto`'s `GetStatusResponse` carries `AmneziaWGInfo amneziawg = 4`
(messages `AmneziaWGInfo` + `AmneziaWGObfuscation`). `coxswain` refuses to
provision devices onto a node until it has these values, and hands the exact
obfuscation set to every client of the node so `caravel` can build a tunnel
that handshakes (DESIGN §3).

Each node randomises **its own** obfuscation set — never fleet-wide:

- `H1`-`H4` are four distinct magic headers, each ≥ 5 (1–4 are reserved for
  AmneziaWG's standard packet types).
- `Jmin < Jmax`; `Jc` is kept small (≈3–10) and `S1`-`S4` bounded (≈15–150) so
  handshakes stay performant. `S2 ≠ S1+56` (else an init packet is
  indistinguishable from a response packet). `I1`-`I5` are left empty.

The set and the node's AmneziaWG keypair are generated once and persisted to
`<config-dir>/awg-node.json` (`0600`), so the values stay **stable** across
node restarts and `awg` reloads — `coxswain` caches them. The data-plane writer
(milestone B2) renders them into the `[Interface]` section of `awg0.conf` and
applies it; `GetStatus` reports the same persisted set.

### Data plane

Manages `awg-quick@awg0` (UDP 443) and `xray.service` (TCP 443). Peer
add/remove must be **live** (no tunnel drop for other peers). Disk-full on a
config write → return a typed error; the running data plane keeps last-known-good.

### AmneziaWG data plane (B2)

`node` owns `awg0.conf` at `/etc/amnezia/amneziawg/awg0.conf` (0600) — the conf
is the source of truth coxswain pushes; every successful `AddPeer`/`RemovePeer`
updates both `awg0` and the conf, so a node restart converges to the same
state. The `[Interface]` block (private key, listen port, MTU, obfuscation
lines) is rendered from `awg-node.json`; the `[Peer]` blocks come from coxswain
and never include `Endpoint` — clients dial the node.

`PushConfigRequest.config` for `PROTOCOL_AMNEZIAWG` is `proto.Marshal` of
`AmneziaWGConfig { repeated Peer peers = 1; }` (canonical docs PR #11 /
coxswain PR #28). The set of node-level obfuscation parameters is deliberately
absent from `AmneziaWGConfig` — `coxswain` sends peers, never obfuscation, and a
request that somehow carries them is ignored.

Live-reload pattern: `awg-quick strip <conf> | awg syncconf awg0 /dev/stdin`
(in-flight tunnels are not dropped). The first apply uses `awg-quick up`;
`awg-quick down/up` remains the fallback. Single peer mutations go through
`awg set awg0 peer <pubkey> ...`; `AddPeer` is an upsert, `RemovePeer` is
idempotent on missing peers.

Sensitive material — the node private key and per-peer PSKs — is supplied
via on-disk conf (0600) or piped on stdin; it never appears on argv, in the
environment, or in logs.

`PushConfig.revision` is monotonically increasing. A revision below the last
applied one is rejected with `FailedPrecondition`; an equal revision is an
idempotent replay (no rewrite, `reloaded=false`). The last applied revision
persists at `<config-dir>/awg-revision`.

### Planned — node cascade / multi-hop (DESIGN decision 18, not scheduled)

A future feature chains nodes: `client → entry node → inner AmneziaWG link →
exit node → internet`. No work now, but **do not harden two assumptions** that
would otherwise be safe today:

- **"A `[Peer]` block never carries an `Endpoint`."** True for client peers
  (clients dial the node) — but the inner link is a `node`→`node` peer where the
  *entry* node **dials the exit**, so that peer *does* have an `Endpoint`. Keep
  the conf renderer able to emit a peer with an endpoint; don't bake "no peer
  ever has one" into the model.
- **"Forwarding ⇒ masquerade everything to the egress interface."** The exit
  side is exactly today's `forwarding + masquerade` (decision 16) — no change.
  The entry side will need a new `transit` mode that *per-device* policy-routes
  a peer into another interface instead of NATing it to the internet. Keep the
  network-policy model open to per-device routing and to more than one managed
  WireGuard interface; don't assume a single global egress for all forwarded
  traffic.

## Reuse

`node`'s control channel is a **plain mTLS gRPC server** — `coxswain` dials it
directly (the node is public). It does **not** need the reverse-tunnel code;
that belongs to `beacon`. You may adapt the **mTLS setup / CA-verification**
helpers the operator wrote for an earlier private project — and if you do,
obey the rebrand rule in `docs/BUILD.md` §4 (strip every origin identifier).

## Milestones

| # | Output |
|---|---|
| B1 | Repo skeleton, config loader, the `gen-csr`/`run`/`version` commands, mTLS `NodeControl` gRPC server skeleton (RPCs return `Unimplemented`). `GetStatus` is implemented early — it reports the per-node AmneziaWG identity + obfuscation set `coxswain` needs before it will provision devices. |
| B2 | AmneziaWG management: `PushConfig` (AmneziaWGConfig wire format), `AddPeer`/`RemovePeer` (live + conf, idempotent), `ListPeers` (conf joined with `awg show`); `GetStatus` reports the AmneziaWG `ServiceStatus`. Obfuscation comes from `awg-node.json` only. |
| B3 | XRay management: `PushConfig`, `AddPeer`/`RemovePeer`, `ListPeers` |
| B4 | `GetMetrics`: per-peer counters + summed totals from `awg show`. `handshakes_total` / `errors_total` are reserved for the B5 polling observer that also feeds `WatchEvents`; they stay at zero in B4 and accumulate once that observer lands. |
| B5 | `WatchEvents` server-stream + polling observer. One observer goroutine polls `awg show` (default 5s), diffs against the previous snapshot, and broadcasts events to subscribers: `PEER_CONNECTED`/`DISCONNECTED`, `HANDSHAKE_UP` on each new or rekey handshake, `HANDSHAKE_DOWN` once when a handshake ages past 180s, `ERROR` on poll failure. Also accumulates B4's `handshakes_total` / `errors_total`. The first poll establishes the baseline silently — replay is via `GetStatus`+`ListPeers`. Slow subscribers drop overflow rather than block the observer. |
| B6 | Cold-start-from-disk + cloud-init packaging (static binary) |

## Non-negotiables

- `node` never dials `coxswain`. It only accepts.
- No config touches disk unless it arrived over a validated mTLS connection
  (the SSH-pushed `node.crt`/`ca.crt`/`node.key` are the onboarding exception).
- No state beyond what `coxswain` pushed + AWG/XRay runtime state. No database.
- Survives controller outage: existing tunnels keep serving.

## Depends on

The `node` control + event-stream protos, owned by `coxswain`, in `docs/proto/`.
A copy is vendored into this repo's `proto/`; generated Go is committed under
`internal/gen/`. Build against them; do not fork them. See `proto/README.md`.
