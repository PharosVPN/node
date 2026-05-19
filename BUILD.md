# buoy — Build Brief (subagent)

**Read first, in order:** `docs/BUILD.md` → `docs/DESIGN.md` → this file.
This is a delegated subproject. If the design is silent on a contract you need,
stop and raise it — do not invent one.

---

## What you are building

`buoy` is the VPN node agent — a single static Go binary that runs on each
public VPN node. It is the *server* side of the control channel; `helm` (the
controller) is the *client* that dials in. `buoy` opens no connection to `helm`.

## Behaviour

### Two modes
- **Enrollment mode** (first boot): listen on the control port, accept only a
  connection presenting a valid one-time **bootstrap token**. On success, write
  `{ca_cert, node_cert, node_key}` to `/etc/buoy/`, exit enrollment mode,
  restart in normal mode. See DESIGN §5.
- **Normal mode:** control port accepts only mTLS connections whose client cert
  chains to the bundled CA cert. Anything else is dropped at the TLS handshake —
  no banner, no 401.

### Control service (gRPC over mTLS) — `helm` calls these
- `Status` — service health, kernel module loaded, listener bind state, peer
  count, last-handshake times.
- `Metrics` — Prometheus-style counters: per-peer bytes in/out, handshakes, errors.
- `PutConfigAWG` / `PutConfigXray` — replace `awg0.conf` / `xray/config.json`,
  reload the service.
- `AddPeerAWG` / `AddPeerXray` — add one peer live, no restart.
- `RemovePeerAWG` / `RemovePeerXray` — remove one peer live.
- `Handshakes` — structured `awg show` output.
- `Restart{AWG,Xray}` — last-resort service restart.
- `WatchEvents` — **server-stream**: handshake up/down, peer connect/disconnect,
  errors. `helm` holds this open; this is what makes the admin UI live.

### Data plane
Manages `awg-quick@awg0` (UDP 443) and `xray.service` (TCP 443). Peer
add/remove must be **live** (no tunnel drop for other peers). Disk-full on a
config write → return a typed error; the running data plane keeps last-known-good.

## Reuse

`buoy`'s control channel is a **plain mTLS gRPC server** — `helm` dials it
directly (the node is public). It does **not** need the reverse-tunnel code;
that belongs to `beacon`. You may adapt the **mTLS setup / CA-verification**
helpers the operator wrote for an earlier private project — and if you do,
obey the rebrand rule in `docs/BUILD.md` §4 (strip every origin identifier).

## Milestones

| # | Output |
|---|---|
| B1 | Skeleton, config, control-port mTLS server, enrollment mode |
| B2 | AWG management: PutConfig, Add/RemovePeer, Handshakes |
| B3 | XRay management: PutConfig, Add/RemovePeer |
| B4 | Status + Metrics |
| B5 | `WatchEvents` server-stream |
| B6 | Cold-start-from-disk + cloud-init packaging (static binary) |

## Non-negotiables

- `buoy` never dials `helm`. It only accepts.
- No config touches disk unless it arrived over a validated mTLS connection.
- No state beyond what `helm` pushed + AWG/XRay runtime state. No database.
- Survives controller outage: existing tunnels keep serving.

## Depends on

The `buoy` control + event-stream protos, owned by `helm`, in `docs/proto/`.
Build against them; do not fork them.
