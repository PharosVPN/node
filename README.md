<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".assets/logo-inverse.svg">
    <img src=".assets/logo.svg" alt="PharosVPN" width="120" height="120">
  </picture>
</p>

# node

> A fixed, public marker anchored out in the water — ships rely on it.

**`node` is the PharosVPN node agent.** It runs on every public VPN node, runs
the data plane (AmneziaWG + XRay), and applies only the configuration the
controller pushes to it over mTLS. It is deliberately dumb: a compromised `node`
cannot compromise the fleet.

Part of the [PharosVPN](https://github.com/PharosVPN) platform — see
[`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md).

## Role

- **Public IP.** Terminates end-user tunnels on UDP 443 (AmneziaWG) and TCP 443
  (XRay / VLESS+REALITY).
- **Stateless except for what `coxswain` gave it.** All config is written to disk
  only after the controller pushes it over a validated mTLS connection.
- **Control port.** Listens for the controller's mTLS/gRPC connection: status,
  metrics, config push, live peer add/remove, service restart — and streams
  live events back.
- **SSH is install-only.** `coxswain` reaches a node over SSH solely to install and
  update the agent (DESIGN §5); every operational instruction is gRPC.
- **Cold-start resilient.** Comes up from disk every boot; controller offline ⇒
  existing tunnels keep working.

## Stack

Go · gRPC server over mTLS · manages `awg-quick@awg0` and `xray.service`.

## Status

🚧 Pre-alpha — scaffolding. See [BUILD.md](BUILD.md).

## License

Apache-2.0. Contributions under the DCO (`git commit -s`).
