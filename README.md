# Integrity Attestation Lab

An educational, cross-platform **C++17 simulator** of the *gateway-and-attestation* pattern used by
session-integrity systems (the architectural family that kernel-based anti-cheat products belong to).
It models how a server-authoritative gateway issues sessions, authenticates periodic heartbeats, and
fails closed when an independent integrity agent cannot vouch for the client.

> ### Scope & disclaimer
> This project is for **education and defensive architecture study only**. It is **not** an anti-cheat
> product, a replacement, an emulator, a bypass, or a kernel driver. It does **not** load, contact,
> patch, hook, or interoperate with any real anti-cheat (Vanguard, EAC, BattlEye, or others). The
> `mock_agent` is an ordinary user-space process; all RPC verbs here are invented lab examples. Every
> "attack" scenario targets **this simulator's own loopback gateway** to demonstrate why a given
> defense exists — it is threat modeling of the lab, not a technique against any third-party system.
> The bundled SHA-256/HMAC is a self-contained teaching primitive; production systems must use a
> vetted cryptographic library and per-device provisioned keys, never the shared constant used here.

---

## Overview

Three independent processes communicate over IPv4 loopback only:

```
        127.0.0.1:48391                 127.0.0.1:48392
  ┌────────────────────┐          ┌──────────────────────┐
  │  heartbeat_client   │  HELLO   │       gateway        │  ATTEST   ┌─────────────┐
  │  (claims state,     ├─────────▶│  (session authority, ├──────────▶│ mock_agent  │
  │   signs heartbeats) │◀─────────┤   fail-closed)       │◀──────────┤ (integrity) │
  └────────────────────┘ SESSION  └──────────┬───────────┘  signed    └─────────────┘
                          ALLOW /             │             attestation
                          BLOCK               ▼
                                      audit.ndjson (hash-chained)
```

The **gateway** is the trust anchor. It never accepts a client's self-reported state as sufficient:
every session and every heartbeat is gated on a freshly challenged, cryptographically signed
attestation from the independently running agent.

## Security model

| Control | Mechanism | Property enforced |
|---|---|---|
| Session binding | Per-session id + secret issued at `HELLO` | Only the holder of the session secret can produce valid heartbeats |
| Message authenticity | `HMAC-SHA256(secret, id\|seq\|nonce\|claim)` on every `BEAT` | A forged or sniffed frame without the secret is rejected (`MAC_INVALID`) |
| Replay / freshness | Nonce rotates on every accepted heartbeat | A captured frame is stale on resend (`NONCE_MISMATCH`) |
| Ordering | Strictly increasing per-session sequence | Gaps and repeats are rejected (`REPLAY_OR_SEQUENCE_GAP`) |
| Liveness | TTL expiry (default 1500 ms) | A silent/paused client loses its session (`HEARTBEAT_TIMEOUT`) |
| Server authority | Independent agent cross-check before issuing a session and each heartbeat | Client-claimed "healthy" is never trusted alone (`CLIENT_INTEGRITY_MISMATCH`) |
| Agent authenticity | Challenge–response; agent signs with the provisioned lab key | A rogue agent that only echoes "healthy" fails closed (`AGENT_NOT_HEALTHY`) |
| Audit integrity | Each log line commits to the previous line's SHA-256 | Deleting or editing a past record breaks the chain and is detectable |

**Design principle:** never trust a value the client controls. Authenticity, freshness, and
independent attestation move trust to properties an attacker cannot forge from the client side;
the truth of runtime state is asserted by the server-authoritative agent, not the client.

### Threat scenarios (demonstrated against the lab's own gateway)

Each is a `heartbeat_client --scenario <name>` run (or a step in the integration test) that *attempts*
to defeat a control and is correctly blocked:

| Scenario | Attempted attack | Expected result |
|---|---|---|
| `normal` | Legitimate, correctly signed heartbeats | `ALLOW` (exit 0) |
| `forged-mac` | Sign a heartbeat without knowing the session secret | `BLOCK\|MAC_INVALID` |
| `replay` | Resend a previously accepted frame verbatim | `BLOCK\|NONCE_MISMATCH` |
| `seq-gap` | Skip a sequence number | `BLOCK\|REPLAY_OR_SEQUENCE_GAP` |
| `bad-nonce` | Present a wrong session nonce | `BLOCK\|NONCE_MISMATCH` |
| `tamper` | Claim `compromised` state | `BLOCK\|CLIENT_INTEGRITY_MISMATCH` |
| `wrong-session` | Use an unknown session id | `BLOCK\|UNKNOWN_SESSION` |
| `expired` | Heartbeat after the TTL elapses | `BLOCK\|HEARTBEAT_TIMEOUT` |
| rogue agent *(test)* | Run an agent with the wrong attestation key | `BLOCK\|AGENT_NOT_HEALTHY` |
| audit tamper *(test)* | Delete/edit an audit record | Hash chain breaks |

## Protocol

Line-oriented, `|`-delimited frames terminated by `\n`, UTF-8, ≤4 KiB.

| Direction | Frame | Notes |
|---|---|---|
| client → gateway | `HELLO` | Request a session |
| gateway → client | `SESSION\|<id>\|<nonce>\|<secret>` | Issued after a valid agent attestation |
| client → gateway | `BEAT\|<id>\|<seq>\|<nonce>\|<claim>\|<mac>` | `mac = HMAC-SHA256(secret, id\|seq\|nonce\|claim)` |
| gateway → client | `ALLOW\|<seq>\|<next_nonce>` | Heartbeat accepted; adopt `next_nonce` |
| gateway → client | `BLOCK\|<reason>` | Rejected; see reason codes above |
| gateway → agent | `ATTEST\|<challenge>` | Fresh random challenge |
| agent → gateway | `ATTEST\|<state>\|<verdict>\|<mac>` | `mac = HMAC-SHA256(lab_key, challenge\|state\|verdict)` |
| any → any | `PING` → `PONG` | Readiness probe |

## Build

Requires CMake ≥ 3.16 and a C++17 compiler (MSVC 2022, Clang, or GCC). No external dependencies.

```shell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Python 3 is used only by the CTest integration harness; the executables themselves do not depend on it.

## Run the demo

Start the agent first, the gateway second, then the client (each in its own terminal).

**Linux / macOS**
```shell
./build/mock_agent --port 48392 --state healthy
./build/gateway --port 48391 --agent-port 48392 --ttl-ms 1500 --audit events.ndjson
./build/heartbeat_client --gateway-port 48391 --scenario normal
```

**Windows (PowerShell, MSVC multi-config build)**
```powershell
.\build\Release\mock_agent.exe --port 48392 --state healthy
.\build\Release\gateway.exe --port 48391 --agent-port 48392 --ttl-ms 1500 --audit events.ndjson
.\build\Release\heartbeat_client.exe --gateway-port 48391 --scenario normal
```

The gateway and agent must share the same `--lab-key` (default `LAB_SHARED_ATTEST_KEY`) for attestation
to succeed; start the agent with a different key to reproduce the rogue-agent scenario.

## Project layout

```
.
├── CMakeLists.txt          # Build + CTest wiring
├── src/
│   ├── net.hpp / net.cpp   # Loopback TCP, framing, SHA-256/HMAC, arg parsing
│   ├── gateway.cpp         # Session authority, heartbeat validation, audit log
│   ├── mock_agent.cpp      # Independent integrity attestation responder
│   └── heartbeat_client.cpp# Scenario driver (legitimate + attack cases)
└── tests/
    └── integration.py      # Multi-process end-to-end + audit-chain verification
```

## Naming conventions

| Element | Convention | Example |
|---|---|---|
| Repository | `kebab-case` | `integrity-attestation-lab` |
| Source files & build targets | `snake_case` | `mock_agent.cpp`, `heartbeat_client` |
| Types | `PascalCase` | `Gateway`, `Session`, `Sha256` |
| Functions & variables | `snake_case` | `check_agent`, `audit_prev` |
| Protocol verbs | `UPPERCASE` | `HELLO`, `BEAT`, `SESSION`, `ATTEST` |
| Reason / verdict codes | `UPPER_SNAKE_CASE` | `MAC_INVALID`, `HEARTBEAT_TIMEOUT` |
| CLI flags | `--kebab-case` | `--agent-port`, `--lab-key` |

## License

MIT — see [LICENSE](LICENSE).
