# Honeypot Ecosystem — node-01 vertical slice

Phase 1 of the deception network: one SSH bastion, fully instrumented, end to
end. Everything under `shared/` is written once here and reused unchanged by
nodes 02 and 03 in phase 5 — which is why node-01 is built as a complete
vertical slice rather than a bare container.

## Quick start

```bash
python tools/bootstrap.py
docker compose build
docker compose up -d
ssh -p 2222 test@localhost      # password: test123
```

`tools/bootstrap.py` generates the backend keypair, a random HMAC secret, and
the node's `sshd_policy.conf`. None of those are in git.

## How a session flows

```
attacker ──ssh──▶ ssh-proxy ──asks──▶ session-broker ──docker──▶ node container
                      │                                              ▲
                      └───────────── bridges the PTY ────────────────┘
                      │
                      ├─▶ events.ndjson ──▶ sidecar ──HMAC──▶ intelligence hub
                      └─▶ transcripts/    (signs, retries, spools)
```

The proxy terminates the attacker's SSH connection, gets an isolated backend
from the broker, opens its own SSH session to it, and relays bytes while
recording. Recording happens **on the wire, outside the attacker's container**,
which is the point: a recorder living inside a box someone has root on is a
recorder they can find, kill, or truncate. Here they can do none of those, and
the node emits no telemetry at all — there is no agent, shipper or spool file
inside their reach to discover.

## What each piece is

| Path | Role |
|---|---|
| `shared/common/cowrie_events.py` | Cowrie-schema event builders. The hub's normalizer is hardcoded to these ids; that contract is fixed. |
| `shared/ssh-proxy/` | The front door. Terminates SSH, authenticates, records, bridges. |
| `shared/ssh-proxy/openssh_profile.py` | The SSH policy we present, and why it is this policy. Read this before changing any algorithm list. |
| `shared/ssh-proxy/hassh.py` | HASSH fingerprinting from the client KEXINIT. |
| `shared/ssh-proxy/recorder.py` | Reconstructs commands from the PTY stream. |
| `shared/session-broker/` | Owns the Docker socket. Hands out one container per attacker IP. |
| `shared/sidecar/` | Holds the HMAC key. Signs and ships telemetry. |
| `nodes/node-01-jump/identity.yaml` | Single source of truth for who the node claims to be. |
| `tests/` | `pytest tests/ -v` |

## Design decisions worth knowing before you change something

**No shims.** The prototype faked `ps`, `netstat`, `whoami`, `id` and `sudo`
with PATH scripts. A `ps` that prints the same six PIDs forever is a
fingerprint, `type sudo` exposes the scheme in one command, and the fake sudo
was bypassable because `/usr/bin/sudo` still existed. Real services run
instead, so every tool tells the truth and there is nothing to catch.

**Real root, worth nothing.** Containment is the runtime's job, not the
disguise's. The broker drops every capability except the handful sshd needs,
caps pids and memory, and attaches nodes to an internal network with no route
to the internet, the hub, or the brain. `sudo su` works.

**A hardened SSH policy, not stock defaults.** AsyncSSH cannot do
`sntrup761x25519-sha512@openssh.com` or any `umac` MAC, so imitating stock
OpenSSH 8.9p1 would leave a profile with no umac but still offering
`hmac-sha1` — a shape no real admin produces. We advertise a coherent
CIS/Mozilla-style hardened set instead, and mirror it into the node's
`sshd_config` so a reader finds corroboration rather than contradiction.

**Fixed credentials, never accept-the-Nth-guess.** Cowrie's default is among
the best known honeypot tells. See `credentials.py`.

**PID 1 must be init.** Docker makes sshd PID 1 by default, and `ps -p 1`
showing sshd is a conclusive container tell for one command's effort.

**Line endings.** `.gitattributes` forces LF. A CRLF shebang kills the node
with exit 127 and an error that blames the script rather than its line endings.

## Verified

- Real OpenSSH client negotiates: banner, kex, cipher, host key, and a
  `publickey,password` auth list
- HASSH parser checked against live OpenSSH client bytes
- Command reconstruction: 11 tests including tab completion, history recall,
  and unechoed sudo passwords
- `last` / `lastlog` read the seeded binary history; logins fall in working
  hours in the node's own timezone
- Session isolation: same source IP reuses its container, a different IP gets
  its own
- HMAC batches validate against the hub's own `verify_hmac` implementation
- Sidecar spools rather than dropping when the hub is unreachable

## Not done yet (phase 2+)

Ambient activity engine, fake-internet gateway, golden-master ageing,
container pre-warming, `/proc/1/cgroup` masking, and the adaptive decoy loop.
See the build plan for the full phase list.
