# Honeypot Ecosystem

Three deception nodes that an attacker can genuinely pivot through, every
action streamed to the intelligence hub within milliseconds, and the GenAI
brain changing the decoys while the attacker is still typing.

This is the honeypot half of the capstone. It talks to two other modules:
the **intelligence hub** (`feature/intelligence-hub`) and the **GenAI brain**
(`ai-brain/content-generator`, already on `main`).

---

## The cycle

```
attacker ──ssh──▶ ssh-proxy ──asks──▶ session-broker ──docker──▶ node container
                      │                                              ▲
                      └───────────── bridges the PTY ────────────────┘
                      │
                      ▼
                events.ndjson
                      │
                   sidecar  (holds the HMAC key)
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
  intelligence hub            GenAI brain
  (learns the patterns)       (chooses decoys)
                                    │
                    decoys ◀── session-broker ◀──┘
```

One signed event goes both ways. The hub branch is sequential and ordered —
it is building a record. The brain branch is queued and non-blocking, because
intent is a property of a command *sequence* and a slow brain must never delay
what reaches the hub.

Measured end-to-end latency, proxy write to hub delivery: **33 ms min,
58 ms median, 95 ms max.**

---

## The estate

| Node | Claims to be | Runs for real | How you reach it |
|---|---|---|---|
| `node-01-jump` | `jump-01` — dev/staging jump host | sshd, cron, rsyslog | SSH on the published port |
| `node-02-erp` | `erp-web` — student ERP portal | nginx, portal app on :8080 | pivot from node-01 with a stolen key |
| `node-03-db` | `db-01` — student records database | mariadb, 240 seeded records | pivot from node-02 with leaked credentials |

Nodes 02 and 03 do not exist until somebody actually pivots. Most sessions
never do, so the common case stays one container per attacker.

### The trust boundary

What an attacker with **root inside a node** can and cannot reach:

| Target | Reachable? | Why |
|---|---|---|
| Internet, hub, brain | no | their network is `internal: true` |
| The sidecar, and so the HMAC key | no | sidecar is on `control` only |
| The session broker (owns the Docker socket) | no | `control` only |
| Another attacker's containers | no | one private network per attacker |
| The SSH proxy | yes | unavoidable — it has to bridge their session. They gain another honeypot session. |

The node emits **no telemetry at all**. There is no agent, no log shipper and
no spool file inside the container to find, because recording happens on the
wire in the proxy.

---

## Prerequisites

- **Docker Desktop** running Linux containers (tested on 28.3.2)
- **Python 3.11+** on the host, for `tools/`
- **~6 GB free RAM** with the hub running (Elasticsearch alone wants 512 MB,
  and each attacker environment is up to three containers)
- **OpenSSH client** (`ssh`, `ssh-keygen`) — present on Windows 10/11, macOS
  and Linux by default

```bash
python -m pip install -r requirements.txt
```

---

## Setup

### 1. Create the shared network (once per machine)

```bash
docker network create honeypot-telemetry
```

This is how the sidecar finds the hub by name instead of gambling on a host
port. See Troubleshooting — a stray service on port 8000 silently ate 28
events during development.

### 2. Generate keys and config

```bash
python tools/bootstrap.py
```

Creates, all of them git-ignored:

| File | What it is |
|---|---|
| `secrets/backend_key` | key the proxy uses to reach node containers |
| `secrets/decoy_deploy_key` | the key planted for the attacker to steal. **A real ed25519 key** — a fake blob fails the moment `ssh -i` touches it |
| `secrets/credentials.yaml` | logins the perimeter accepts (node-01 accounts only) |
| `secrets/peer_credentials.yaml` | logins the pivot gateway accepts (node-02/03 accounts) |
| `.env` | environment, including a fresh random `HMAC_SECRET` |
| `nodes/*/sshd_policy.conf` | the SSH policy, generated from the same module the proxy advertises |

> **`--force` regenerates the keys.** That invalidates `authorized_keys` in
> every already-built node image and breaks the inner SSH with "Auth failed",
> and it rotates `HMAC_SECRET` so the hub rejects everything with 401. If you
> use it, rebuild all nodes and re-sync the hub's `.env`.

### 3. Build the node images

```bash
python tools/build_nodes.py
```

All three come from one parameterised image, `shared/node-build/Dockerfile`.
Takes several minutes the first time.

### 4. Start the stack

```bash
docker compose up -d
```

---

## Running the intelligence hub

The hub lives on a different branch. Use a git worktree so both are checked
out at once — you need them running together:

```bash
git worktree add ../GenAIHoneypot-hub feature/intelligence-hub
```

Then create `intelligence_hub/.env`. **`HMAC_SECRET` must be byte-identical
to this module's**, or every signed event is rejected with 401:

```
HMAC_SECRET=<copy from honeypot-ecosystem/.env>
POSTGRES_USER=hubadmin
POSTGRES_PASSWORD=<pick one>
POSTGRES_DB=threatintel
NEO4J_USER=neo4j
NEO4J_PASSWORD=<pick one>
LOG_LEVEL=info
CORS_ORIGIN=http://localhost:5173
```

```bash
cd ../GenAIHoneypot-hub/intelligence_hub; docker compose up -d
```

First start pulls Elasticsearch, Postgres, Neo4j and Redis — give it a few
minutes.

| Service | URL |
|---|---|
| Dashboard | http://localhost:5173 |
| Hub API | http://localhost:8000 |
| Honeypot SSH | `localhost:2222` |

---

## Testing it

### Walk the whole chain

Open **http://localhost:5173**, go to **Live Feed**, leave it open. Then:

```bash
ssh -p 2222 devuser@localhost
```

Password `dev@123`. Use `devuser` — it has sudo, which the chain needs.
(Also accepted: `test`/`test123`, `student`/`student123`, `ubuntu`/`ubuntu`,
`git`/`git`.)

**Look around.** Every command appears on Live Feed in under 100 ms:

```bash
w; last | head; ps aux | head; ls -la /home/devuser
```

**Find the breadcrumb:**

```bash
grep DEPLOY_KEY /opt/deploy/sync-erp.sh
```

**Escalate and steal the key** — it is owned by another user, so this needs
root:

```bash
sudo cp /home/ta_miller/.ssh/id_erp_deploy /tmp/k; sudo chown devuser /tmp/k; chmod 600 /tmp/k
```

**Pivot to node-02.** It is spawned on demand, so the first connection takes
a few seconds:

```bash
ssh -i /tmp/k -o StrictHostKeyChecking=no deploy@erp-web
```

**Read what the app leaks, then reach the database:**

```bash
cat /opt/erp/settings.py
```

```bash
set +H; mysql -h db-01 -u erp_admin -pTr3llis!84m -e "select count(*) from erp.students;"
```

(`set +H` stops interactive bash expanding the `!` in the password.)

Then check **Sessions**, **Alerts** and **IOC Intel** in the dashboard. The
`sensor` changes from `node-01-jump` to `node-02-erp` as you pivot — proof
the pivot is being recorded through the proxy rather than travelling
host-to-host unobserved.

### Watch the adaptive loop

```bash
docker compose logs -f sidecar
```

You will see the cycle fire:

```
sidecar.brain session dd53f3…: intent=reconnaissance action=populate_developer_workstation confidence=0.63 (ml)
sidecar.brain planted 'populate_developer_workstation' for 172.23.0.1 (2 file(s))
```

Then back in your SSH session, `ls -la ~` — files the brain decided to plant
have appeared **while you were sitting there**.

### Check session isolation

```bash
touch /tmp/iwashere
```

Exit, reconnect — it is still there. That is your own container. Meanwhile a
different source IP gets a different container on a different subnet and
cannot reach yours at all.

### Run the unit tests

```bash
python -m pytest tests/ -v
```

Eleven tests covering command reconstruction: tab completion, history recall,
unechoed sudo passwords, and the ANSI/CR edge cases that broke it twice.

---

## What each piece is

| Path | Role |
|---|---|
| `shared/common/cowrie_events.py` | Cowrie-schema event builders. The hub's normalizer is hardcoded to these ids — that contract is fixed |
| `shared/ssh-proxy/proxy.py` | Perimeter front door. Terminates SSH, authenticates, records, bridges |
| `shared/ssh-proxy/peer_gateway.py` | Second listener for pivots to node-02/03 |
| `shared/ssh-proxy/openssh_profile.py` | The SSH policy we present, and why. **Read before touching any algorithm list** |
| `shared/ssh-proxy/hassh.py` | HASSH client fingerprinting from KEXINIT |
| `shared/ssh-proxy/recorder.py` | Reconstructs commands from the PTY stream |
| `shared/session-broker/broker.py` | Owns the Docker socket. Networks, containers, lazy peers, decoy placement |
| `shared/sidecar/shipper.py` | Holds the HMAC key. Signs and streams to the hub |
| `shared/sidecar/brain_courier.py` | The adaptive branch: intent → action → planted decoys |
| `shared/sidecar/watcher.py` | inotify, so events are never waiting on a timer |
| `shared/node-build/` | One image definition for all three nodes |
| `nodes/*/identity.yaml` | Single source of truth for who each node claims to be |

---

## Design decisions worth knowing before you change something

**No shims.** The original prototype faked `ps`, `netstat`, `whoami`, `id` and
`sudo` with PATH scripts. A `ps` that prints the same six PIDs forever is a
fingerprint, `type sudo` exposes the whole scheme in one command, and the fake
sudo was bypassable because `/usr/bin/sudo` still existed. Real services run
instead, so every tool tells the truth.

**Real root, worth nothing.** Containment is the runtime's job. `sudo su`
works, `cat /etc/shadow` works — and every capability except the handful sshd
needs is dropped, with no route off the attacker's own network.

**A hardened SSH policy, not stock defaults.** AsyncSSH cannot do
`sntrup761x25519-sha512@openssh.com` or any `umac` MAC, so imitating stock
OpenSSH 8.9p1 would leave a profile with no umac but still offering
`hmac-sha1` — a shape no real admin produces. We advertise a coherent
CIS/Mozilla-style hardened set instead, and mirror it into each node's
`sshd_config` so a reader finds corroboration rather than contradiction.

**Fixed credentials, never accept-the-Nth-guess.** Cowrie's default is among
the best known honeypot tells.

**PID 1 must be init.** Docker would make sshd PID 1, and `ps -p 1` showing
sshd is a container giveaway for one command's effort.

**Line endings.** `.gitattributes` forces LF. A CRLF shebang kills a node with
exit 127 and an error that blames the script rather than its line endings.

---

## Troubleshooting

**Dashboard stuck on "Loading intelligence data…"**
Vite's proxy must target the compose service name, not `localhost` — inside
the frontend container `localhost` is the frontend itself. Already fixed in
`vite.config.js`; set `VITE_API_TARGET=http://localhost:8000` only if you run
`npm run dev` on the host instead.

**Sidecar logs "hub unreachable" or a redirect**
Something else owns host port 8000. On one dev machine it was Splunk, which
answered `303` — and an earlier shipper treated anything under 400 as success,
so 28 events went into Splunk while being logged as delivered. The sidecar now
reaches the hub over the `honeypot-telemetry` network by name; make sure that
network exists and the hub's backend is attached.

**Hub rejects everything with 401**
`HMAC_SECRET` differs between `honeypot-ecosystem/.env` and
`intelligence_hub/.env`. Usually caused by `bootstrap.py --force`.

**Inner SSH fails with "Auth failed for user devuser"**
`bootstrap.py --force` rotated the backend key after the node images were
built. Run `python tools/build_nodes.py`.

**Pivot fails with "No route to host"**
The proxy has not claimed the `.21`/`.31` addresses on that attacker's
network. It needs `NET_ADMIN` (set in `docker-compose.yml`) and `iproute2` in
its image. The broker logs `proxy now answers for erp-web, db-01 on …` when it
works.

**node-03 refuses connections for the first ~30 s**
mariadb initialises its data directory on first boot. One retry succeeds.

**Attack Map is empty**
Geo enrichment silently no-ops without a GeoLite2 database. Drop
`GeoLite2-City.mmdb` into `intelligence_hub/geoip/`.

---

## Not done yet

- The **MySQL session** between node-02 and node-03 is not proxied. The
  command and its credentials are captured on node-02; the wire protocol is
  not. A MySQL-aware proxy is separate work.
- `/proc/version` and `/proc/sys/kernel/osrelease` still report the host
  kernel. `uname` is handled by an LD_PRELOAD shim, but masking procfs needs a
  mount the container cannot perform on itself — host-side work for
  deployment.
- **Ambient activity engine** (live log growth, processes churning) and the
  **fake-internet gateway**. History is currently seeded at build time.
- `POST /ingest/batch` on the hub accepts unsigned events. Sensors do not use
  it — they stream signed events to `/ingest/` — but set
  `allow_unsigned_batch=false` before exposing the hub anywhere.
- Nothing is internet-exposed yet. See the pre-launch checklist in the build
  plan before that changes.

---

## Change log

What has changed since the March state of this repo. If you last saw it then,
read this section.

### Where we started

`main` held only `ai-brain/content-generator`. Two branches were unmerged:
`feature/entrypoint-ssh-honeypot` (four files — a Dockerfile, compose file,
README and a zip of captured logs) and `feature/intelligence-hub`. The
`phase-2/*` and `feature/adaptive-learning` branches were already fully merged
and are dead.

### Honeypot: rebuilt from the prototype

The original was a single Ubuntu container with real sshd, `script(1)`
transcript logging, and PATH shims faking `ps`, `whoami` and `sudo`. It was
replaced rather than extended, for reasons that were found by running it:

- **Recording moved out of the node.** A recorder inside the box an attacker
  owns can be found, killed or truncated by root. It now runs in the SSH
  proxy, on the wire.
- **Cowrie-schema events.** The hub's normalizer is hardcoded to Cowrie event
  ids. The proxy emits all seven types the hub scores, including HASSH.
- **Command reconstruction** from the PTY stream, handling tab completion,
  history recall and unechoed passwords. Covered by tests.
- **Realism fixes**, most found by SSHing in and looking: the double MOTD
  leaking `microsoft-standard-WSL2`; `uname -r` contradicting the motd (fixed
  with an LD_PRELOAD shim compiled in a builder stage); `ps -p 1` showing
  sshd; `netstat` printing `hp-ssh-proxy.honeypot-ecosystem_deception`; `sudo`
  that could never succeed; empty home directories; the bait credentials
  containing the literal string `FAKE`.
- **Three nodes**, from one parameterised image, with nodes 02 and 03 spawned
  lazily on first pivot.

### Isolation

Per-source-IP containers first, then a private Docker network per attacker
after testing showed attacker A could reach attacker B's container.

### Zero-trust pipeline

- Sidecar holds the HMAC key; nodes hold nothing.
- Streams **single signed events** to `/ingest/`, the only endpoint that
  verifies signatures. Batching sent everything down the one path where the
  check does not run.
- **inotify instead of polling** — median latency 1000 ms → 58 ms.
- Disk-backed spool, so an unreachable hub costs latency rather than evidence.

### Adaptive loop

The sidecar fans out to the GenAI brain as well as the hub. Intent
classification works without an LLM key (rules plus RandomForest); decoy
content falls back to local bundles when no key is configured. Chosen decoys
are written into the attacker's own container by the broker, using
`put_archive` so no process appears in their `ps`.

### Intelligence hub

Fixed on the hub branch: `frontend/Dockerfile` was committed empty (0 bytes),
so the dashboard could never start; `vite.config.js` proxied to `localhost`,
which inside the container is the frontend itself, so every API call vanished;
`/ingest/batch` now guarded by `allow_unsigned_batch`.

### Not merged to main

Everything lives on `feature/honeypot-ecosystem` and
`feature/intelligence-hub`. Merge is deliberately deferred.
