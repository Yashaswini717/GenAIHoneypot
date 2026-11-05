# GenAI Honeypot Ecosystem with Adaptive Synthetic Decoys and Zero-Trust Sharing

An SSH honeypot that works out what each attacker is trying to do, and changes what they
find while they are still connected. Every two commands, an intent classifier names the
attack stage, a learning bandit picks a decoy for it, an LLM writes the decoy files, and they
land inside that attacker's own isolated machines. Every event also goes to a separate
intelligence hub, which accepts it only if it is signed, fresh and new.

## How it works

```
attacker ──ssh──▶ SSH proxy (gw-01) ──their shell──▶ their own machines
                         │                            jump-01, erp-web, db-01
                         │ events                                 ▲
                         ▼                                        │ decoys
                      sidecar ──────── files to plant ──────▶ session broker
                 (holds the HMAC key)
                         │
           ┌─────────────┴──────────────┐
           ▼                            ▼
   intelligence hub                 AI brain
   signed events only               intent → decoy choice → LLM files
```

1. **SSH proxy** (`honeypot-ecosystem/shared/ssh-proxy`, container `gw-01`). The attacker
   logs in here. It records every keystroke on the wire, so nothing inside the attacker's
   machine can find or stop the recording. It writes events to a file that only the sidecar
   reads.
2. **Session broker** (`honeypot-ecosystem/shared/session-broker`). Starts each attacker's own
   machines: `jump-01` at login, and `erp-web` and `db-01` only when they pivot. Each attacker
   gets private networks with no route to the internet, and their machines are kept for
   return visits.
3. **Sidecar** (`honeypot-ecosystem/shared/sidecar`). The only honeypot component that holds
   the HMAC key. It signs every event for the hub. Every two commands, it sends the last three
   to the brain, and plants whatever the brain chooses through the broker. Its tripwire
   catches a planted credential being used.
4. **AI brain** (`ai-brain/content-generator`).
   - An intent classifier names one of five stages: reconnaissance, privilege escalation,
     persistence, lateral movement or data exfiltration. Rules decide first; otherwise a
     gradient-boosted model, which also knows the previous stage, decides.
   - A Thompson-sampling bandit picks one of 15 decoy actions for that stage. It learns from
     what the attacker does next: honeytoken used 1.0, escalated 0.7, continued 0.4,
     de-escalated 0.2, left 0.0.
   - An LLM writes richer decoy files for the chosen action. Any OpenAI-compatible provider
     works.
5. **Intelligence hub** (`intelligence_hub`). Accepts an event only if its HMAC-SHA256
   signature checks out, its timestamp is within five minutes, and its event id is new. It then
   enriches, scores and stores it in Elasticsearch, Postgres and Neo4j. A React dashboard shows
   a live feed, alerts, sessions and an attack map.

Template decoys land within a second of a decision, and LLM-written ones one to five minutes
later. Without an LLM key everything still runs, using the template decoys alone.

## Results

Measured on this system in November 2026.

| Result | Value | Caveat |
|---|---|---|
| Intent accuracy on real attack traffic | 0.768 (95% CI 0.73–0.80); 0.815 weighted by traffic | 30 real SSH sessions (509 windows) from the public CyberLab honeynet data. Labelled by the team, so not a blind test |
| Intent accuracy on the synthetic test set | 0.961 (220 of 229 windows) | Includes earlier test sets whose misses shaped the rules: a coverage check, not proof of generalisation |
| The classifier before this term's rework | 0.481 dev, 0.522 test | On the evaluation sets of 1 November |
| Time for a decoy to land | Templates: within 1 s. LLM files: 1–5 min | Mistral's free `ministral-8b-latest` |
| Automated tests | Honeypot 202, brain 237, hub 121 passing | Two brain tests fail on Windows only, because they check Unix file permissions |

Accuracy is scored on windows of three commands, as the sidecar sends them. To print the
tables, run `python -m ml.intent_classification.evaluation` from `ai-brain/content-generator`.

## What is where

| Path | What it holds |
|---|---|
| `honeypot-ecosystem/` | SSH proxy, session broker, sidecar and the three node images. [Its README](honeypot-ecosystem/README.md) has the setup, design notes and troubleshooting |
| `ai-brain/content-generator/` | The FastAPI brain: intent classification (`ml/intent_classification/`), the adaptive engine (`core/`) and LLM decoy generation (`populator/`) |
| `intelligence_hub/` | FastAPI backend and React dashboard. [Its README](intelligence_hub/README.md) documents the signed ingest contract |
| `deploy/` | Deployment to one AWS server, with attacker machines under gVisor and the hub kept private |

## Run it locally

You need Docker Desktop, Python 3.11+ and about 6 GB of free memory. From `honeypot-ecosystem/`:

```bash
python -m pip install -r requirements.txt
docker network create honeypot-telemetry   # once per machine
python tools/bootstrap.py                  # keys, logins, and a .env with a fresh HMAC_SECRET
python tools/build_nodes.py                # the three node images; several minutes the first time
docker compose up -d
```

Next, create `intelligence_hub/.env`. Copy `HMAC_SECRET` exactly from `honeypot-ecosystem/.env`;
the honeypot README lists the other settings under
["Running the intelligence hub"](honeypot-ecosystem/README.md#running-the-intelligence-hub).
Then start the hub:

```bash
cd ../intelligence_hub && docker compose up -d
```

| Service | Address |
|---|---|
| Dashboard | http://localhost:5173 |
| Hub API | http://localhost:8000 |
| Honeypot SSH | `localhost:2222` |

The LLM is optional. To turn it on, set `OPENAI_API_KEY` in `honeypot-ecosystem/.env`. For a
provider other than OpenRouter, also set `OPENAI_BASE_URL` and `LLM_MODEL`; `.env.example`
lists three tested free providers. Then run `docker compose up -d ai-brain` in
`honeypot-ecosystem/`.

## Tests

Each module pins its own versions, so give each one its own virtual environment. Install the
following, then run `python -m pytest tests/ -q` from the module's folder:

| Module | Install |
|---|---|
| `honeypot-ecosystem/` | `requirements.txt` and `httpx==0.27.0` |
| `ai-brain/content-generator/` | `requirements.txt` |
| `intelligence_hub/` | `backend/requirements.txt`, `pytest==8.2.0` and `pytest-asyncio==0.23.7` |

## Known limits

- **Windows with no evidence.** A bot's cleanup or upload (`rm -f`, `scp -t`) says nothing
  about its stage, so the model has to guess. These windows are most of the real-traffic
  misses.
- **No blind test yet.** The team labelled the real-traffic set itself. The next set should
  come from the honeypot's own captures, labelled by someone who has not seen the rules.
- **No adaptive-versus-static result yet.** The experiment is built in:
  `EXPERIMENT_CONTROL_RATIO` holds back 15% of attackers, who get only the fixed decoys. But it
  needs live traffic.
- **Not on the internet yet.** The AWS deployment is prepared on a server but not exposed.

The honeypot README lists more under ["Not done yet"](honeypot-ecosystem/README.md#not-done-yet).

## Deployment

[`deploy/aws/README.md`](deploy/aws/README.md) walks through one EC2 server:
- the honeypot on port 22;
- the hub reachable only through an SSH tunnel;
- attacker machines under gVisor.

`deploy/server-setup.sh` runs `prepare`, `go-live`, `check` and `stop`. Its example instance
type and region may not be allowed on a free-plan AWS account.

## Data

The real-traffic evaluation set comes from the CyberLab honeynet dataset
([doi:10.5281/zenodo.3687527](https://doi.org/10.5281/zenodo.3687527)), licensed CC BY 4.0.
Public addresses, domains, keys and payloads are scrubbed on import.
