# Intelligence Hub

Receives events from the honeypot sensors, enriches and scores them, and
stores them in Elasticsearch, Neo4j and Postgres for the dashboard. Setup
for running it next to the honeypot is in `honeypot-ecosystem/README.md`.
This file documents the ingest contract, which the zero-trust claim rests on.

## Two ingest paths, two trust models

| Path | Used by | Authenticated by | Counts as attacker activity |
|---|---|---|---|
| `POST /ingest/` | honeypot sidecars, one event per request | HMAC signature over a timestamp, an event id and the body | yes |
| `POST /ingest/batch` | an operator, through the dashboard's Ingest Logs page | `Authorization: Bearer <OPERATOR_TOKEN>` | no |

### The sensor path: `POST /ingest/`

The sidecar (`honeypot-ecosystem/shared/sidecar/shipper.py`) is the only
process holding `HMAC_SECRET`. Each request carries:

| Header | Value |
|---|---|
| `X-Timestamp` | when this attempt was signed, in whole Unix seconds |
| `X-Event-Id` | the event's id, 16–128 characters of `A-Z a-z 0-9 _ -`. The sidecar uses the first 32 hex digits of the body's SHA-256, so every retry of an event carries the same id |
| `X-Signature` | hex HMAC-SHA256 over `b"<timestamp>.<event id>." + body` |

The hub (`backend/ingest/signing.py`) refuses a request whose signature does
not match, or whose timestamp is more than `INGEST_CLOCK_SKEW_SECONDS` from
its own clock. It then records the event id in Redis and refuses any later
request with the same id. Together, these mean a captured request cannot be
replayed: inside the clock window its id has already been recorded, and
outside it the timestamp is refused. The same record makes the sidecar's
at-least-once retries idempotent, because an event whose response was lost
is answered 409 when it is resent.

| Status | Meaning | The sidecar |
|---|---|---|
| 200 | ingested | done |
| 409 | that event id was already ingested | treats it as delivered |
| 400 | unparseable body, or malformed `X-Timestamp` / `X-Event-Id` | dead-letters it |
| 422 | valid JSON, but not a valid event (e.g. no timestamp) | dead-letters it |
| 401 | bad signature, or a timestamp outside the window | retries: a wrong secret or clock affects every event |
| 503 | Redis unavailable (the hub fails closed), or the same event is mid-ingest | retries |
| 500 | storing failed | retries |

### The operator path: `POST /ingest/batch`

A browser cannot hold the signing secret, so uploads take the operator token
instead. The path stays disabled until `OPERATOR_TOKEN` is set. The Ingest
Logs page asks for the token, keeps it only in memory, and posts through the
Vite proxy (`/api/ingest/batch`).

An upload is whatever file the operator chose, not something a sensor
recorded. So every uploaded event is tagged `source=operator_upload`, and
its session id is prefixed with `upload-`. The retention figures leave those
sessions out (and report how many they left out), and an upload never merges
into a live session that has the same id.

## Settings

All are environment variables, or entries in `intelligence_hub/.env`.

| Variable | Default | |
|---|---|---|
| `HMAC_SECRET` | required | Must match `honeypot-ecosystem/.env`. The hub refuses to start with a published one (`dev`, `change-me`). |
| `INSECURE_DEV_MODE` | `false` | Allows a published secret, for local development only. With `HMAC_SECRET=dev` it also turns signature checks off, which is announced at startup. |
| `INGEST_CLOCK_SKEW_SECONDS` | `300` | How far a sensor request's timestamp may be from the hub's clock. |
| `INGEST_DEDUP_TTL_SECONDS` | `86400` | How long accepted event ids are remembered. Never less than twice the clock window. |
| `OPERATOR_TOKEN` | unset | Enables `/ingest/batch`. At least 16 characters. |
| `ALLOW_UNSIGNED_BATCH` | `false` | **Deprecated, removed next release.** Accepts uploads with no token, which used to be the default. |
| `ALLOW_LEGACY_SIGNATURES` | `false` | **Deprecated, removed next release.** Accepts body-only signatures from old sidecars during an upgrade. They carry no timestamp, so a captured one can be replayed once its id has expired. |

## Upgrading from body-only signatures

Upgrade the hub and the sidecar together. If one side runs ahead, its
counterpart gets 401s and the sidecar holds the events in its spool. Old
sidecars already retried every failure, and new ones retry 401s. The held
events are delivered once both sides match. To upgrade the hub first and keep
events flowing from an old sidecar meanwhile, set
`ALLOW_LEGACY_SIGNATURES=true` until the sidecar is rebuilt.

## Tests

```bash
python -m pytest tests/ -q
```

Redis and the stores are faked, so no services are needed.
`tests/test_ingest_contract.py` runs the real sidecar against the real
receiver, and it is skipped if `honeypot-ecosystem/` is not checked out
alongside the hub.
