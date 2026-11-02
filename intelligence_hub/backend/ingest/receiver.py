import hmac
import json
import logging
from datetime import datetime
import redis.asyncio as aioredis

from fastapi import APIRouter, Request, HTTPException, status
from config import settings
from ingest.normalizer import (
    SOURCE_OPERATOR_UPLOAD,
    SOURCE_SENSOR,
    MalformedEvent,
    normalize,
    parse_event,
)
from ingest.signing import EVENT_ID_HEADER, Rejected, authenticate
from enrichment.geoip import enrich_geoip
from enrichment.mitre import enrich_mitre
from enrichment.scorer import ALERT_THRESHOLD, compute_threat_score
from database.elastic import index_event, upsert_ioc
from database.neo4j import write_session_graph
from database.postgres import AsyncSessionLocal, Session, Alert, AlertStatus
from sqlalchemy import select

router = APIRouter()
log = logging.getLogger("ingest")
_redis = None

#: Redis key recording an event id the sensor path has accepted. The value is
#: "processing" while the event is being stored, then "done".
_EVENT_KEY = "ingest:event:{}"


def get_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def report_ingest_posture() -> None:
    """Say at startup, loudly, which protections configuration has relaxed."""
    if settings.signatures_disabled:
        log.warning(
            "INSECURE_DEV_MODE with HMAC_SECRET=dev: /ingest/ is NOT verifying "
            "signatures. Anyone who can reach this hub can inject events."
        )
    elif settings.insecure_dev_mode:
        log.warning("INSECURE_DEV_MODE is set: the hub would start with a published HMAC secret.")
    if settings.allow_legacy_signatures:
        log.warning(
            "ALLOW_LEGACY_SIGNATURES is set (deprecated): body-only signatures are "
            "accepted, and those carry no timestamp to stop a late replay."
        )
    if settings.allow_unsigned_batch:
        log.warning(
            "ALLOW_UNSIGNED_BATCH is set (deprecated): /ingest/batch accepts uploads "
            "without the operator token."
        )
    elif not settings.operator_token:
        log.info("OPERATOR_TOKEN is not set: operator uploads to /ingest/batch are disabled.")


# --------------------------------------------------------------------------
# accepting each sensor event once
# --------------------------------------------------------------------------
#
# The signature proves a request came from a sidecar and is recent; this
# proves it is the first time. A claim is taken before the event is stored,
# so two copies arriving together cannot both be stored, and is withdrawn if
# storing fails, so the sidecar's retry is not refused for an event the hub
# never kept.


async def _claim(event_id: str) -> None:
    key = _EVENT_KEY.format(event_id)
    try:
        r = get_redis()
        # The "processing" claim lives for two clock windows -- as long as
        # any copy of this request can still carry an acceptable timestamp --
        # so replay protection holds even if marking it done fails later.
        claimed = await r.set(key, "processing", nx=True, ex=2 * settings.ingest_clock_skew_seconds)
        state = None if claimed else await r.get(key)
    except Exception as exc:
        # Fail closed. Without the record, a replay cannot be told apart from
        # a first delivery, and the sidecar will simply retry a 503.
        log.error("replay protection unavailable: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Replay protection is unavailable (Redis); retry later",
        ) from exc
    if claimed:
        return
    if state == "done":
        # The sidecar treats this as delivered: an earlier attempt landed.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event {event_id} has already been ingested",
        )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=f"Event {event_id} is being ingested by another request; retry later",
        headers={"Retry-After": "5"},
    )


async def _mark_done(event_id: str) -> None:
    try:
        await get_redis().set(_EVENT_KEY.format(event_id), "done", ex=settings.dedup_ttl_seconds)
    except Exception as exc:
        # The event is stored; failing the request now would only get it
        # stored twice. The "processing" claim still covers the replay window.
        log.error("could not mark event %s as ingested: %s", event_id, exc)


async def _release(event_id: str) -> None:
    try:
        await get_redis().delete(_EVENT_KEY.format(event_id))
    except Exception as exc:
        log.warning("could not release claim on event %s, it expires by itself: %s", event_id, exc)


def _authenticate(request: Request, body: bytes) -> str | None:
    """The event id to deduplicate on, or HTTPException."""
    if settings.signatures_disabled:
        # Development only, and announced at startup. Still deduplicates when
        # a sidecar supplies an id, so its retries behave as they will live.
        return request.headers.get(EVENT_ID_HEADER) or None
    try:
        return authenticate(
            request.headers,
            body,
            secret=settings.hmac_secret,
            clock_skew=settings.ingest_clock_skew_seconds,
            allow_legacy=settings.allow_legacy_signatures,
        )
    except Rejected as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from None


def _authorize_operator(request: Request) -> None:
    """Only an operator holding the token may upload events by hand."""
    if settings.allow_unsigned_batch:
        return  # deprecated escape hatch, announced at startup
    if not settings.operator_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Operator uploads are disabled: set OPERATOR_TOKEN on the hub to "
                "enable them. Sensors stream signed events to POST /ingest/ instead."
            ),
        )
    scheme, _, supplied = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        supplied.strip().encode(), settings.operator_token.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid operator token is required (Authorization: Bearer <token>)",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def process_event(raw: dict, source: str = SOURCE_SENSOR):
    """Full pipeline: normalize → enrich → score → store → publish."""

    # 1. Normalize. Anything wrong with the event itself surfaces here, as
    #    MalformedEvent, before a single store has been touched.
    normalized = normalize(raw, source)
    event = normalized.model_dump()

    # 2. Enrich
    event = enrich_geoip(event)
    event = enrich_mitre(event)
    event = compute_threat_score(event)

    # Serialise the timestamp only once scoring has run. This used to happen
    # immediately after model_dump(), which left compute_threat_score comparing
    # a str where it expected a datetime — so its off-hours branch was
    # unreachable and the boost silently never applied. Elasticsearch and Redis
    # are the only consumers that need a string, and both come after here.
    event["timestamp"] = normalized.timestamp.isoformat()

    # 3. Store in Elasticsearch
    await index_event(event)

    # 4. Upsert IOCs
    await upsert_ioc("ip", event["src_ip"], event)
    if event.get("hassh"):
        await upsert_ioc("hassh", event["hassh"], event)
    if event.get("username"):
        await upsert_ioc("username", event["username"], event)

    # 5. Write to Neo4j graph
    await write_session_graph(event)

    # 6. Upsert session in Postgres
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Session).where(Session.session_id == event["session_id"])
        )
        sess = result.scalar_one_or_none()
        if not sess:
            sess = Session(
                session_id  = event["session_id"],
                src_ip      = event["src_ip"],
                attacker_id = event.get("attacker_id") or event["src_ip"],
                adaptive    = event.get("adaptive"),
                sensor_id   = event["sensor_id"],
                protocol    = event.get("protocol", "ssh"),
                started_at  = normalized.timestamp.replace(tzinfo=None),
                hassh       = event.get("hassh"),
                ssh_version = event.get("ssh_version"),
                country     = event.get("country"),
                city        = event.get("city"),
                threat_score = event.get("threat_score", 0),
                # Fixed when the row is created. Upload session ids are
                # prefixed, so an upload never lands on a sensor's row.
                source      = event["source"],
            )
            db.add(sess)
        else:
            sess.event_count  += 1
            sess.threat_score  = max(sess.threat_score or 0, event.get("threat_score", 0))
            if event.get("event_type") == "brute_force":
                sess.login_attempts = (sess.login_attempts or 0) + 1
            if event.get("event_type") == "session_end" and event.get("duration"):
                sess.ended_at = normalized.timestamp.replace(tzinfo=None)
                sess.duration = event.get("duration")
            if event.get("hassh") and not sess.hassh:
                sess.hassh = event["hassh"]
            # A pivot's session.connect is emitted before the broker has
            # resolved who owns the environment, so that first event carries
            # the fallback (attacker_id == src_ip, which on a pivot is our own
            # jump host). Every later event in the session carries the real
            # owner.
            #
            # So a value that differs from src_ip is authoritative and must
            # overwrite: refusing to correct an already-set field left every
            # pivot session attributed to an internal address, which is the
            # precise failure this column exists to prevent.
            incoming = event.get("attacker_id")
            if incoming and incoming != event["src_ip"]:
                sess.attacker_id = incoming
            elif incoming and not sess.attacker_id:
                sess.attacker_id = incoming
            if sess.adaptive is None and event.get("adaptive") is not None:
                sess.adaptive = event["adaptive"]
            if event.get("country") and not sess.country:
                sess.country = event["country"]

        # 7. Alert on a high threat score, once per session and kind of
        #    threat. A bot that runs the same download ten times has done one
        #    thing an analyst needs to look at, so later events of the same
        #    kind raise the open alert's score instead of adding rows.
        score = event.get("threat_score", 0)
        if score >= ALERT_THRESHOLD:
            alert_type = event.get("command_category") or event.get("event_type", "unknown")
            result = await db.execute(
                select(Alert).where(
                    Alert.session_id == event["session_id"],
                    Alert.alert_type == alert_type,
                    Alert.status == AlertStatus.open,
                ).limit(1)
            )
            alert = result.scalar_one_or_none()
            if alert is None:
                db.add(Alert(
                    session_id      = event["session_id"],
                    src_ip          = event["src_ip"],
                    alert_type      = alert_type,
                    description     = event.get("raw_message", ""),
                    threat_score    = score,
                    mitre_technique = event.get("mitre_technique"),
                    country         = event.get("country"),
                    status          = AlertStatus.open,
                ))
            elif score > (alert.threat_score or 0):
                alert.threat_score = score
                alert.description  = event.get("raw_message", "")
                alert.updated_at   = datetime.utcnow()

        await db.commit()

    # 8. Publish to Redis for WebSocket live feed. Best effort: the event is
    #    stored by now, and failing the request here would only make the
    #    sidecar send it again.
    try:
        r = get_redis()
        await r.publish("events:live", json.dumps(event, default=str))
    except Exception as exc:
        log.warning("live feed publish failed for %s: %s", event["session_id"], exc)

    return event


@router.post("/")
async def ingest_log(request: Request):
    """One sensor event (Cowrie JSON), signed by a honeypot sidecar.

    The signature covers X-Timestamp and X-Event-Id as well as the body (see
    ingest/signing.py), and each event id is accepted once:

        200  ingested
        400  unparseable body, or malformed X-Timestamp / X-Event-Id
        401  missing or invalid signature, or a timestamp outside the window
        409  this event id was already ingested -- the sender may drop it
        422  valid JSON, but not a valid event
        503  replay protection unavailable, or the same event is mid-ingest

    A 4xx says the request itself is wrong and resending it will not help; a
    5xx says try again.
    """
    body = await request.body()
    event_id = _authenticate(request, body)

    try:
        raw = parse_event(body)
    except MalformedEvent as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None

    if event_id:
        await _claim(event_id)
    try:
        event = await process_event(raw, source=SOURCE_SENSOR)
    except MalformedEvent as exc:
        if event_id:
            await _release(event_id)
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None
    except BaseException:
        if event_id:
            await _release(event_id)
        raise
    if event_id:
        await _mark_done(event_id)
    return {"status": "ok", "threat_score": event.get("threat_score"), "session": event.get("session_id")}


@router.post("/batch")
async def ingest_batch(request: Request):
    """Operator upload path: multiple Cowrie log lines as NDJSON.

    This exists for the dashboard's Ingest Logs page, which lets an analyst
    upload a Cowrie JSONL file by hand. A browser cannot hold the signing
    secret, so instead of a signature this path requires the operator token
    (`Authorization: Bearer <OPERATOR_TOKEN>`), and it is disabled until one
    is configured.

    What arrives here is whatever file the operator chose, not something a
    sensor recorded, so every event is tagged `source=operator_upload` and
    its session id prefixed with `upload-`. The retention figures leave those
    sessions out, and an upload can never merge into a live session.

    Honeypot sensors do NOT use this path. Sidecars stream single signed
    events to /ingest/.
    """
    _authorize_operator(request)

    body = await request.body()
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploads must be UTF-8 NDJSON",
        ) from None
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    results = []
    for line in lines:
        try:
            raw = parse_event(line)
            event = await process_event(raw, source=SOURCE_OPERATOR_UPLOAD)
            results.append({"session": event.get("session_id"), "score": event.get("threat_score")})
        except Exception as e:
            results.append({"error": str(e)})
    return {"processed": len(results), "source": SOURCE_OPERATOR_UPLOAD, "results": results}
