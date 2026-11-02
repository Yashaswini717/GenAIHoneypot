"""In-memory stand-ins for the hub's stores, for the ingest tests.

Each fake implements only what `ingest.receiver` calls. They are deliberately
dumb: the tests are about what the receiver decides to store and refuse, not
about Redis, Postgres or Elasticsearch.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest
import redis.exceptions
from fastapi import FastAPI

from config import settings
from ingest import receiver
from ingest.signing import content_event_id, sign

#: A legitimate sensor event, as the SSH proxy writes it.
EVENT = {
    "eventid": "cowrie.command.input",
    "session": "a1b2c3d4e5f6",
    "src_ip": "203.0.113.7",
    "src_port": 51234,
    "dst_ip": "10.20.0.5",
    "dst_port": 22,
    "sensor": "node-01-jump",
    "attacker": "203.0.113.7",
    "adaptive": True,
    "timestamp": "2026-11-01T10:00:00.000000Z",
    "input": "uname -a",
    "message": "CMD: uname -a",
}

#: Pass as a field's value to leave the field out of the event.
DROP = object()


def event_body(**changes) -> bytes:
    event = {**EVENT, **changes}
    return json.dumps({k: v for k, v in event.items() if v is not DROP}).encode()


def signed(body: bytes, *, ts: float | None = None, event_id: str | None = None,
           secret: str | None = None) -> dict[str, str]:
    """Headers exactly as a sidecar sends them."""
    timestamp = str(int(time.time() if ts is None else ts))
    event_id = event_id or content_event_id(body)
    return {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Event-Id": event_id,
        "X-Signature": sign(secret or settings.hmac_secret, timestamp, event_id, body),
    }


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}
        self.published: list[tuple[str, str]] = []
        self.down = False

    def _check(self) -> None:
        if self.down:
            raise redis.exceptions.ConnectionError("Redis is down")

    async def set(self, key, value, nx=False, ex=None):
        self._check()
        if nx and key in self.values:
            return None
        self.values[key] = value
        self.ttls[key] = ex
        return True

    async def get(self, key):
        self._check()
        return self.values.get(key)

    async def delete(self, *keys):
        self._check()
        return sum(1 for key in keys if self.values.pop(key, None) is not None)

    async def publish(self, channel, message):
        self._check()
        self.published.append((channel, message))
        return 1


class _Result:
    def __init__(self, value) -> None:
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class FakeDB:
    """Stands in for `AsyncSessionLocal`: calling it opens a 'session'."""

    def __init__(self) -> None:
        self.sessions: dict[str, receiver.Session] = {}
        self.alerts: list = []

    def __call__(self):
        return _FakeDBSession(self)


class _FakeDBSession:
    def __init__(self, db: FakeDB) -> None:
        self.db = db

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, statement):
        # The receiver's queries: a Session by session_id, or the open
        # Alert for a session and alert type.
        params = statement.compile().params
        if statement.column_descriptions[0]["entity"] is receiver.Alert:
            wanted = {name.rsplit("_", 1)[0]: value for name, value in params.items()}
            for alert in self.db.alerts:
                if (alert.session_id, alert.alert_type, alert.status) == (
                        wanted["session_id"], wanted["alert_type"], wanted["status"]):
                    return _Result(alert)
            return _Result(None)
        (session_id,) = params.values()
        return _Result(self.db.sessions.get(session_id))

    def add(self, obj) -> None:
        if isinstance(obj, receiver.Session):
            # Column defaults are applied by the database on INSERT.
            obj.event_count = obj.event_count or 0
            obj.login_attempts = obj.login_attempts or 0
            self.db.sessions[obj.session_id] = obj
        else:
            self.db.alerts.append(obj)

    async def commit(self) -> None:
        pass


@pytest.fixture
def stores(monkeypatch):
    """The receiver wired to fakes, plus an app serving only /ingest."""
    fakes = SimpleNamespace(redis=FakeRedis(), db=FakeDB(), indexed=[], fail_next_index=False)

    async def index_event(event):
        if fakes.fail_next_index:
            fakes.fail_next_index = False
            raise RuntimeError("Elasticsearch unavailable")
        fakes.indexed.append(dict(event))

    async def nothing(*args, **kwargs):
        return None

    monkeypatch.setattr(receiver, "_redis", fakes.redis)
    monkeypatch.setattr(receiver, "index_event", index_event)
    monkeypatch.setattr(receiver, "upsert_ioc", nothing)
    monkeypatch.setattr(receiver, "write_session_graph", nothing)
    monkeypatch.setattr(receiver, "AsyncSessionLocal", fakes.db)

    app = FastAPI()
    app.include_router(receiver.router, prefix="/ingest")
    fakes.app = app
    return fakes
