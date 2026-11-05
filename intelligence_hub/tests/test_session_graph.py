"""A session's start in the graph is its first event, not its latest.

`write_session_graph` runs for every event. Its Session MERGE used a plain SET
for `started_at`, so each event moved the session's start to its own time.
"""

from __future__ import annotations

import asyncio
import re

from database import neo4j as graph

EVENT = {
    "src_ip": "203.0.113.7",
    "session_id": "a1b2c3d4e5f6",
    "timestamp": "2026-11-05T11:16:52.846924+00:00",
    "protocol": "ssh",
}


class FakeGraphSession:
    def __init__(self, queries: list) -> None:
        self.queries = queries

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def run(self, query, params=None):
        self.queries.append((query, params or {}))


class FakeDriver:
    def __init__(self) -> None:
        self.queries: list = []

    def session(self):
        return FakeGraphSession(self.queries)


def session_merge(monkeypatch) -> str:
    driver = FakeDriver()
    monkeypatch.setattr(graph, "driver", driver)
    asyncio.run(graph.write_session_graph(dict(EVENT)))
    (query,) = [q for q, _ in driver.queries if "MERGE (s:Session" in q]
    return query


def test_started_at_is_set_only_when_the_session_is_created(monkeypatch):
    query = session_merge(monkeypatch)
    assert "ON CREATE SET s.started_at = $timestamp" in query
    assert query.count("started_at") == 1, query


def test_the_other_session_fields_still_follow_every_event(monkeypatch):
    query = session_merge(monkeypatch)
    assert re.search(r"\n\s*SET s\.protocol\s*= \$protocol", query), query
    assert re.search(r"s\.src_ip\s*= \$src_ip", query), query
