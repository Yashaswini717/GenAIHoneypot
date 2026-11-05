"""GET /alerts/ reports how many alerts match, not how many are on the page.

`total` used to be len(alerts) -- the page length -- so a client paging
through 129 alerts 50 at a time was told there were 50.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import alerts as alerts_api
from database.postgres import AlertStatus


def alert(n: int) -> SimpleNamespace:
    return SimpleNamespace(
        id=n, session_id=f"s{n}", src_ip="203.0.113.7", alert_type="persistence",
        description="authorized_keys modified", threat_score=85, mitre_technique="T1098",
        country=None, status=AlertStatus.open, created_at=datetime(2026, 11, 5, 10, 0, n),
    )


class FakeAlertDB:
    """Stands in for `AsyncSessionLocal`: the count answers `matching`, the page query `page`."""

    def __init__(self, matching: int, page: list) -> None:
        self.matching = matching
        self.page = page
        self.count = None
        self.query = None

    def __call__(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def scalar(self, statement):
        self.count = statement
        return self.matching

    async def execute(self, statement):
        self.query = statement
        page = self.page
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: page))


def get(monkeypatch, db: FakeAlertDB, url: str) -> dict:
    monkeypatch.setattr(alerts_api, "AsyncSessionLocal", db)
    app = FastAPI()
    app.include_router(alerts_api.router, prefix="/alerts")
    response = TestClient(app).get(url)
    assert response.status_code == 200, response.text
    return response.json()


def test_total_counts_every_matching_alert_not_the_page(monkeypatch):
    body = get(monkeypatch, FakeAlertDB(matching=129, page=[alert(1), alert(2)]), "/alerts/?limit=2")
    assert body["total"] == 129
    assert [a["id"] for a in body["alerts"]] == [1, 2]


def test_the_count_applies_the_status_filter_and_no_paging(monkeypatch):
    db = FakeAlertDB(matching=1, page=[alert(1)])
    get(monkeypatch, db, "/alerts/?status=acked&limit=1&offset=2")
    count_sql, page_sql = str(db.count), str(db.query)
    assert "count(" in count_sql.lower()
    assert "WHERE alerts.status" in count_sql and "WHERE alerts.status" in page_sql
    assert list(db.count.compile().params.values()) == [AlertStatus.acked]
    assert "LIMIT" not in count_sql and "OFFSET" not in count_sql


def test_without_a_status_the_count_covers_every_alert(monkeypatch):
    db = FakeAlertDB(matching=0, page=[])
    body = get(monkeypatch, db, "/alerts/")
    assert body == {"total": 0, "alerts": []}
    assert "WHERE" not in str(db.count)
