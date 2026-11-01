"""The real sidecar against the real hub receiver, end to end.

`test_ingest.py` and the sidecar's own tests each pin the signing scheme to a
shared vector. This goes further: it runs the shipper from
`honeypot-ecosystem/shared/sidecar` against this hub's `/ingest/` router over
an in-process transport, so a disagreement anywhere in between -- header
names, what is signed, how a 409 or a 422 is read -- fails here.

Skipped when the sidecar is not checked out next to the hub.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path

import httpx
import pytest

from config import settings
from hubfakes import DROP, event_body, stores  # noqa: F401  (stores is a fixture)

SIDECAR = Path(__file__).resolve().parents[2] / "honeypot-ecosystem" / "shared" / "sidecar"

pytestmark = pytest.mark.skipif(
    not (SIDECAR / "shipper.py").exists(), reason="sidecar not checked out alongside the hub"
)


@pytest.fixture
def sidecar(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(SIDECAR))
    shipper = importlib.import_module("shipper")
    monkeypatch.setattr(shipper, "config", shipper.ShipperConfig(
        hub_url="http://hub",
        hmac_secret=settings.hmac_secret,
        event_path=tmp_path / "events.ndjson",
        state_path=tmp_path / "state" / "offset.json",
        spool_dir=tmp_path / "pending",
        dead_letter_dir=tmp_path / "dead-letter",
        brain_enabled=False,
    ))
    yield shipper
    sys.modules.pop("shipper", None)


def test_the_sidecar_and_the_hub_agree(stores, sidecar):
    good = event_body()
    malformed = event_body(timestamp=DROP)
    later = event_body(input="cat /etc/passwd", timestamp="2026-11-01T10:00:05.000000Z")

    async def run():
        shipper = sidecar.Shipper()
        shipper.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=stores.app))
        try:
            first = await shipper.deliver(good)
            assert first.outcome is sidecar.Outcome.DELIVERED

            # The response to `good` was "lost", so it sits in the spool too,
            # alongside an event the hub will refuse and one it has not seen.
            for body in (good, malformed, later):
                shipper.spool.add(body)
            await shipper.drain_spool()
            return shipper
        finally:
            await shipper.close()

    shipper = asyncio.run(run())

    assert shipper.delivered == 2       # good, then later
    assert shipper.duplicates == 1      # good again: 409, dropped as delivered
    assert shipper.dead_lettered == 1   # malformed: 422, set aside
    assert shipper.spool.pending() == []  # nothing left blocking the spool
    assert len(shipper.dead.pending()) == 1
    assert [e["command"] for e in stores.indexed] == ["uname -a", "cat /etc/passwd"]
