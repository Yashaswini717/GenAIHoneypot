"""The decoy stock: model-written decoys made ahead of time, each served once.

Why: on the cloud honeypot the logged-in bots stayed 6 to 67 seconds, and a
model-written profile takes minutes, so decoys generated on demand reached
nobody. These tests pin what keeps a stock from turning into static decoys:
every set is single use, no file content is ever served twice, and credentials
are never stocked.
"""

from __future__ import annotations

import asyncio
import itertools
import json

import pytest

from populator.strategies import STOCK_CONTEXTS, content_key
from storage.decoy_stock import DecoyStock, StockFiller


def _set(tag: str) -> list[dict]:
    return [
        {"path": "app/main.py", "content": f"main {tag}\n", "permissions": 0o644},
        {"path": "nginx.conf", "content": f"nginx {tag}\n", "permissions": 0o644},
    ]


def test_an_empty_stock_gives_nothing(temp_dir):
    assert DecoyStock(temp_dir).take("web_server") is None


def test_a_set_is_served_once_and_then_gone(temp_dir):
    stock = DecoyStock(temp_dir)
    stock.put("web_server", _set("a"))

    first = stock.take("web_server")
    assert [f["content"] for f in first["files"]] == ["main a\n", "nginx a\n"]
    assert stock.take("web_server") is None, "a set must never be handed out twice"
    assert list((temp_dir / "web_server").iterdir()) == [], "nothing of it is left behind"


def test_two_sets_go_to_two_attackers(temp_dir):
    stock = DecoyStock(temp_dir)
    stock.put("web_server", _set("a"))
    stock.put("web_server", _set("b"))

    one, two = stock.take("web_server"), stock.take("web_server")
    assert {f["content"] for f in one["files"]}.isdisjoint(f["content"] for f in two["files"])
    assert stock.take("web_server") is None


def test_another_worker_cannot_take_the_same_set(temp_dir):
    """The brain runs several worker processes over one stock directory."""
    worker_a, worker_b = DecoyStock(temp_dir), DecoyStock(temp_dir)
    worker_a.put("web_server", _set("a"))

    assert worker_a.take("web_server") is not None
    assert worker_b.take("web_server") is None


def test_a_file_served_before_is_never_served_again(temp_dir):
    """A model asked the same thing twice can answer the same way twice."""
    stock = DecoyStock(temp_dir)
    stock.record_served([{"path": "nginx.conf", "content": "nginx a\n"}])  # someone already got this
    stock.put("web_server", _set("a"))

    taken = stock.take("web_server")
    assert [f["content"] for f in taken["files"]] == ["main a\n"]


def test_a_set_made_only_of_repeats_is_skipped(temp_dir):
    stock = DecoyStock(temp_dir)
    stock.put("web_server", _set("a"))
    stock.take("web_server")
    stock.put("web_server", _set("a"))  # the model said exactly the same again
    stock.put("web_server", _set("b"))

    taken = stock.take("web_server")
    assert [f["content"] for f in taken["files"]] == ["main b\n", "nginx b\n"]
    assert stock.take("web_server") is None


def test_the_stock_and_what_was_served_survive_a_restart(temp_dir):
    DecoyStock(temp_dir).put("web_server", _set("a"))
    DecoyStock(temp_dir).put("web_server", _set("b"))
    first = DecoyStock(temp_dir).take("web_server")

    restarted = DecoyStock(temp_dir)
    second = restarted.take("web_server")
    assert first["files"] != second["files"]
    restarted.put("web_server", first["files"])  # e.g. a model repeating an old answer
    assert restarted.take("web_server") is None


def test_empty_content_is_not_stocked(temp_dir):
    stock = DecoyStock(temp_dir)
    assert stock.put("web_server", [{"path": "x", "content": ""}]) is None
    assert stock.count("web_server") == 0


def test_the_most_needed_key_is_filled_first(temp_dir):
    stock = DecoyStock(temp_dir, per_key=2)
    stock.put("web_server", _set("a"))
    stock.put("web_server", _set("b"))
    stock.put("database_server", _set("c"))

    assert stock.most_needed(["web_server", "database_server", "developer_minimal"]) == "developer_minimal"
    stock.put("developer_minimal", _set("d"))
    stock.put("developer_minimal", _set("e"))
    assert stock.most_needed(["web_server", "database_server", "developer_minimal"]) == "database_server"
    stock.put("database_server", _set("f"))
    assert stock.most_needed(["web_server", "database_server", "developer_minimal"]) is None


def test_a_key_cannot_reach_outside_the_stock(temp_dir):
    stock = DecoyStock(temp_dir)
    for bad in ("../etc", "a/b", ".hidden", ""):
        with pytest.raises(ValueError):
            stock.put(bad, _set("x"))


def test_no_credential_is_ever_written_to_stock(temp_dir):
    """Stock is made by build_content, which never mints a honeytoken."""
    stock = DecoyStock(temp_dir)
    stock.put("developer_workstation", _set("a"))
    item = next((temp_dir / "developer_workstation").glob("*.json"))
    assert set(json.loads(item.read_text())) == {"key", "made", "files", "failures"}


def test_every_action_maps_to_a_stocked_key():
    from core.adaptive_actions import ACTION_TO_PROFILE

    for action, profile in ACTION_TO_PROFILE.items():
        assert content_key(profile, action) in STOCK_CONTEXTS, action


# --------------------------------------------------------------------------
# the filler
# --------------------------------------------------------------------------


def _maker(counter=None):
    counter = counter if counter is not None else itertools.count()

    async def make(context):
        n = next(counter)
        return [{"path": "f.txt", "content": f"{context['action']} {n}\n", "permissions": 0o644}], []

    return make


def test_the_filler_fills_every_key_to_its_target(temp_dir):
    stock = DecoyStock(temp_dir, per_key=2)
    filler = StockFiller(stock, STOCK_CONTEXTS, _maker())

    async def run():
        while await filler.fill_once():
            pass

    asyncio.run(run())
    assert {key: stock.count(key) for key in STOCK_CONTEXTS} == {key: 2 for key in STOCK_CONTEXTS}


def test_the_filler_replaces_what_was_taken(temp_dir):
    stock = DecoyStock(temp_dir, per_key=1)
    filler = StockFiller(stock, {"web_server": STOCK_CONTEXTS["web_server"]}, _maker())

    async def run():
        await filler.fill_once()
        stock.take("web_server")
        assert await filler.fill_once() is True
        assert await filler.fill_once() is False

    asyncio.run(run())
    assert stock.count("web_server") == 1


def test_a_failing_model_stores_nothing_and_backs_off(temp_dir):
    stock = DecoyStock(temp_dir, per_key=1)

    async def failing(context):
        return [], ["config/nginx", "source/webapp"]

    filler = StockFiller(stock, {"web_server": STOCK_CONTEXTS["web_server"]}, failing)

    async def run():
        assert await filler.fill_once() is True
        assert filler._last_ok is False

    asyncio.run(run())
    assert stock.count("web_server") == 0


def test_the_running_filler_stops_when_the_stock_is_full(temp_dir):
    stock = DecoyStock(temp_dir, per_key=1)
    calls = itertools.count()
    filler = StockFiller(stock, STOCK_CONTEXTS, _maker(calls), poll_seconds=0.01)

    async def run():
        task = asyncio.create_task(filler.run())
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert all(stock.count(key) == 1 for key in STOCK_CONTEXTS)
    assert next(calls) == len(STOCK_CONTEXTS), "it made exactly what was missing, then waited"


# --------------------------------------------------------------------------
# live generation goes first
# --------------------------------------------------------------------------


def test_the_filler_waits_while_an_attacker_is_generated_for(temp_dir):
    """One rate-limited model account serves both; the attacker goes first."""
    stock = DecoyStock(temp_dir)
    assert not stock.live_busy()

    marker = stock.live_started()
    assert stock.live_busy()

    async def run():
        waiter = asyncio.create_task(stock.wait_while_live(poll_seconds=0.01))
        await asyncio.sleep(0.05)
        assert not waiter.done(), "it must wait while the live generation runs"
        stock.live_finished(marker)
        await asyncio.wait_for(waiter, 1)

    asyncio.run(run())
    assert not stock.live_busy()


def test_a_marker_left_by_a_crashed_request_does_not_stop_the_filler(temp_dir):
    import os
    import time

    stock = DecoyStock(temp_dir)
    marker = stock.live_started()
    old = time.time() - 3600
    os.utime(marker, (old, old))

    assert not stock.live_busy()
    assert not marker.exists()


def test_the_pacer_spaces_the_fillers_model_calls(temp_dir):
    import time
    from storage.decoy_stock import StepPacer

    pacer = StepPacer(DecoyStock(temp_dir), min_interval=0.1)

    async def run():
        stamps = []
        for _ in range(3):
            await pacer()
            stamps.append(time.monotonic())
        return stamps

    stamps = asyncio.run(run())
    assert all(b - a >= 0.09 for a, b in zip(stamps, stamps[1:]))


def test_the_pacer_also_waits_for_live_generation(temp_dir):
    from storage.decoy_stock import StepPacer

    stock = DecoyStock(temp_dir)
    pacer = StepPacer(stock, min_interval=0)
    marker = stock.live_started()

    async def run():
        task = asyncio.create_task(pacer())
        await asyncio.sleep(0.05)
        assert not task.done()
        stock.live_finished(marker)
        await asyncio.wait_for(task, 5)

    asyncio.run(run())
