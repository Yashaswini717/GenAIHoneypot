"""The backend waits for its databases instead of failing on the first refusal.

After a reboot Docker restarts every container at once, ignoring depends_on,
so the backend can come up before Elasticsearch, PostgreSQL or Neo4j accept
connections. Startup must outlast that, and still fail when one never answers.
"""

from __future__ import annotations

import pytest

import main


class Flaky:
    """An init function that is refused `failures` times, then succeeds."""

    def __init__(self, failures: int):
        self.failures = failures
        self.calls = 0

    async def __call__(self):
        self.calls += 1
        if self.calls <= self.failures:
            raise ConnectionError("connection refused")
        return "ready"


class Clock:
    def __init__(self):
        self.slept: list[float] = []

    async def sleep(self, seconds: float):
        self.slept.append(seconds)


@pytest.mark.asyncio
async def test_retries_until_the_database_answers():
    init, clock = Flaky(failures=3), Clock()
    assert await main._until_ready("db", init, sleep=clock.sleep) == "ready"
    assert init.calls == 4
    assert clock.slept == [1.0, 2.0, 4.0]


@pytest.mark.asyncio
async def test_no_wait_when_the_database_is_already_up():
    init, clock = Flaky(failures=0), Clock()
    await main._until_ready("db", init, sleep=clock.sleep)
    assert init.calls == 1
    assert clock.slept == []


@pytest.mark.asyncio
async def test_gives_up_when_patience_runs_out():
    init, clock = Flaky(failures=10**6), Clock()
    with pytest.raises(ConnectionError):
        await main._until_ready("db", init, patience=30, sleep=clock.sleep)
    assert clock.slept == [1.0, 2.0, 4.0, 8.0, 10.0]  # backoff capped at 10s
    assert sum(clock.slept) <= 30
