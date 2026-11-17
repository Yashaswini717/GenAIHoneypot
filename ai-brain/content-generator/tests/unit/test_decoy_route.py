"""/api/v1/decoys/generate with the decoy stock behind it.

The model-written half comes from stock when there is any, served to one
attacker only; credentials are always made for the request and registered to
that attacker. These tests drive the route function directly with stubbed
generators.
"""

from __future__ import annotations

import asyncio
import itertools
from types import SimpleNamespace

import pytest

from api.routes import decoys as route
from api.schemas.decoys import GenerateDecoysRequest
from populator.filesystem import FilesystemPopulator
from populator.strategies import PopulationStrategy
from storage.decoy_stock import DecoyStock


class _Gen:
    """A generator stub whose every answer is different, as a model's is."""

    def __init__(self, label: str, counter) -> None:
        self.label = label
        self.counter = counter

    async def generate(self, context):
        kind = context.get("token_type") or context.get("config_type") or context.get("log_type") or self.label
        return SimpleNamespace(content=f"{kind}-{next(self.counter)}")


@pytest.fixture
def harness(temp_dir, honeytoken_store, monkeypatch):
    counter = itertools.count(1)
    stock = DecoyStock(temp_dir / "stock")

    async def strategy_for(_llm_client):
        strategy = PopulationStrategy(None, FilesystemPopulator(base_path=temp_dir), honeytoken_store)
        for attr, label in (("source_code_gen", "source"), ("config_gen", "config"), ("log_gen", "log"),
                            ("doc_gen", "doc"), ("token_gen", "token")):
            setattr(strategy, attr, _Gen(label, counter))
        return strategy

    monkeypatch.setattr(route, "get_population_strategy", strategy_for)
    monkeypatch.setattr(route, "get_decoy_stock", lambda: stock)

    def ask(attacker: str, action: str = "show_fake_endpoints"):
        request = GenerateDecoysRequest(action=action, honeypot_id=f"node-01-jump-{attacker}")
        return asyncio.run(route.generate_decoys(request, llm_client=None))

    return SimpleNamespace(stock=stock, ask=ask, store=honeytoken_store)


def _model_written(response) -> set[str]:
    token_values = {t.token_value for t in response.tokens}
    return {f.content for f in response.files if not any(v in f.content for v in token_values)}


def test_a_stocked_set_goes_to_one_attacker_and_the_next_gets_fresh_content(harness):
    harness.stock.put("web_server", [
        {"path": "app/main.py", "content": "stocked main\n", "permissions": 0o644},
        {"path": "nginx.conf", "content": "stocked nginx\n", "permissions": 0o644},
    ])

    first = harness.ask("203.0.113.1")
    second = harness.ask("203.0.113.2")

    assert (first.source, second.source) == ("stock", "live")
    assert {"stocked main\n", "stocked nginx\n"} <= _model_written(first)
    assert _model_written(first).isdisjoint(_model_written(second)), "no two attackers see the same file"
    assert {f.path for f in first.files} >= {"/home/devuser/app/main.py", "/home/devuser/nginx.conf"}
    assert harness.stock.count("web_server") == 0


def test_credentials_are_made_for_each_attacker_even_from_stock(harness):
    for tag in ("a", "b"):
        harness.stock.put("web_server", [{"path": "nginx.conf", "content": f"stocked {tag}\n", "permissions": 0o644}])

    first, second = harness.ask("203.0.113.1"), harness.ask("203.0.113.2")

    assert first.source == second.source == "stock"
    one = {t.token_value for t in first.tokens}
    two = {t.token_value for t in second.tokens}
    assert one and two and one.isdisjoint(two)
    for value in one:
        assert harness.store.check_honeytoken(value).honeypot_id == "node-01-jump-203.0.113.1"
    for value in two:
        assert harness.store.check_honeytoken(value).honeypot_id == "node-01-jump-203.0.113.2"


def test_content_generated_live_is_never_served_again_from_stock(harness):
    live = harness.ask("203.0.113.1")
    repeated = next(iter(_model_written(live)))
    harness.stock.put("web_server", [
        {"path": "nginx.conf", "content": repeated, "permissions": 0o644},       # the model repeating itself
        {"path": "app/main.py", "content": "something new\n", "permissions": 0o644},
    ])

    later = harness.ask("203.0.113.2")

    assert later.source == "stock"
    assert repeated not in _model_written(later)
    assert "something new\n" in _model_written(later)


def test_without_stock_the_route_generates_as_before(harness, monkeypatch):
    monkeypatch.setattr(route, "get_decoy_stock", lambda: None)

    response = harness.ask("203.0.113.1", action="populate_developer_workstation")

    assert response.source == "live"
    assert any(f.path == "/home/devuser/.aws/credentials" for f in response.files)
    assert any(f.path == "/home/devuser/projects/app/src/main.py" for f in response.files)


def test_the_minimal_banner_takes_from_its_own_stock(harness):
    harness.stock.put("developer_workstation", [{"path": ".bashrc", "content": "full profile\n", "permissions": 0o644}])
    harness.stock.put("developer_minimal", [{"path": "scripts/util.py", "content": "minimal\n", "permissions": 0o644}])

    response = harness.ask("203.0.113.1", action="serve_minimal_banner")

    assert response.source == "stock"
    assert "minimal\n" in _model_written(response)
    assert harness.stock.count("developer_workstation") == 1, "the full profile's stock is untouched"


def test_live_generation_holds_the_filler_back_while_it_runs(harness, monkeypatch):
    seen = []
    original = PopulationStrategy.build_content

    async def watching(self, context):
        seen.append(harness.stock.live_busy())
        return await original(self, context)

    monkeypatch.setattr(PopulationStrategy, "build_content", watching)

    response = harness.ask("203.0.113.1")

    assert response.source == "live"
    assert seen == [True], "the filler must see a live generation in progress"
    assert not harness.stock.live_busy(), "and the marker is gone afterwards"
