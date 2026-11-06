"""Pivot targets (erp-web, db-01) must live on the sealed back network only.

Found on the AWS server on 2026-11-05. `_spawn_peer` started each peer on
Docker's default network and connected the back network afterwards:

- The default bridge routes to the internet. Attacker containers on erp-web and
  db-01 could open connections to 1.1.1.1:443 and to the cloud metadata address,
  while jump-01, created on its sealed network, could not.
- gVisor never sees an interface added after the container starts. Under runsc
  the back network was missing inside the peer, so the proxy got "connection
  refused" and every pivot failed.
- Docker's embedded DNS does not answer inside gVisor, so erp-web could not
  resolve db-01 by its alias. db-01 now comes up first, and erp-web gets its
  address as a hosts entry.
- Docker copied the cloud host's search domain (ap-southeast-2.compute.internal)
  into each node's resolv.conf, which tells an attacker the host is on AWS.

`_spawn_peer` is extracted from source and run against fakes, as in
test_broker_placement.py, because importing broker.py pulls in docker, fastapi
and pydantic.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

BROKER = Path(__file__).resolve().parents[1] / "shared" / "session-broker" / "broker.py"
SRC = BROKER.read_text(encoding="utf-8")


class NotFound(Exception):
    pass


class FakeNetwork:
    def __init__(self, name: str) -> None:
        self.name = name
        self.connected: list = []

    def connect(self, container, **kwargs) -> None:
        self.connected.append((container, kwargs))


class FakeContainer:
    def __init__(self, name: str, network: str, address: str) -> None:
        self.name = name
        self.attrs = {"NetworkSettings": {"Networks": {network: {"IPAddress": address}}}}

    def reload(self) -> None:
        pass


class FakeContainers:
    def __init__(self) -> None:
        self.runs: list[dict] = []

    def get(self, name: str):
        raise NotFound(name)

    def run(self, image: str, **kwargs):
        self.runs.append({"image": image, **kwargs})
        address = f"172.24.0.{len(self.runs) + 1}"
        return FakeContainer(kwargs["name"], kwargs["network"], address)


class FakeAPI:
    @staticmethod
    def create_endpoint_config(**kwargs) -> dict:
        return {"endpoint": kwargs}


def _spawn_peer_with_fakes():
    match = re.search(r"^def _spawn_peer\(.*?(?=\n(?:def |#: |@|\Z))", SRC, re.S | re.M)
    assert match, "could not extract _spawn_peer from broker.py"

    back = FakeNetwork("cs.internal-abc123-b")
    containers = FakeContainers()
    proxy_attached: list = []
    plan = {
        21: {"node": "node-02-erp", "hostname": "erp-web", "image": "honeypot/node-02-erp:current"},
        31: {"node": "node-03-db", "hostname": "db-01", "image": "honeypot/node-03-db:current"},
    }
    ns = {
        "Any": object,
        "PEER_PLAN": plan,
        "NODE_DOMAIN": "cs.internal",
        "NODE_CAPABILITIES": ["SETUID", "SETGID"],
        "PIDS_LIMIT": 200,
        "CPU_QUOTA": 50000,
        "NotFound": NotFound,
        "os": os,
        "log": logging.getLogger("test-broker"),
        "_docker": SimpleNamespace(containers=containers, api=FakeAPI()),
        "_ensure_back_network": lambda key: back,
        "_attach_proxy": proxy_attached.append,
        "_peer_container_name": lambda key, node: f"{node}-{key}",
        "_kvm_style_mac": lambda seed: "52:54:00:00:00:01",
        "_runtime_options": lambda: {"runtime": "runsc"},
        "_address_of": lambda container, network=None: (
            container.attrs["NetworkSettings"]["Networks"][network]["IPAddress"]
        ),
    }
    exec(match.group(0), ns)
    ns["_spawn_peer"]("203.0.113.7", 21)  # erp-web, which brings up db-01 first
    return containers.runs, back, proxy_attached


RUNS, BACK, PROXY_ATTACHED = _spawn_peer_with_fakes()


def test_the_database_comes_up_before_the_web_node() -> None:
    assert [run["hostname"] for run in RUNS] == ["db-01", "erp-web"]


def test_the_web_node_can_resolve_the_database_without_dockers_dns() -> None:
    """Docker's embedded DNS does not answer inside gVisor."""
    db_address = "172.24.0.2"  # the first container the fake hands out
    web = RUNS[1]
    assert web["extra_hosts"] == {"db-01": db_address, "db-01.cs.internal": db_address}


@pytest.mark.parametrize("index", [0, 1])
def test_a_peer_searches_the_estates_domain_not_the_cloud_hosts(index: int) -> None:
    assert RUNS[index]["dns_search"] == ["cs.internal"]


def test_the_entry_node_searches_the_estates_domain_too() -> None:
    """jump-01 is created in _create_container, which is not extracted here."""
    body = re.search(r"^def _create_container\(.*?(?=\n(?:def |#: |@|\Z))", SRC, re.S | re.M)
    assert body and "dns_search=[NODE_DOMAIN]" in body.group(0)


@pytest.mark.parametrize("index", [0, 1])
def test_a_peer_is_created_on_the_back_network_only(index: int) -> None:
    """network=None means Docker's default bridge, which reaches the internet."""
    run = RUNS[index]
    assert run["network"] == BACK.name
    assert set(run["networking_config"]) == {BACK.name}, (
        "a peer must have no endpoint on any network but the sealed back network"
    )


@pytest.mark.parametrize("index", [0, 1])
def test_a_peer_keeps_its_dns_aliases(index: int) -> None:
    """erp-web's settings.py names db-01, which resolves only through the alias."""
    run = RUNS[index]
    aliases = run["networking_config"][BACK.name]["endpoint"]["aliases"]
    host = run["hostname"]
    assert aliases == [host, f"{host}.cs.internal"]


def test_no_network_is_attached_to_a_peer_after_it_starts() -> None:
    """gVisor would never see it, and the pivot would fail."""
    assert BACK.connected == []


def test_the_proxy_is_still_put_on_the_back_network() -> None:
    assert PROXY_ATTACHED and all(net is BACK for net in PROXY_ATTACHED)
