"""Warm sandboxes: nodes kept started for the next new attacker.

A new node takes about 3.4 s to answer under gVisor, and on the cloud honeypot
(2026-11-06) a bot that had already logged in gave up 60 ms before its shell was
ready. With WARM_POOL_SIZE > 0 the broker keeps nodes started and unowned and
hands one over on the next new session.

Like the other broker tests, these read broker.py as text and run the real
functions against a fake Docker, rather than importing docker and fastapi.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "shared" / "session-broker" / "broker.py").read_text(encoding="utf-8")
_END = r"(?=\n(?:def |async def |class |#: |@|\Z))"


class NotFound(Exception):
    pass


class DockerException(Exception):
    pass


def _extract(names: list[str], ns: dict[str, Any]) -> None:
    for name in names:
        match = re.search(rf"^(?:async )?def {name}\(.*?{_END}", SRC, re.S | re.M)
        assert match, f"could not extract {name} from broker.py"
        exec(match.group(0), ns)


def _extract_class(name: str, ns: dict[str, Any]) -> None:
    match = re.search(rf"^@dataclass\nclass {name}\b.*?{_END}", SRC, re.S | re.M)
    assert match, f"could not extract {name} from broker.py"
    exec(match.group(0), ns)


def _extract_assignment(name: str, ns: dict[str, Any]) -> None:
    match = re.search(rf"^{name}\b.*?(?=\n\n)", SRC, re.S | re.M)
    assert match, f"could not extract {name} from broker.py"
    exec(match.group(0), ns)


# --------------------------------------------------------------------------
# a Docker with just enough behaviour
# --------------------------------------------------------------------------

_ids = itertools.count(1)
_subnets = itertools.count(10)


class FakeNetwork:
    def __init__(self, docker: "FakeDocker", name: str, labels: dict[str, str]):
        self.docker, self.name = docker, name
        subnet = f"172.30.{next(_subnets)}.0/24"
        self.attrs = {"Labels": labels, "Containers": {}, "IPAM": {"Config": [{"Subnet": subnet}]}}
        self.hosts = itertools.count(2)

    def reload(self) -> None:
        pass

    def disconnect(self, *args, **kwargs) -> None:
        pass

    def remove(self) -> None:
        if any(c["Name"] != "gw-01" for c in self.attrs["Containers"].values()):
            raise DockerException("network has active endpoints")
        self.docker.networks_by_name.pop(self.name, None)


class FakeNode:
    def __init__(self, docker: "FakeDocker", name: str, network: FakeNetwork, labels: dict[str, str], mac: str):
        self.docker = docker
        self.id = f"c{next(_ids):04d}"
        self.name, self.labels, self.mac = name, labels, mac
        self.status = "running"
        prefix = network.attrs["IPAM"]["Config"][0]["Subnet"].rsplit(".", 1)[0]
        self.attrs = {"NetworkSettings": {"Networks": {network.name: {"IPAddress": f"{prefix}.{next(network.hosts)}"}}}}
        network.attrs["Containers"][self.id] = {"Name": name}  # as Docker reports it

    def reload(self) -> None:
        pass

    def rename(self, new: str) -> None:
        if new in {c.name for c in self.docker.nodes.values()}:
            raise DockerException(f"Conflict: {new} is in use")
        self.name = new

    def remove(self, force: bool = False) -> None:
        self.docker.nodes.pop(self.id, None)
        for network in self.docker.networks_by_name.values():
            network.attrs["Containers"].pop(self.id, None)

    def diff(self):
        return []


class FakeDocker:
    def __init__(self) -> None:
        self.nodes: dict[str, FakeNode] = {}
        self.networks_by_name: dict[str, FakeNetwork] = {}
        self.containers = SimpleNamespace(run=self._run, get=self._get, list=self._list)
        self.networks = SimpleNamespace(create=self._create_network, get=self._get_network, list=self._list_networks)

    def _run(self, image, *, name, network, labels, mac_address, **kwargs):
        if name in {c.name for c in self.nodes.values()}:
            raise DockerException(f"Conflict: {name}")
        node = FakeNode(self, name, self.networks_by_name[network], labels, mac_address)
        self.nodes[node.id] = node
        return node

    def _get(self, ref: str) -> FakeNode:
        for node in self.nodes.values():
            if ref in (node.id, node.name):
                return node
        raise NotFound(ref)

    def _list(self, all: bool = False, filters: dict | None = None):
        key, _, value = filters["label"].partition("=")
        return [n for n in self.nodes.values() if n.labels.get(key) == value]

    def _create_network(self, name, *, driver, internal, labels):
        assert internal, "attacker networks must have no route out"
        self.networks_by_name[name] = FakeNetwork(self, name, labels)
        return self.networks_by_name[name]

    def _get_network(self, name: str) -> FakeNetwork:
        try:
            return self.networks_by_name[name]
        except KeyError:
            raise NotFound(name) from None

    def _list_networks(self, filters: dict | None = None):
        key, _, value = filters["label"].partition("=")
        return [n for n in self.networks_by_name.values() if n.attrs["Labels"].get(key) == value]


@pytest.fixture
def broker():
    docker = FakeDocker()
    ns: dict[str, Any] = {
        "asyncio": asyncio, "hashlib": hashlib, "secrets": secrets, "time": time,
        "dataclass": dataclass, "field": field, "Any": Any,
        "log": logging.getLogger("broker-under-test"),
        "NotFound": NotFound, "DockerException": DockerException,
        "_docker": docker,
        "NODE_IMAGE": "honeypot/node-01-jump:current", "NODE_HOSTNAME": "jump-01", "NODE_DOMAIN": "cs.internal",
        "NODE_NETWORK": "deception-net", "ENTRY_NODE_NAME": "node-01-jump",
        "PEER_NODES": ["erp-web", "db-01", "backup-01"], "NODE_CAPABILITIES": [], "MEM_LIMIT": "512m",
        "PIDS_LIMIT": 200, "CPU_QUOTA": 50000, "NODE_RUNTIME": "", "PROXY_CONTAINER": "gw-01",
        "WARM_POOL_SIZE": 2, "IDLE_TTL_SECONDS": 7200,
        # The proxy's side is exercised elsewhere; here it only has to be called.
        "_attach_proxy": lambda network: None,
        "_claim_peer_addresses": lambda key, network: {},
    }
    _extract_assignment("PEER_PLAN", ns)
    _extract_class("Backend", ns)
    _extract_class("PoolMember", ns)
    _extract(
        [
            "_safe_name", "_network_name", "_back_network_name", "_kvm_style_mac", "_runtime_options",
            "_peer_hosts", "_address_of", "_front_network_of", "_network_of", "_ensure_network",
            "_adopt_existing", "_create_container", "_run_node", "_pool_network", "_create_pool_member",
            "_name_taken", "_assign", "_new_backend", "_fill_pool", "_discard_member", "_force_remove",
            "_detach_proxy", "_reconcile_unkeyed", "_reap_unkeyed", "_clear_empty_pool_networks",
            "_collect_changes", "_log_changes", "_destroy", "_destroy_peers", "_peer_container_name",
            "_peer_exists",
        ],
        ns,
    )
    ns["state"] = SimpleNamespace(backends={}, pool=[], pool_filling=False, unkeyed={})
    ns["docker"] = docker
    ns["run"] = lambda coro: asyncio.run(coro)
    return ns


def _fill(broker) -> None:
    broker["run"](broker["_fill_pool"]())


# --------------------------------------------------------------------------
# the pool
# --------------------------------------------------------------------------


def test_the_pool_fills_to_its_size_with_unowned_nodes(broker):
    _fill(broker)

    pool = broker["state"].pool
    assert len(pool) == 2
    for member in pool:
        node = broker["docker"]._get(member.container_id)
        assert node.labels == {"honeypot.role": "node", "honeypot.node": "node-01-jump", "honeypot.pool": "1"}
        assert "honeypot.key" not in node.labels, "a warm node belongs to nobody yet"
        assert re.fullmatch(r"jump-01-[0-9a-f]{6}", member.name), "named like any other node"
        assert node.mac.startswith("52:54:00:")
        network = broker["docker"].networks_by_name[member.network_name]
        assert network.attrs["Labels"] == {"honeypot.role": "attacker-net", "honeypot.pool": "1"}
    assert len({m.network_name for m in pool}) == 2, "each warm node has its own network"


def test_a_new_attacker_gets_a_warm_node_under_their_own_name(broker):
    _fill(broker)
    member = broker["state"].pool[0]

    backend, warm = broker["run"](broker["_new_backend"]("203.0.113.7"))

    assert warm
    assert backend.container_id == member.container_id
    assert backend.container_name == broker["_safe_name"]("203.0.113.7")
    assert broker["docker"]._get(member.container_id).name == backend.container_name
    assert (backend.address, backend.network_name) == (member.address, member.network_name)
    assert len(broker["state"].pool) == 1


def test_with_the_pool_empty_a_node_is_started_as_before(broker):
    backend, warm = broker["run"](broker["_new_backend"]("203.0.113.8"))

    assert not warm
    node = broker["docker"]._get(backend.container_id)
    assert node.labels["honeypot.key"] == "203.0.113.8"
    assert backend.network_name == broker["_network_name"]("203.0.113.8")


def test_an_attackers_own_node_wins_over_a_warm_one(broker):
    """After a broker restart a returning attacker's node is found by name, and a
    warm node must not shadow it -- nor be spent on them."""
    owner = "203.0.113.9"
    old, _ = broker["run"](broker["_new_backend"](owner))  # their node from before
    _fill(broker)

    backend, warm = broker["run"](broker["_new_backend"](owner))

    assert not warm and backend.container_id == old.container_id
    assert len(broker["state"].pool) == 2


def test_a_dead_warm_node_is_discarded_and_a_fresh_one_started(broker):
    _fill(broker)
    dead = broker["state"].pool[0]
    broker["docker"]._get(dead.container_id).status = "exited"

    backend, warm = broker["run"](broker["_new_backend"]("203.0.113.10"))

    assert not warm
    assert dead.container_id not in broker["docker"].nodes
    assert dead.network_name not in broker["docker"].networks_by_name
    assert backend.network_name == broker["_network_name"]("203.0.113.10")


def test_the_reuse_path_finds_a_warm_nodes_own_network(broker):
    _fill(broker)
    backend, _ = broker["run"](broker["_new_backend"]("203.0.113.11"))

    network = broker["_network_of"](backend)

    assert network.name == backend.network_name
    assert broker["_network_name"]("203.0.113.11") not in broker["docker"].networks_by_name, (
        "no network may be made for the key when the node lives on its warm one"
    )


def test_reaping_a_warm_node_removes_its_own_network(broker):
    _fill(broker)
    owner = "203.0.113.12"
    backend, _ = broker["run"](broker["_new_backend"](owner))
    broker["state"].backends[owner] = backend

    broker["run"](broker["_destroy"](owner))

    assert backend.container_id not in broker["docker"].nodes
    assert backend.network_name not in broker["docker"].networks_by_name


# --------------------------------------------------------------------------
# across a broker restart
# --------------------------------------------------------------------------


def test_a_handed_out_warm_node_is_tracked_after_a_restart_and_reaped_on_the_ttl(broker):
    _fill(broker)
    backend, _ = broker["run"](broker["_new_backend"]("203.0.113.13"))
    for member in broker["state"].pool:  # what the shutdown handler does with idle ones
        broker["_discard_member"](member)
    broker["state"].pool.clear()

    found = broker["_reconcile_unkeyed"]()
    assert [b.container_id for b in found] == [backend.container_id]
    for b in found:
        broker["state"].unkeyed[b.container_id] = b

    broker["run"](broker["_reap_unkeyed"](time.time()))
    assert backend.container_id in broker["docker"].nodes, "not before the idle TTL"

    broker["run"](broker["_reap_unkeyed"](time.time() + 7201))
    assert backend.container_id not in broker["docker"].nodes
    assert backend.network_name not in broker["docker"].networks_by_name


def test_a_returning_owner_reclaims_their_warm_node_after_a_restart(broker):
    _fill(broker)
    owner = "203.0.113.14"
    first, _ = broker["run"](broker["_new_backend"](owner))
    broker["state"].pool.clear()

    again = broker["_create_container"](owner)  # the path for a key the broker holds nothing for

    assert again.container_id == first.container_id
    assert again.network_name == first.network_name
    assert broker["_network_name"](owner) not in broker["docker"].networks_by_name


def test_networks_left_by_vanished_warm_nodes_are_cleared(broker):
    _fill(broker)
    gone = broker["state"].pool[0]
    broker["docker"]._get(gone.container_id).remove(force=True)

    cleared = broker["_clear_empty_pool_networks"]()

    assert cleared == 1
    assert gone.network_name not in broker["docker"].networks_by_name
    assert broker["state"].pool[1].network_name in broker["docker"].networks_by_name


def test_the_pool_is_off_unless_asked_for():
    assert re.search(r'^WARM_POOL_SIZE = int\(os\.environ\.get\("WARM_POOL_SIZE", "0"\)\)', SRC, re.M)
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'WARM_POOL_SIZE: "${WARM_POOL_SIZE:-0}"' in compose
