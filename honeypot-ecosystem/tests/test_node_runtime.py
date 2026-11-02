"""Attacker nodes can be sandboxed under gVisor on an internet-facing host.

An attacker gets root inside a node (sudo works on purpose), and root in a
container still talks to the host's kernel. NODE_RUNTIME=runsc puts gVisor's
user-space kernel in between. Locally it stays empty and nothing changes.

Broker code is extracted from source rather than imported, as in the other
broker tests: importing broker.py needs docker, fastapi and pydantic.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BROKER_SRC = (ROOT / "shared" / "session-broker" / "broker.py").read_text(encoding="utf-8")


def runtime_options(node_runtime: str) -> dict[str, str]:
    match = re.search(r"^def _runtime_options\(.*?(?=^\S)", BROKER_SRC, re.S | re.M)
    assert match, "could not extract _runtime_options from broker.py"
    ns = {"NODE_RUNTIME": node_runtime}
    exec(match.group(0), ns)
    return ns["_runtime_options"]()


def test_no_setting_keeps_dockers_default_runtime():
    assert runtime_options("") == {}


def test_runsc_runs_attacker_nodes_under_gvisor():
    assert runtime_options("runsc") == {"runtime": "runsc"}


def test_every_kind_of_node_takes_the_runtime():
    """The entry node and the pivot peers are created in two places. Both must
    take it, or an attacker could pivot from a sandboxed node to a plain one."""
    creations = re.findall(r"_docker\.containers\.run\((.*?)\n    \)", BROKER_SRC, re.S)
    assert len(creations) == 2, f"expected the entry and peer creations, found {len(creations)}"
    assert all("**_runtime_options()" in call for call in creations)


def test_the_setting_reaches_the_broker_container():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'NODE_RUNTIME: "${NODE_RUNTIME:-}"' in compose
