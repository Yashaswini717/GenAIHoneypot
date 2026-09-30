"""The broker must rebuild its state from entry nodes only.

Every container an attacker owns -- the jump host and both pivot targets --
carries the same `honeypot.key`, because the key is their source IP. A
reconcile that selects on `honeypot.role=node` therefore adopts all three
under one key, and the last one Docker happens to list wins.

That is not a cosmetic bug. It routed a perimeter SSH session to `erp-web`
instead of the jump host after a broker restart, and it did so
nondeterministically, because container listing order is not guaranteed. The
session then failed outright.

These tests read broker.py as text rather than importing it: importing pulls
in docker, fastapi and pydantic to check a label filter and a dictionary
build, which is a lot of machinery for two assertions.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

BROKER = Path(__file__).resolve().parents[1] / "shared" / "session-broker" / "broker.py"
SRC = BROKER.read_text(encoding="utf-8")


def _reconcile_body() -> str:
    match = re.search(r"^def _reconcile\(.*?(?=\n(?:def |@app|#: |\Z))", SRC, re.S | re.M)
    assert match, "could not find _reconcile in broker.py"
    return match.group(0)


def test_reconcile_selects_entry_nodes_only() -> None:
    """The label filter must narrow to the entry node, not to every node.

    `honeypot.role=node` is true of all three tiers; only `honeypot.node`
    distinguishes the jump host from a pivot target.
    """
    body = _reconcile_body()
    assert "honeypot.node=" in body, (
        "_reconcile must filter on honeypot.node. Filtering on honeypot.role=node "
        "matches the jump host AND both pivot targets, which share one "
        "honeypot.key -- so they collapse to a single entry and the perimeter "
        "routes to whichever Docker listed last."
    )
    assert 'filters={"label": "honeypot.role=node"}' not in body, (
        "_reconcile is back to selecting every node tier"
    )


def test_entry_label_and_reconcile_filter_share_one_constant() -> None:
    """Written twice, they can drift; drift here is silent and total.

    If the label written at creation and the filter read at startup stop
    matching, reconcile quietly adopts nothing and every returning attacker
    is handed a brand new environment.
    """
    assert re.search(r"^ENTRY_NODE_NAME = ", SRC, re.M), "ENTRY_NODE_NAME is missing"

    labels = re.findall(r'"honeypot\.node":\s*([^\n,]+)', SRC)
    assert labels, "no honeypot.node label is written anywhere"
    assert "ENTRY_NODE_NAME" in labels[0], (
        f"the entry container labels honeypot.node with {labels[0].strip()} rather "
        "than ENTRY_NODE_NAME, so it can drift from the reconcile filter"
    )
    assert "ENTRY_NODE_NAME" in _reconcile_body(), (
        "_reconcile hardcodes the node name instead of reading ENTRY_NODE_NAME"
    )


def test_peers_are_labelled_by_their_own_role() -> None:
    """Peers still carry honeypot.node, so they remain findable and reapable.

    Narrowing reconcile must not make pivot targets invisible: the reaper
    selects on honeypot.role=node to clean them up, and _spawn_peer finds
    them by name.
    """
    labels = re.findall(r'"honeypot\.node":\s*([^\n,]+)', SRC)
    assert len(labels) >= 2, "expected both an entry and a peer honeypot.node label"
    assert any("spec[" in label for label in labels[1:]), (
        "peer containers should label honeypot.node from their own spec"
    )


@pytest.mark.parametrize("required", ["honeypot.role", "honeypot.key"])
def test_shared_labels_survive(required: str) -> None:
    """Reaping and ownership still depend on these being on every node."""
    assert f'"{required}"' in SRC, f"{required} label was dropped from broker.py"
