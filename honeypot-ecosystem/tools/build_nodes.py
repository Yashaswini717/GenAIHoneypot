#!/usr/bin/env python3
"""Build every node image from the one shared definition.

Each node differs only in its identity, its entrypoint, and the extra packages
its role needs; everything that makes a container look like a real Linux host
lives in shared/node-build/Dockerfile and is inherited.

    python tools/build_nodes.py            # all nodes
    python tools/build_nodes.py node-02-erp
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Extra apt packages per node. The base image deliberately ships no compiler,
#: so nothing here should reintroduce one.
EXTRA_PACKAGES = {
    "node-01-jump": "",
    # mariadb-client is not optional: this node's whole role is talking to
    # db-01, and its own settings.py names the host. An app server with no
    # database client is a contradiction an attacker sees the moment they
    # try to use the credentials it just leaked them.
    "node-02-erp": "nginx mariadb-client",
    "node-03-db": "mariadb-server mariadb-client",
}


def build(node: str) -> bool:
    image = f"honeypot/{node}:current"
    print(f"\n=== {node} -> {image} ===", flush=True)
    result = subprocess.run(
        [
            "docker", "build",
            "-f", "shared/node-build/Dockerfile",
            "--build-arg", f"NODE={node}",
            "--build-arg", f"EXTRA_PACKAGES={EXTRA_PACKAGES.get(node, '')}",
            "-t", image,
            ".",
        ],
        cwd=ROOT,
    )
    ok = result.returncode == 0
    print(f"{'ok' if ok else 'FAILED'}: {image}", flush=True)
    return ok


def main() -> int:
    nodes = sys.argv[1:] or sorted(EXTRA_PACKAGES)
    failed = [n for n in nodes if not build(n)]
    if failed:
        print(f"\nfailed: {', '.join(failed)}")
        return 1
    print(f"\nbuilt {len(nodes)} node image(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
