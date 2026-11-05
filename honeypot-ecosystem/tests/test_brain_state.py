"""The brain's learning has to outlive its container.

What the bandit has learned, the honeytokens the brain registered and its
generation log are one SQLite file. At its default place, /app/data inside the
container, every recreate -- any `docker compose up -d` after a change to .env
or to the image -- threw away everything learned since the image was built.
These tests hold the compose file to keeping that file on a named volume.
"""
from __future__ import annotations

import posixpath
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
BRAIN = COMPOSE["services"]["ai-brain"]
SQLITE_PREFIX = "sqlite:///"


def database_dir() -> str:
    url = BRAIN["environment"]["DATABASE_URL"]
    assert url.startswith(SQLITE_PREFIX), url
    path = url[len(SQLITE_PREFIX):]
    # sqlite:////abs/file is an absolute path; sqlite:///rel/file is relative
    # to the working directory, which is inside the image.
    assert path.startswith("/"), f"relative database path {path!r} would live in the container"
    return posixpath.dirname(path)


def mounts() -> dict[str, str]:
    """Container path -> source, for the brain's volumes."""
    found = {}
    for entry in BRAIN.get("volumes", []):
        source, target = entry.split(":")[:2]
        found[target] = source
    return found


def test_the_brain_database_is_on_a_named_volume():
    source = mounts().get(database_dir())
    assert source, f"nothing is mounted at {database_dir()}"
    # A named volume, not a bind mount of a folder on the host.
    assert not source.startswith((".", "/", "~")), source
    assert source in (COMPOSE.get("volumes") or {}), f"volume {source!r} is not declared"


def test_the_volume_is_not_over_the_images_data_folder():
    # The image copies the build machine's data/ folder to /app/data, local
    # database included. A new volume there would start as a copy of it.
    directory = database_dir()
    assert directory != "/app/data" and not directory.startswith("/app/"), directory
