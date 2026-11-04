"""What an attacker finds when they come back.

The broker keeps one container per source IP precisely so a returning attacker
finds their own changes: the cron job they planted, the account they added,
the decoys we showed them. Three things broke that promise, none of them with
an error:

1. The proxy's own key lived in the attacker's `~/.ssh/authorized_keys`. The
   most common SSH bot replaces that file, which locked the proxy -- and so
   the attacker -- out of their container until the reaper deleted it.
2. Reaping removed the jump host but not the pivot targets behind it, which
   leaked memory and left node-02/03 remembering a visit node-01 had forgotten.
3. Every return visit planted the same decoys again, restoring files the
   attacker had deleted and overwriting ones they had changed.
4. Only the decoy files were backdated. The directories made for them, and
   the ones given new entries, showed the time of the plant.

Broker code is extracted from source rather than imported, as in the other
broker tests: importing broker.py needs docker, fastapi and pydantic.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BROKER_SRC = (ROOT / "shared" / "session-broker" / "broker.py").read_text(encoding="utf-8")

_TOP_LEVEL_END = r"(?=\n(?:def |async def |class |#: |@|\Z))"


def _extract(names: list[str], ns: dict[str, Any]) -> dict[str, Any]:
    for name in names:
        match = re.search(rf"^(?:async )?def {name}\(.*?{_TOP_LEVEL_END}", BROKER_SRC, re.S | re.M)
        assert match, f"could not extract {name} from broker.py"
        exec(match.group(0), ns)
    return ns


def _extract_assignment(name: str, ns: dict[str, Any]) -> None:
    match = re.search(rf"^{name}\b.*?(?=\n\n)", BROKER_SRC, re.S | re.M)
    assert match, f"could not extract {name} from broker.py"
    exec(match.group(0), ns)


class NotFound(Exception):
    pass


class DockerException(Exception):
    pass


# --------------------------------------------------------------------------
# 1. the proxy's key is out of the attacker's reach
# --------------------------------------------------------------------------


@pytest.fixture
def rendered(tmp_path, monkeypatch):
    """Run the real render_users and render_sshd into a temporary root.

    Account management is faked -- useradd only creates the home directory --
    and the timezone is fixed, because Windows ships no tz database.
    """
    sys.path.insert(0, str(ROOT / "shared" / "node-build"))
    import render_node

    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBACKENDKEYFORTESTS deploy@ops"
    pubkey = tmp_path / "backend_key.pub"
    pubkey.write_text(key + "\n", encoding="utf-8")
    monkeypatch.setattr(render_node, "BACKEND_PUBKEY", pubkey)
    monkeypatch.setattr(render_node, "zone", lambda name: timezone(timedelta(hours=5, minutes=30)))

    root = tmp_path / "root"

    def fake_run(command, *args, **kwargs):
        if command[:2] == ["getent", "passwd"]:
            return subprocess.CompletedProcess(command, 2, "", "")
        if command[0] == "useradd":
            home = command[command.index("--home-dir") + 1]
            (root / home.lstrip("/")).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(render_node.subprocess, "run", fake_run)

    identity = yaml.safe_load((ROOT / "nodes" / "node-01-jump" / "identity.yaml").read_text(encoding="utf-8"))
    renderer = render_node.NodeRenderer(identity, root)
    renderer.render_users()
    renderer.render_sshd()
    return SimpleNamespace(root=root, key=key, identity=identity, module=render_node)


def test_backend_key_lives_where_the_login_account_cannot_reach(rendered):
    login_users = [u["name"] for u in rendered.identity["users"] if u.get("login")]
    assert login_users, "node-01 should have login accounts"

    central = rendered.root / rendered.module.CENTRAL_KEYS_DIR.lstrip("/")
    for name in login_users:
        assert (central / name).read_text(encoding="utf-8").strip() == rendered.key, name
        # Not in the home directory, which the attacker owns once logged in.
        own_keys = rendered.root / "home" / name / ".ssh" / "authorized_keys"
        assert not own_keys.exists() or rendered.key not in own_keys.read_text(encoding="utf-8"), name

    for user in rendered.identity["users"]:
        if not user.get("login"):
            assert not (central / user["name"]).exists(), f"{user['name']} cannot log in, so needs no key"


def test_sshd_reads_both_the_users_keys_and_the_central_ones(rendered):
    config = (rendered.root / "etc" / "ssh" / "sshd_config").read_text(encoding="utf-8")
    line = next(l for l in config.splitlines() if l.startswith("AuthorizedKeysFile"))
    assert line.split()[1:] == [".ssh/authorized_keys", f"{rendered.module.CENTRAL_KEYS_DIR}/%u"]


def test_the_bot_that_replaces_authorized_keys_no_longer_locks_the_proxy_out(rendered):
    """`rm -rf ~/.ssh && mkdir ~/.ssh && echo "ssh-rsa ... mdrfckr" >> ~/.ssh/authorized_keys`."""
    home_ssh = rendered.root / "home" / "devuser" / ".ssh"
    shutil.rmtree(home_ssh, ignore_errors=True)
    home_ssh.mkdir(parents=True)
    (home_ssh / "authorized_keys").write_text("ssh-rsa AAAAB3NzaC1yc2E mdrfckr\n", encoding="utf-8")

    central = rendered.root / rendered.module.CENTRAL_KEYS_DIR.lstrip("/") / "devuser"
    assert rendered.key in central.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="NTFS has no Unix permission bits")
def test_central_keys_pass_sshd_strict_modes(rendered):
    central = rendered.root / rendered.module.CENTRAL_KEYS_DIR.lstrip("/")
    assert central.stat().st_mode & 0o022 == 0, "directory must not be group/world writable"
    for entry in central.iterdir():
        assert entry.stat().st_mode & 0o777 == 0o644


def test_central_key_directory_is_not_stamped_with_the_build_date(rendered):
    central = rendered.root / rendered.module.CENTRAL_KEYS_DIR.lstrip("/")
    assert time.time() - central.stat().st_mtime > 100 * 86400


# --------------------------------------------------------------------------
# 2. pivot targets go with their owner
# --------------------------------------------------------------------------


class FakeContainer:
    def __init__(self, name: str, labels: dict[str, str], changes: list[dict] | None = None):
        self.id = self.name = name
        self.labels = labels
        self.changes = changes or [{"Kind": 1, "Path": "/tmp/iwashere"}]

    def diff(self):
        return self.changes


class FakeDocker:
    def __init__(self):
        self.containers_by_name: dict[str, FakeContainer] = {}
        self.networks_by_name: dict[str, SimpleNamespace] = {}
        self.removed: list[str] = []
        self.containers = SimpleNamespace(get=self._get, list=self._list)
        self.networks = SimpleNamespace(get=self._get_network, list=self._list_networks)

    def add(self, name: str, **labels: str) -> None:
        container = FakeContainer(name, labels)
        container.remove = lambda force=False, n=name: self._remove(n)
        self.containers_by_name[name] = container

    def add_network(self, name: str, **labels: str) -> None:
        self.networks_by_name[name] = SimpleNamespace(
            name=name,
            attrs={"Labels": labels},
            disconnect=lambda *a, **k: None,
            remove=lambda n=name: self.networks_by_name.pop(n),
        )

    def _list_networks(self, filters: dict | None = None):
        wanted = dict([filters["label"].split("=", 1)]) if filters else {}
        return [n for n in self.networks_by_name.values() if wanted.items() <= n.attrs["Labels"].items()]

    def _remove(self, name: str) -> None:
        self.removed.append(name)
        del self.containers_by_name[name]

    def _get(self, name: str) -> FakeContainer:
        try:
            return self.containers_by_name[name]
        except KeyError:
            raise NotFound(name) from None

    def _get_network(self, name: str):
        try:
            return self.networks_by_name[name]
        except KeyError:
            raise NotFound(name) from None

    def _list(self, all: bool = False, filters: dict | None = None):
        wanted = dict([filters["label"].split("=", 1)]) if filters else {}
        return [c for c in self.containers_by_name.values() if all and wanted.items() <= c.labels.items()]


@pytest.fixture
def broker():
    docker = FakeDocker()
    ns: dict[str, Any] = {
        "hashlib": hashlib,
        "asyncio": asyncio,
        "log": logging.getLogger("broker-under-test"),
        "Any": Any,
        "NotFound": NotFound,
        "DockerException": DockerException,
        "NODE_DOMAIN": "cs.internal",
        "NODE_HOSTNAME": "jump-01",
        "PROXY_CONTAINER": "gw-01",
        "_docker": docker,
        "state": SimpleNamespace(backends={}),
    }
    _extract_assignment("PEER_PLAN", ns)
    _extract(
        [
            "_safe_name", "_network_name", "_back_network_name", "_peer_container_name", "_peer_exists",
            "_collect_changes", "_force_remove", "_detach_proxy", "_log_changes", "_destroy",
            "_destroy_peers", "_reap_orphans",
        ],
        ns,
    )

    def environment(owner: str, with_entry: bool = True, pivoted: bool = True) -> None:
        """An attacker's estate. Without an entry node it is what an out-of-band
        `docker rm` of the jump host leaves: its network, and any peers."""
        if with_entry:
            name = ns["_safe_name"](owner)
            docker.add(name, **{"honeypot.node": "node-01-jump", "honeypot.key": owner})
            ns["state"].backends[owner] = SimpleNamespace(
                container_id=name, container_name=name, session_count=3
            )
        docker.add_network(ns["_network_name"](owner), **{"honeypot.role": "attacker-net", "honeypot.key": owner})
        if pivoted:
            for spec in ns["PEER_PLAN"].values():
                docker.add(ns["_peer_container_name"](owner, spec["node"]), **{"honeypot.node": spec["node"], "honeypot.key": owner})
            docker.add_network(ns["_back_network_name"](owner), **{"honeypot.role": "peer-net", "honeypot.key": owner})

    ns["environment"] = environment
    ns["docker"] = docker
    return ns


def test_reaping_removes_the_pivot_targets_and_their_network(broker):
    broker["environment"]("203.0.113.5")
    broker["environment"]("198.51.100.9")  # someone else, who must be untouched

    asyncio.run(broker["_destroy"]("203.0.113.5"))

    docker = broker["docker"]
    left = {c.labels["honeypot.key"] for c in docker.containers_by_name.values()}
    assert left == {"198.51.100.9"}, f"containers still up for: {left}"
    assert broker["_back_network_name"]("203.0.113.5") not in docker.networks_by_name
    assert broker["_network_name"]("203.0.113.5") not in docker.networks_by_name
    assert broker["_back_network_name"]("198.51.100.9") in docker.networks_by_name


def test_attackers_who_never_pivoted_are_reaped_cleanly(broker):
    owner = "203.0.113.6"
    name = broker["_safe_name"](owner)
    broker["docker"].add(name, **{"honeypot.node": "node-01-jump", "honeypot.key": owner})
    broker["state"].backends[owner] = SimpleNamespace(container_id=name, container_name=name, session_count=1)

    asyncio.run(broker["_destroy"](owner))

    assert broker["docker"].containers_by_name == {}


def test_startup_removes_what_a_departed_attacker_left_behind(broker):
    """Found in Docker: a jump host deleted out from under the broker stranded
    its peers, its back network AND its own network."""
    broker["environment"]("203.0.113.7", with_entry=False)  # jump host gone
    broker["environment"]("198.51.100.10")                  # live, adopted at startup

    cleaned = broker["_reap_orphans"]({"198.51.100.10"})

    assert cleaned == 1
    docker = broker["docker"]
    assert {c.labels["honeypot.key"] for c in docker.containers_by_name.values()} == {"198.51.100.10"}
    assert {n.attrs["Labels"]["honeypot.key"] for n in docker.networks_by_name.values()} == {"198.51.100.10"}


def test_startup_also_clears_the_network_of_an_attacker_who_never_pivoted(broker):
    broker["environment"]("203.0.113.8", with_entry=False, pivoted=False)

    assert broker["_reap_orphans"](set()) == 1
    assert broker["docker"].networks_by_name == {}


# --------------------------------------------------------------------------
# 3. decoys land once per environment, and never over an existing file
# --------------------------------------------------------------------------


class PlantingContainer:
    """A container whose filesystem is a set of paths, as the broker sees it."""

    def __init__(self, prepare_script: str, existing: set[str],
                 dirs: dict[str, int] | None = None, ancestor_script: str | None = None):
        self.id = "c0ffee"
        self.attrs = {"Created": "2026-03-01T10:00:00.123456789Z"}
        self.prepare_script = prepare_script
        self.files = set(existing)
        # Directories that exist, with their mtimes, for the ancestor script.
        self.dirs = dict(dirs or {})
        self.ancestor_script = ancestor_script
        self.archived: list[str] = []
        self.execs: list[list[str]] = []

    def exec_run(self, command, user="root"):
        self.execs.append(command)
        if command[:3] == ["sh", "-c", self.prepare_script]:
            present = [p for p in command[4:] if p in self.files]
            return (0, "\n".join(present).encode())
        if self.ancestor_script and command[:3] == ["sh", "-c", self.ancestor_script]:
            lines = []
            for path in command[4:]:
                directory = path.rpartition("/")[0] or "/"
                while directory not in self.dirs and directory != "/":
                    directory = directory.rpartition("/")[0] or "/"
                lines.append(f"{self.dirs.get(directory, 0)} {directory}")
            return (0, "\n".join(lines).encode())
        return (0, b"")

    def put_archive(self, directory, data):
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive.getmembers():
                path = f"{directory.rstrip('/')}/{member.name}"
                self.archived.append(path)
                self.files.add(path)
        return True


@pytest.fixture
def writer():
    ns: dict[str, Any] = {"hashlib": hashlib, "time": time, "datetime": datetime, "log": logging.getLogger("t"), "Any": Any}
    for const in ("_DECOY_AGE_MIN_DAYS", "_DECOY_AGE_MAX_DAYS"):
        ns[const] = int(re.search(rf"^{const} = (\d+)", BROKER_SRC, re.M).group(1))
    for script in ("_PREPARE_SCRIPT", "_ANCESTOR_SCRIPT", "_BACKDATE_SCRIPT"):
        _extract_assignment(script, ns)
    _extract(["_prepare_paths", "_existing_ancestors", "_write_files", "_directory_times",
              "_date_directories", "_container_epoch", "_decoy_mtime", "_owner_for", "_owned_ancestors"], ns)

    def run(existing: set[str], files: list[tuple[str, str, int]], dirs: dict[str, int] | None = None):
        container = PlantingContainer(ns["_PREPARE_SCRIPT"], existing, dirs,
                                      ns["_ANCESTOR_SCRIPT"] if dirs is not None else None)
        ns["_docker"] = SimpleNamespace(containers=SimpleNamespace(get=lambda _id: container))
        written, skipped = ns["_write_files"](container.id, files)
        return container, written, skipped

    ns["run"] = run
    return ns


def test_existing_files_are_never_overwritten(writer):
    """Generated profiles used to replace .bash_history, .bashrc and the live auth.log."""
    container, written, skipped = writer["run"](
        existing={"/home/devuser/.bash_history", "/var/log/auth.log"},
        files=[
            ("/home/devuser/.bash_history", "ls\nexit\n", 0o600),
            ("/var/log/auth.log", "Jan  1 sshd[1]: model-written line\n", 0o640),
            ("/home/devuser/projects/app/README.md", "# app\n", 0o644),
        ],
    )
    assert (written, skipped) == (1, 2)
    assert container.archived == ["/home/devuser/projects/app/README.md"]


def test_nothing_is_archived_when_everything_already_exists(writer):
    container, written, skipped = writer["run"](
        existing={"/home/devuser/.aws/credentials"},
        files=[("/home/devuser/.aws/credentials", "[default]\n", 0o600)],
    )
    assert (written, skipped) == (0, 1)
    assert container.archived == []
    assert all("chown" not in " ".join(e) for e in container.execs), "nothing written, nothing to chown"


def test_one_exec_prepares_every_path(writer):
    """The existence check replaced the per-directory mkdir rather than adding to it."""
    container, _, _ = writer["run"](
        existing=set(),
        files=[("/srv/exports/a.csv", "a\n", 0o640), ("/opt/deploy/b.sh", "b\n", 0o750)],
    )
    prepares = [e for e in container.execs if e[:3] == ["sh", "-c", writer["_PREPARE_SCRIPT"]]]
    assert len(prepares) == 1
    assert not any(e[:2] == ["mkdir", "-p"] for e in container.execs)


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
def test_prepare_script_reports_existing_paths_and_creates_missing_parents(writer, tmp_path):
    existing = tmp_path / "home" / "devuser" / ".bashrc"
    existing.parent.mkdir(parents=True)
    existing.write_text("# rc\n", encoding="utf-8")
    missing = tmp_path / "srv" / "exports" / "students.csv"

    result = subprocess.run(
        ["sh", "-c", writer["_PREPARE_SCRIPT"], "sh", existing.as_posix(), missing.as_posix()],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [existing.as_posix()]
    assert missing.parent.is_dir() and not missing.exists()


# --------------------------------------------------------------------------
# 4. the directories decoys land in are dated like the decoys
# --------------------------------------------------------------------------


def test_a_new_directory_takes_the_time_of_the_newest_decoy_below_it(writer):
    home = "/home/devuser"
    files = (f"{home}/app/main.py", f"{home}/app/config.py", f"{home}/.config/gh/hosts.yml")
    times = writer["_directory_times"](
        dict(zip(files, (700, 900, 600))),
        {path: (home, 1_000) for path in files},
    )
    assert times[f"{home}/app"] == 900
    assert times[f"{home}/.config/gh"] == times[f"{home}/.config"] == 600
    assert times[home] == 1_000, "older decoys must not move the home directory's own date"


def test_an_existing_directory_moves_only_as_far_as_its_newest_new_entry(writer):
    home = "/home/devuser"
    times = writer["_directory_times"]({f"{home}/nginx.conf": 1_500}, {f"{home}/nginx.conf": (home, 1_000)})
    assert times == {home: 1_500}


def test_planting_dates_the_directory_it_made_and_restores_the_one_it_added_to(writer):
    """Seen 2026-11-04: `ls -la ~/app` showed `.` and `..` from today above months-old files."""
    created = writer["_container_epoch"](PlantingContainer("", set()))  # newer than any decoy
    container, written, _ = writer["run"](
        existing=set(),
        files=[("/home/devuser/app/main.py", "print()\n", 0o644)],
        dirs={"/home/devuser": created, "/home": created, "/": created},
    )
    assert written == 1
    stamp = writer["_decoy_mtime"](created, container.id, "/home/devuser/app/main.py")
    dated = [e for e in container.execs if e[:3] == ["sh", "-c", writer["_BACKDATE_SCRIPT"]]]
    assert len(dated) == 1, "one exec dates every directory"
    assert dict(zip(dated[0][5::2], map(int, dated[0][4::2]))) == {
        "/home/devuser/app": stamp,
        "/home/devuser": created,
    }


def test_nothing_is_dated_when_nothing_was_written(writer):
    container, written, _ = writer["run"](
        existing={"/home/devuser/.bashrc"},
        files=[("/home/devuser/.bashrc", "# rc\n", 0o644)],
        dirs={"/home/devuser": 1_000, "/home": 1_000, "/": 1_000},
    )
    assert written == 0
    assert not any(e[:3] == ["sh", "-c", writer["_BACKDATE_SCRIPT"]] for e in container.execs)


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
def test_ancestor_script_reports_the_nearest_existing_directory_and_its_time(writer, tmp_path):
    home = tmp_path / "home" / "devuser"
    home.mkdir(parents=True)
    os.utime(home, (1_700_000_000, 1_700_000_000))

    result = subprocess.run(
        ["sh", "-c", writer["_ANCESTOR_SCRIPT"], "sh",
         (home / "app" / "src" / "main.py").as_posix(), (home / ".bashrc").as_posix()],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [f"1700000000 {home.as_posix()}"] * 2
    assert not (home / "app").exists(), "it only looks; creating is _prepare_paths's job"


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
def test_backdate_script_sets_each_directorys_time(writer, tmp_path):
    first, second = tmp_path / "app", tmp_path / "logs"
    first.mkdir()
    second.mkdir()

    result = subprocess.run(
        ["sh", "-c", writer["_BACKDATE_SCRIPT"], "sh",
         "1600000000", first.as_posix(), "1650000000", second.as_posix()],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert int(first.stat().st_mtime) == 1_600_000_000
    assert int(second.stat().st_mtime) == 1_650_000_000


class FakeHTTPException(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code


@pytest.fixture
def plant():
    calls: list[tuple[str, list]] = []
    ns: dict[str, Any] = {
        "asyncio": asyncio,
        "hashlib": hashlib,
        "log": logging.getLogger("t"),
        "HTTPException": FakeHTTPException,
        "_docker": object(),
        "Any": Any,
        # The attacker's pivot targets that exist, by container name.
        "peers": set(),
    }
    backend = SimpleNamespace(container_id="c1", container_name="jump-01-abc123", planted=set(), touch=lambda: None)
    ns["state"] = SimpleNamespace(backends={"203.0.113.5": backend})

    def fake_write(container_id, files):
        calls.append((container_id, files))
        if ns.get("fail_next"):
            ns["fail_next"] = False
            raise RuntimeError("docker went away")
        return len(files), 0

    ns["_write_files"] = fake_write
    ns["_peer_exists"] = lambda name: name in ns["peers"]
    _extract_assignment("PEER_PLAN", ns)
    _extract(["plant_decoys", "_peer_container_name"], ns)

    def request(action: str, *, src_ip: str = "203.0.113.5", attacker: str | None = None, node: str | None = None):
        file = SimpleNamespace(path="/home/devuser/notes.txt", content="x\n", mode=0o644)
        return SimpleNamespace(src_ip=src_ip, attacker=attacker, node=node, action=action,
                               intent="reconnaissance", files=[file])

    def call(action: str, **where):
        return asyncio.run(ns["plant_decoys"](request(action, **where)))

    ns.update(call=call, calls=calls, backend=backend)
    return ns


def test_an_action_is_planted_once_per_environment(plant):
    first = plant["call"]("show_fake_endpoints")
    again = plant["call"]("show_fake_endpoints")    # the attacker's next visit
    other = plant["call"]("serve_fake_network_map")

    assert first["status"] == "ok"
    assert again["status"] == "already-planted"
    assert other["status"] == "ok"
    assert len(plant["calls"]) == 2, "the repeat must not touch the container"


def test_a_failed_plant_can_be_retried(plant):
    plant["fail_next"] = True
    with pytest.raises(FakeHTTPException):
        plant["call"]("show_fake_endpoints")
    assert "show_fake_endpoints" not in plant["backend"].planted
    assert plant["call"]("show_fake_endpoints")["status"] == "ok"


# A session on erp-web reached from the attacker's own node-01: its source
# address is that jump host, which owns no environment.
PIVOT = {"src_ip": "172.23.0.2", "attacker": "203.0.113.5", "node": "node-02-erp"}


def test_a_pivot_is_planted_into_the_attackers_own_copy_of_that_node(plant):
    """Pivots were looked up by source address and always got no-active-session."""
    erp = plant["_peer_container_name"]("203.0.113.5", "node-02-erp")
    plant["peers"].add(erp)

    result = plant["call"]("expose_fake_internal_ips", **PIVOT)

    assert result == {"status": "ok", "planted": 1, "skipped": 0, "container": erp}
    assert plant["calls"][0][0] == erp


def test_a_pivot_without_that_attackers_node_plants_nothing(plant):
    result = plant["call"]("expose_fake_internal_ips", **PIVOT)    # no erp-web was ever spawned
    assert result["status"] == "no-active-session"
    assert plant["calls"] == []


def test_the_source_address_alone_still_finds_nothing_on_a_pivot(plant):
    """Without the recorded owner a pivot must not land anywhere, least of all node-01."""
    result = plant["call"]("expose_fake_internal_ips", src_ip="172.23.0.2")
    assert result["status"] == "no-active-session"
    assert plant["calls"] == []


def test_each_node_is_planted_once_on_its_own(plant):
    plant["peers"].add(plant["_peer_container_name"]("203.0.113.5", "node-02-erp"))

    on_jump = plant["call"]("show_fake_endpoints", attacker="203.0.113.5", node="node-01-jump")
    on_erp = plant["call"]("show_fake_endpoints", **PIVOT)
    again = plant["call"]("show_fake_endpoints", **PIVOT)

    assert (on_jump["status"], on_erp["status"], again["status"]) == ("ok", "ok", "already-planted")
    assert [target for target, _ in plant["calls"]] == ["c1", on_erp["container"]]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
