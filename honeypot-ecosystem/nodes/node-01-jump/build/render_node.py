#!/usr/bin/env python3
"""Render the node's identity, history and decoys from identity.yaml.

Everything an attacker can read about who this machine is comes from one
file, so the three-way contradiction in the prototype — /etc/hostname saying
one domain, the motd another, /etc/issue a third — cannot recur.

What gets built here:

  * identity files: hostname, hosts, os-release, issue, motd, timezone
  * real accounts with real homes, shells, groups and password ages
  * an sshd_config carrying the same policy the SSH proxy advertises
  * seeded history: auth.log, syslog, wtmp, lastlog, shell histories
  * the decoy chain, and a honeytoken manifest recording what was planted
  * file mtimes scattered across the seeded period rather than all equal

Run at image build time:

    python3 render_node.py --identity identity.yaml --root /
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from seed_history import (  # noqa: E402
    LoginRecord,
    scatter_events,
    write_lastlog,
    write_wtmp,
    zone,
)

#: Fixed so a rebuild reproduces the same box. A honeypot whose file contents
#: change every build is one whose "history" is obviously synthetic to anyone
#: who sees two versions of it.
SEED = 0x9E3779B9


class NodeRenderer:
    def __init__(self, identity: dict, root: Path) -> None:
        self.identity = identity
        self.root = root
        self.rng = random.Random(SEED)

        host = identity["host"]
        self.hostname = host["name"]
        self.domain = host["domain"]
        self.fqdn = f"{self.hostname}.{self.domain}"

        history = identity["history"]
        self.tz = zone(history["timezone"])
        self.workday = (history["workday_start"], history["workday_end"])

        # "Now" is pinned to the build date so the seeded past is coherent,
        # then real time carries on from there once the master runs.
        now = datetime.now(self.tz).replace(minute=0, second=0, microsecond=0)
        self.now = now
        self.boot = now - timedelta(days=history["days"])

        self.honeytokens: list[dict] = []

    # -- helpers -----------------------------------------------------------

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*[p.lstrip("/") for p in parts])

    def write(self, target: str, content: str, mode: int = 0o644, when: datetime | None = None) -> Path:
        destination = self.path(target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        destination.chmod(mode)
        if when is not None:
            self.set_time(destination, when)
        return destination

    def set_time(self, target: Path, when: datetime) -> None:
        stamp = when.timestamp()
        os.utime(target, (stamp, stamp))

    def random_moment(self, min_days_ago: int, max_days_ago: int) -> datetime:
        """A working-hours moment between min and max days in the past."""
        day = self.now - timedelta(days=self.rng.randint(min_days_ago, max_days_ago))
        return day.replace(
            hour=self.rng.randint(*self.workday),
            minute=self.rng.randint(0, 59),
            second=self.rng.randint(0, 59),
            microsecond=0,
        )

    def run(self, *command: str) -> None:
        subprocess.run(command, check=True, capture_output=True)

    # -- identity ----------------------------------------------------------

    def render_identity(self) -> None:
        host = self.identity["host"]

        # /etc/hostname, /etc/hosts and /etc/resolv.conf are owned by Docker:
        # they are read-only bind mounts during build and are regenerated when
        # the container starts, so anything written here would be discarded.
        # The hostname comes from the container's own config (the broker sets
        # it), and the extra host entries are appended at boot by the
        # entrypoint from the file below.
        hosts = [
            "",
            "# Departmental hosts - managed by config, do not edit by hand",
        ]
        for entry in self.identity.get("known_hosts", []):
            names = " ".join([entry["name"], *entry.get("aliases", [])])
            hosts.append(f"{entry['address']}\t{names}")
        self.write("/etc/hosts.extra", "\n".join(hosts) + "\n")

        version = host["os_release"]
        self.write(
            "/etc/os-release",
            f'PRETTY_NAME="Ubuntu {version}"\n'
            'NAME="Ubuntu"\n'
            f'VERSION_ID="{host["os_version_id"]}"\n'
            f'VERSION="{version}"\n'
            "VERSION_CODENAME=jammy\n"
            "ID=ubuntu\n"
            "ID_LIKE=debian\n"
            'HOME_URL="https://www.ubuntu.com/"\n'
            'SUPPORT_URL="https://help.ubuntu.com/"\n'
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
            "UBUNTU_CODENAME=jammy\n",
        )

        # A legal banner is normal on university infrastructure and costs
        # nothing in realism — real estates put one on every host.
        self.write(
            "/etc/issue",
            f"Ubuntu {version} \\n \\l\n\n",
        )
        self.write(
            "/etc/issue.net",
            "Authorised access only. All connections are logged.\n",
        )

        uptime_days = (self.now - self.boot).days
        self.write(
            "/etc/motd",
            f"Welcome to Ubuntu {version} (GNU/Linux {host['kernel']} {host['arch']})\n"
            "\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n"
            "\n"
            f"  System information as of {self.now.strftime('%a %d %b %Y %I:%M:%S %p IST')}\n"
            "\n"
            "  System load:  0.08              Processes:             118\n"
            f"  Usage of /:   61.4% of 78.21GB  Users logged in:       0\n"
            "  Memory usage: 34%               IPv4 address for eth0: 10.60.0.11\n"
            "  Swap usage:   0%\n"
            "\n"
            f"  {host['role']} — {self.fqdn}\n"
            f"  Last patched {uptime_days - self.rng.randint(20, 60)} days ago. "
            "Maintenance window: Sundays 02:00-04:00 IST.\n"
            "  Issues: itsupport (ext. 4412)\n"
            "\n",
        )

    # -- accounts ----------------------------------------------------------

    def render_users(self) -> None:
        pubkey = Path("/tmp/build/backend_key.pub")
        authorized = pubkey.read_text(encoding="utf-8").strip() if pubkey.exists() else ""

        for user in self.identity["users"]:
            name, uid, shell = user["name"], user["uid"], user["shell"]
            home = f"/home/{name}"

            if name == "ubuntu":  # present on Ubuntu cloud images already
                subprocess.run(["userdel", "-r", name], capture_output=True)

            # Distro system accounts (backup, games, news, list, irc, ...)
            # already exist and must not be recreated or renumbered. Colliding
            # with one is a configuration mistake, not a runtime condition, so
            # say what happened rather than surfacing "exit status 9".
            existing = subprocess.run(["getent", "passwd", name], capture_output=True, text=True)
            if existing.returncode == 0:
                current_uid = int(existing.stdout.split(":")[2])
                raise SystemExit(
                    f"identity.yaml wants to create '{name}' at uid {uid}, but that "
                    f"account already exists at uid {current_uid} (a distro system "
                    f"account). Rename it in identity.yaml — recreating or renumbering "
                    f"a system account would break the packages that own it."
                )

            self.run(
                "useradd",
                "--uid", str(uid),
                "--create-home",
                "--home-dir", home,
                "--shell", shell,
                "--comment", user["gecos"],
                name,
            )
            # Locked local passwords: authentication happens at the proxy, so
            # a shadow entry here would be a second, contradictory source of
            # truth about who can log in.
            self.run("usermod", "-p", "!", name)

            if user.get("sudo"):
                self.run("usermod", "-aG", "sudo", name)

            if user.get("login") and authorized:
                ssh_dir = self.path(home, ".ssh")
                ssh_dir.mkdir(parents=True, exist_ok=True)
                ssh_dir.chmod(0o700)
                keys = ssh_dir / "authorized_keys"
                keys.write_text(authorized + "\n", encoding="utf-8")
                keys.chmod(0o600)

            # Ubuntu 22.04 creates homes 0750, which would hide devuser's
            # home from every account without sudo -- and those are exactly
            # the accounts most bots land on, so the decoy chain would dead-end
            # for them. Set explicitly per user instead of inheriting the
            # distro default.
            self.path(home).chmod(int(str(user.get("home_mode", "0750")), 8))
            self.run("chown", "-R", f"{name}:{name}", home)

        # Age the passwords so `chage -l` does not say every account was
        # created today.
        for user in self.identity["users"]:
            days_ago = self.rng.randint(200, 900)
            changed = (self.now - timedelta(days=days_ago)).strftime("%Y-%m-%d")
            subprocess.run(["chage", "-d", changed, user["name"]], capture_output=True)

    # -- sshd --------------------------------------------------------------

    def render_sshd(self) -> None:
        """Write the sshd_config whose policy matches what the proxy presents.

        This file is readable by anyone who lands on the box. If it described
        a different algorithm policy than the handshake they just completed,
        that contradiction alone would give the game away — so both sides are
        generated from the same source.
        """
        policy = Path("/tmp/build/sshd_policy.conf")
        policy_text = policy.read_text(encoding="utf-8") if policy.exists() else ""

        self.write(
            "/etc/ssh/sshd_config",
            "# Package-generated configuration file\n"
            "# See the sshd_config(5) manpage for details\n"
            "\n"
            "Include /etc/ssh/sshd_config.d/*.conf\n"
            "\n"
            "Port 22\n"
            "AddressFamily any\n"
            "\n"
            "SyslogFacility AUTH\n"
            "LogLevel INFO\n"
            "\n"
            f"{policy_text}\n"
            "AuthorizedKeysFile     .ssh/authorized_keys\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "PrintMotd no\n"
            "PrintLastLog yes\n"
            "TCPKeepAlive yes\n"
            "AcceptEnv LANG LC_*\n"
            "Subsystem sftp /usr/lib/openssh/sftp-server\n"
            "\n"
            "Banner /etc/issue.net\n",
            when=self.now - timedelta(days=self.rng.randint(60, 200)),
        )

    # -- history -----------------------------------------------------------

    def render_history(self) -> None:
        login_users = [u for u in self.identity["users"] if u["shell"] != "/usr/sbin/nologin"]
        internal_hosts = ["10.60.14.22", "10.60.14.87", "10.60.15.3", "172.20.9.14", "10.60.14.51"]

        logins: list[LoginRecord] = []
        last_by_uid: dict[int, LoginRecord] = {}

        moments = scatter_events(
            self.boot + timedelta(days=1),
            self.now - timedelta(hours=6),
            per_active_hour=0.09,
            workday_start=self.workday[0],
            workday_end=self.workday[1],
            rng=self.rng,
        )

        for moment in moments:
            user = self.rng.choice(login_users)
            record = LoginRecord(
                user=user["name"],
                line=f"pts/{self.rng.randint(0, 3)}",
                host=self.rng.choice(internal_hosts),
                started=moment,
                duration_minutes=self.rng.choice([3, 8, 14, 22, 41, 67, 95, 140, 210]),
                pid=self.rng.randint(1200, 31000),
            )
            logins.append(record)
            existing = last_by_uid.get(user["uid"])
            if existing is None or record.started > existing.started:
                last_by_uid[user["uid"]] = record

        write_wtmp(self.path("/var/log/wtmp"), logins, self.boot)
        write_lastlog(self.path("/var/log/lastlog"), last_by_uid)
        self.path("/var/log/lastlog").chmod(0o644)

        self._render_auth_log(logins)
        self._render_syslog()
        self._render_shell_histories()

    def _render_auth_log(self, logins: list[LoginRecord]) -> None:
        """auth.log carrying real logins, sudo use and background brute force.

        The failed-password noise matters: any host with SSH open to the
        internet accumulates thousands of them, so an auth.log that contains
        only successful logins is the log of a machine nobody can reach.
        """
        lines: list[tuple[datetime, str]] = []
        recent = [entry for entry in logins if entry.started > self.now - timedelta(days=7)]

        for entry in recent:
            stamp = entry.started
            lines.append(
                (
                    stamp,
                    f"sshd[{entry.pid}]: Accepted publickey for {entry.user} "
                    f"from {entry.host} port {self.rng.randint(40000, 61000)} ssh2: "
                    f"ED25519 SHA256:{_fake_fingerprint(self.rng)}",
                )
            )
            lines.append(
                (
                    stamp + timedelta(seconds=1),
                    f"sshd[{entry.pid}]: pam_unix(sshd:session): session opened for user "
                    f"{entry.user}(uid={1000 + self.rng.randint(0, 7)}) by (uid=0)",
                )
            )
            if self.rng.random() < 0.4:
                lines.append(
                    (
                        stamp + timedelta(minutes=self.rng.randint(1, 20)),
                        f"sudo: {entry.user} : TTY={entry.line} ; PWD=/home/{entry.user} ; "
                        f"USER=root ; COMMAND={self.rng.choice(_SUDO_COMMANDS)}",
                    )
                )
            ended = stamp + timedelta(minutes=entry.duration_minutes)
            lines.append(
                (
                    ended,
                    f"sshd[{entry.pid}]: pam_unix(sshd:session): session closed for user {entry.user}",
                )
            )

        # Background scanning, which every internet-facing host sees.
        noise = scatter_events(
            self.now - timedelta(days=7),
            self.now - timedelta(minutes=20),
            per_active_hour=2.2,
            workday_start=0,
            workday_end=24,
            rng=self.rng,
        )
        for moment in noise:
            source = f"{self.rng.randint(23, 220)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
            user = self.rng.choice(["root", "admin", "oracle", "postgres", "pi", "user", "ftp", "guest"])
            pid = self.rng.randint(1200, 31000)
            # One connection, one source port. Drawing it twice produced pairs
            # of lines for the same event with different ports, which real
            # sshd never emits and an attentive reader would notice.
            port = self.rng.randint(40000, 61000)
            lines.append(
                (
                    moment,
                    f"sshd[{pid}]: Invalid user {user} from {source} port {port}",
                )
            )
            lines.append(
                (
                    moment + timedelta(seconds=2),
                    f"sshd[{pid}]: Failed password for invalid user {user} from {source} "
                    f"port {port} ssh2",
                )
            )

        lines.sort(key=lambda item: item[0])
        rendered = "".join(
            f"{when.strftime('%b %e %H:%M:%S')} {self.hostname} {text}\n" for when, text in lines
        )
        self.write("/var/log/auth.log", rendered, mode=0o640, when=self.now - timedelta(minutes=12))

    def _render_syslog(self) -> None:
        lines: list[tuple[datetime, str]] = []
        moments = scatter_events(
            self.now - timedelta(days=7),
            self.now - timedelta(minutes=5),
            per_active_hour=1.4,
            workday_start=self.workday[0],
            workday_end=self.workday[1],
            rng=self.rng,
        )
        for moment in moments:
            lines.append((moment, self.rng.choice(_SYSLOG_LINES).format(pid=self.rng.randint(400, 30000))))

        # Cron is the thing that runs at 2am on a machine nobody is using.
        cursor = self.now - timedelta(days=7)
        while cursor < self.now:
            nightly = cursor.replace(hour=2, minute=17, second=self.rng.randint(0, 59))
            if nightly < self.now:
                pid = self.rng.randint(400, 30000)
                lines.append((nightly, f"CRON[{pid}]: (backup) CMD (/opt/deploy/nightly-sync.sh >/dev/null 2>&1)"))
            cursor += timedelta(days=1)

        lines.sort(key=lambda item: item[0])
        rendered = "".join(
            f"{when.strftime('%b %e %H:%M:%S')} {self.hostname} {text}\n" for when, text in lines
        )
        self.write("/var/log/syslog", rendered, mode=0o640, when=self.now - timedelta(minutes=3))

    def _render_shell_histories(self) -> None:
        """Per-user shell history that reads like work, not like a script.

        This is also where the decoy chain's first breadcrumb sits: devuser's
        history references the deploy script and the erp host, which is how a
        curious attacker learns those exist without being handed them.
        """
        for user in self.identity["users"]:
            profile = user.get("profile")
            commands = _HISTORY.get(profile)
            if not commands:
                continue
            home = self.path(f"/home/{user['name']}")
            if not home.exists():
                continue
            history = home / ".bash_history"
            history.write_text("\n".join(commands) + "\n", encoding="utf-8")
            history.chmod(0o600)
            self.set_time(history, self.random_moment(1, 14))
            self.run("chown", f"{user['name']}:{user['name']}", str(history))

    # -- decoys ------------------------------------------------------------

    def render_decoys(self) -> None:
        """Plant the two-step chain and record every honeytoken planted.

        Note what is not here: the string FAKE. The prototype's bait contained
        AKIAIOSFODNN7FAKE00 and glpat-xxFAKETOKENxx1234, which any attacker
        greps for in seconds. These are format-valid and indistinguishable
        from real credentials by inspection; what makes them safe is that they
        are registered as honeytokens, so using one raises an alert rather
        than granting access.
        """
        chain = self.identity["decoy_chain"]
        target = chain["target"]

        aws_key = _aws_access_key(self.rng)
        aws_secret = _aws_secret(self.rng)
        gitlab_token = _gitlab_token(self.rng)
        db_password = _password(self.rng)

        self._record_token("aws_access_key_id", aws_key, "/opt/deploy/sync-erp.sh")
        self._record_token("aws_secret_access_key", aws_secret, "/opt/deploy/sync-erp.sh")
        self._record_token("gitlab_pat", gitlab_token, "/home/devuser/.git-credentials")
        self._record_token("db_password", db_password, "/opt/deploy/sync-erp.sh")

        key_path = chain["key"]["path"]

        # Step one: a readable deploy script that names where the key lives.
        self.write(
            chain["hint"]["path"],
            "#!/bin/bash\n"
            "# Nightly content sync to the ERP staging host.\n"
            "# Owner: ta_miller  |  raise a ticket before editing\n"
            "set -euo pipefail\n"
            "\n"
            f'REMOTE_HOST="{target}"\n'
            'REMOTE_USER="deploy"\n'
            f'DEPLOY_KEY="${{DEPLOY_KEY:-{key_path}}}"\n'
            "\n"
            "# TODO: move these into the vault, ticket ITS-2291\n"
            f'export AWS_ACCESS_KEY_ID="{aws_key}"\n'
            f'export AWS_SECRET_ACCESS_KEY="{aws_secret}"\n'
            f'export ERP_DB_PASSWORD="{db_password}"\n'
            "\n"
            'if [[ ! -r "$DEPLOY_KEY" ]]; then\n'
            '  echo "deploy key not readable by $(whoami)" >&2\n'
            "  exit 1\n"
            "fi\n"
            "\n"
            'rsync -az --delete -e "ssh -i $DEPLOY_KEY -o StrictHostKeyChecking=no" \\\n'
            '  /srv/erp-content/ "${REMOTE_USER}@${REMOTE_HOST}:/srv/erp-content/"\n',
            mode=0o755,
            when=self.random_moment(30, 120),
        )

        # Step two: the key, owned by another user and unreadable without
        # escalating. devuser has sudo, so this is a step, not a wall.
        self.write(
            key_path,
            _openssh_private_key(self.rng),
            mode=0o600,
            when=self.random_moment(120, 200),
        )
        self.run("chown", "ta_miller:ta_miller", str(self.path(key_path)))
        self._record_token("ssh_deploy_key", key_path, key_path)

        self.write(
            "/home/devuser/.git-credentials",
            f"https://oauth2:{gitlab_token}@git.{self.domain}\n",
            mode=0o600,
            when=self.random_moment(20, 90),
        )
        self.run("chown", "devuser:devuser", str(self.path("/home/devuser/.git-credentials")))

        self._render_alternate_route(chain, key_path, target)
        self._write_manifest()

    def _render_alternate_route(self, chain: dict, key_path: str, target: str) -> None:
        """A second, deeper path to the same key, through git history.

        Real systems leak in more than one way, and an attacker who reaches
        for `git log -p` before `find` should be rewarded for it rather than
        hitting a dead end.
        """
        repo = self.path(chain["alternate"]["repo"])
        repo.mkdir(parents=True, exist_ok=True)
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "S. Miller",
            "GIT_AUTHOR_EMAIL": f"ta_miller@{self.domain}",
            "GIT_COMMITTER_NAME": "S. Miller",
            "GIT_COMMITTER_EMAIL": f"ta_miller@{self.domain}",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }

        def git(*args: str, when: datetime) -> None:
            stamp = when.strftime("%Y-%m-%dT%H:%M:%S%z")
            subprocess.run(
                ["git", "-C", str(repo), *args],
                check=True,
                capture_output=True,
                env={**env, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp},
            )

        first = self.random_moment(300, 320)
        second = first + timedelta(days=11)
        third = second + timedelta(days=6)

        git("init", "-q", "-b", "main", when=first)
        (repo / "README.md").write_text(
            "# erp-backend\n\nStaging deployment helpers for the ERP service.\n",
            encoding="utf-8",
        )
        (repo / "deploy.env").write_text(
            f"DEPLOY_HOST={target}\nDEPLOY_USER=deploy\nDEPLOY_KEY={key_path}\n",
            encoding="utf-8",
        )
        git("add", "-A", when=first)
        git("commit", "-q", "-m", "Initial deployment helpers", when=first)

        (repo / "deploy.sh").write_text(
            '#!/bin/bash\nsource "$(dirname "$0")/deploy.env"\n'
            'ssh -i "$DEPLOY_KEY" "${DEPLOY_USER}@${DEPLOY_HOST}" /srv/erp/restart.sh\n',
            encoding="utf-8",
        )
        git("add", "-A", when=second)
        git("commit", "-q", "-m", "Add restart helper", when=second)

        # The removal is the point: the secret is gone from the working tree
        # but still recoverable with `git log -p`, exactly like the real
        # mistake this imitates.
        (repo / "deploy.env").unlink()
        (repo / ".gitignore").write_text("deploy.env\n*.pyc\n__pycache__/\n", encoding="utf-8")
        (repo / "deploy.sh").write_text(
            '#!/bin/bash\n# deploy.env is no longer committed - see the ops runbook\n'
            'source "$(dirname "$0")/deploy.env"\n'
            'ssh -i "$DEPLOY_KEY" "${DEPLOY_USER}@${DEPLOY_HOST}" /srv/erp/restart.sh\n',
            encoding="utf-8",
        )
        git("add", "-A", when=third)
        git("commit", "-q", "-m", "Stop committing deploy.env (creds should not be in git)", when=third)

        self.run("chown", "-R", "devuser:devuser", str(repo))

    def _record_token(self, kind: str, value: str, location: str) -> None:
        self.honeytokens.append({"type": kind, "value": value, "planted_at": location})

    def _write_manifest(self) -> None:
        """Record what was planted, outside the image.

        Phase 4 registers these with the brain's honeytoken store so that a
        credential turning up anywhere else raises a tripwire alert. The
        manifest is written to the build context, never into the node — an
        inventory of our own decoys is the one file an attacker must not find.
        """
        manifest = Path("/tmp/build/honeytokens.json")
        manifest.write_text(
            json.dumps(
                {
                    "node": self.hostname,
                    "generated": self.now.isoformat(),
                    "tokens": self.honeytokens,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"planted {len(self.honeytokens)} honeytokens", file=sys.stderr)

    # -- filesystem realism ------------------------------------------------

    def scatter_mtimes(self) -> None:
        """Spread modification times across the seeded period.

        A tree where every file shares one mtime is a tree that was unpacked,
        not lived in. `ls -lat ~` is a cheap check and attackers do run it.
        """
        for user in self.identity["users"]:
            home = self.path(f"/home/{user['name']}")
            if not home.exists():
                continue
            for item in home.rglob("*"):
                if ".git" in item.parts:
                    continue
                self.set_time(item, self.random_moment(1, 200))
            self.set_time(home, self.random_moment(1, 30))


# --------------------------------------------------------------------------
# content
# --------------------------------------------------------------------------

_SUDO_COMMANDS = [
    "/usr/bin/apt-get update",
    "/usr/bin/systemctl restart ssh",
    "/usr/bin/tail -f /var/log/syslog",
    "/bin/journalctl -u cron",
    "/usr/bin/du -sh /srv/erp-content",
]

_SYSLOG_LINES = [
    "systemd[1]: Started Session {pid} of user devuser.",
    "systemd[1]: Starting Daily apt download activities...",
    "systemd[1]: Finished Daily apt download activities.",
    "cron[{pid}]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)",
    "rsyslogd[{pid}]: rsyslogd was HUPed",
    "systemd-logind[{pid}]: New session {pid} of user ta_miller.",
    "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.233 DST=10.60.0.11 PROTO=TCP DPT=23",
    "node_exporter[{pid}]: level=info msg=\"Listening on\" address=:9100",
]

_HISTORY = {
    "developer": [
        "cd projects/erp-backend",
        "git status",
        "git pull",
        "ls -la",
        "vim deploy.sh",
        "./deploy.sh",
        "tail -50 /var/log/syslog",
        "df -h",
        "cd /opt/deploy",
        "ls -l",
        "cat sync-erp.sh",
        "sudo systemctl status cron",
        "ssh deploy@erp-web",
        "rsync -az /srv/erp-content/ erp-web:/srv/erp-content/",
        "python3 -m http.server 8080",
        "htop",
        "exit",
    ],
    "teaching_assistant": [
        "cd /srv/erp-content",
        "ls -la",
        "du -sh *",
        "sudo tail -f /var/log/auth.log",
        "crontab -l",
        "ssh-keygen -l -f ~/.ssh/id_erp_deploy",
        "exit",
    ],
    "faculty": [
        "ls",
        "cd Documents",
        "ls -la",
        "cat schedule.txt",
        "exit",
    ],
    "student": [
        "ls",
        "python3 assignment2.py",
        "cat results.txt",
        "exit",
    ],
}


def _fake_fingerprint(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(rng.choice(alphabet) for _ in range(43))


def _aws_access_key(rng: random.Random) -> str:
    return "AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))


def _aws_secret(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(rng.choice(alphabet) for _ in range(40))


def _gitlab_token(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    return "glpat-" + "".join(rng.choice(alphabet) for _ in range(20))


def _password(rng: random.Random) -> str:
    words = ["Monsoon", "Trellis", "Quartz", "Falcon", "Harbour", "Lantern"]
    return f"{rng.choice(words)}{rng.randint(10, 99)}!{rng.choice('adfgkmp')}"


def _openssh_private_key(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body = "".join(rng.choice(alphabet) for _ in range(380))
    lines = [body[i : i + 70] for i in range(0, len(body), 70)]
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )


# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--root", default=Path("/"), type=Path)
    args = parser.parse_args()

    identity = yaml.safe_load(args.identity.read_text(encoding="utf-8"))
    renderer = NodeRenderer(identity, args.root)

    renderer.render_identity()
    renderer.render_users()
    renderer.render_sshd()
    renderer.render_history()
    renderer.render_decoys()
    renderer.scatter_mtimes()

    print(f"rendered {renderer.fqdn}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
