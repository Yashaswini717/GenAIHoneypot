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
            # ASCII only. The motd is rendered by a terminal whose encoding we
            # do not control, and an em-dash came back as a replacement
            # character in a real session — a small thing, but a real server's
            # banner does not have mojibake in it.
            f"  {host['role']} - {self.fqdn}\n"
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
            # Real passwords for login accounts, locked for the rest.
            #
            # These were previously locked with `usermod -p '!'` on the theory
            # that authentication belongs to the proxy. That was wrong twice
            # over: `sudo` then failed for everyone with "Sorry, try again",
            # which no working dev box does, and it dead-ended the decoy chain
            # whose second step is `sudo cat` on another user's key. The proxy
            # gets the same passwords from tools/bootstrap.py, so the two
            # never disagree.
            password = user.get("password")
            if user.get("login") and password:
                subprocess.run(
                    ["chpasswd"],
                    input=f"{name}:{password}\n".encode(),
                    check=True,
                    capture_output=True,
                )
            else:
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

    # -- lived-in home directories -----------------------------------------

    def render_homes(self) -> None:
        """Give every account a home that looks used.

        Nothing populated homes before this, and it showed: `/home/test` was
        completely empty and `/home/devuser` held a single `projects` folder.
        An attacker who lands in an empty home on a machine claiming ninety
        days of uptime has learned everything they need in one `ls`.

        Content is per role. A TA's home does not look like a student's, a
        student's does not look like a developer's, and the shared `test`
        account looks like what it is: an account someone created years ago
        and never cleaned up.
        """
        for user in self.identity["users"]:
            name = user["name"]
            profile = user.get("profile")
            home = self.path(f"/home/{name}")
            if not home.exists():
                continue

            files = HOME_CONTENT.get(profile, {})
            for relative, body in files.items():
                target = home / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    body.format(domain=self.domain, host=self.hostname),
                    encoding="utf-8",
                )
                target.chmod(0o600 if relative.startswith(".") else 0o644)

            # ssh client state, which every account that reaches other hosts
            # accumulates. known_hosts naming the pivot targets is a hint in
            # its own right, and its absence on a jump box would be strange.
            if profile in ("developer", "teaching_assistant"):
                ssh_dir = home / ".ssh"
                ssh_dir.mkdir(parents=True, exist_ok=True)
                ssh_dir.chmod(0o700)
                (ssh_dir / "known_hosts").write_text(
                    "\n".join(
                        f"{entry['name']},{entry['address']} ssh-ed25519 "
                        f"AAAAC3NzaC1lZDI1NTE5AAAAI{_fake_fingerprint(self.rng)[:32]}"
                        for entry in self.identity.get("known_hosts", [])
                    )
                    + "\n",
                    encoding="utf-8",
                )
                (ssh_dir / "config").write_text(
                    "Host erp erp-web\n"
                    f"  HostName erp-web.{self.domain}\n"
                    "  User deploy\n"
                    "  IdentityFile ~/.ssh/id_erp_deploy\n"
                    "\n"
                    "Host db-01\n"
                    f"  HostName db-01.{self.domain}\n"
                    "  User dbadmin\n",
                    encoding="utf-8",
                )
                for item in ssh_dir.iterdir():
                    item.chmod(0o600)

            self.run("chown", "-R", f"{name}:{name}", str(home))

    # -- the rest of the estate --------------------------------------------

    def render_environment(self) -> None:
        """Populate the parts of the filesystem the story depends on.

        Every one of these is referenced somewhere an attacker can read, and
        a reference that leads nowhere is worse than no reference at all. The
        sshd_config comment points at /opt/deploy/CHANGELOG; cron logs a
        nightly run of /opt/deploy/nightly-sync.sh; the deploy script rsyncs
        /srv/erp-content. Before this, all three were missing, /var/backups
        was empty despite a nightly backup job, and /var/mail had nothing in
        it despite cron running for ninety days.
        """
        # The content the deploy script actually syncs.
        for relative, body in ERP_CONTENT.items():
            self.write(f"/srv/erp-content/{relative}", body, when=self.random_moment(1, 40))

        self.write(
            "/opt/deploy/CHANGELOG",
            "2026-02-14  ssh hardening applied per CIS benchmark (ITS-2104)\n"
            "2026-03-02  rotated deploy key after ta handover\n"
            "2026-04-19  nightly-sync moved to 02:17 to clear the backup window\n"
            "2026-06-08  added erp-content pre-flight check\n"
            "2026-07-30  reviewed sshd config, no changes\n",
            when=self.random_moment(25, 40),
        )

        self.write(
            "/opt/deploy/nightly-sync.sh",
            "#!/bin/bash\n"
            "# Wrapper invoked from the backup user's crontab at 02:17.\n"
            "set -eo pipefail\n"
            'LOG="/var/log/erp-sync.log"\n'
            'echo "[$(date -Is)] nightly sync starting" >> "$LOG"\n'
            '/opt/deploy/sync-erp.sh >> "$LOG" 2>&1 || echo "[$(date -Is)] sync FAILED" >> "$LOG"\n'
            'tar czf "/var/backups/erp-content-$(date +%Y%m%d).tar.gz" /srv/erp-content 2>/dev/null\n'
            'find /var/backups -name "erp-content-*.tar.gz" -mtime +14 -delete\n',
            mode=0o755,
            when=self.random_moment(25, 40),
        )

        # Backups the nightly job would have left behind, with the retention
        # window the script itself declares.
        for days_ago in range(1, 15):
            when = self.now - timedelta(days=days_ago)
            stamp = when.strftime("%Y%m%d")
            path = self.write(
                f"/var/backups/erp-content-{stamp}.tar.gz",
                f"\x1f\x8b\x08\x00{'archive placeholder ' * self.rng.randint(40, 90)}",
            )
            self.set_time(path, when.replace(hour=2, minute=18))

        # The log that job appends to.
        sync_lines = []
        for days_ago in range(60, 0, -1):
            when = (self.now - timedelta(days=days_ago)).replace(hour=2, minute=17)
            sync_lines.append(f"[{when.isoformat()}] nightly sync starting")
            if self.rng.random() < 0.06:
                sync_lines.append(f"[{when.isoformat()}] sync FAILED")
        self.write("/var/log/erp-sync.log", "\n".join(sync_lines) + "\n", mode=0o644)

        # Cron mail. An account that has existed for months with an empty
        # mail spool has never had a cron job fail, which is not how servers
        # work.
        self.write(
            "/var/mail/devuser",
            "From root@{host}  Tue Aug 11 02:17:41 2026\n"
            "From: root@{host} (Cron Daemon)\n"
            "To: devuser@{host}\n"
            "Subject: Cron <backup@{host}> /opt/deploy/nightly-sync.sh\n"
            "\n"
            "rsync: connection unexpectedly closed (0 bytes received so far)\n"
            "rsync error: error in rsync protocol data stream (code 12)\n"
            "\n".format(host=self.hostname),
            mode=0o660,
            when=self.random_moment(14, 18),
        )
        self.run("chown", "devuser:mail", str(self.path("/var/mail/devuser")))

        # Real crontabs, so `crontab -l` and /etc/cron.d agree with the
        # syslog entries and with the mail above.
        self.write(
            "/etc/cron.d/erp-sync",
            "# Nightly ERP staging sync\n"
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "MAILTO=devuser\n"
            "17 2 * * *  root  /opt/deploy/nightly-sync.sh\n"
            "*/15 * * * *  root  /usr/bin/find /tmp -type f -mtime +7 -delete\n",
        )

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


#: Per-role home directory content.
#
# Written through str.format with {domain} and {host}, so any literal brace in
# a value must be doubled. Keep shell variables out of these files for that
# reason; scripts belong in render_environment where no formatting happens.
HOME_CONTENT: dict[str, dict[str, str]] = {
    "developer": {
        "notes.txt": (
            "ERP staging notes\n"
            "=================\n"
            "- staging box is erp-web, deploy user is 'deploy'\n"
            "- key lives with ta_miller since the handover, ask before rotating\n"
            "- db-01 only accepts connections from erp-web, not from here\n"
            "- nightly sync runs 02:17, check /var/log/erp-sync.log if content is stale\n"
            "- ITS ticket for moving creds into the vault: ITS-2291 (still open)\n"
        ),
        "TODO.md": (
            "# This week\n\n"
            "- [x] patch sshd config to match the CIS profile\n"
            "- [x] move nightly sync off the backup window\n"
            "- [ ] rotate the deploy key, it predates the TA handover\n"
            "- [ ] get creds out of sync-erp.sh and into the vault (ITS-2291)\n"
            "- [ ] attendance-api still has no tests\n"
            "- [ ] ask prof davis about the exam server capacity for December\n"
        ),
        "Documents/handover.md": (
            "Handover notes\n"
            "==============\n\n"
            "Written up after Sanjay left in March.\n\n"
            "Deployments\n"
            "-----------\n"
            "Everything staging goes through /opt/deploy/sync-erp.sh. It reads the\n"
            "deploy key from a path set in DEPLOY_KEY; the default in the script is\n"
            "correct. Sanjay kept the key in his home, we moved it to ta_miller\n"
            "so the TAs could run deployments during the semester.\n\n"
            "Databases\n"
            "---------\n"
            "db-01 is reachable from erp-web only. If you need a dump, run it there\n"
            "and rsync it back rather than opening the firewall.\n\n"
            "Access\n"
            "------\n"
            "Everyone in the sudo group can run the deploy. Students on this box\n"
            "have no sudo and should not need it.\n"
        ),
        "Documents/meeting-2026-07-14.md": (
            "Infra sync, 14 July\n"
            "===================\n"
            "Present: devuser, ta_miller, prof davis (partial)\n\n"
            "- exam server load last semester peaked at 340 concurrent, we sized for 200\n"
            "- agreed to move the results endpoint off the ERP box before December\n"
            "- prof davis wants read-only access to the attendance API for his TAs\n"
            "- ITS still have not scheduled the vault migration, chase in August\n"
        ),
        "projects/attendance-api/README.md": (
            "# attendance-api\n\n"
            "Flask service backing the attendance kiosks in the CS block.\n\n"
            "Runs on erp-web behind nginx at /api/attendance. Config comes from\n"
            "the environment; see the deployment notes in Documents/handover.md.\n\n"
            "No tests yet. Sorry.\n"
        ),
        "projects/attendance-api/app.py": (
            "from datetime import date\n\n"
            "from flask import Flask, jsonify, request\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.get('/api/attendance/<course>')\n"
            "def attendance(course):\n"
            "    # TODO: this still trusts the course code from the caller\n"
            "    rows = query_attendance(course, date.today())\n"
            "    return jsonify(rows)\n\n\n"
            "@app.post('/api/attendance/<course>')\n"
            "def mark(course):\n"
            "    payload = request.get_json()\n"
            "    return jsonify(record(course, payload)), 201\n"
        ),
        "scratch/db-dump-notes.txt": (
            "pg dump from erp-web, 12 June, before the schema change\n"
            "restored fine on the staging copy\n"
            "do not run this against db-01 directly, it locks the students table\n"
        ),
    },
    "teaching_assistant": {
        "labs/lab04-networks.md": (
            "CS340 Lab 4 - Network Reconnaissance\n"
            "====================================\n\n"
            "Objectives: understand host discovery and service enumeration on a\n"
            "network you are authorised to test.\n\n"
            "Use the lab subnet only. Scanning departmental infrastructure is a\n"
            "disciplinary matter, see the acceptable use policy.\n\n"
            "Submission: writeup as PDF via the ERP portal by Friday 23:59.\n"
        ),
        "labs/lab05-privesc.md": (
            "CS340 Lab 5 - Privilege Escalation\n"
            "==================================\n\n"
            "Covers SUID binaries, sudo misconfiguration and PATH hijacking on the\n"
            "provided lab VM image. Do not attempt any of this on the jump host.\n"
        ),
        "grading/cs340_marks_provisional.csv": (
            "roll,name,lab1,lab2,lab3,lab4,total\n"
            "PES1UG22CS041,A Bhat,8,9,7,9,33\n"
            "PES1UG22CS118,M Rao,7,7,8,6,28\n"
            "PES1UG22CS207,S Nair,9,10,9,10,38\n"
            "PES1UG22CS233,K Iyer,6,5,7,7,25\n"
            "PES1UG22CS301,R Menon,10,9,10,9,38\n"
        ),
        "notes.txt": (
            "deployments are mine since the handover in march\n"
            "key is in .ssh, prof davis has a copy in his safe\n"
            "if the nightly sync fails check erp-web is actually up first\n"
        ),
    },
    "faculty": {
        "courses/cs340/syllabus.md": (
            "CS340 - Systems and Network Security\n"
            "====================================\n\n"
            "Unit 1  Threat models, attacker economics\n"
            "Unit 2  Network reconnaissance and defence\n"
            "Unit 3  Access control, privilege escalation\n"
            "Unit 4  Deception technologies and honeypots\n"
            "Unit 5  Incident response\n\n"
            "Assessment: 40 percent labs, 60 percent end semester.\n"
        ),
        "courses/cs340/exam-plan.txt": (
            "December end-sem\n"
            "one question from unit 4 on deception, they will not expect it\n"
            "lab component moderated by ta_miller\n"
            "capacity request with ITS for 340 concurrent, still pending\n"
        ),
        "Documents/research-notes.md": (
            "# Reading notes\n\n"
            "Provos and Holz on virtual honeypots still the clearest treatment of\n"
            "interaction levels. Worth setting as unit 4 reading.\n\n"
            "The interesting failure mode is not detection of the decoy, it is the\n"
            "operator forgetting the decoy is instrumented.\n"
        ),
    },
    "student": {
        "cs340/lab4/writeup.md": (
            "# Lab 4 writeup\n\n"
            "Scanned the lab subnet as instructed. Found three hosts responding.\n"
            "Still need to finish the service enumeration section before Friday.\n"
        ),
        "cs340/lab4/scan-output.txt": (
            "10.99.4.11  open: 22, 80\n"
            "10.99.4.12  open: 22\n"
            "10.99.4.19  open: 22, 3306\n"
        ),
        "assignment2.py": (
            "# CS340 assignment 2 - simple port scanner\n"
            "import socket\n\n\n"
            "def probe(host, port, timeout=0.4):\n"
            "    s = socket.socket()\n"
            "    s.settimeout(timeout)\n"
            "    try:\n"
            "        s.connect((host, port))\n"
            "        return True\n"
            "    except OSError:\n"
            "        return False\n"
            "    finally:\n"
            "        s.close()\n"
        ),
        "results.txt": "lab1 8\nlab2 7\nlab3 8\n",
    },
    "minimal": {
        # The shared/leftover accounts. Sparse on purpose, but never empty --
        # an account that has existed for months has *something* in it.
        "notes.txt": (
            "temporary account, ask devuser before using\n"
            "was set up for the ITS audit in march, should have been removed\n"
        ),
        ".profile-backup": "# saved before the shell change, 2026-03-04\n",
    },
    "service": {
        "README": (
            "Service account for the ERP content sync. Do not log in as this\n"
            "account; use sudo from your own account instead.\n"
        ),
    },
}

#: What the deploy script actually rsyncs. Referenced by /opt/deploy/sync-erp.sh.
ERP_CONTENT: dict[str, str] = {
    "README": (
        "Staging content root for the ERP service.\n"
        "Synced nightly from jump-01 by /opt/deploy/nightly-sync.sh.\n"
    ),
    "notices/2026-08-semester-registration.html": (
        "<h2>Semester registration opens 1 September</h2>\n"
        "<p>Students must clear pending dues before registering. Contact the\n"
        "department office for exemptions.</p>\n"
    ),
    "notices/2026-07-exam-schedule.html": (
        "<h2>End semester examination schedule</h2>\n"
        "<p>The provisional timetable is available on the student portal.</p>\n"
    ),
    "templates/marksheet.html": (
        "<html><body><h1>Statement of Marks</h1>\n"
        "<!-- populated by the ERP results module -->\n"
        "</body></html>\n"
    ),
    "config/services.yml": (
        "erp:\n"
        "  host: erp-web\n"
        "  port: 8080\n"
        "attendance:\n"
        "  host: erp-web\n"
        "  path: /api/attendance\n"
        "results:\n"
        "  host: db-01\n"
        "  readonly: true\n"
    ),
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
    renderer.render_homes()
    renderer.render_environment()
    renderer.render_history()
    renderer.render_decoys()
    renderer.scatter_mtimes()

    print(f"rendered {renderer.fqdn}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
