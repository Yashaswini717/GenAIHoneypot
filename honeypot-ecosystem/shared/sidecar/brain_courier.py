"""The adaptive half of the cycle.

Every event the sidecar signs goes two ways at once: to the intelligence hub,
which learns the attack patterns, and to here, which feeds the GenAI brain so
the decoys change while the attacker is still typing. Both branches start from
the same signed event, so what the hub analyses and what the brain reacts to
can never diverge.

    attacker -> node -> proxy -> events.ndjson -> sidecar ─┬─> hub    (analysis)
                                                           └─> brain  (decoys)
                                                                 │
                                          decoys <- broker <──────┘

The two branches have different shapes and must not share a code path. The hub
wants every event, in order, one at a time — it is building a record. The brain
wants a session's accumulated behaviour, because intent is a property of a
sequence, not of a single command. So the hub branch stays strictly sequential
while this one runs off a queue: a slow or absent brain can never delay,
reorder, or drop what reaches the hub.

Working without an LLM key
--------------------------
Intent classification does not need one — it is rules plus a RandomForest, so
`/api/v1/intent-classify` works keyless and the adaptive loop is fully
demonstrable. Only content *generation* needs a model, so decoy bodies come
from the brain when it can produce them and from local bundles when it cannot.
Same code path either way, so a key changes the quality of the content and
nothing about the mechanism.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

log = logging.getLogger("sidecar.brain")

#: Classify once a session has this many new commands. One command is rarely
#: enough to infer intent, and waiting for many wastes the early window where
#: adapting still changes the attacker's path.
CLASSIFY_EVERY = 2

#: Do not re-classify faster than this, however fast commands arrive. Protects
#: the brain from a paste-bomb turning into a request flood.
MIN_CLASSIFY_INTERVAL = 1.5

#: Sessions we stop tracking after this long idle, so a long-running sidecar
#: does not accumulate state for every attacker it has ever seen.
SESSION_TTL = 3600


@dataclass
class SessionState:
    session_id: str
    src_ip: str
    sensor: str
    commands: list[str] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    unclassified: int = 0
    last_classified: float = 0.0
    last_seen: float = field(default_factory=time.time)
    pending_decision: str | None = None
    last_intent: str | None = None
    deployed_actions: set[str] = field(default_factory=set)


class BrainCourier:
    """Feeds session behaviour to the brain and plants what it decides."""

    def __init__(
        self,
        *,
        brain_url: str,
        broker_url: str,
        enabled: bool = True,
        timeout: float = 20.0,
    ) -> None:
        self.brain_url = brain_url.rstrip("/")
        self.broker_url = broker_url.rstrip("/")
        self.enabled = enabled
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10000)
        self.sessions: dict[str, SessionState] = {}
        self.client = httpx.AsyncClient(timeout=timeout)
        self.classified = 0
        self.deployed = 0
        self.brain_available: bool | None = None

    # -- ingestion ---------------------------------------------------------

    def offer(self, event: dict[str, Any]) -> None:
        """Hand an event to the brain branch. Never blocks the hub branch."""
        if not self.enabled:
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            # Dropping adaptive input is survivable; delaying the audit trail
            # is not. The hub branch must never wait on this queue.
            log.warning("brain queue full, dropping an event for adaptation")

    # -- main loop ---------------------------------------------------------

    async def run(self) -> None:
        log.info(
            "brain courier %s: %s (decoys via %s)",
            "enabled" if self.enabled else "disabled",
            self.brain_url,
            self.broker_url,
        )
        while True:
            try:
                event = await self.queue.get()
                await self._handle(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.error("brain courier error", exc_info=True)
            finally:
                self._expire_sessions()

    async def _handle(self, event: dict[str, Any]) -> None:
        session_id = event.get("session")
        if not session_id:
            return

        eventid = event.get("eventid", "")
        state = self.sessions.get(session_id)

        if eventid == "cowrie.session.closed":
            self.sessions.pop(session_id, None)
            return

        if eventid != "cowrie.command.input":
            return

        command = event.get("input")
        if not command:
            return

        if state is None:
            state = SessionState(
                session_id=session_id,
                src_ip=event.get("src_ip", ""),
                sensor=event.get("sensor", ""),
            )
            self.sessions[session_id] = state

        state.commands.append(command)
        state.timestamps.append(event.get("timestamp", ""))
        state.unclassified += 1
        state.last_seen = time.time()

        if state.unclassified < CLASSIFY_EVERY:
            return
        if time.time() - state.last_classified < MIN_CLASSIFY_INTERVAL:
            return

        await self._classify_and_adapt(state)

    # -- brain -------------------------------------------------------------

    async def _classify_and_adapt(self, state: SessionState) -> None:
        decision = await self._classify(state)
        if decision is None:
            return

        state.unclassified = 0
        state.last_classified = time.time()
        self.classified += 1

        intent = decision.get("intent")
        action = decision.get("action")
        state.last_intent = intent
        state.pending_decision = decision.get("decision_id")

        log.info(
            "session %s: intent=%s action=%s confidence=%.2f (%s)",
            state.session_id,
            intent,
            action,
            decision.get("confidence", 0.0),
            decision.get("source", "?"),
        )

        if not action or action in state.deployed_actions:
            # Planting the same decoy twice would make files appear to change
            # under the attacker for no reason, which is its own tell.
            return

        await self._deploy(state, action, intent or "unknown")
        state.deployed_actions.add(action)

    async def _classify(self, state: SessionState) -> dict[str, Any] | None:
        """Ask the brain what this attacker is doing and what to show them."""
        payload = {
            # The full sequence, not just the new commands: intent is a
            # property of the whole session's shape.
            "commands": state.commands[-40:],
            "event_timestamps": [t for t in state.timestamps[-40:] if t],
            "source_ip": state.src_ip,
            "session_id": state.session_id,
            "metadata": {"honeypot_id": state.sensor or "node-01-jump"},
        }
        try:
            response = await self.client.post(
                f"{self.brain_url}/api/v1/intent-classify",
                json=payload,
            )
            response.raise_for_status()
            if self.brain_available is not True:
                log.info("brain reachable at %s", self.brain_url)
                self.brain_available = True
            return response.json()
        except Exception as exc:
            if self.brain_available is not False:
                log.warning(
                    "brain unreachable (%s); the hub branch is unaffected", exc
                )
                self.brain_available = False
            return None

    # -- decoys ------------------------------------------------------------

    async def _deploy(self, state: SessionState, action: str, intent: str) -> None:
        """Materialise the chosen decoy into this attacker's own container.

        The sidecar deliberately cannot do this itself: writing into a
        container needs the Docker socket, and the process holding the HMAC
        key must not also hold that. The broker owns container mutation, so
        the request goes there.
        """
        files = DECOY_BUNDLES.get(action)
        if not files:
            log.debug("no decoy bundle defined for action %r", action)
            return

        try:
            response = await self.client.post(
                f"{self.broker_url}/session/decoys",
                json={
                    "src_ip": state.src_ip,
                    "action": action,
                    "intent": intent,
                    "files": [
                        {"path": path, "content": body, "mode": mode}
                        for path, body, mode in files
                    ],
                },
            )
            response.raise_for_status()
            self.deployed += 1
            log.info(
                "planted %r for %s (intent=%s, %d file(s))",
                action,
                state.src_ip,
                intent,
                len(files),
            )
        except Exception as exc:
            log.warning("could not plant decoys for %s: %s", state.src_ip, exc)

    async def close(self) -> None:
        await self.client.aclose()

    def _expire_sessions(self) -> None:
        cutoff = time.time() - SESSION_TTL
        for key in [k for k, v in self.sessions.items() if v.last_seen < cutoff]:
            self.sessions.pop(key, None)


# --------------------------------------------------------------------------
# Offline decoy bundles
# --------------------------------------------------------------------------
#
# Keyed by the brain's action labels (see core/adaptive_actions.py). These are
# the keyless fallback: with an LLM key the brain generates richer content, but
# the loop is fully demonstrable without one, and the mechanism is identical.
#
# Each entry is (path, content, octal mode).

DECOY_BUNDLES: dict[str, list[tuple[str, str, int]]] = {
    "plant_honeytoken_credentials": [
        (
            "/home/devuser/.aws/credentials",
            "[default]\n"
            "aws_access_key_id = AKIA4YTQ2VN6XZDR3PLM\n"
            "aws_secret_access_key = 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\n"
            "region = ap-south-1\n\n"
            "[erp-staging]\n"
            "aws_access_key_id = AKIA7BXK4WPQ5NZTM2RJ\n"
            "aws_secret_access_key = Rz3MvKp8QwLd6TgYhN1cXsE2bJfU9AoPiVmZtQrD\n",
            0o600,
        ),
    ],
    "inject_fake_sudo_config": [
        (
            "/etc/sudoers.d/90-erp-deploy",
            "# Added for the ERP deployment pipeline, ITS-2104\n"
            "devuser  ALL=(ALL) NOPASSWD: /opt/deploy/sync-erp.sh\n"
            "ta_miller ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart erp-*\n",
            0o440,
        ),
    ],
    "expose_fake_authorized_keys": [
        (
            "/home/devuser/.ssh/authorized_keys2",
            "# legacy key file, kept for the jenkins runner\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vN2xKpQmZ4bWtE9RfYuLd3Hs"
            "GnJcVoP1TaXqZmB8wKdEyNrFhQ2uCiLoAvMsXzPbTgJkRnDeWyUqHfMcZaVtBoNx"
            " jenkins@build-01\n",
            0o600,
        ),
    ],
    "simulate_cron_jobs": [
        (
            "/etc/cron.d/erp-report",
            "# Weekly results export for the registrar\n"
            "SHELL=/bin/bash\n"
            "MAILTO=devuser\n"
            "30 3 * * 1  root  /usr/local/bin/erp-export --target db-01 --out /srv/exports\n",
            0o644,
        ),
    ],
    "expose_fake_internal_ips": [
        (
            "/home/devuser/notes-network.txt",
            "internal ranges, from the ITS handover\n"
            "  10.60.0.0/24   cs department services\n"
            "  10.60.4.0/24   lab machines (no route from here)\n"
            "  10.61.0.0/24   registrar / erp production\n"
            "erp-web 10.60.0.21, db-01 10.60.0.31, backup-01 10.60.0.41\n"
            "prod erp is 10.61.0.14, jump via erp-web only\n",
            0o644,
        ),
    ],
    "serve_fake_network_map": [
        (
            "/home/devuser/Documents/network-map.md",
            "# CS department network\n\n"
            "| host       | address     | role                    |\n"
            "|------------|-------------|-------------------------|\n"
            "| jump-01    | 10.60.0.11  | staging jump host       |\n"
            "| erp-web    | 10.60.0.21  | ERP portal, nginx       |\n"
            "| db-01      | 10.60.0.31  | MySQL, student records  |\n"
            "| backup-01  | 10.60.0.41  | nightly archives        |\n\n"
            "db-01 accepts connections from erp-web only.\n",
            0o644,
        ),
    ],
    "plant_ssh_honeytoken": [
        (
            "/home/devuser/.ssh/id_rsa_backup",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt\n"
            "cnNhAAAAAwEAAQAAAYEAwK7pQmZ4bWtE9RfYuLd3HsGnJcVoP1TaXqZmB8wKdEyNrFhQ\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
            0o600,
        ),
    ],
    "serve_fake_sensitive_files": [
        (
            "/srv/exports/students_2026_provisional.csv",
            "roll,name,programme,cgpa,email\n"
            "PES1UG22CS041,A Bhat,BTech CSE,8.42,pes1ug22cs041@pesu.example\n"
            "PES1UG22CS118,M Rao,BTech CSE,7.15,pes1ug22cs118@pesu.example\n"
            "PES1UG22CS207,S Nair,BTech CSE,9.08,pes1ug22cs207@pesu.example\n"
            "PES1UG22CS233,K Iyer,BTech CSE,6.77,pes1ug22cs233@pesu.example\n",
            0o640,
        ),
    ],
    "plant_tracked_honeytoken_archive": [
        (
            "/srv/exports/erp-db-dump-20260812.sql",
            "-- MySQL dump 10.13  Distrib 8.0.36\n"
            "-- Host: db-01    Database: erp\n"
            "USE `erp`;\n"
            "INSERT INTO `admin_users` VALUES\n"
            "  (1,'erp_admin','$2y$10$K7vN2xQpZmB8wKdEyNrFhO','admin@pesu.example'),\n"
            "  (2,'registrar','$2y$10$T9aXqZmB4wKdEyNrFhQ2uC','registrar@pesu.example');\n",
            0o640,
        ),
    ],
    "simulate_privileged_process_list": [
        (
            "/home/devuser/scratch/ps-audit.txt",
            "captured during the incident review, 12 aug\n"
            "root      1842  /usr/sbin/erp-agent --config /etc/erp/agent.conf\n"
            "root      1901  /usr/bin/python3 /opt/erp/results_sync.py --db db-01\n"
            "mysql     2210  /usr/sbin/mysqld --datadir=/var/lib/mysql\n",
            0o644,
        ),
    ],
    "show_fake_endpoints": [
        (
            "/home/devuser/Documents/api-endpoints.md",
            "# Internal endpoints\n\n"
            "- http://erp-web:8080/admin        ERP admin console\n"
            "- http://erp-web:8080/api/results  results export, token auth\n"
            "- http://erp-web/api/attendance    attendance kiosks\n"
            "- mysql://db-01:3306/erp           read replica for reporting\n\n"
            "Admin console is on the internal interface only.\n",
            0o644,
        ),
    ],
}


# The four profile-wide actions. These were left out at first on the grounds
# that they map to whole-profile population rather than a single file drop --
# which was a mistake worth recording: `populate_developer_workstation` is the
# *first* candidate the bandit considers for reconnaissance, and
# reconnaissance is what almost every session starts as. Leaving it unmapped
# meant the most common decision in the entire system planted nothing at all,
# and the adaptive loop looked broken while behaving exactly as written.
#
# Every action in the brain's catalogue now has a bundle. An unmapped action
# is a silent no-op, and silent no-ops are worse than thin content.

DECOY_BUNDLES["populate_developer_workstation"] = [
    (
        "/home/devuser/.netrc",
        "machine git.cs.internal\n"
        "  login devuser\n"
        "  password gl-8QxTv2NmKdRw7ZpLcYh\n",
        0o600,
    ),
    (
        "/home/devuser/projects/erp-backend/.env.local",
        "# local overrides, not committed\n"
        "DB_HOST=db-01\n"
        "DB_USER=erp_admin\n"
        "DB_PASSWORD=Tr3llis!84m\n"
        "ERP_ADMIN_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlcnBfYWRtaW4ifQ\n",
        0o600,
    ),
]

DECOY_BUNDLES["serve_minimal_banner"] = [
    (
        "/home/devuser/scratch/session-notes.txt",
        "reminder: the staging box only accepts the deploy key, not passwords\n"
        "if you need shell there ask ta_miller, they hold the key now\n",
        0o644,
    ),
]

DECOY_BUNDLES["populate_production_server"] = [
    (
        "/opt/deploy/prod-rollout.sh",
        "#!/bin/bash\n"
        "# Production rollout. Requires the registrar sign-off, do not run ad hoc.\n"
        "PROD_HOST=10.61.0.14\n"
        "PROD_USER=erpdeploy\n"
        "VAULT_TOKEN=hvs.CAESIJx7Kd0pQzXn2WvBcE9RmY4uHgL1sJfA6ToPiNxZeV\n"
        "ssh -i /etc/deploy/prod_rsa ${PROD_USER}@${PROD_HOST} /srv/erp/rollout.sh\n",
        0o750,
    ),
]

DECOY_BUNDLES["populate_database_server"] = [
    (
        "/home/devuser/.my.cnf",
        "[client]\n"
        "host = db-01\n"
        "user = erp_readonly\n"
        "password = R3adOnly!2026\n\n"
        "[mysqldump]\n"
        "user = erp_admin\n"
        "password = Tr3llis!84m\n",
        0o600,
    ),
]

assert len(DECOY_BUNDLES) == 15, (
    f"every action in the brain's ACTION_CATALOG needs a bundle; have "
    f"{len(DECOY_BUNDLES)}"
)
