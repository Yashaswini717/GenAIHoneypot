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

Closing the loop
----------------
Planting bait is only half of it. A decoy is worth something only if we can
tell whether it worked, and the bandit that chooses between decoys learns from
exactly that. Two things here provide the answer:

  * A decision is scored when the session ends or goes idle, not only when the
    session lives long enough to be classified a second time. Short sessions
    are the common case, so without this the most frequently chosen actions
    were the ones the bandit had the least evidence about.

  * A planted credential appearing in a later command is caught and scored at
    once. That is the strongest signal available -- the attacker did not merely
    find the bait, they believed it -- and it is visible here because every
    command already flows through this process on its way to the brain.

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
import re
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

#: How many recent commands describe what the attacker is doing *now*.
#:
#: This was 40, on the reasoning that intent is a property of a sequence rather
#: than of one command. The reasoning is right; the number was not. Forty is
#: the whole session for any realistic session, so the window never slid --
#: and since every session opens with reconnaissance, reconnaissance outvoted
#: everything that came after it, permanently. Every classification this
#: system had ever made was `reconnaissance`: four of five intent classes and
#: twelve of fifteen decoy actions had never once been reached.
#:
#: It also quietly disabled the bandit's progression reward, which is defined
#: as intent moving along the kill chain. Intent never moved, so
#: REWARD_ESCALATED and REWARD_SESSION_DEESCALATED could not fire and every
#: decision resolved at the same middling 0.4 -- leaving the arms to be
#: compared on a signal that barely varied.
#:
#: Measured against a labelled fourteen-command attack (recon -> privesc ->
#: persistence -> lateral -> exfil), correct classifications by window size:
#:
#:     2 -> 11/13    3 -> 9/13    5 -> 7/13    8 -> 4/13    40 -> 4/13
#:
#: Monotonic, so smaller tracks the attacker better. Three rather than two
#: because one or two commands is a keystroke, not a sequence, and the extra
#: command costs two classifications to buy stability against a single
#: ambiguous line.
CLASSIFY_WINDOW = 3

#: Sessions we stop tracking after this long idle, so a long-running sidecar
#: does not accumulate state for every attacker it has ever seen.
SESSION_TTL = 3600

#: Generation gets its own, much longer budget than the rest of the client.
#:
#: A profile is six to ten sequential model calls, so it takes tens of seconds
#: on a good day and minutes on a slow provider -- while classify and plant are
#: sub-second and want a short timeout so a wedged brain cannot stall the queue.
#: Sharing one 20s deadline meant the sidecar hung up at 20s on a request the
#: brain went on to answer successfully at 26s: the content was generated,
#: charged for, and thrown away unread. This runs in a background task, so a
#: long wait here costs nothing.
GENERATE_TIMEOUT = 300.0


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
    #: Decoy values this session has already been caught using. Reported once
    #: each -- an attacker who runs the same mysql command five times has told
    #: us one thing, not five.
    tripped: set[str] = field(default_factory=set)
    #: Credentials the brain generated into this session's content. Per session
    #: rather than global because they are generated fresh per environment,
    #: unlike the static bundle values.
    extra_tokens: list[tuple[str, str]] = field(default_factory=list)

    @property
    def honeypot_id(self) -> str:
        """Identifies this attacker's environment to the brain.

        Was the bare sensor name, which is shared by every attacker on the
        node. That made honeytoken attribution collective: a credential used by
        one attacker looked, to the reward calculator, like evidence for
        everyone's pending decisions. Keyed by source IP it matches how the
        broker isolates environments in the first place, and it survives a
        returning attacker the same way their container does.
        """
        safe_ip = self.src_ip.replace(":", "-") or "unknown"
        return f"{self.sensor or 'node-01-jump'}-{safe_ip}"


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
        self.resolved = 0
        self.tripped = 0
        self.brain_available: bool | None = None
        #: Generation runs alongside the queue rather than in it. Held so a
        #: running task is not garbage collected, and so shutdown can wait.
        self._tasks: set[asyncio.Future] = set()

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
            expired: list[SessionState] = []
            try:
                event = await self.queue.get()
                await self._handle(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.error("brain courier error", exc_info=True)
            finally:
                expired = self._expire_sessions()

            # Resolved out here rather than in the finally: awaiting during a
            # CancelledError unwind would delay shutdown, and on that path the
            # brain is going away too.
            for state in expired:
                await self._resolve_on_close(state, reason="idle")

    async def _handle(self, event: dict[str, Any]) -> None:
        session_id = event.get("session")
        if not session_id:
            return

        eventid = event.get("eventid", "")
        state = self.sessions.get(session_id)

        if eventid == "cowrie.session.closed":
            self.sessions.pop(session_id, None)
            # Nothing else will ever resolve this session's last decision.
            #
            # /intent-classify resolves the *previous* decision each time it is
            # called again for the same session, so a decision only ever scores
            # if the session survives long enough to be classified twice. With
            # CLASSIFY_EVERY = 2 that is four commands. Sessions shorter than
            # that -- a look around and a disconnect, which is the common case,
            # not the edge case -- left a decision pending forever, so the arms
            # the bandit picked most often were the ones it learned least about.
            if state is not None:
                await self._resolve_on_close(state, reason="closed")
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

        # Before anything else: did they just use something we planted? This is
        # checked on every command, independently of the classify cadence,
        # because a credential being used is the single most informative thing
        # an attacker can do and it must not wait for a rate limit.
        await self._check_tripwire(state, command)

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
            # A sliding window, not the whole session. Intent is a property of
            # a sequence, but of the *recent* one -- what they are doing now,
            # not everything they have ever done. See CLASSIFY_WINDOW.
            "commands": state.commands[-CLASSIFY_WINDOW:],
            "event_timestamps": [t for t in state.timestamps[-CLASSIFY_WINDOW:] if t],
            "source_ip": state.src_ip,
            "session_id": state.session_id,
            "metadata": {"honeypot_id": state.honeypot_id},
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

        # The bundle goes in now, and the generated profile follows in the
        # background if the brain can produce one.
        #
        # Not the other way round, and not "wait and plant only the better one":
        # a full profile is several sequential model calls, so waiting would
        # stall adaptation for every other attacker behind this one in the queue
        # and leave this attacker looking at an empty home directory in the
        # meantime. The bundle is instant and works with no API key at all, so
        # it is the floor; generated content is the improvement on top.
        self._spawn(self._generate_and_plant(state, action, intent))

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
            return

        # Only after the files are actually in place. Declaring bait we failed
        # to plant would leave the store claiming an exposure that does not
        # exist.
        await self._register_tokens(state, action)

    # -- generated content -------------------------------------------------

    def _spawn(self, coro: Any) -> None:
        """Run something alongside the queue without blocking it.

        The task is held in a set until it finishes: asyncio only keeps a weak
        reference to a running task, so a fire-and-forget `create_task` can be
        garbage collected mid-flight and simply never complete.
        """
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _generate_and_plant(self, state: SessionState, action: str, intent: str) -> None:
        """Ask the brain for real generated content and plant what comes back.

        This is the half of the loop that was previously written to a directory
        inside the brain's own container, where nothing could read it. The brain
        still generates exactly the same profiles; it now hands them back rather
        than filing them somewhere unreachable, and this process — which can
        reach the broker — puts them where the attacker will find them.

        Failure is ordinary, not exceptional: with no model key configured the
        brain answers 503 and the bundle that was already planted stands on its
        own. That is the documented degradation, and it is why the bundle goes
        in first.
        """
        try:
            response = await self.client.post(
                f"{self.brain_url}/api/v1/decoys/generate",
                json={"action": action, "honeypot_id": state.honeypot_id},
                timeout=GENERATE_TIMEOUT,
            )
            if response.status_code == 503:
                log.info("brain produced nothing for %r; bundle stands alone", action)
                return
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            # Deliberately not debug. This was debug once, and a timeout here
            # meant generated content was silently discarded with nothing in
            # the log to say so -- the bundle still landed, so the loop looked
            # healthy while the generative half was quietly doing nothing.
            log.warning("generation request failed for %r: %s", action, exc)
            return

        files = body.get("files") or []
        if not files:
            return

        # Watch for the credentials that were generated into this content, or
        # the richer decoys would be the only ones with no tripwire behind them.
        for token in body.get("tokens") or []:
            value = token.get("token_value")
            if value and len(value) >= 10:
                state.extra_tokens.append((token.get("token_type", "generated"), value))

        planted = await self._plant_files(state, f"{action}:generated", intent, files)
        if planted:
            log.info(
                "planted generated %s for %s (%d file(s), %d tracked credential(s))",
                body.get("profile", "?"),
                state.src_ip,
                len(files),
                len(body.get("tokens") or []),
            )

    async def _plant_files(
        self, state: SessionState, action: str, intent: str, files: list[dict[str, Any]]
    ) -> bool:
        """POST a set of files to the broker for placement. Never raises."""
        try:
            response = await self.client.post(
                f"{self.broker_url}/session/decoys",
                json={
                    "src_ip": state.src_ip,
                    "action": action,
                    "intent": intent,
                    "files": files,
                },
            )
            response.raise_for_status()
            return True
        except Exception as exc:
            log.warning("could not plant %s for %s: %s", action, state.src_ip, exc)
            return False

    # -- tripwire ----------------------------------------------------------

    async def _check_tripwire(self, state: SessionState, command: str) -> None:
        """Catch a planted credential being used, and score it immediately.

        Matching is plain substring containment against the decoy values, which
        is the right test for the thing being caught: a credential typed into a
        command line appears verbatim, whether as `-pTr3llis!84m`, inside a
        connection string, or echoed into a config file. Every declared value is
        long and random enough that an accidental match is not a realistic
        concern -- `_verify_tokens` enforces a length floor for exactly that.

        Reading the decoy file is deliberately NOT a trigger. `ls -la ~/.aws`
        and `cat credentials` say the attacker found the bait; using the
        credential says they believed it. Only the second is worth a reward of
        1.0, and only the second is unambiguous.
        """
        if not isinstance(command, str):
            return  # malformed event; a substring test would raise on it

        # Static bundle values plus anything the brain generated for this
        # session specifically.
        candidates = ALL_TOKEN_VALUES + tuple(state.extra_tokens)
        hits = [
            (token_type, value)
            for token_type, value in candidates
            if value in command and value not in state.tripped
        ]
        if not hits:
            return

        for token_type, value in hits:
            state.tripped.add(value)
            self.tripped += 1
            log.warning(
                "TRIPWIRE session %s (%s): used decoy %s",
                state.session_id,
                state.src_ip,
                token_type,
            )
            await self._report_trip(state, token_type, value)

        # Resolve here rather than leaving it to the next classify.
        #
        # The implicit path would ask RewardCalculator, which decides by
        # listing tokens for a honeypot_id and comparing timestamps -- workable,
        # but it credits by environment while this credits by session, and this
        # process is the only thing that knows which session actually typed the
        # credential. Resolving now also means the decoy that led them here is
        # scored while it is still obviously the cause.
        await self._resolve_hit(state)

    async def _report_trip(self, state: SessionState, token_type: str, value: str) -> None:
        """Record the access in the brain's store, registering the value if new.

        Registration first because a value can be reached without ever having
        been planted by us: the same database password is seeded into the node
        image at build time, so an attacker can find and use it having never
        been shown a bundle. Registration is idempotent, so paying for it here
        costs one request and removes that whole gap.
        """
        payload = {
            "token_type": token_type,
            "token_value": value,
            "honeypot_id": state.honeypot_id,
            "token_metadata": {
                "source": "sidecar_tripwire",
                "session": state.session_id,
                "src_ip": state.src_ip,
            },
        }
        try:
            await self.client.post(f"{self.brain_url}/api/v1/honeytokens/", json=payload)
            await self.client.post(
                f"{self.brain_url}/api/v1/honeytokens/check",
                json={"token_value": value},
            )
        except Exception as exc:
            log.warning("could not report a tripwire for %s: %s", state.src_ip, exc)

    async def _resolve_hit(self, state: SessionState) -> None:
        """Score the pending decision at 1.0 -- the attacker took the bait."""
        if state.pending_decision is None:
            return
        try:
            response = await self.client.post(
                f"{self.brain_url}/api/v1/adaptive/feedback",
                json={"session_id": state.session_id, "signal": "honeytoken_triggered"},
            )
            response.raise_for_status()
            count = response.json().get("decisions_resolved", 0)
        except Exception as exc:
            log.warning("could not score a tripwire hit for %s: %s", state.src_ip, exc)
            return

        self.resolved += count
        state.pending_decision = None
        log.info(
            "session %s: resolved %d decision(s) as honeytoken_triggered",
            state.session_id,
            count,
        )

    async def _register_tokens(self, state: SessionState, action: str) -> None:
        """Declare a bundle's credentials up front, as it is planted.

        Not strictly required -- `_report_trip` registers on demand -- but it
        means `GET /honeytokens/` answers "what bait is currently out there"
        for an analyst, rather than only ever listing bait that has already
        been used.
        """
        for token_type, value in BUNDLE_TOKENS.get(action, []):
            try:
                await self.client.post(
                    f"{self.brain_url}/api/v1/honeytokens/",
                    json={
                        "token_type": token_type,
                        "token_value": value,
                        "honeypot_id": state.honeypot_id,
                        "file_path": action,
                        "token_metadata": {"source": "decoy_bundle", "action": action},
                    },
                )
            except Exception as exc:
                log.debug("could not pre-register %s for %s: %s", token_type, action, exc)

    # -- resolution --------------------------------------------------------

    async def _resolve_on_close(self, state: SessionState, *, reason: str = "closed") -> None:
        """Score the session's last decoy decision now that the session is over.

        Which signal to send is decided by whether the attacker did anything at
        all after the decoy was planted. `unclassified` is the number of
        commands seen since the last classification, so it answers exactly that
        without inventing a duration threshold:

            0 commands   they were shown a decoy and left      -> terminated, 0.0
            1+ commands  they kept working, just not long
                         enough to trip the next classify      -> continued, 0.4

        Sending a flat 0.0 for both would punish an arm for a session that was
        still going; sending 0.4 for both would reward one that ended on the
        spot. The distinction is free -- the courier already tracks it.

        NOTE for the honeytoken tripwire work: this path calls
        `resolve_pending_for_session`, which applies the reward directly and
        does NOT consult `RewardCalculator`. That is correct only while nothing
        can trigger a honeytoken. Once a tripwire exists, a token tripped during
        this session must win over both signals here, or session close will
        overwrite the strongest evidence the bandit can get with a 0.
        """
        if state.pending_decision is None:
            # Never classified, so the bandit was never asked and there is
            # nothing outstanding. Most sessions end here.
            return

        engaged = state.unclassified > 0
        signal = "session_continued" if engaged else "session_terminated"

        try:
            response = await self.client.post(
                f"{self.brain_url}/api/v1/adaptive/feedback",
                json={"session_id": state.session_id, "signal": signal},
            )
            response.raise_for_status()
            count = response.json().get("decisions_resolved", 0)
        except Exception as exc:
            # Losing one reward update is survivable and must never disturb the
            # hub branch, which has already shipped this event regardless.
            log.warning(
                "could not resolve session %s (%s): %s", state.session_id, reason, exc
            )
            return

        self.resolved += count
        log.info(
            "session %s %s: resolved %d decision(s) as %s "
            "(%d command(s) after the last decoy; %d total)",
            state.session_id,
            reason,
            count,
            signal,
            state.unclassified,
            self.resolved,
        )

    async def close(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.client.aclose()

    def _expire_sessions(self) -> list[SessionState]:
        """Drop sessions we have stopped hearing from, and hand them back.

        A session can go quiet without ever producing `session.closed` -- the
        TCP connection stays open while the attacker does nothing, and the
        wall-clock cap is six hours against this hour-long TTL. Those used to be
        popped and forgotten, which leaked a pending decision exactly the way an
        unreported close did. Returning them lets the caller score them instead.
        """
        cutoff = time.time() - SESSION_TTL
        expired = [v for v in self.sessions.values() if v.last_seen < cutoff]
        for state in expired:
            self.sessions.pop(state.session_id, None)
        return expired


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


# --------------------------------------------------------------------------
# Which values in those bundles are tripwires
# --------------------------------------------------------------------------
#
# A planted file is only bait. The moment worth catching is the attacker
# *using* what they found -- and that moment is visible, because the proxy
# reconstructs every command and this process reads all of them. The README's
# own walkthrough ends with the attacker typing
#
#     mysql -h db-01 -u erp_admin -pTr3llis!84m -e "select count(*) ..."
#
# which puts the credential in the command stream in plain text. Matching
# against known decoy values turns that into the one unambiguous reward signal
# the bandit has: they did not merely see the bait, they acted on it.
#
# Only credentials go here. A fake cron entry or a network map has nothing an
# attacker would ever type back, so those bundles simply have no tripwire.
#
# Note Tr3llis!84m appears under two different actions. That is exactly why
# registration has to be idempotent by value.

#: How each kind of credential is recognised inside a bundle's own content.
#:
#: The values are NOT repeated here. They used to be -- copied out of the
#: bundles above into a parallel table -- which meant the same secret appeared
#: twice in this file and could drift out of sync if a decoy were edited. It
#: also doubled what a secret scanner finds, and a repository whose product is
#: convincing fake credentials trips those constantly.
#:
#: Locators instead: each pattern captures the value where it already lives.
TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key":    re.compile(r"aws_access_key_id\s*=\s*(\S+)"),
    "aws_secret_key":    re.compile(r"aws_secret_access_key\s*=\s*(\S+)"),
    "ssh_public_key":    re.compile(r"ssh-rsa\s+(\S{40,})"),
    "ssh_private_key":   re.compile(r"^([A-Za-z0-9+/]{60,}=*)$", re.M),
    "password_hash":     re.compile(r"(\$2[aby]\$\d{2}\$[A-Za-z0-9./]{10,})"),
    "gitlab_token":      re.compile(r"\b(gl-[A-Za-z0-9_\-]{10,})"),
    "vault_token":       re.compile(r"\b(hvs\.[A-Za-z0-9_\-]{10,})"),
    "jwt":               re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"),
    "database_password": re.compile(r"(?:DB_PASSWORD|password)\s*=?\s+?=?\s*(\S+)"),
}

#: What each bundle is expected to yield, and how many of each.
#:
#: The counts are the guard. A pattern that stops matching -- because a decoy
#: was reworded, or a new one was added without a locator -- fails loudly at
#: import instead of quietly leaving that credential with no tripwire behind
#: it, which is the failure mode this whole mechanism exists to prevent.
BUNDLE_TOKEN_SPEC: dict[str, dict[str, int]] = {
    "plant_honeytoken_credentials":     {"aws_access_key": 2, "aws_secret_key": 2},
    "expose_fake_authorized_keys":      {"ssh_public_key": 1},
    "plant_ssh_honeytoken":             {"ssh_private_key": 1},
    "plant_tracked_honeytoken_archive": {"password_hash": 2},
    "populate_developer_workstation":   {"gitlab_token": 1, "database_password": 1, "jwt": 1},
    "populate_production_server":       {"vault_token": 1},
    "populate_database_server":         {"database_password": 2},
}

#: Minimum length for a value to be used as a tripwire. Short strings match
#: innocuous commands; `password = 1234` would fire on half of everything.
_MIN_TOKEN_LEN = 10


def _extract_tokens() -> dict[str, list[tuple[str, str]]]:
    """Pull each bundle's credentials out of the content it already carries."""
    found: dict[str, list[tuple[str, str]]] = {}
    for action, expected in BUNDLE_TOKEN_SPEC.items():
        bundle = DECOY_BUNDLES.get(action)
        assert bundle is not None, f"BUNDLE_TOKEN_SPEC names an unknown action: {action}"
        body = "\n".join(content for _, content, _ in bundle)

        entries: list[tuple[str, str]] = []
        for token_type, count in expected.items():
            pattern = TOKEN_PATTERNS[token_type]
            values = [v for v in pattern.findall(body) if len(v) >= _MIN_TOKEN_LEN]
            # De-duplicate while preserving order: the same password legitimately
            # appears in two places inside one bundle.
            seen, unique = set(), []
            for v in values:
                if v not in seen:
                    seen.add(v)
                    unique.append(v)
            assert len(unique) >= count, (
                f"{action}: expected {count} {token_type} value(s), found "
                f"{len(unique)}. The decoy was edited without updating its "
                f"locator, and that credential would have had no tripwire."
            )
            entries.extend((token_type, v) for v in unique[:count])
        found[action] = entries
    return found


BUNDLE_TOKENS: dict[str, list[tuple[str, str]]] = _extract_tokens()


#: Every distinct decoy credential, scanned against each reconstructed command.
#: Flattened once at import rather than per command -- this runs on every
#: command from every attacker. Keyed by value so a password appearing in two
#: bundles is scanned for once.
ALL_TOKEN_VALUES: tuple[tuple[str, str], ...] = tuple(
    {
        value: (token_type, value)
        for tokens in BUNDLE_TOKENS.values()
        for token_type, value in tokens
    }.values()
)
