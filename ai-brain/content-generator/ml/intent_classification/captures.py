"""Turns sessions the deployed honeypot captured into holdout transcripts.

Why this exists
---------------
Every labelled session so far was written by the people who wrote the rules,
so even the holdout measured how well the rules cover attacks their authors
thought of. Sessions the sensors actually recorded are the measurement that
counts. This module gets them from the event log into `eval_transcripts.py`
without anyone copying commands around by hand.

Workflow, from ai-brain/content-generator
-----------------------------------------
1. Freeze the classifier: a holdout measures one fixed system, once.
2. Export events. The sensor's own log is complete:

       docker compose -f ../../honeypot-ecosystem/docker-compose.yml cp sidecar:/var/spool/honeypot ./telemetry

   The hub's copy in Elasticsearch works too, 10,000 events per request:

       curl -s "http://localhost:9200/cowrie-events/_search?size=10000&q=event_type:command_exec" -o es.json

   Cowrie logs from elsewhere read the same: cowrie.json*, gzipped or not, or
   a published dataset such as the CyberLab honeynet's (Zenodo 3687527). Pass
   a dataset's citation with --credit; a CC BY licence requires it.
3. Extract sessions to label:

       python -m ml.intent_classification.captures extract ./telemetry --limit 60

4. Label every step R P S L X or N by the guide in eval_transcripts.py, before
   running the classifier on any of them:

       python -m ml.intent_classification.captures label

   A command shaped like one labelled before offers that answer again (Enter
   takes it). Or edit capture_candidates.json by hand; "drop": true leaves a
   session out.
5. Add them as the holdout (written to captured_sessions.json):

       python -m ml.intent_classification.captures add

6. Score once with `python -m ml.intent_classification.evaluation`, give the
   holdout floors in tests/test_intent_eval.py, and treat it as spent from
   then on: set its sessions' "split" to "test" before the next one.

What extraction does
--------------------
Commands are grouped by session and put in time order. Sessions from inside
the estate are skipped -- those are the team's own logins -- unless
--include-private says the sensor sits behind NAT and sees every attacker
that way. Runs of one script become one transcript, even when the script
changes a password, a number or a file name every time (`shape`): a bot
five hundred sessions ran is one data point, or it would outvote everything
else in the holdout. Scripts already labelled are left out. --protocol ssh
keeps what this honeypot can actually be sent: public datasets also hold
telnet IoT bots, whose many variants would otherwise fill the sample. Nothing
the classifier says about a session is written: labels must not lean on it.

The labelled file is meant to be committed, so commands are scrubbed first
(`scrub`). Scrubbing is best effort: read the file before committing it.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import random
import re
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

from .eval_transcripts import CAPTURED_PATH, HAND_WRITTEN, LABEL_CODES, SPLITS, TRANSCRIPTS, load_captured
from .evaluation import MIN_WINDOW, WINDOW
from .rules import is_external_host

#: Fewer commands than this leave the sidecar nothing to classify.
MIN_COMMANDS = 2
#: A median gap between commands shorter than this is a script typing.
BOT_GAP_SECONDS = 2.0
DEFAULT_CANDIDATES = Path("capture_candidates.json")

_ABOUT_CANDIDATES = (
    "Captured sessions to label for the intent-classification holdout. Give every step a label "
    "(R P S L X or N) by the guide in ml/intent_classification/eval_transcripts.py, before running "
    "the classifier on any of them. Set \"drop\": true on a session that should not be scored. "
    "Then: python -m ml.intent_classification.captures add"
)
_ABOUT_CAPTURED = (
    "Sessions the honeypot's sensors captured, labelled by hand (see captures.py). "
    "eval_transcripts.py loads them; each is scored in its own split."
)


# --------------------------------------------------------------------------
# reading events
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Command:
    session: str
    command: str
    timestamp: str
    sensor: str
    #: Who is typing. After a pivot the sensor sees a compromised node
    #: connecting, so the original attacker travels as its own field.
    origin: str


def command_from(event: dict[str, Any]) -> Optional[Command]:
    """The command in a sensor event (Cowrie format) or a hub one (Elasticsearch), if any."""
    if event.get("eventid") == "cowrie.command.input":
        command, sensor = event.get("input"), event.get("sensor")
        session = event.get("session") or event.get("session_id")
        if command is None and str(event.get("message", "")).startswith("CMD: "):
            # Published datasets often keep only Cowrie's log line (CyberLab's does).
            command = str(event["message"])[len("CMD: "):]
    elif event.get("event_type") == "command_exec":
        command, session, sensor = event.get("command"), event.get("session_id"), event.get("sensor_id")
    else:
        return None
    timestamp = event.get("timestamp")
    if not isinstance(command, str) or not command.strip() or not session or not timestamp:
        return None
    origin = event.get("attacker") or event.get("attacker_id") or event.get("src_ip") or ""
    return Command(str(session), command.strip(), str(timestamp), str(sensor or ""), str(origin))


_LOG_NAME = re.compile(r"\.(nd)?jsonl?(\.|$)|\.log(\.|$)")


def _files(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(p for p in path.rglob("*") if p.is_file() and _LOG_NAME.search(p.name))
    return [path]


def _unwrap(value: Any) -> Iterator[dict[str, Any]]:
    """The events in one JSON value: an event, a list, a search response, an
    elasticdump line, or sessions keyed by id."""
    if isinstance(value, list):
        for item in value:
            yield from _unwrap(item)
    elif isinstance(value, dict):
        if isinstance(value.get("hits"), dict):
            yield from _unwrap(value["hits"].get("hits", []))
        elif isinstance(value.get("_source"), dict):
            yield value["_source"]
        elif value and all(isinstance(item, list) for item in value.values()):
            # {session id: [its events]}, how the CyberLab honeynet dataset
            # publishes Cowrie logs. An event always has scalar fields.
            for events in value.values():
                yield from _unwrap(events)
        else:
            yield value


def _parse_line(line: str) -> Any:
    """One line as JSON: a value per line, or one element per line of a JSON
    array (`[{...},` / `{...},` / `{...}]`), as some datasets are published."""
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return json.loads(line.strip().removeprefix("[").removesuffix(",").removesuffix("]"))


def _values(file: Path, stats: Counter) -> Iterator[Any]:
    """The JSON values in one file, a line at a time when the file allows it:
    a day of a busy honeynet is a hundred megabytes once unzipped."""
    opener = gzip.open if file.name.endswith(".gz") else open
    with opener(file, "rt", encoding="utf-8", errors="replace") as handle:
        lines = (line for line in handle if line.strip() not in ("", "[", "]"))
        first = next(lines, None)
        if first is None:
            return
        try:
            value = _parse_line(first)
        except json.JSONDecodeError:
            pass
        else:
            yield value
            for line in lines:
                try:
                    yield _parse_line(line)
                except json.JSONDecodeError:
                    stats["unreadable lines"] += 1
            return
    # One document over many lines, such as a search response saved pretty-printed.
    with opener(file, "rt", encoding="utf-8", errors="replace") as handle:
        try:
            yield json.load(handle)
        except json.JSONDecodeError:
            stats["unreadable files"] += 1


def read_events(paths: Iterable[Path], stats: Counter) -> Iterator[dict[str, Any]]:
    """Every event in the given files and directories: NDJSON or JSON, gzipped or not."""
    for path in paths:
        for file in _files(Path(path)):
            stats["files"] += 1
            for value in _values(file, stats):
                yield from _unwrap(value)


# --------------------------------------------------------------------------
# scrubbing
# --------------------------------------------------------------------------
#
# A public address becomes a documentation address (RFC 5737) and a public
# domain an example.net name (RFC 2606). `is_external_host` treats both
# exactly as it treated the originals, so a scrubbed session classifies as the
# captured one did. The same original always gets the same replacement, and
# each replacement stands for millions of originals, so nothing maps back.
# Private addresses and local names stay: they are the honeypot's own estate,
# and they carry meaning -- 10.x is lateral movement, 169.254.169.254 the
# cloud metadata service.

_DOCUMENTATION_NETS = tuple(ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_URL_HOST = re.compile(r"(?P<lead>\b[a-zA-Z][\w+.-]*://(?:[^\s/@'\"]*@)?)(?P<host>[A-Za-z0-9.-]+)")
#: Bare domains are only recognised by TLDs that are not also file extensions
#: (no .sh, .py, .in, .me), so `cat run.sh` stays as it is.
_DOMAIN = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+(?:com|net|org|info|biz|io|xyz|top|ru|su|cn|cc|tk|pw|ws|online|site|club|"
    r"shop|live|space|icu|buzz|cyou|fun|store|tech|vip|win|bid|cf|ga|gq|ml)(?![\w-])",
    re.IGNORECASE,
)
_RESERVED_NAMES = ("example.com", "example.net", "example.org", ".example", ".test", ".invalid", ".localhost")
_SSH_KEY = re.compile(r"((?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+)AAAA[0-9A-Za-z+/]+=*")
_ENCODED_BLOB = re.compile(r"[A-Za-z0-9+/]{100,}=*")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){32,}")


def _digest(text: str) -> int:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:12], 16)


def _scrub_address(match: re.Match[str]) -> str:
    try:
        address = ipaddress.ip_address(match.group())
    except ValueError:
        return match.group()
    if not address.is_global:
        return match.group()
    digest = _digest(match.group())
    network = _DOCUMENTATION_NETS[digest % len(_DOCUMENTATION_NETS)]
    return str(network.network_address + 1 + (digest // len(_DOCUMENTATION_NETS)) % 254)


def _scrub_name(name: str) -> str:
    """A public domain's registered part replaced; its subdomain labels kept,
    since an encoded label is what makes a lookup DNS exfiltration."""
    lowered = name.lower()
    if _IPV4.fullmatch(name) or not is_external_host(lowered) or lowered.endswith(_RESERVED_NAMES):
        return name
    labels = name.split(".")
    registered = ".".join(labels[-2:]).lower()
    return ".".join(labels[:-2] + [f"host{_digest(registered) % 1000}", "example", "net"])


def scrub(command: str) -> str:
    """The command with what identifies people and infrastructure replaced."""
    command = _SSH_KEY.sub(r"\1AAAA_REDACTED", command)
    command = _ENCODED_BLOB.sub(lambda m: f"{m.group()[:16]}_TRUNCATED_{len(m.group())}", command)
    command = _HEX_ESCAPES.sub(lambda m: f"{m.group()[:32]}_TRUNCATED_{len(m.group()) // 4}", command)
    command = _URL_HOST.sub(lambda m: m.group("lead") + _scrub_name(m.group("host")), command)
    command = _DOMAIN.sub(lambda m: _scrub_name(m.group()), command)
    return _IPV4.sub(_scrub_address, command)


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------


_QUOTED = re.compile(r"(['\"]).*?\1")
_RANDOM_TOKEN = re.compile(r"\b(?=\w*\d)(?=\w*[a-zA-Z])\w{6,}\b")
_DIGITS = re.compile(r"\d+")


def shape(command: str) -> str:
    """The command with what changes between runs of one script masked: quoted
    strings, random-looking names, numbers.

    Bots vary a password or a file name every run, so exact matching leaves
    hundreds of copies of one script. A day of the CyberLab honeynet held 575
    exactly-distinct sequences and nine scripts, one of them behind 552.
    """
    return _DIGITS.sub("0", _RANDOM_TOKEN.sub("T", _QUOTED.sub("Q", command)))


def _moment(timestamp: str) -> datetime:
    try:
        moment = datetime.fromisoformat(timestamp)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _tempo(run: list[Command]) -> str:
    moments = [_moment(command.timestamp) for command in run]
    gaps = [(later - earlier).total_seconds() for earlier, later in zip(moments, moments[1:])]
    return "bot" if gaps and statistics.median(gaps) < BOT_GAP_SECONDS else "human"


def _windows(commands: tuple[str, ...]) -> list[tuple[str, ...]]:
    """The windows the sidecar would classify, as evaluation.iter_windows builds them."""
    return [commands[max(0, end - WINDOW):end] for end in range(MIN_WINDOW, len(commands) + 1)]


def _from_inside(origin: str) -> bool:
    """An address inside the estate: the team's own logins -- or, behind NAT, everyone."""
    try:
        ipaddress.ip_address(origin)
    except ValueError:
        return False
    return not is_external_host(origin)


def _candidate(sequence: tuple[str, ...], run: list[Command], runs: int, overlap: int, credit: str) -> dict[str, Any]:
    first = run[0]
    moment = _moment(first.timestamp)
    dated = moment.year > 1
    sensor = first.sensor or "an unnamed sensor"
    slug = re.sub(r"[^a-z0-9]+", "-", first.sensor.lower()).strip("-") or "sensor"
    source = f"captured on {sensor}, {moment:%Y-%m-%d}" if dated else f"captured on {sensor}"
    if runs > 1:
        source += f"; {runs} sessions ran this script"
    if credit:
        source += f"; {credit}"
    session = hashlib.sha1(first.session.encode("utf-8")).hexdigest()[:8]
    return {
        "name": f"cap-{slug}-{moment:%Y%m%d}-{session}" if dated else f"cap-{slug}-{session}",
        "tempo": _tempo(run),
        "source": source,
        # How much traffic this one transcript stands for, should a score ever
        # need weighting by it.
        "sessions": runs,
        # Windows of this session the generator also produces verbatim. Real
        # bots type `uname -a` then `whoami` too: worth knowing, not a leak.
        "training_overlap": overlap,
        "steps": [
            {"label": None, "command": command, "timestamp": original.timestamp}
            for command, original in zip(sequence, run)
        ],
    }


def extract(
    events: Iterable[dict[str, Any]],
    stats: Counter,
    *,
    known: Iterable[tuple[str, ...]] = (),
    training: Iterable[tuple[str, ...]] = (),
    min_commands: int = MIN_COMMANDS,
    include_private: bool = False,
    limit: Optional[int] = None,
    seed: int = 0,
    scrub_commands: bool = True,
    merge_similar: bool = True,
    protocol: Optional[str] = None,
    credit: str = "",
) -> list[dict[str, Any]]:
    """Captured events -> sessions ready to label, one per distinct script.

    With `merge_similar`, runs whose commands have the same `shape` count as
    one script, and a script whose shape matches a labelled transcript counts
    as labelled. `protocol` keeps only sessions over it ("ssh"), read from
    whichever of a session's events carries it -- in Cowrie, the connect
    event. `credit` is appended to every session's source: the citation a
    published dataset's licence asks for travels with each session.
    """
    by_session: dict[str, list[Command]] = {}
    protocols: dict[str, str] = {}
    seen: set[tuple[str, str, str]] = set()
    for event in events:
        stats["events"] += 1
        session = event.get("session") or event.get("session_id")
        if session and event.get("protocol"):
            protocols.setdefault(str(session), str(event["protocol"]).lower())
        command = command_from(event)
        if command is None:
            continue
        key = (command.session, command.timestamp, command.command)
        if key in seen:  # the same event read twice: from the log and a spool copy, say
            stats["repeated events"] += 1
            continue
        seen.add(key)
        stats["commands"] += 1
        by_session.setdefault(command.session, []).append(command)
    stats["sessions"] = len(by_session)

    def script(sequence: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(shape(command) for command in sequence) if merge_similar else sequence

    scripts: dict[tuple[str, ...], list[tuple[tuple[str, ...], list[Command]]]] = {}
    exact: set[tuple[str, ...]] = set()
    for run in by_session.values():
        run.sort(key=lambda command: _moment(command.timestamp))  # stable: ties keep log order
        if len(run) < min_commands:
            stats["too short"] += 1
        elif not include_private and _from_inside(run[0].origin):
            stats["from inside"] += 1
        elif protocol and protocols.get(run[0].session) != protocol.lower():
            stats["other protocol"] += 1
        else:
            sequence = tuple(scrub(c.command) if scrub_commands else c.command for c in run)
            exact.add(sequence)
            scripts.setdefault(script(sequence), []).append((sequence, run))

    labelled = {script(tuple(sequence)) for sequence in known}
    fresh = [runs for key, runs in scripts.items() if key not in labelled]
    stats["exact sequences"] = len(exact)
    stats["distinct"] = len(scripts)
    stats["already labelled"] = len(scripts) - len(fresh)
    if limit is not None and len(fresh) > limit:
        fresh = random.Random(seed).sample(fresh, limit)

    training = set(training)
    candidates = []
    for runs in fresh:
        sequence, first = min(runs, key=lambda pair: _moment(pair[1][0].timestamp))
        overlap = sum(window in training for window in _windows(sequence))
        stats["windows"] += len(_windows(sequence))
        stats["sharing a window with training"] += overlap > 0
        candidates.append(_candidate(sequence, first, len(runs), overlap, credit))
    candidates.sort(key=lambda candidate: _moment(candidate["steps"][0]["timestamp"]))
    return candidates


# --------------------------------------------------------------------------
# files
# --------------------------------------------------------------------------


def _read(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8")).get("sessions", [])


def _write(path: Path, about: str, sessions: list[dict[str, Any]]) -> None:
    """One step per line, so the file reads -- and labels -- comfortably in an editor."""
    def dump(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    lines = ["{", f'  "about": {dump(about)},', '  "sessions": [']
    for index, session in enumerate(sessions):
        steps = session["steps"]
        lines.append("    {")
        lines.extend(f"      {dump(key)}: {dump(value)}," for key, value in session.items() if key != "steps")
        lines.append('      "steps": [')
        lines.extend(f"        {dump(step)}{',' if number < len(steps) - 1 else ''}" for number, step in enumerate(steps))
        lines.append("      ]")
        lines.append("    }" + ("," if index < len(sessions) - 1 else ""))
    lines += ["  ]", "}", ""]
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text("\n".join(lines), encoding="utf-8")
    os.replace(temporary, path)


# --------------------------------------------------------------------------
# labelling
# --------------------------------------------------------------------------


def _guide() -> str:
    """The labelling guide from eval_transcripts.py, so there is only one copy of it."""
    from . import eval_transcripts

    doc = eval_transcripts.__doc__ or ""
    start = doc.find("Labelling guide")
    return doc[start:doc.find("Splits", start)].strip() if start >= 0 else "See eval_transcripts.py."


def _next_unlabelled(sessions: list[dict[str, Any]]) -> Optional[tuple[int, int]]:
    for number, session in enumerate(sessions):
        if not session.get("drop"):
            for index, step in enumerate(session["steps"]):
                if step.get("label") is None:
                    return number, index
    return None


def _remembered(sessions: list[dict[str, Any]]) -> dict[str, str]:
    """The label already given to each command shape. Bots repeat the same
    commands across hundreds of sessions, so the labeller's own earlier answer
    is offered again -- theirs, never the classifier's."""
    return {shape(step["command"]): step["label"] for s in sessions for step in s["steps"] if step.get("label")}


def label(
    path: Path = DEFAULT_CANDIDATES,
    ask: Callable[[str], str] = input,
    say: Callable[[str], None] = print,
) -> int:
    """Ask for each unlabelled step in turn, saving after every answer, so it can stop anywhere."""
    sessions = _read(path)
    remembered = _remembered(sessions)
    history: list[tuple[int, Optional[int]]] = []
    while (position := _next_unlabelled(sessions)) is not None:
        number, index = position
        session, steps = sessions[number], sessions[number]["steps"]
        left = sum(step.get("label") is None for s in sessions if not s.get("drop") for step in s["steps"])
        say(f"\n[{number + 1}/{len(sessions)}, {left} steps left] {session['name']} ({session['tempo']}) {session['source']}")
        start, end = max(0, index - 8), min(len(steps), index + 4)
        if start:
            say("     ...")
        for shown in range(start, end):
            say(f"  {'>' if shown == index else ' '} {steps[shown].get('label') or '.'}  {steps[shown]['command']}")
        if end < len(steps):
            say("     ...")
        suggestion = remembered.get(shape(steps[index]["command"]))
        hint = f" (Enter: {suggestion})" if suggestion else ""
        answer = ask(f"label R P S L X N{hint} | u undo | d drop session | ? guide | q quit > ").strip().upper()
        if not answer and suggestion:
            answer = suggestion
        if answer == "Q":
            break
        if answer == "?":
            say(_guide())
            continue
        if answer == "U":
            if not history:
                say("nothing to undo")
                continue
            undo_session, undo_step = history.pop()
            if undo_step is None:
                sessions[undo_session].pop("drop", None)
            else:
                sessions[undo_session]["steps"][undo_step]["label"] = None
                remembered = _remembered(sessions)
        elif answer == "D":
            session["drop"] = True
            history.append((number, None))
        elif answer in LABEL_CODES:
            steps[index]["label"] = answer
            remembered[shape(steps[index]["command"])] = answer
            history.append((number, index))
            if index == len(steps) - 1 and all(step["label"] == "N" for step in steps):
                say("every step of this session is N, so it has no stage to score: undo, or drop it")
        else:
            say("not one of R P S L X N")
            continue
        _write(path, _ABOUT_CANDIDATES, sessions)

    left = sum(step.get("label") is None for s in sessions if not s.get("drop") for step in s["steps"])
    say(f"{left} step(s) still to label in {path}" if left else
        f"all labelled. Next: python -m ml.intent_classification.captures add {path}")
    return 0


# --------------------------------------------------------------------------
# adding to the evaluation set
# --------------------------------------------------------------------------


def add(
    path: Path = DEFAULT_CANDIDATES,
    split: str = "holdout",
    into: Path = CAPTURED_PATH,
    say: Callable[[str], None] = print,
) -> int:
    """Add the labelled sessions in `path` to the captured set -- all of them, or none."""
    existing = _read(into) if into.exists() else []
    taken_names = {t.name for t in HAND_WRITTEN} | {session["name"] for session in existing}
    taken = {tuple(command for command, _ in t.steps) for t in HAND_WRITTEN}
    taken |= {tuple(step["command"] for step in session["steps"]) for session in existing}

    problems: list[str] = []
    added: list[dict[str, Any]] = []
    repeated = 0
    for session in _read(path):
        if session.get("drop"):
            continue
        steps = session["steps"]
        sequence = tuple(step["command"] for step in steps)
        if session["name"] in taken_names or sequence in taken:
            repeated += 1
            continue
        codes = [str(step.get("label")).upper() for step in steps]
        unlabelled = [number for number, code in enumerate(codes, 1) if code not in LABEL_CODES]
        if unlabelled:
            problems.append(f"{session['name']}: step(s) {unlabelled} have no label")
            continue
        if set(codes) == {"N"}:
            problems.append(f"{session['name']}: every step is N; drop it or label its stage")
            continue
        added.append({
            "name": session["name"],
            "split": split,
            "tempo": session["tempo"],
            "source": session["source"],
            "sessions": session.get("sessions", 1),
            "training_overlap": session.get("training_overlap", 0),
            "steps": [
                {"label": code, "command": step["command"], "timestamp": step["timestamp"]}
                for code, step in zip(codes, steps)
            ],
        })
        taken_names.add(session["name"])
        taken.add(sequence)

    if problems:
        say("Nothing added. Fix these first:")
        for problem in problems:
            say(f"  {problem}")
        return 1

    # Written beside the real file and loaded back before it replaces it: a
    # malformed captured set would break every import of eval_transcripts.
    staged = into.with_name(into.name + ".new")
    _write(staged, _ABOUT_CAPTURED, existing + added)
    try:
        load_captured(staged)
    except ValueError:
        staged.unlink()
        raise
    os.replace(staged, into)

    windows = sum(len(_windows(tuple(step["command"] for step in s["steps"]))) for s in added)
    say(f"added {len(added)} session(s), {windows} windows, to {into.name} as {split}"
        + (f"; {repeated} were already there" if repeated else ""))
    if added and split == "holdout":
        say("Score it once: python -m ml.intent_classification.evaluation")
    return 0


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def _report(stats: Counter, written: int, out: Path) -> str:
    lines = [f"read {stats['events']} events from {stats['files']} file(s)"
             + "".join(f", {stats[k]} {k}" for k in ("unreadable lines", "unreadable files", "repeated events") if stats[k])]
    lines.append(f"{stats['commands']} commands in {stats['sessions']} sessions: {stats['too short']} too short, "
                 f"{stats['from inside']} from inside the estate"
                 + (f", {stats['other protocol']} over other protocols" if stats["other protocol"] else ""))
    merged = (f", {stats['distinct']} scripts once runs differing only in passwords, numbers or names are merged"
              if stats["exact sequences"] != stats["distinct"] else "")
    lines.append(f"{stats['exact sequences']} distinct command sequences{merged}; {stats['already labelled']} already labelled")
    lines.append(f"wrote {written} session(s), {stats['windows']} windows, to {out}; "
                 f"{stats['sharing a window with training']} share a window with the training data")
    if not written and stats["from inside"]:
        lines.append("Sessions from inside the estate were skipped. If the sensor sits behind NAT, every attacker "
                     "looks like that: rerun with --include-private.")
    elif written:
        lines.append(f"Next: python -m ml.intent_classification.captures label {out}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ml.intent_classification.captures",
        description="Turn sessions the honeypot captured into labelled holdout transcripts.",
        epilog="See the module docstring (captures.py) for the whole workflow.",
    )
    actions = parser.add_subparsers(dest="action", required=True)

    extracting = actions.add_parser("extract", help="group captured events into sessions to label")
    extracting.add_argument("paths", nargs="+", type=Path, help="event files or directories: NDJSON or JSON, .gz too")
    extracting.add_argument("--out", type=Path, default=DEFAULT_CANDIDATES)
    extracting.add_argument("--limit", type=int, help="keep a random sample of this many sessions")
    extracting.add_argument("--seed", type=int, default=0, help="for --limit")
    extracting.add_argument("--min-commands", type=int, default=MIN_COMMANDS)
    extracting.add_argument("--include-private", action="store_true",
                            help="keep sessions from inside the estate: the sensor is behind NAT")
    extracting.add_argument("--no-scrub", action="store_true",
                            help="keep commands exactly as captured (then do not commit the result)")
    extracting.add_argument("--exact", action="store_true",
                            help="keep runs that differ only in passwords, numbers or random names apart")
    extracting.add_argument("--protocol", help="keep only sessions over this protocol, e.g. ssh")
    extracting.add_argument("--force", action="store_true", help="replace a candidates file that has labels in it")
    extracting.add_argument("--credit", default="",
                            help="attribution added to every session's source: a dataset's citation and licence")

    labelling = actions.add_parser("label", help="label the extracted sessions one step at a time")
    labelling.add_argument("path", nargs="?", type=Path, default=DEFAULT_CANDIDATES)

    adding = actions.add_parser("add", help="add labelled sessions to captured_sessions.json")
    adding.add_argument("path", nargs="?", type=Path, default=DEFAULT_CANDIDATES)
    adding.add_argument("--split", choices=SPLITS, default="holdout")

    args = parser.parse_args(argv)
    if args.action == "label":
        return label(args.path)
    if args.action == "add":
        return add(args.path, split=args.split)

    if args.out.exists() and not args.force and any(
        step.get("label") for session in _read(args.out) for step in session["steps"]
    ):
        print(f"{args.out} already has labels in it; pass --force to replace it")
        return 1
    from .dataset import build_training_dataset

    stats: Counter = Counter()
    candidates = extract(
        read_events(args.paths, stats),
        stats,
        known={tuple(command for command, _ in t.steps) for t in TRANSCRIPTS},
        training={tuple(window["commands"]) for window in build_training_dataset()},
        min_commands=args.min_commands,
        include_private=args.include_private,
        limit=args.limit,
        seed=args.seed,
        scrub_commands=not args.no_scrub,
        merge_similar=not args.exact,
        protocol=args.protocol,
        credit=args.credit,
    )
    _write(args.out, _ABOUT_CANDIDATES, candidates)
    print(_report(stats, len(candidates), args.out))
    return 0


if __name__ == "__main__":  # pragma: no cover - command line
    raise SystemExit(main())
