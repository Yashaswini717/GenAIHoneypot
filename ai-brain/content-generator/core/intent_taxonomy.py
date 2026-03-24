from __future__ import annotations

from typing import Final


INTENT_CLASSES: Final[list[str]] = [
    "reconnaissance",
    "privilege_escalation",
    "persistence",
    "lateral_movement",
    "data_exfiltration",
]


COMMAND_KEYWORDS: Final[dict[str, tuple[str, ...]]] = {
    "reconnaissance": (
        "nmap",
        "whoami",
        "uname",
        "hostname",
        "ifconfig",
        "ipconfig",
        "netstat",
        "ss ",
        "ps ",
        "tasklist",
        "ls ",
        "dir ",
        "find ",
        "cat /etc/passwd",
        "curl",
        "wget",
    ),
    "privilege_escalation": (
        "sudo",
        "su ",
        "chmod +s",
        "setcap",
        "sudoers",
        "runas",
        "seimpersonate",
        "getsystem",
        "passwd",
        "visudo",
    ),
    "persistence": (
        "crontab",
        "systemctl enable",
        "service create",
        "schtasks",
        "reg add",
        "startup",
        "rc.local",
        "authorized_keys",
        "launchctl",
        "wmic startup",
    ),
    "lateral_movement": (
        "ssh ",
        "scp ",
        "sftp",
        "psexec",
        "wmic /node",
        "net use",
        "smbclient",
        "winrm",
        "rdp",
        "mount ",
        "mstsc",
    ),
    "data_exfiltration": (
        "tar ",
        "zip ",
        "gzip ",
        "base64 ",
        "nc ",
        "netcat",
        "curl -x",
        "curl -f",
        "scp ",
        "aws s3 cp",
        "rsync",
        "upload",
    ),
}


HTTP_PATH_KEYWORDS: Final[dict[str, tuple[str, ...]]] = {
    "reconnaissance": (
        "/admin",
        "/login",
        "/config",
        "/debug",
        "/.git",
        "/backup",
        "/api",
        "/status",
        "/metrics",
    ),
    "privilege_escalation": (
        "/sudo",
        "/token",
        "/session",
        "/admin/users",
        "/role",
        "/impersonate",
    ),
    "persistence": (
        "/cron",
        "/jobs",
        "/keys",
        "/startup",
        "/schedule",
    ),
    "lateral_movement": (
        "/remote",
        "/ssh",
        "/rdp",
        "/node",
        "/share",
        "/internal",
    ),
    "data_exfiltration": (
        "/download",
        "/export",
        "/dump",
        "/backup",
        "/archive",
        "/reports",
    ),
}


DB_QUERY_KEYWORDS: Final[dict[str, tuple[str, ...]]] = {
    "reconnaissance": (
        "information_schema",
        "pg_catalog",
        "show tables",
        "show databases",
        "describe ",
        "explain ",
        "select @@version",
    ),
    "privilege_escalation": (
        "grant ",
        "alter role",
        "create user",
        "superuser",
        "xp_cmdshell",
        "set role",
    ),
    "persistence": (
        "create trigger",
        "create event",
        "create function",
        "alter system",
        "copy program",
    ),
    "lateral_movement": (
        "dblink",
        "federated",
        "linked server",
        "openquery",
    ),
    "data_exfiltration": (
        "copy ",
        "into outfile",
        "select *",
        "union select",
        "export",
        "dumpfile",
    ),
}
