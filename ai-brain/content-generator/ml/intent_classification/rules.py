"""Hard-evidence rules: the classifier's first, and most confident, opinion.

Each command in the window is read on its own (see `shell.py`) and yields
evidence -- named rules, each pointing at an intent. The newest command that
carries any evidence decides.

Why the newest, and not the majority
------------------------------------
The window slides. Three commands is "what the attacker is doing now" plus a
little context, and the stage a window is labelled with is the stage at its
newest command. Counting rule groups across the whole window let whatever
came first outvote what is happening now: `ssh deploy@erp-web` followed by
`cat /opt/erp/settings.py` stayed "lateral movement" for two more
classifications, long after the attacker had moved on to reading config.
The sidecar measured the same effect from the other side -- smaller windows
tracked the attacker better, monotonically (brain_courier.py,
CLASSIFY_WINDOW). Measured on the labelled transcripts in
`eval_transcripts.py`, majority voting got 29/77 dev windows right; this
gets far more (see `evaluation.py` for the current figures).

Older commands still matter: they decide when the newest commands are neutral
(`cd`, `chmod +x`), they raise confidence when they agree, and they mark the
decision as contested -- with every intent in contention named -- when they
disagree, so the confidence of a contested call stays below a clean one.

One command can carry evidence for two stages (`ssh host 'tar czf - /data'`).
The deeper kill-chain stage wins that tie: it is the one that says what the
command is for.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from core.intent_taxonomy import INTENT_CLASSES, KILL_CHAIN_ORDER

from .shell import Segment, segments

R = "reconnaissance"
P = "privilege_escalation"
S = "persistence"
L = "lateral_movement"
X = "data_exfiltration"

Evidence = dict[str, list[str]]
_Hit = Callable[[str, str], None]


@dataclass
class RuleMatch:
    intent: str
    confidence: float
    matched_rules: list[str]


# --------------------------------------------------------------------------
# vocabularies
# --------------------------------------------------------------------------

#: Programs that only describe the host they run on.
_HOST_ENUMERATION = frozenset({
    "whoami", "id", "w", "who", "last", "lastb", "lastlog", "users", "groups", "uname",
    "hostname", "hostnamectl", "lsb_release", "uptime", "ps", "top", "htop", "pstree",
    "netstat", "ss", "ifconfig", "arp", "route", "lscpu", "nproc", "free", "df", "lsblk",
    "lsof", "env", "printenv", "which", "whereis", "getent", "dmesg", "lspci", "lsusb",
    "finger", "vmstat", "iostat", "sestatus", "getenforce",
    "date", "timedatectl", "locale", "lsmod", "showmount", "blkid", "nvidia-smi",
})
#: Credential guessing against another machine's services (T1110 aimed at
#: lateral movement): the attacker is trying to get onto the next host.
_BRUTEFORCE = frozenset({"hydra", "thc-hydra", "medusa", "ncrack", "patator"})
#: DNS tunnelling tools, and the lookup programs that carry data when their
#: query names are built from a variable or are long encoded chunks.
_DNS_TUNNEL = frozenset({"iodine", "dnscat", "dnscat2", "dns2tcp"})
_DNS_LOOKUP = frozenset({"dig", "nslookup", "host", "drill"})
_ENCODED_LABEL = re.compile(r"\$|[A-Za-z0-9+/=_-]{40,}")
#: Cloud API calls that mint a new way back in (T1098.001, T1136.003).
_CLOUD_PERSIST = re.compile(
    r"^(create-access-key|create-user|create-login-profile|attach-user-policy|put-user-policy"
    r"|update-assume-role-policy|add-iam-policy-binding|create-for-rbac)$"
)
#: Payloads written into a script that something privileged will run: a SUID
#: shell or a copy of one, the classic writable-cron-script escalation.
_SUID_PAYLOAD = re.compile(r"chmod\s+([ugoa]*\+s|[2467][0-7]{3})|cp\s+/bin/(ba)?sh\s|/bin/(ba)?sh\s+-p")
#: Application code. Patching it in place is a backdoor (credential capture,
#: a hidden route), the same family as a web shell.
_APP_CODE = re.compile(r"^/(opt|srv|var/www|usr/share/nginx|home/[^/]+/(app|apps|www|site))/.+\.(py|php\d?|js|rb|pl|jsp|go)$")
#: Package managers, and the arguments that make them list what is installed
#: rather than change it (software discovery, T1518).
_PACKAGE_LISTING: dict[str, frozenset[str]] = {
    "dpkg": frozenset({"-l", "--list", "-s", "--status", "-L", "--listfiles"}),
    "rpm": frozenset({"-qa", "-q", "-qi", "-ql"}),
    "apt": frozenset({"list"}),
    "apt-cache": frozenset({"policy", "show", "search"}),
    "pip": frozenset({"list", "freeze", "show"}),
    "pip3": frozenset({"list", "freeze", "show"}),
    "snap": frozenset({"list"}),
}
#: Container and orchestration subcommands, split by what they do to the estate.
_CONTAINER_LOOK = frozenset({
    "ps", "images", "inspect", "info", "version", "network", "get", "describe", "auth",
    "cluster-info", "config", "top", "logs", "whoami",
})
_CONTAINER_ENTER = frozenset({"exec", "attach", "rsh", "cp", "port-forward"})
#: Tools that run commands on other machines (T1021, T1072).
_REMOTE_EXEC = frozenset({
    "ansible", "ansible-playbook", "salt", "salt-ssh", "pssh", "parallel-ssh", "pdsh",
    "clush", "rsh", "rlogin", "rexec",
})
_FILE_DISCOVERY = frozenset({"ls", "ll", "dir", "tree", "stat", "find", "locate", "du", "file"})
_NETWORK_DISCOVERY = frozenset({
    "nmap", "masscan", "zmap", "ping", "fping", "arp-scan", "traceroute", "tracepath",
    "dig", "nslookup", "netdiscover",
})
_READERS = frozenset({
    "cat", "head", "tail", "less", "more", "strings", "grep", "egrep", "fgrep", "rg",
    "awk", "sed", "nl", "od", "view", "bat", "vi", "vim", "nano",
})
_EDITORS = frozenset({"vi", "vim", "nano", "emacs", "ed"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ash", "ksh", "python", "python3", "perl"})
_DB_CLIENTS = frozenset({"mysql", "mariadb", "psql", "sqlite3", "mongo", "mongosh", "sqlcmd", "cqlsh"})
_DB_DUMPERS = frozenset({"mysqldump", "mariadb-dump", "pg_dump", "pg_dumpall", "mongodump", "mongoexport"})
_ACCOUNT_TOOLS = frozenset({"useradd", "adduser", "usermod", "chpasswd", "passwd", "chage"})
_REMOTE_SERVICES = frozenset({
    "smbclient", "rdesktop", "xfreerdp", "evil-winrm", "psexec", "psexec.py",
    "wmiexec.py", "smbexec.py", "crackmapexec", "nxc", "winrs",
})

#: Files whose contents describe the host, its users, or the way into it.
_RECON_FILE = re.compile(
    r"/proc/|/etc/(passwd|group|os-release|issue|hosts|resolv\.conf|ssh/sshd_config|crontab|cron\.)"
    r"|known_hosts|\.ssh/config|authorized_keys|\.bash_history|\.aws/|credentials|\.netrc|\.pgpass"
    r"|\.my\.cnf|\.env\b|settings\.py|wp-config|config\.(php|ya?ml|json|ini)|\.pem\b|id_(rsa|dsa|ecdsa|ed25519)"
    r"|\.git-credentials|\.docker/config|\.kube/config|\.conf\b"
    r"|login\.defs|\.bashrc|\.bash_profile|\.profile\b|\.zshrc|/var/log/|/etc/(shells|fstab|exports)\b",
    re.IGNORECASE,
)
#: Files that hold records rather than configuration. Reading one is collecting
#: data (T1005); copying one into a scratch directory is staging it (T1074).
_DATA_FILE = re.compile(r"\.(csv|tsv|sql|dump|xlsx?|db|sqlite3?|mdb|accdb)$|/exports?/", re.IGNORECASE)
_SENSITIVE_DATA = re.compile(
    r"\.(kdbx?|sql|dump|csv|tsv|xlsx?|docx?|db|sqlite3?|bak|mdb|accdb|pst)$"
    r"|/(Documents|exports?|backups?|reports?)(/|$)|passwords?|wallet",
    re.IGNORECASE,
)
_STAGING_DEST = re.compile(r"^(/tmp|/dev/shm|/var/tmp|/run/user/\d+)(/|$)|(^|/)\.[^/.][^/]*/?$")
_DISK_DEVICE = re.compile(r"^/dev/(sd[a-z]|nvme\d|xvd[a-z]|vd[a-z]|mmcblk\d|mapper/)")
_SECRET_PATTERN = re.compile(r"pass|secret|token|key|cred|private", re.IGNORECASE)
_CREDENTIAL_STORE = re.compile(r"/etc/(shadow|gshadow|master\.passwd|security/opasswd)\b")
_SUDOERS = re.compile(r"/etc/sudoers")
_SUID_PERM = re.compile(r"-perm\s+[-/+]?(4000|2000|6000|u=s|g=s|u\+s|g\+s)")
_SETUID_MODE = re.compile(r"^([ugoa]*\+[rwx]*s[rwx]*|[2467][0-7]{3})$")
_PRIVESC_TOOLS = re.compile(
    r"linpeas|linenum|lse\.sh|linux-exploit-suggester|les\.sh|pspy|beroot|unix-privesc-check|searchsploit",
    re.IGNORECASE,
)
_HOST_ROOT_MOUNT = re.compile(r"(^|\s)-v\s*/:|--volume[= ]/:")
_AUTH_KEYS = re.compile(r"authorized_keys2?$")
_CRON_PATH = re.compile(r"^/etc/cron|^/var/spool/cron|/etc/crontab$")
_BOOT_PATH = re.compile(r"rc\.local$|^/etc/init\.d/|^/etc/rc\d\.d/")
_PROFILE_PATH = re.compile(r"(^|/)(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.bash_login)$|^/etc/(profile|bash\.bashrc|environment)")
_SYSTEMD_PATH = re.compile(r"/systemd/(system|user)/")
_PRELOAD_PATH = re.compile(r"^/etc/ld\.so\.preload$")
_SSHD_CONFIG = re.compile(r"^/etc/ssh/(sshd_config(\.d/.*)?|sshrc)$|(^|/)\.ssh/rc$")
_PAM_PATH = re.compile(r"^/etc/pam\.d/|/security/pam_[\w-]+\.so$")
_MOTD_PATH = re.compile(r"^/etc/update-motd\.d/")
_WEB_SHELL = re.compile(r"^/(var/www|srv/www|srv/http|usr/share/nginx)/.*\.(php\d?|phtml|jsp|aspx?|cgi)$", re.IGNORECASE)
_ACCOUNT_FILES = re.compile(r"^/etc/(passwd|shadow|group|gshadow)$")
_SYSTEM_BIN = re.compile(r"^/(usr/(local/)?)?s?bin/")
_STAGING_DIR = re.compile(r"^(/tmp/|/dev/shm/|/var/tmp/|\./|~/|/home/)")
_NET_FS = re.compile(r"-t\s+(cifs|smbfs|nfs4?)\b|^//|\s//")
_HTTP_SERVER = re.compile(r"-m\s+(http\.server|SimpleHTTPServer|uploadserver)")
_URL = re.compile(r"^(https?|ftp)://", re.IGNORECASE)
_HOST_PORT = re.compile(r"^[\w.-]+:\d+(/|$)")

_SQL_START = re.compile(
    r"^\s*(select|show|describe|desc|use|insert|update|delete|grant|revoke|create|alter|drop|copy|with)(?=\s|;|$)",
    re.IGNORECASE,
)
_SQL_PRIVESC = re.compile(r"\b(grant\s+\w|alter\s+(user|role)|set\s+role|superuser|xp_cmdshell)", re.IGNORECASE)
#: A new account is a way back in (persistence, as the labelling guide has it);
#: granting rights to an account is escalation. `CREATE USER ... GRANT ALL`
#: is both, and the deeper stage -- persistence -- wins.
_SQL_ACCOUNT = re.compile(r"\bcreate\s+(user|role|login)\b", re.IGNORECASE)
_SQL_PERSIST = re.compile(r"\b(create\s+(or\s+replace\s+)?(trigger|event|function|procedure)|alter\s+system)\b", re.IGNORECASE)
_SQL_RECON = re.compile(
    r"\bshow\s+(databases|schemas|tables|full\s+tables|grants|columns)\b|information_schema|pg_catalog"
    r"|sqlite_master|\b(describe|desc)\s+\w|\bselect\s+(@@version|version\s*\(|current_user|user\s*\(|database\s*\()"
    r"|from\s+mysql\.user\b|(^|\s)\\d[a-z+]*\b|(^|\s)\.(tables|schema|databases)\b",
    re.IGNORECASE,
)
_SQL_EXFIL = re.compile(
    r"\bselect\b[\s\S]+?\bfrom\b|\binto\s+(out|dump)file\b|\bcopy\s*\(\s*select|\bunion\s+select\b|(^|\s)\.dump\b",
    re.IGNORECASE,
)

#: Address space that belongs to the estate. Everything else is outside it --
#: including the documentation ranges, which only ever stand in for public
#: addresses. (`ipaddress.is_private` counts those as private, so the old
#: scp rule called every transfer to them internal.)
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")
)
_LOCAL_SUFFIXES = (".internal", ".local", ".lan", ".corp", ".home", ".intra", ".localdomain")

#: ssh options that consume a value (`-i key`, `-o Opt=x`, `-L spec`, ...).
_SSH_VALUE_OPTIONS = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
_SSHPASS_VALUE_OPTIONS = frozenset({"-p", "-f", "-d", "-P"})


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def is_external_host(host: str) -> bool:
    """True when a transfer destination lies outside the estate."""
    host = host.strip("[]")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Bare names and shell variables resolve inside the estate (erp-web,
        # db-01, $h); dotted names outside the local suffixes do not.
        if "$" in host or "." not in host:
            return False
        return not host.lower().endswith(_LOCAL_SUFFIXES)
    return not any(address in net for net in _INTERNAL_NETS)


def _url_host(arg: str) -> str:
    """The host in `ftp://user@host:21/path`, `user@host`, or a bare host."""
    if "://" in arg:
        arg = arg.split("://", 1)[1]
    return arg.split("/", 1)[0].split("@")[-1].split(":")[0]


def _remote_hosts(program: str, args: list[str]) -> list[str]:
    """Hosts named as the remote side of an scp/rsync/sftp invocation."""
    hosts = []
    candidates = [a for a in args if not a.startswith("-")]
    for arg in candidates:
        if "://" in arg:
            hosts.append(arg.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0])
            continue
        if program == "sftp":
            hosts.append(arg.split("@")[-1].split(":")[0])
            break
        if arg.startswith(("/", "./", "~")):
            continue
        match = re.match(r"^(?:[^@/\s]+@)?(\[[^\]]+\]|[^:/\s]+):", arg)
        if match:
            hosts.append(match.group(1))
    return hosts


def _ssh_destination(args: list[str]) -> tuple[Optional[str], str, bool]:
    """(destination, remote command, is_tunnel) for an ssh argument list."""
    tunnel = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-") and len(arg) > 1:
            letters = arg[1:]
            tunnel = tunnel or any(ch in "LDR" for ch in letters)
            consume_next = False
            for index, letter in enumerate(letters):
                if letter in _SSH_VALUE_OPTIONS:
                    consume_next = index == len(letters) - 1
                    break
            i += 2 if consume_next else 1
            continue
        return arg, " ".join(args[i + 1:]), tunnel
    return None, "", tunnel


def _in_place_files(args: list[str]) -> list[str]:
    """Files a `sed -i` / `perl -pi -e` edits: every positional that is not the script."""
    files: list[str] = []
    explicit_script = skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in ("-e", "--expression", "-f", "--file"):
            explicit_script = skip = True
            continue
        if arg.startswith("-"):
            explicit_script = explicit_script or arg.startswith(("--expression=", "--file="))
            continue
        files.append(arg)
    return files if explicit_script else files[1:]


def _write_targets(seg: Segment) -> list[str]:
    """Paths a segment writes to: redirections, tee, cp/mv destinations, editors, in-place edits."""
    targets = list(seg.writes)
    plain = [a for a in seg.args if not a.startswith("-")]
    if seg.program == "tee":
        targets.extend(plain)
    elif seg.program in {"cp", "mv", "install", "ln"} and len(plain) >= 2:
        targets.append(plain[-1])
    elif seg.program in _EDITORS:
        targets.extend(plain)
    elif seg.program == "sed" and any(a.startswith(("-i", "--in-place")) for a in seg.args):
        targets.extend(_in_place_files(seg.args))
    elif seg.program == "perl" and any("i" in _short_cluster(a) for a in seg.args) and "-e" in seg.args:
        targets.extend(_in_place_files(seg.args))
    return targets


def _tar_creates(args: list[str]) -> bool:
    if "--create" in args:
        return True
    for position, arg in enumerate(args):
        if arg.startswith("--"):
            continue
        cluster = arg[1:] if arg.startswith("-") else (arg if position == 0 else "")
        if cluster.isalpha() and "c" in cluster:
            return True
    return False


def _curl_uploads(args: list[str]) -> bool:
    for i, arg in enumerate(args):
        if arg in ("-F", "--form", "-T", "--upload-file") or arg.startswith(("--form=", "--upload-file=")):
            return True
        if arg.startswith("-") and not arg.startswith("--") and arg[-1:] in ("F", "T") and arg[1:].isalpha():
            return True
        if arg in ("-d", "--data", "--data-binary", "--data-raw") and i + 1 < len(args) and args[i + 1].startswith("@"):
            return True
        if arg.startswith(("--data-binary=@", "--data=@")):
            return True
    return False


def _short_cluster(arg: str) -> str:
    """The letters of a single-dash option cluster (`-qO-` -> `qO-`), else ''."""
    return arg[1:] if arg.startswith("-") and not arg.startswith("--") else ""


def _saves_download(seg: Segment) -> bool:
    """True when curl/wget writes what it fetches to a file rather than the terminal.

    The difference is the difference between reading a page and pulling a tool:
    `curl -s http://erp-web/admin | head` is looking around, `wget x.sh` and
    `curl -o .k ...` are fetching something to run, which says nothing about
    the stage by itself.
    """
    args = seg.args
    if seg.program == "wget":
        # wget saves unless pointed at stdout: -O- / -qO- / -O - / --output-document=-
        for i, arg in enumerate(args):
            if arg == "--output-document=-" or _short_cluster(arg).endswith("O-"):
                return False
            if _short_cluster(arg).endswith("O") and i + 1 < len(args) and args[i + 1] == "-":
                return False
        return True
    # curl prints to stdout unless given -o/-O (possibly clustered) or the long forms.
    return any(
        arg in ("--output", "--remote-name", "--remote-name-all") or _short_cluster(arg)[-1:] in ("o", "O")
        for arg in args
    )


def sql_evidence(sql: str, hit: _Hit, prefix: str = "sql") -> bool:
    """Classify a SQL statement, from any source. Returns True if anything matched."""
    matched = False
    if _SQL_PRIVESC.search(sql):
        hit(P, f"{prefix}:privileged_change")
        matched = True
    if _SQL_PERSIST.search(sql):
        hit(S, f"{prefix}:persistence_object")
        matched = True
    if _SQL_ACCOUNT.search(sql):
        hit(S, f"{prefix}:account_creation")
        matched = True
    if _SQL_RECON.search(sql):
        hit(R, f"{prefix}:schema_enumeration")
        matched = True
    elif _SQL_EXFIL.search(sql):
        hit(X, f"{prefix}:data_read")
        matched = True
    return matched


# --------------------------------------------------------------------------
# per-command evidence
# --------------------------------------------------------------------------


def _segment_evidence(seg: Segment, following: Optional[Segment], hit: _Hit, depth: int) -> None:
    prog = seg.program
    args = seg.args
    text = seg.text
    lowered = [a.lower() for a in args]
    targets = _write_targets(seg)

    # -- privilege escalation --------------------------------------------
    if {"sudo", "doas"} & set(seg.wrappers) or prog in {"sudo", "doas"}:
        hit(P, "command:sudo")
    if prog in {"su", "pkexec"}:
        hit(P, "command:switch_user")
    if prog == "find" and _SUID_PERM.search(text):
        hit(P, "command:suid_search")
    if prog in {"getcap", "setcap"}:
        hit(P, "command:capabilities")
    if prog == "chmod" and any(_SETUID_MODE.match(a) for a in args):
        hit(P, "command:setuid_bit")
    if prog in {"unshadow", "john", "hashcat"}:
        hit(P, "command:password_cracking")
    if prog in {"docker", "podman"} and "run" in args and (_HOST_ROOT_MOUNT.search(text) or "--privileged" in args):
        hit(P, "command:container_escape")
    if _PRIVESC_TOOLS.search(text):
        hit(P, "command:privesc_enumeration")
    if any(_CREDENTIAL_STORE.search(a) for a in args + seg.reads):
        hit(P, "command:credential_store_read")
    if prog == "visudo" or any(_SUDOERS.search(t) for t in targets):
        hit(P, "command:sudoers_change")
    elif (prog in _READERS or prog in {"ls", "stat"}) and any(_SUDOERS.search(a) for a in args):
        hit(P, "command:sudoers_read")
    if prog == "nsenter":
        hit(P, "command:namespace_escape")
    if prog == "lxc" and (args[:1] == ["exec"] or re.search(r"security\.privileged|source=/(\s|$)", text)):
        hit(P, "command:container_escape")
    if prog == "mount" and any(_DISK_DEVICE.match(a) for a in args):
        hit(P, "command:host_disk_mount")
    if prog == "chroot" and args[:1] and re.match(r"^/(mnt|host|media|rootfs)(/|$)", args[0]):
        hit(P, "command:chroot_escape")
    if "-p" in args and ("bash" in prog or prog in {"sh", "dash", "zsh"}):
        hit(P, "command:suid_shell")
    if targets and prog in {"echo", "printf", "cat", "tee"} and _SUID_PAYLOAD.search(text):
        hit(P, "command:suid_payload_drop")

    # -- persistence -------------------------------------------------------
    if prog == "crontab":
        # Listing cron is looking around; anything else installs or replaces it.
        listing = "-l" in args and not seg.piped_in and not {"-e", "-r", "-"} & set(args)
        if listing:
            hit(R, "command:cron_listing")
        else:
            hit(S, "command:cron_install")
    for target in targets:
        if _AUTH_KEYS.search(target):
            hit(S, "command:authorized_keys_write")
        elif _CRON_PATH.search(target):
            hit(S, "command:cron_install")
        elif _BOOT_PATH.search(target):
            hit(S, "command:boot_script")
        elif _PROFILE_PATH.search(target):
            hit(S, "command:shell_profile_hook")
        elif _SYSTEMD_PATH.search(target):
            hit(S, "command:systemd_unit")
        elif _PRELOAD_PATH.search(target):
            hit(S, "command:preload_hook")
        elif _SSHD_CONFIG.search(target):
            hit(S, "command:sshd_config_change")
        elif _PAM_PATH.search(target):
            hit(S, "command:pam_change")
        elif _MOTD_PATH.search(target):
            hit(S, "command:motd_hook")
        elif _WEB_SHELL.search(target):
            hit(S, "command:web_shell")
        elif _ACCOUNT_FILES.search(target):
            hit(S, "command:account_file_change")
        elif _APP_CODE.search(target):
            hit(S, "command:app_code_change")
    if prog in {"aws", "gcloud", "az"} and any(_CLOUD_PERSIST.match(a) for a in args):
        hit(S, "command:cloud_credential_creation")
    if prog in {"cp", "mv", "install"} and targets and _SYSTEM_BIN.match(targets[-1]):
        sources = [a for a in args if not a.startswith("-")][:-1]
        if any(_STAGING_DIR.match(source) for source in sources):
            hit(S, "command:binary_install")
    if prog == "chage" and seg.has_short_flag("l"):
        hit(R, "command:password_policy")
    elif prog in _ACCOUNT_TOOLS:
        hit(S, "command:account_change")
    if prog in {"insmod", "modprobe"} and args:
        hit(S, "command:kernel_module")
    if (prog == "systemctl" and {"enable", "daemon-reload", "link"} & set(lowered)) or prog in {"update-rc.d", "chkconfig"}:
        hit(S, "command:service_enable")
    if prog in {"chattr", "lockr"}:
        hit(S, "command:file_attribute_lock")
    if prog == "at" and args:
        hit(S, "command:scheduled_task")

    # -- lateral movement --------------------------------------------------
    if prog in {"ssh", "autossh"}:
        destination, remote, tunnel = _ssh_destination(args)
        if destination is not None:
            hit(L, "command:ssh_tunnel" if tunnel else "command:ssh_session")
            if remote and depth < 2:
                for intent, rules in command_evidence(remote, depth + 1).items():
                    for rule in rules:
                        hit(intent, f"remote:{rule}")
    if prog == "sshpass":
        hit(L, "command:sshpass")
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in _SSHPASS_VALUE_OPTIONS else 1
        if i < len(args) and depth < 2:
            for intent, rules in command_evidence(" ".join(args[i:]), depth + 1).items():
                for rule in rules:
                    hit(intent, rule)
    if prog in {"scp", "rsync", "sftp"}:
        hosts = _remote_hosts(prog, args)
        if any(is_external_host(host) for host in hosts):
            hit(X, "command:external_transfer")
        elif hosts:
            hit(L, "command:internal_transfer")
    if prog == "ssh-copy-id":
        hit(L, "command:key_push")
    if prog == "smbclient" and seg.has_short_flag("L"):
        hit(R, "command:share_discovery")
    elif prog in _REMOTE_SERVICES or (prog == "mount" and _NET_FS.search(text)):
        hit(L, "command:remote_service")
    if prog in {"kubectl", "oc", "docker", "podman", "crictl"} and args[:1] and args[0] in _CONTAINER_ENTER:
        hit(L, "command:container_exec")
    if prog in _REMOTE_EXEC or (prog == "telnet" and any(not a.startswith("-") for a in args)):
        hit(L, "command:remote_execution")
    if prog in _BRUTEFORCE:
        hit(L, "command:remote_bruteforce")

    # -- data exfiltration -------------------------------------------------
    if prog == "tar" and _tar_creates(args):
        hit(X, "command:archive")
    if prog == "zip" or (prog in {"7z", "7za", "rar"} and args[:1] == ["a"]):
        hit(X, "command:archive")
    if prog in {"gzip", "bzip2", "xz", "zstd", "pigz"} and not seg.has_short_flag("d") and "--decompress" not in args:
        hit(X, "command:compress")
    if prog in {"base64", "basenc", "uuencode"} and not (seg.has_short_flag("d") or "--decode" in args):
        hit(X, "command:encode")
    if prog == "xxd" and not seg.has_short_flag("r"):
        hit(X, "command:encode")
    if prog == "split":
        hit(X, "command:chunking")
    if prog in _DB_DUMPERS or (prog == "sqlite3" and ".dump" in lowered):
        hit(X, "command:database_dump")
    if prog == "curl" and _curl_uploads(args):
        hit(X, "command:http_upload")
    if prog == "wget" and any(a.startswith(("--post-file", "--body-file")) for a in args):
        hit(X, "command:http_upload")
    if prog in {"nc", "ncat", "netcat", "socat"}:
        if seg.has_short_flag("z"):
            hit(R, "command:port_probe")
        elif (seg.reads or seg.piped_in) and not seg.has_short_flag("l"):
            hit(X, "command:socket_transfer")
    if prog == "aws" and len(args) >= 2 and args[0] == "s3":
        if args[1] in {"cp", "sync", "mv"}:
            hit(X, "command:cloud_transfer")
        elif args[1] == "ls":
            hit(R, "command:cloud_discovery")
    if prog in {"gsutil", "rclone", "azcopy"} and args[:1] and args[0] in {"cp", "copy", "sync", "mv"}:
        hit(X, "command:cloud_transfer")
    if (prog.startswith("python") and _HTTP_SERVER.search(text)) or (prog == "php" and "-S" in args) or (
        prog == "httpd" and "busybox" in seg.wrappers
    ):
        hit(X, "command:file_server")
    if prog == "gpg" and not ("--decrypt" in args or seg.has_short_flag("d")) and (
        {"--symmetric", "--encrypt"} & set(args) or seg.has_short_flag("c") or seg.has_short_flag("e")
    ):
        hit(X, "command:encrypt")
    if prog == "openssl" and args[:1] and (args[0] == "enc" or re.match(r"^(aes|des|chacha|camellia|bf)", args[0])) and "-d" not in args:
        hit(X, "command:encrypt")
    if prog in {"ccrypt", "age", "mcrypt"} and not (seg.has_short_flag("d") or "--decrypt" in args):
        hit(X, "command:encrypt")
    if prog in {"cp", "mv", "install", "rsync"} and not _remote_hosts(prog, args):
        plain = [a for a in args if not a.startswith("-")]
        if len(plain) >= 2 and _STAGING_DEST.search(plain[-1]) and any(_SENSITIVE_DATA.search(s) for s in plain[:-1]):
            hit(X, "command:data_staging")
    if prog == "dd":
        source = next((a[3:] for a in args if a.startswith("if=")), "")
        if _DISK_DEVICE.match(source) or _SENSITIVE_DATA.search(source):
            hit(X, "command:disk_image")
    if prog in {"cat", "head", "tail", "less", "more", "strings", "column"} and any(_DATA_FILE.search(a) for a in args) and not targets:
        hit(X, "command:data_read")
    if any(t.startswith(("/dev/tcp/", "/dev/udp/")) for t in seg.writes) and prog in {"cat", "tar", "dd", "gzip", "base64", "cpio", "xxd", "zip"}:
        hit(X, "command:socket_transfer")
    if prog in _DNS_TUNNEL or (prog in _DNS_LOOKUP and any(_ENCODED_LABEL.search(a) for a in args if not a.startswith(("-", "+", "@")))):
        hit(X, "command:dns_exfil")
    if prog in {"ftp", "lftp"} and any(is_external_host(_url_host(a)) for a in args if not a.startswith("-")):
        hit(X, "command:ftp_session")
    if prog in {"put", "mput", "send"} and args:
        # Typed inside an interactive ftp/sftp client, which the recorder
        # reconstructs like any other line.
        hit(X, "command:ftp_upload")
    if prog == "ncftpput" or (prog in {"tftp", "lftp"} and any(re.search(r"\b(m?put|mirror\s+-R)\b", a) for a in args)):
        hit(X, "command:file_transfer")
    if prog == "redis-cli" and "--rdb" in args:
        hit(X, "command:database_dump")
    if (prog == "az" and "upload" in lowered) or prog in {"mega-put", "megaput"}:
        hit(X, "command:cloud_transfer")
    if prog == "redis-cli" and "--rdb" not in args and set(lowered) & {"info", "keys", "scan", "--scan", "config", "dbsize", "client"}:
        hit(R, "command:datastore_enumeration")
    if prog in {"mongo", "mongosh"} and re.search(r"listDatabases|show\s+(dbs|collections)|getCollectionNames|db\.stats", text):
        hit(R, "command:datastore_enumeration")
    if prog == "psql" and {"-l", "--list"} & set(args):
        hit(R, "command:datastore_enumeration")
    elif prog in _DB_CLIENTS and not sql_evidence(" ".join(args), hit):
        # A client with no statement opens an interactive session -- on another
        # host, that is reaching a new machine with stolen credentials.
        host = next((args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-h", "--host")), "")
        if host and host not in {"localhost", "127.0.0.1", "::1"}:
            hit(L, "command:database_login")

    # -- reconnaissance ----------------------------------------------------
    if prog in _HOST_ENUMERATION or (prog == "history" and not seg.has_short_flag("c")):
        hit(R, "command:host_enumeration")
    if prog == "ip" and args[:1] and args[0] in {"a", "addr", "address", "r", "route", "n", "neigh", "link", "-br", "-4", "-6"}:
        hit(R, "command:host_enumeration")
    if (prog in {"fdisk", "parted", "sfdisk"} and seg.has_short_flag("l")) or (prog == "mount" and not args):
        hit(R, "command:host_enumeration")
    if prog == "lxc" and args[:1] and args[0] in {"list", "info", "image", "storage", "network"} and not re.search(r"security\.privileged|source=/", text):
        hit(R, "command:host_enumeration")
    if prog in _NETWORK_DISCOVERY:
        hit(R, "command:network_discovery")
    if prog in _FILE_DISCOVERY and not (prog == "find" and _SUID_PERM.search(text)):
        hit(R, "command:file_discovery")
    if prog in _READERS and any(_RECON_FILE.search(a) for a in args) and not targets:
        hit(R, "command:config_or_secret_read")
    if prog in {"grep", "egrep", "fgrep", "rg"} and _SECRET_PATTERN.search(" ".join(a for a in args if not a.startswith("/"))):
        hit(R, "command:secret_search")
    if prog in {"curl", "wget"} and not _curl_uploads(args) and any(_URL.match(a) or _HOST_PORT.match(a) for a in args):
        piped_to_shell = following is not None and following.piped_in and following.program in _SHELLS
        if seg.has_flag("-I", "--head") or not (_saves_download(seg) or piped_to_shell):
            hit(R, "command:http_probe")
    if prog in {"docker", "podman", "kubectl", "oc", "crictl"} and args[:1] and args[0] in _CONTAINER_LOOK:
        hit(R, "command:host_enumeration")
    if prog in _PACKAGE_LISTING and set(args) & _PACKAGE_LISTING[prog]:
        hit(R, "command:software_discovery")
    if prog in {"aws", "gcloud", "az"} and any(re.match(r"^(list|describe|get)(-|$)", a) for a in args) and not (
        prog == "aws" and args[:1] == ["s3"]
    ):
        hit(R, "command:cloud_discovery")
    if prog in {"systemctl", "service"} and set(lowered) & {"list-units", "list-unit-files", "status", "--status-all"}:
        hit(R, "command:host_enumeration")
    if "busybox" in seg.wrappers and prog.isupper():
        hit(R, "command:busybox_probe")


def command_evidence(command: str, depth: int = 0) -> Evidence:
    """Every rule one command trips, grouped by intent."""
    evidence: Evidence = {}

    def hit(intent: str, rule: str) -> None:
        rules = evidence.setdefault(intent, [])
        if rule not in rules:
            rules.append(rule)

    # A line that is SQL rather than shell -- typed inside an interactive
    # mysql/psql session, which the recorder reconstructs like any other line.
    if _SQL_START.match(command):
        sql_evidence(command, hit)

    parsed = segments(command)
    for index, seg in enumerate(parsed):
        following = parsed[index + 1] if index + 1 < len(parsed) else None
        _segment_evidence(seg, following, hit, depth)
    return evidence


# --------------------------------------------------------------------------
# http_logs / db_queries
# --------------------------------------------------------------------------
#
# The sidecar sends commands only; these sources exist for other callers of
# /intent-classify. They have no order relative to the commands, so they are
# consulted only when no command carries evidence, and they also count as
# context that can agree or disagree with a command-based decision.

_HTTP_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (R, "http:discovery_path", ("/admin", "/debug", "/.git", "/metrics", "/status")),
    (P, "http:role_or_token_abuse", ("/token/elevate", "/session/impersonate", "/admin/users/role")),
    (S, "http:persistence_path", ("/cron", "/jobs/schedule", "/keys/authorized", "/startup")),
    (L, "http:lateral_path", ("/remote/node/connect", "/internal/share", "/ssh/session", "/rdp")),
    (X, "http:export_path", ("/download", "/archive/upload", "/reports/export", "/dump", "/export")),
)
_DB_QUERY_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (L, "db:remote_query", ("dblink", "openquery", "linked server", "federated")),
)


def _log_evidence(activity: dict[str, Any]) -> Evidence:
    evidence: Evidence = {}

    def hit(intent: str, rule: str) -> None:
        rules = evidence.setdefault(intent, [])
        if rule not in rules:
            rules.append(rule)

    http_text = "\n".join(str(v).lower() for v in activity.get("http_logs", []) if v)
    for intent, rule, needles in _HTTP_RULES:
        if any(needle in http_text for needle in needles):
            hit(intent, rule)
    for query in activity.get("db_queries", []) or []:
        sql_evidence(str(query), hit, prefix="db")
        lowered = str(query).lower()
        for intent, rule, needles in _DB_QUERY_RULES:
            if any(needle in lowered for needle in needles):
                hit(intent, rule)
    return evidence


# --------------------------------------------------------------------------
# decision
# --------------------------------------------------------------------------


def _deepest(intents) -> str:
    return max(intents, key=lambda intent: KILL_CHAIN_ORDER.get(intent, 0))


def _decide(deciding: Evidence, age: int, others: list[Evidence]) -> RuleMatch:
    winner = _deepest(deciding)
    rules = list(deciding[winner])
    if len(deciding) > 1:
        rules.append("tiebreak:kill_chain_depth(" + "|".join(sorted(deciding)) + ")")

    disagreeing = {intent for evidence in others for intent in evidence if intent != winner}
    agreeing = sum(1 for evidence in others if winner in evidence)

    if disagreeing:
        rules.append("tiebreak:recency(" + "|".join(sorted(disagreeing | {winner})) + ")")
        confidence = 0.70
    else:
        confidence = (0.85 if age == 0 else 0.75) + 0.05 * agreeing
        if len(deciding) > 1:
            confidence -= 0.05
    return RuleMatch(intent=winner, confidence=round(min(confidence, 0.95), 2), matched_rules=rules)


def _decide_by_count(evidence: Evidence) -> RuleMatch:
    counts = {intent: len(rules) for intent, rules in evidence.items()}
    top = max(counts.values())
    tied = [intent for intent, count in counts.items() if count == top]
    winner = _deepest(tied)
    rules = list(evidence[winner])
    if len(tied) > 1:
        rules.append("tiebreak:kill_chain_depth(" + "|".join(sorted(tied)) + ")")
        return RuleMatch(intent=winner, confidence=0.65, matched_rules=rules)
    second = max([c for i, c in counts.items() if i != winner], default=0)
    confidence = min(0.95, 0.7 + 0.1 * top + 0.05 * (top - second))
    return RuleMatch(intent=winner, confidence=round(confidence, 2), matched_rules=rules)


def window_evidence(activity: dict[str, Any]) -> list[Evidence]:
    """Per-command evidence for the window, oldest first."""
    return [command_evidence(str(command)) for command in activity.get("commands", []) if command]


def detect_intent_by_rules(activity: dict[str, Any]) -> RuleMatch | None:
    """The rules' verdict on a window, or None when nothing in it is evidence."""
    per_command = window_evidence(activity)
    context = _log_evidence(activity)

    for age, evidence in enumerate(reversed(per_command)):
        if evidence:
            index = len(per_command) - 1 - age
            others = [e for i, e in enumerate(per_command) if i != index and e]
            if context:
                others.append(context)
            return _decide(evidence, age, others)

    if context:
        return _decide_by_count(context)
    return None


def evidenced_intents(activity: dict[str, Any]) -> list[str]:
    """Every intent with evidence anywhere in the window, deepest first."""
    found = {intent for evidence in window_evidence(activity) for intent in evidence}
    found |= set(_log_evidence(activity))
    return sorted(found, key=lambda intent: -KILL_CHAIN_ORDER.get(intent, 0))


assert set(KILL_CHAIN_ORDER) == set(INTENT_CLASSES)
