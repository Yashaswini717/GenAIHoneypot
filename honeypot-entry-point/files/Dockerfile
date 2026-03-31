# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------
# Base packages
# --------------------------------------------------
RUN apt-get update && apt-get install -y \
    passwd \
    sudo \
    vim \
    nano \
    curl \
    wget \
    net-tools \
    iproute2 \
    procps \
    htop \
    ca-certificates \
    openssh-client \
    openssh-server \
    python3 \
    python3-pip \
    bsdutils \
    gcc \
    make \
    git \
    tmux \
    nmap \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install requests

# --------------------------------------------------
# SSH server setup
# --------------------------------------------------
RUN mkdir -p /var/run/sshd && ssh-keygen -A

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    echo "Banner /etc/issue" >> /etc/ssh/sshd_config && \
    echo "PrintMotd yes" >> /etc/ssh/sshd_config

# --------------------------------------------------
# Logging infrastructure
# --------------------------------------------------
RUN mkdir -p /var/log/honeypot

COPY --chmod=755 <<'EOF' /usr/local/bin/logshell
#!/bin/bash
SESSION_ID=$(date +%Y%m%d_%H%M%S)_$$
LOG_FILE="/var/log/honeypot/session_${SESSION_ID}.log"
TIMING_FILE="/var/log/honeypot/timing_${SESSION_ID}.log"
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] SESSION_START ip=${SSH_CLIENT%% *} user=$(whoami)" >> /var/log/honeypot/sessions.log
script -q -f -a "$LOG_FILE" /bin/bash -c 'source /opt/fakeroot/rootrc; exec bash' 2>/dev/null
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] SESSION_END id=${SESSION_ID}" >> /var/log/honeypot/sessions.log
EOF

COPY --chmod=755 <<'EOF' /usr/local/bin/alert.py
#!/usr/bin/env python3
import requests, os, datetime, socket

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

def notify():
    if not WEBHOOK_URL:
        return
    try:
        ip = os.environ.get("SSH_CLIENT", "unknown").split()[0]
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        hostname = socket.gethostname()
        payload = {
            "content": (
                f"🚨 **Honeypot Login Detected**\n"
                f"```\nTime    : {ts}\nFrom IP : {ip}\nHost    : {hostname}\n```"
            )
        }
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass

if __name__ == "__main__":
    notify()
EOF

# Entrypoint: starts sshd + keeps container alive
COPY --chmod=755 <<'EOF' /usr/local/bin/entrypoint.sh
#!/bin/bash
/usr/sbin/sshd -D
EOF

# Per-session shell launched by sshd via ForceCommand
COPY --chmod=755 <<'EOF' /usr/local/bin/honeypot-session.sh
#!/bin/bash
python3 /usr/local/bin/alert.py
SESSION_ID=$(date +%Y%m%d_%H%M%S)_$$
LOG_FILE="/var/log/honeypot/session_${SESSION_ID}.log"
TIMING_FILE="/var/log/honeypot/timing_${SESSION_ID}.log"
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] SESSION_START ip=${SSH_CLIENT%% *} user=${USER}" >> /var/log/honeypot/sessions.log
script -q -f -a "$LOG_FILE" /bin/bash -c 'source /opt/fakeroot/rootrc; exec bash' 2>/dev/null
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] SESSION_END id=${SESSION_ID}" >> /var/log/honeypot/sessions.log
EOF

# Tell sshd to run our honeypot shell for every login
RUN echo "ForceCommand /usr/local/bin/honeypot-session.sh" >> /etc/ssh/sshd_config

# --------------------------------------------------
# Fake root illusion
# --------------------------------------------------
RUN mkdir -p /opt/fakeroot/bin

COPY --chmod=755 <<'EOF' /opt/fakeroot/bin/whoami
#!/bin/bash
echo root
EOF

COPY --chmod=755 <<'EOF' /opt/fakeroot/bin/id
#!/bin/bash
echo "uid=0(root) gid=0(root) groups=0(root)"
EOF

COPY <<'EOF' /opt/fakeroot/rootrc
export PS1="root@dev-server:~# "
EOF

COPY --chmod=755 <<'EOF' /opt/fakeroot/bin/sudo
#!/bin/bash
if [ "$1" = "-l" ]; then
  echo "User devuser may run the following commands on dev-server:"
  echo "    (ALL : ALL) NOPASSWD: ALL"
  exit 0
fi
if [ "$1" = "-s" ] || [ "$1" = "-i" ]; then
  exec /bin/bash --noprofile --rcfile /opt/fakeroot/rootrc
fi
export HOME=/root USER=root LOGNAME=root
exec /bin/bash --noprofile --rcfile /opt/fakeroot/rootrc -c "${*}"
EOF

COPY --chmod=755 <<'EOF' /opt/fakeroot/bin/netstat
#!/bin/bash
echo "Active Internet connections (servers and established)"
echo "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
echo "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      312/sshd"
echo "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      891/mysqld"
echo "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      934/apache2"
echo "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      934/apache2"
echo "tcp        0      0 dev-server:ssh          10.0.0.45:52314         ESTABLISHED 1042/sshd: devuser"
echo "tcp        0      0 127.0.0.1:3306          127.0.0.1:54212         ESTABLISHED 891/mysqld"
EOF

COPY --chmod=755 <<'EOF' /opt/fakeroot/bin/ps
#!/bin/bash
echo "  PID TTY          TIME CMD"
echo "    1 ?        00:00:01 systemd"
echo "  312 ?        00:00:02 sshd"
echo "  891 ?        00:00:11 mysqld"
echo "  934 ?        00:00:04 apache2"
echo "  935 ?        00:00:00 apache2"
echo " 1042 ?        00:00:00 sshd: devuser@pts/0"
echo " 1043 pts/0    00:00:00 bash"
echo " 1089 pts/0    00:00:00 ps"
EOF

COPY --chmod=755 <<'EOF' /opt/fakeroot/bin/mysql
#!/bin/bash
if [ "$1" = "--version" ]; then
  echo "mysql  Ver 8.0.31 Distrib 8.0.31, for Linux (x86_64)"
  exit 0
fi
echo "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: NO)"
EOF

COPY --chmod=755 <<'EOF' /opt/fakeroot/bin/git
#!/bin/bash
case "$1" in
  log)
    echo "commit 3f9a1bc7d2e8a4f6b1c9d0e2f3a4b5c6d7e8f9a0 (HEAD -> main, origin/main)"
    echo "Author: Dev User <devuser@university.edu>"
    echo "Date:   Fri Nov 10 14:22:01 2023 +0000"
    echo ""
    echo "    fix: patched auth bypass in login module"
    ;;
  status)
    echo "On branch main"
    echo "Your branch is up to date with 'origin/main'."
    echo "nothing to commit, working tree clean"
    ;;
  *)
    /usr/bin/git "$@"
    ;;
esac
EOF

ENV PATH="/opt/fakeroot/bin:$PATH"

# --------------------------------------------------
# Realistic system identity
# --------------------------------------------------
RUN echo "dev-server.cs.university.edu" > /etc/hostname

RUN printf 'prof_davis:x:1001:1001:Professor Alan Davis:/home/prof_davis:/bin/bash\n\
ta_miller:x:1002:1002:Sarah Miller (TA):/home/ta_miller:/bin/bash\n\
student_raj:x:1003:1003:Raj Patel:/home/raj_patel:/bin/bash\n\
sysadmin:x:1004:1004:Systems Administrator:/home/sysadmin:/bin/bash\n' >> /etc/passwd

RUN mkdir -p /home/prof_davis /home/ta_miller /home/raj_patel /home/sysadmin

COPY <<'EOF' /etc/issue
============================================================
  PES UNIVERSITY -- CS Department Server
  Authorized users only. All activity is logged and monitored.
  Unauthorized access will be reported to law enforcement.
============================================================

EOF

COPY <<'EOF' /etc/motd

Welcome to dev-server.cs.pesu.pes.edu (Ubuntu 22.04 LTS)
Last login: Mon Nov 13 09:42:17 2023 from 10.0.0.45

System information:
  Load average : 0.12, 0.08, 0.05
  Disk usage   : 47% of 500GB
  Memory       : 3.1GB / 16GB

Scheduled maintenance: Sunday 02:00-04:00 UTC
Questions? Contact helpdesk@cs.pesu.pes.edu

EOF

# --------------------------------------------------
# Create non-root user
# --------------------------------------------------
RUN useradd -m -s /bin/bash devuser && \
    echo "devuser:password" | chpasswd && \
    echo "devuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    chown -R devuser:devuser /var/log/honeypot

# --------------------------------------------------
# Bait files
# --------------------------------------------------
COPY --chown=devuser:devuser <<'EOF' /home/devuser/.bash_history
ssh admin@192.168.1.10
mysql -u root -p
sudo cat /etc/shadow
cat .credentials
nano projects/group_a_backend/.env
git log
git push origin main
python3 manage.py runserver
sudo systemctl restart apache2
curl http://localhost:3000/api/health
history -c
EOF

COPY --chmod=600 --chown=devuser:devuser <<'EOF' /home/devuser/.credentials
[university-vpn]
username=devuser
password=Fall2023!

[gitlab]
token=glpat-xxFAKETOKENxx1234

[mysql-local]
user=root
password=D3vS3rver#2023

[aws-dev]
access_key=AKIAIOSFODNN7FAKE00
secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY
EOF

RUN mkdir -p /home/devuser/.ssh /home/devuser/projects/group_a_backend/src \
    /home/devuser/Desktop/assignments \
    /home/devuser/Documents/research/thesis/drafts \
    /home/devuser/Documents/research/datasets/raw \
    /home/devuser/Documents/fall_2023/cs440_ai \
    /home/devuser/Documents/fall_2023/math302_stats \
    /home/devuser/public_html/assets \
    /home/devuser/downloads && \
    chown -R devuser:devuser /home/devuser

COPY --chmod=600 --chown=devuser:devuser <<'EOF' /home/devuser/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...FAKEKEY...AAAAAAAAAB
-----END OPENSSH PRIVATE KEY-----
EOF

COPY --chmod=644 --chown=devuser:devuser <<'EOF' /home/devuser/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...FAKEKEY... devuser@dev-server
EOF

COPY --chmod=600 --chown=devuser:devuser <<'EOF' /home/devuser/.ssh/config
Host university-backup
  HostName backup.cs.university.edu
  User devuser
  IdentityFile ~/.ssh/id_rsa
EOF

COPY --chmod=600 --chown=devuser:devuser <<'EOF' /home/devuser/projects/group_a_backend/.env
# group_a_backend -- DO NOT COMMIT
APP_ENV=development
SECRET_KEY=django-insecure-f4k3s3cr3tk3y!2023!university

DB_ENGINE=django.db.backends.mysql
DB_HOST=db.cs.university.edu
DB_PORT=3306
DB_NAME=group_a_db
DB_USER=group_a_admin
DB_PASSWORD=Gr0up@2023!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKE00
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY
AWS_S3_BUCKET=university-cs-group-a
AWS_REGION=us-east-1

SENDGRID_API_KEY=SG.FAKEAPIKEY.0000000000000000000000
OPENAI_API_KEY=sk-FAKEKEY00000000000000000000000000000000
EOF

COPY --chown=devuser:devuser <<'EOF' /home/devuser/todo_list.txt
TODO (week of Nov 13):
[x] Push thesis chapter 3 to remote
[ ] Change DB password -- IT says current one (D3vS3rver#2023) is too old
[ ] Ask Prof. Davis about thesis deadline extension
[ ] Renew SSL cert (expires Dec 1)
[ ] Update backup script -- creds in /home/sysadmin/backup.conf
[ ] Move API keys to vault (currently hardcoded in .env)
[ ] Fix auth bug in group_a_backend before Friday demo
EOF

COPY --chown=devuser:devuser <<'EOF' /home/devuser/Documents/research/thesis/drafts/thesis_v3_final.tex
\documentclass{article}
\title{Anomaly Detection in IoT Sensor Networks Using LSTM Autoencoders}
\author{Dev User}
\begin{document}
\maketitle
\section{Introduction}
This thesis investigates the application of deep learning...
% TODO: expand intro, Prof. Davis wants 3 more pages
\end{document}
EOF

COPY --chown=devuser:devuser <<'EOF' /home/devuser/Documents/research/datasets/raw/sensor_logs_2023.csv
timestamp,sensor_id,temperature,humidity,pressure,anomaly
2023-10-01T00:00:00Z,SN001,22.4,61.2,1013.2,0
2023-10-01T00:05:00Z,SN001,22.5,61.0,1013.1,0
2023-10-01T00:10:00Z,SN001,38.9,85.3,998.7,1
EOF

COPY --chown=devuser:devuser <<'EOF' /home/devuser/Documents/fall_2023/cs440_ai/hw1_search.py
# CS440 AI -- HW1: Search Algorithms
# devuser | Fall 2023

def bfs(graph, start, goal):
    from collections import deque
    queue = deque([[start]])
    visited = set()
    while queue:
        path = queue.popleft()
        node = path[-1]
        if node == goal:
            return path
        if node not in visited:
            visited.add(node)
            for neighbor in graph.get(node, []):
                queue.append(path + [neighbor])
    return None
EOF

COPY --chown=devuser:devuser <<'EOF' /home/devuser/projects/group_a_backend/README.md
# Group A Backend
Django REST API for the CS senior project.

## Setup
Copy `.env.example` to `.env` and fill in credentials.
See `.env` for current dev credentials (do not push!).

## Contacts
- devuser (backend lead)
- ta_miller@university.edu (TA / code review)
EOF

EXPOSE 22
CMD ["/usr/local/bin/entrypoint.sh"]
