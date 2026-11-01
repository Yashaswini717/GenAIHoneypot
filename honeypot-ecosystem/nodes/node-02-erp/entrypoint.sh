#!/bin/bash
## node-02: the ERP portal. Everything started here is a real service.
##
## That is the whole disguise. Once nginx and gunicorn genuinely run, `ps`,
## `ss`, `/proc` and the logs under /var/log/nginx agree with each other for
## free, because none of them is being lied to. An attacker who pivots here
## from jump-01 finds a web server that actually serves the portal the deploy
## script on jump-01 talks about.
set -euo pipefail

## Deletes /.dockerenv without naming it. The line survives comment
## stripping, so a literal `rm -f /.dockerenv` in an installed boot script
## would hand over the one thing the rest of this work exists to hide --
## and it reads as damning to anyone who knows what that file is. A sweep
## for build-pipeline markers is the same operation and an ordinary thing
## for a provisioning script to do.
# Clear provisioning markers left in / by the image pipeline.
find / -maxdepth 1 -name '.*env' -type f -delete 2>/dev/null || true
## Record the boot in wtmp and utmp, which on a systemd host systemd does.
##
## Without it `last reboot` kept answering with the *seeded* boot record --
## 94 days ago -- while uptime, ps and syslog's boot sequence all agreed the
## box came up minutes ago. One `last reboot` against one `uptime` and the
## story falls apart, so the record has to be the real one.
##
## utmp is written rather than appended: a fresh boot's utmp holds the boot
## and runlevel records and nothing else, and sessions are added to it as
## people log in.
## A shutdown record before the boot, which is what a clean shutdown writes.
## Without it `last reboot` listed both the seeded boot and this one as
## "still running" -- a machine cannot be up twice, and only the current
## boot is ever open on a real host.
DOWN_STAMP="$(date -u -d '4 seconds ago' '+%Y-%m-%dT%H:%M:%S,%6N+00:00')"
printf '[1] [00000] [~~  ] [shutdown] [~           ] [%-20s] [0.0.0.0        ] [%s]
' \
    "$(uname -r)" "$DOWN_STAMP" | utmpdump -r >> /var/log/wtmp 2>/dev/null || true

BOOT_STAMP="$(date -u '+%Y-%m-%dT%H:%M:%S,%6N+00:00')"
BOOT_RECORDS="$(
    printf '[2] [00000] [~~  ] [reboot  ] [~           ] [%-20s] [0.0.0.0        ] [%s]
' \
        "$(uname -r)" "$BOOT_STAMP"
    printf '[1] [00000] [~~  ] [runlevel] [~           ] [%-20s] [0.0.0.0        ] [%s]
' \
        "$(uname -r)" "$BOOT_STAMP"
)"
printf '%s
' "$BOOT_RECORDS" | utmpdump -r >> /var/log/wtmp 2>/dev/null || true
printf '%s
' "$BOOT_RECORDS" | utmpdump -r > /var/run/utmp 2>/dev/null || true

mkdir -p /run/sshd /var/run/rsyslog /var/log/nginx

if [[ -f /etc/hosts.extra && -s /etc/hosts.extra ]] && ! grep -q "Departmental hosts" /etc/hosts; then
    cat /etc/hosts.extra >> /etc/hosts
fi

if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    ssh-keygen -A >/dev/null 2>&1
fi

service rsyslog start >/dev/null 2>&1 || rsyslogd
service cron start >/dev/null 2>&1 || cron

## The application behind nginx. Bound to localhost only: the admin console
## being reachable from outside would contradict the "internal interface only"
## note the attacker finds on jump-01.
if [[ -x /opt/erp/portal.py ]]; then
    (cd /opt/erp && nohup python3 portal.py >>/var/log/erp-portal.log 2>&1 &) || true
fi

nginx -g 'daemon on;' >/dev/null 2>&1 || true

# Hand off to sshd, which keeps the node alive.
exec /usr/sbin/sshd -D -e
