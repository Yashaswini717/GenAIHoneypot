#!/bin/bash
# node-02: the ERP portal. Everything started here is a real service.
#
# That is the whole disguise. Once nginx and gunicorn genuinely run, `ps`,
# `ss`, `/proc` and the logs under /var/log/nginx agree with each other for
# free, because none of them is being lied to. An attacker who pivots here
# from jump-01 finds a web server that actually serves the portal the deploy
# script on jump-01 talks about.
set -euo pipefail

rm -f /.dockerenv
mkdir -p /run/sshd /var/run/rsyslog /var/log/nginx

if [[ -f /etc/hosts.extra && -s /etc/hosts.extra ]] && ! grep -q "Departmental hosts" /etc/hosts; then
    cat /etc/hosts.extra >> /etc/hosts
fi

if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    ssh-keygen -A >/dev/null 2>&1
fi

service rsyslog start >/dev/null 2>&1 || rsyslogd
service cron start >/dev/null 2>&1 || cron

# The application behind nginx. Bound to localhost only: the admin console
# being reachable from outside would contradict the "internal interface only"
# note the attacker finds on jump-01.
if [[ -x /opt/erp/portal.py ]]; then
    (cd /opt/erp && nohup python3 portal.py >>/var/log/erp-portal.log 2>&1 &) || true
fi

nginx -g 'daemon on;' >/dev/null 2>&1 || true

exec /usr/sbin/sshd -D -e
