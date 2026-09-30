#!/bin/bash
# Bring the node up as a machine, not as a container.
#
# Everything started here is a real service. That is the whole disguise: once
# sshd, cron and rsyslog are genuinely running, `ps`, `ss`, `systemctl`,
# /proc and `top` agree with each other for free, because none of them is
# being lied to. There is nothing to maintain and nothing to catch.
set -euo pipefail

# --------------------------------------------------------------------------
# Container tells
# --------------------------------------------------------------------------

# The single most checked container indicator, and free to remove.
rm -f /.dockerenv

# Residual tells that cannot be cleared from inside a container with no
# CAP_SYS_ADMIN, listed here so they stay visible rather than forgotten:
#
#   /proc/1/cgroup      shows a docker path on cgroup v1. Needs a bind mount
#                       from the host side; the session broker is where that
#                       belongs. On cgroup v2 it reads "0::/", which is much
#                       less distinctive.
#   /sys/class/dmi      absent, where a VM would expose vendor strings.
#   MAC address         Docker's 02:42 prefix. The broker sets a KVM-style
#                       52:54:00 address instead.
#
# These are tracked as phase 3 pre-launch audit items.

# --------------------------------------------------------------------------
# Services
# --------------------------------------------------------------------------

mkdir -p /run/sshd /var/run/rsyslog

# Docker rewrites /etc/hosts on every container start, so the departmental
# host entries have to be appended at boot rather than baked into the image.
# They matter: a deploy script that references a hostname which does not
# resolve is obviously staged, and the pivot targets must look routable.
if [[ -f /etc/hosts.extra ]] && ! grep -q "Departmental hosts" /etc/hosts; then
    cat /etc/hosts.extra >> /etc/hosts
fi

# Host keys are generated on first boot and then persist for the life of the
# image, exactly as on a real install. They are per-image, not per-container,
# so every backend an attacker reaches presents the same fingerprint — a
# fingerprint that changed between reconnects would be a glaring tell.
if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    ssh-keygen -A >/dev/null 2>&1
fi

service rsyslog start >/dev/null 2>&1 || rsyslogd

# Wait for rsyslogd to bind /dev/log before anything tries to log. Without
# this the exporter's startup line was written into a socket that did not
# exist yet: logger exits 0 regardless, so the line simply vanished and the
# first thing in syslog after a boot was whatever happened a minute later.
for _ in $(seq 1 50); do
    [[ -S /dev/log ]] && break
    sleep 0.1
done

service cron start >/dev/null 2>&1 || cron

# The metrics exporter identity.yaml declares on :9100.
#
# It has to genuinely run. It was declared as a service, and the seeded syslog
# recorded it starting, while nothing listened on the port -- so `ss -tlnp`
# contradicted the logs in one command, on the node an attacker lands on
# first. The real Debian package is cheaper than a convincing fake: a Go
# binary, real /proc metrics, real socket.
#
# Started as the prometheus user the package creates, exactly as its unit
# would, and it writes its own log under /var/log.
if [[ -x /usr/bin/prometheus-node-exporter ]]; then
    EXPORTER_LOG=/var/log/prometheus-node-exporter.log
    EXPORTER_PID=/run/prometheus-node-exporter.pid
    install -o prometheus -g prometheus -m 0640 /dev/null "$EXPORTER_LOG" 2>/dev/null || true
    # start-stop-daemon rather than `su -c`, which leaves su and sh sitting
    # in `ps` as the daemon's parents. No systemd-started daemon has those,
    # and that chain is more conspicuous than the exporter it starts. This
    # execs directly, so the process reparents to init exactly as it would
    # after a real boot. --no-close keeps the redirect below.
    #
    # Nothing here writes a syslog line on the exporter's behalf. An
    # earlier version did, and it lost a race with rsyslogd binding
    # /dev/log -- logger exits 0 either way, so the line just vanished.
    # More to the point, a hand-written line is a claim about what a
    # daemon did. The exporter writes its own log; every exporter line
    # on this box came from the exporter.
    start-stop-daemon --start --quiet --background --no-close --make-pidfile \
        --pidfile "$EXPORTER_PID" --chuid prometheus:prometheus \
        --exec /usr/bin/prometheus-node-exporter -- \
        --web.listen-address=:9100 >>"$EXPORTER_LOG" 2>&1
fi

# A login banner references a last-patched date; keep the apt timestamp
# consistent with it so `ls -l /var/lib/apt/lists` does not contradict the motd.
touch -d "$(date -d '37 days ago' '+%Y-%m-%d %H:%M:%S')" /var/lib/apt/lists 2>/dev/null || true

# Runs as a child of /sbin/init, so sshd lands at an ordinary PID with init
# above it -- the shape a real boot produces.
exec /usr/sbin/sshd -D -e
