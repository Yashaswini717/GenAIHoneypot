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
service cron start >/dev/null 2>&1 || cron

# A login banner references a last-patched date; keep the apt timestamp
# consistent with it so `ls -l /var/lib/apt/lists` does not contradict the motd.
touch -d "$(date -d '37 days ago' '+%Y-%m-%d %H:%M:%S')" /var/lib/apt/lists 2>/dev/null || true

# Runs as a child of /sbin/init, so sshd lands at an ordinary PID with init
# above it -- the shape a real boot produces.
exec /usr/sbin/sshd -D -e
