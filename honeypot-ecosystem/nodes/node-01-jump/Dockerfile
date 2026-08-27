# node-01-jump — the SSH bastion an attacker actually lands on.
#
# Two rules govern this image.
#
# 1. Nothing is faked that can be run for real. The prototype this replaces
#    shimmed `ps`, `netstat`, `whoami`, `id` and `sudo` with shell scripts on
#    the PATH. That is worse than no disguise: a `ps` that prints the same six
#    PIDs forever is a fingerprint, `type sudo` exposes the whole scheme in
#    one command, and the fake sudo was bypassable anyway because /usr/bin/sudo
#    was still there. So there are no shims here. Real sshd, real cron, real
#    rsyslog, real sudo — and every tool tells the truth, because the truth is
#    already what we want it to say.
#
# 2. The attacker gets real root, and it is worth nothing. Containment comes
#    from the runtime, not from lying: the session broker drops every
#    capability except the handful sshd needs, caps pids and memory, and
#    attaches the container to an internal network with no route to the
#    internet, the hub, or the brain. Under userns-remap, root here maps to an
#    unprivileged uid on the host. `sudo su` works, `cat /etc/shadow` works,
#    and there is nothing to catch.
#
# Note what this image does NOT emit: telemetry. There is no log shipper, no
# agent and no event spool inside the attacker's reach, because recording
# happens on the wire in the SSH proxy. Nothing here for them to find.

FROM ubuntu:22.04

ARG NODE_TZ=Asia/Kolkata
ENV DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------
# Packages
# --------------------------------------------------------------------------
#
# tzdata is not optional and not cosmetic. Without it /usr/share/zoneinfo is
# empty, the /etc/localtime symlink dangles, glibc silently falls back to UTC,
# and `date` prints a garbage zone name ("Asia"). A host that claims an Indian
# university but timestamps every log in UTC while calling the zone "Asia" has
# told the attacker it was assembled. Verified: with tzdata absent, seeded
# working-hours login history displays as 03:00-13:00.
#
# Deliberately absent: gcc, make, cc, nmap. A jump box has no business holding
# a compiler, and with no real egress an attacker cannot fetch one either —
# which removes the most practical path to a kernel exploit. python3 stays,
# because a dev box without python would itself be odd.

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        tzdata \
        tini \
        ca-certificates \
        python3 \
        cron \
        rsyslog \
        vim \
        nano \
        less \
        curl \
        wget \
        git \
        tmux \
        htop \
        net-tools \
        iproute2 \
        procps \
        psmisc \
        rsync \
        sudo \
        file \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN ln -snf "/usr/share/zoneinfo/${NODE_TZ}" /etc/localtime \
    && echo "${NODE_TZ}" > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata

# --------------------------------------------------------------------------
# Identity, history and decoys
# --------------------------------------------------------------------------

COPY build/ /tmp/build/
COPY identity.yaml /tmp/build/identity.yaml
COPY --chmod=0644 sshd_policy.conf /tmp/build/sshd_policy.conf

# The proxy authenticates to this node with a key. Only the public half ever
# reaches the image, so an attacker with root here finds nothing to steal —
# and the key authorises a shell on a throwaway container in any case.
COPY --chmod=0644 backend_key.pub /tmp/build/backend_key.pub

RUN python3 -m pip install --no-cache-dir --quiet pyyaml 2>/dev/null || \
    (apt-get update && apt-get install -y --no-install-recommends python3-yaml && rm -rf /var/lib/apt/lists/*)

RUN python3 /tmp/build/render_node.py --identity /tmp/build/identity.yaml --root / \
    && rm -rf /tmp/build

# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

COPY --chmod=0755 entrypoint.sh /usr/local/sbin/node-init

# PID 1 must look like an init system, because on every real Linux it is one.
# Left alone, Docker makes sshd PID 1, and `ps -p 1` showing sshd is a
# conclusive container tell that costs an attacker one command to check.
#
# tini installed over /sbin/init gives us a genuine process supervisor that
# reaps zombies properly AND reports as `init` in ps comm output, with sshd,
# cron and rsyslog as ordinary children at ordinary PIDs -- which is the shape
# of a real boot.
RUN cp /usr/bin/tini /sbin/init && chmod 0755 /sbin/init

EXPOSE 22
ENTRYPOINT ["/sbin/init", "-s", "--"]
CMD ["/usr/local/sbin/node-init"]
