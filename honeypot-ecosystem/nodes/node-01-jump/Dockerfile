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

# --------------------------------------------------------------------------
# Builder: compile the uname() shim
# --------------------------------------------------------------------------
#
# A separate stage purely so gcc never reaches the final image. The shim makes
# uname() report the kernel we claim rather than the host's — see
# build/unamed.c for why that matters.

FROM ubuntu:22.04 AS shimbuilder

ARG KERNEL_RELEASE="5.15.0-118-generic"
ARG KERNEL_VERSION="#128-Ubuntu SMP Fri Jul 5 09:28:59 UTC 2026"

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY build/unamed.c /tmp/unamed.c
RUN gcc -shared -fPIC -O2 -Wall \
        -DFAKE_RELEASE="\"${KERNEL_RELEASE}\"" \
        -DFAKE_VERSION="\"${KERNEL_VERSION}\"" \
        -o /tmp/libnodeenv.so /tmp/unamed.c -ldl \
    && test -s /tmp/libnodeenv.so


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
        dnsutils \
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
# Kill the dynamic MOTD
# --------------------------------------------------------------------------
#
# Ubuntu's /etc/update-motd.d scripts run at every login and build a banner
# from the LIVE kernel, which in a container is the Docker host's. A real
# session showed our carefully written motd immediately after this:
#
#   Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.6.87.2-microsoft-standard-WSL2 ...)
#   This system has been minimized by removing packages ...
#   To restore this content, you can run the 'unminimize' command.
#
# Two banners is odd; a banner naming WSL2 and "minimized" is conclusive. The
# scripts go, so pam_motd prints exactly one thing: /etc/motd, which we wrote.
RUN rm -rf /etc/update-motd.d/* /etc/legal /var/lib/update-notifier \
    && rm -f /etc/motd.dynamic /run/motd.dynamic \
    && touch /etc/update-motd.d/.keep

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

# --------------------------------------------------------------------------
# uname() shim
# --------------------------------------------------------------------------
#
# Installed last, and verified immediately. /etc/ld.so.preload applies to every
# dynamically linked process on the system, so a broken library here would make
# the loader print a warning before every single command an attacker runs —
# considerably louder than the WSL2 kernel string it exists to hide. The build
# fails rather than shipping that.

COPY --from=shimbuilder /tmp/libnodeenv.so /lib/x86_64-linux-gnu/libnodeenv.so

RUN chmod 0644 /lib/x86_64-linux-gnu/libnodeenv.so \
    && echo "/lib/x86_64-linux-gnu/libnodeenv.so" > /etc/ld.so.preload \
    && ldconfig \
    && echo "--- verifying the preload does not break the system ---" \
    && /bin/true \
    && test -z "$(/bin/echo -n 2>&1)" \
    && uname -r | grep -qv microsoft \
    && echo "uname now reports: $(uname -r)"

EXPOSE 22
ENTRYPOINT ["/sbin/init", "-s", "--"]
CMD ["/usr/local/sbin/node-init"]
