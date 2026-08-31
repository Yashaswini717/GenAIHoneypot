# One image definition, three nodes.
#
# node-01 was built from a Dockerfile of its own. Copying that file twice more
# for the ERP and database nodes would mean three places to fix every realism
# lesson we have already paid for -- the tzdata trap, the double MOTD, the
# uname shim, PID 1, no compiler. Those are properties of "a believable Linux
# host", not of any one role, so they live here once and every node inherits
# them.
#
# What differs per node is its identity.yaml, its entrypoint (which services it
# genuinely runs), and any extra packages that role needs.
#
# Build from the honeypot-ecosystem root:
#
#   docker build -f shared/node-build/Dockerfile --build-arg NODE=node-02-erp \
#                -t honeypot/node-02-erp:current .
#
# or just: python tools/build_nodes.py

# --------------------------------------------------------------------------
# Builder: compile the uname() shim
# --------------------------------------------------------------------------
#
# A separate stage purely so gcc never reaches the final image. The shim makes
# uname() report the kernel we claim rather than the host's -- without it a
# container on Docker Desktop answers "6.6.87.2-microsoft-standard-WSL2",
# contradicting our own motd. See unamed.c.

FROM ubuntu:22.04 AS shimbuilder

ARG KERNEL_RELEASE="5.15.0-118-generic"
ARG KERNEL_VERSION="#128-Ubuntu SMP Fri Jul 5 09:28:59 UTC 2026"

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY shared/node-build/unamed.c /tmp/unamed.c
RUN gcc -shared -fPIC -O2 -Wall \
        -DFAKE_RELEASE="\"${KERNEL_RELEASE}\"" \
        -DFAKE_VERSION="\"${KERNEL_VERSION}\"" \
        -o /tmp/libnodeenv.so /tmp/unamed.c -ldl \
    && test -s /tmp/libnodeenv.so


# --------------------------------------------------------------------------
# The node
# --------------------------------------------------------------------------

FROM ubuntu:22.04

ARG NODE
ARG NODE_TZ=Asia/Kolkata
ARG EXTRA_PACKAGES=""
ENV DEBIAN_FRONTEND=noninteractive

# Base toolset every node has. Deliberately absent: gcc, make, cc, nmap. No
# host in this estate has business holding a compiler, and with no real egress
# an attacker cannot fetch one -- which removes the most practical route to a
# kernel exploit. python3 stays; a university box without it would be odd.
#
# tzdata is not cosmetic: without it /usr/share/zoneinfo is empty, the
# /etc/localtime symlink dangles, glibc silently falls back to UTC, and `date`
# prints the zone as "Asia". Seeded working-hours history then displays as
# 03:00-13:00.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server tzdata tini ca-certificates python3 python3-yaml \
        cron rsyslog vim nano less curl wget git tmux htop \
        net-tools iproute2 dnsutils procps psmisc rsync sudo file unzip \
        ${EXTRA_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

RUN ln -snf "/usr/share/zoneinfo/${NODE_TZ}" /etc/localtime \
    && echo "${NODE_TZ}" > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata

# Ubuntu's dynamic MOTD scripts run at every login and build a banner from the
# LIVE kernel -- the host's. That produced two banners, the first naming
# WSL2 and "This system has been minimized". Removed, so pam_motd prints
# exactly one thing: the /etc/motd we render.
RUN rm -rf /etc/update-motd.d/* /etc/legal /var/lib/update-notifier \
    && rm -f /etc/motd.dynamic /run/motd.dynamic \
    && mkdir -p /etc/update-motd.d && touch /etc/update-motd.d/.keep

# --------------------------------------------------------------------------
# Identity, history and decoys
# --------------------------------------------------------------------------

COPY shared/node-build/ /tmp/build/
COPY nodes/${NODE}/ /tmp/build/

RUN python3 /tmp/build/render_node.py --identity /tmp/build/identity.yaml --root / \
    && rm -rf /tmp/build

# --------------------------------------------------------------------------
# Init and the uname shim
# --------------------------------------------------------------------------
#
# PID 1 must look like an init system, because on every real Linux it is one.
# Docker would otherwise make sshd PID 1, and `ps -p 1` showing sshd is a
# conclusive container tell for one command's effort.
RUN cp /usr/bin/tini /sbin/init && chmod 0755 /sbin/init

COPY --from=shimbuilder /tmp/libnodeenv.so /lib/x86_64-linux-gnu/libnodeenv.so

# Verified immediately, because /etc/ld.so.preload applies to every dynamically
# linked process: a broken library here would print a loader warning before
# every single command an attacker runs, far louder than the kernel string it
# hides. The build fails rather than shipping that.
RUN chmod 0644 /lib/x86_64-linux-gnu/libnodeenv.so \
    && echo "/lib/x86_64-linux-gnu/libnodeenv.so" > /etc/ld.so.preload \
    && ldconfig \
    && test -z "$(/bin/echo -n 2>&1)" \
    && uname -r | grep -qv microsoft \
    && echo "uname now reports: $(uname -r)"

COPY --chmod=0755 nodes/${NODE}/entrypoint.sh /usr/local/sbin/node-init

EXPOSE 22
ENTRYPOINT ["/sbin/init", "-s", "--"]
CMD ["/usr/local/sbin/node-init"]
