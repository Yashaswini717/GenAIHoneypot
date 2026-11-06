#!/usr/bin/env bash
# Puts the honeypot and the intelligence hub on a fresh Ubuntu 24.04 server.
#
#   sudo bash deploy/server-setup.sh prepare   # once, while you still log in on port 22
#   sudo bash deploy/server-setup.sh go-live   # from a session on ADMIN_SSH_PORT
#   sudo bash deploy/server-setup.sh check     # any time; exit status = failures
#   sudo bash deploy/server-setup.sh stop      # kill switch
#
# Two phases because the honeypot must own port 22 -- that is where attacks
# arrive -- so the real SSH has to move first, and moving it in one step is how
# people lock themselves out of a cloud server. `prepare` adds the admin port
# next to 22; `go-live` drops 22 only when it sees you logged in on the admin
# port. Re-running any phase is safe. Step-by-step guide: deploy/aws/README.md.
set -euo pipefail

# 3389, not a high port. An EC2 Instance Connect Endpoint, the only way in from a
# network that allows just 80 and 443, tunnels to ports 22 and 3389 and refuses
# any other ("The specified RemotePort is not valid"). Port 22 becomes the
# honeypot's, so admin SSH has to be on 3389, and the security group should allow
# 3389 only from the endpoint's security group. It is SSH on that port, not RDP.
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-3389}"
# Real bots arrive from thousands of addresses and each gets its own container,
# so a small server needs a lower ceiling and a shorter idle life than local runs.
MAX_CONTAINERS="${MAX_CONTAINERS:-15}"
SESSION_IDLE_TTL="${SESSION_IDLE_TTL:-7200}"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HP="$REPO/honeypot-ecosystem"
HUB="$REPO/intelligence_hub"
SSHD_DROPIN=/etc/ssh/sshd_config.d/10-honeypot-admin.conf

say() { printf '\n== %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# Output is captured and then tested, never piped into `grep -q`: under
# pipefail, grep -q exiting at its first match can kill the writer with
# SIGPIPE and turn a match into a failure -- a false PASS in check().
has_runsc() { [[ " $(docker info --format '{{range $name, $_ := .Runtimes}}{{$name}} {{end}}') " == *" runsc "* ]]; }
broker_runtime() { (cd "$HP" && docker compose logs session-broker 2>/dev/null) | grep "session broker up" | tail -1; }
sidecar_401s() { (cd "$HP" && docker compose logs --since 1h sidecar 2>/dev/null) | grep -c '" 401' || true; }

set_env() {  # set_env FILE KEY VALUE -- replace KEY=... in FILE, or append it
    if grep -q "^$2=" "$1"; then sed -i "s|^$2=.*|$2=$3|" "$1"; else printf '%s=%s\n' "$2" "$3" >> "$1"; fi
}

admin_ssh() {  # admin_ssh "22 22022" -- sshd listens on exactly these ports
    {
        echo "# Written by deploy/server-setup.sh. Once live, port 22 belongs to the honeypot."
        for port in $1; do echo "Port $port"; done
        echo "PasswordAuthentication no"
        echo "KbdInteractiveAuthentication no"
        echo "PermitRootLogin no"
    } > "$SSHD_DROPIN"
    sshd -t || die "sshd rejected $SSHD_DROPIN; nothing was restarted"
    systemctl daemon-reload
    # Ubuntu 24.04 starts sshd from ssh.socket, whose ports are generated from
    # sshd_config on daemon-reload. Established sessions survive the restart.
    if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then systemctl restart ssh.socket; else systemctl restart ssh; fi
}

install_docker() {
    command -v docker >/dev/null && return
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc]" \
        "https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -q
    apt-get install -yq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_gvisor() {
    if ! command -v runsc >/dev/null; then
        curl -fsSL https://gvisor.dev/archive.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg]" \
            "https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
        apt-get update -q
        apt-get install -yq runsc
    fi
    runsc install  # registers the "runsc" runtime in /etc/docker/daemon.json
}

rotate_docker_logs() {
    # Docker keeps container logs forever by default; months of attacker
    # traffic would fill the disk. Merged so runsc's entry is kept.
    python3 - <<'PY'
import json, pathlib
path = pathlib.Path("/etc/docker/daemon.json")
config = json.loads(path.read_text() or "{}") if path.exists() else {}
config.setdefault("log-driver", "json-file")
config.setdefault("log-opts", {"max-size": "20m", "max-file": "5"})
path.write_text(json.dumps(config, indent=2) + "\n")
PY
    systemctl restart docker
}

write_hub_env() {
    token() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }
    (
        umask 077
        cat > "$HUB/.env" <<EOF
$(grep '^HMAC_SECRET=' "$HP/.env")
POSTGRES_USER=hubadmin
POSTGRES_PASSWORD=$(token 24)
POSTGRES_DB=threatintel
NEO4J_USER=neo4j
NEO4J_PASSWORD=$(token 24)
LOG_LEVEL=info
CORS_ORIGIN=http://localhost:5173
OPERATOR_TOKEN=$(token 32)
EOF
    )
}

prepare() {
    say "Packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -yq ca-certificates curl gnupg git python3-venv unattended-upgrades
    install_docker
    [[ -n "${SUDO_USER:-}" ]] && usermod -aG docker "$SUDO_USER"

    say "gVisor, so attacker nodes run on a user-space kernel rather than the host's"
    install_gvisor
    rotate_docker_logs
    has_runsc || die "Docker does not list the runsc runtime"
    docker run --rm --runtime=runsc hello-world >/dev/null || die "a container would not start under gVisor"

    if grep -q '^PROXY_PUBLISH_PORT=22$' "$HP/.env" 2>/dev/null; then
        # Already live: the honeypot holds 22. Asking sshd for it as well would
        # fail ssh.socket as a whole -- admin port included -- and lock you out.
        say "Admin SSH stays on port $ADMIN_SSH_PORT only (already live)"
        admin_ssh "$ADMIN_SSH_PORT"
    else
        say "Admin SSH on port $ADMIN_SSH_PORT, alongside 22 for now"
        admin_ssh "22 $ADMIN_SSH_PORT"
    fi

    say "Honeypot: secrets, settings, node images"
    cd "$HP"
    [[ -d .venv ]] || python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
    .venv/bin/python tools/bootstrap.py  # leaves existing secrets alone
    set_env .env NODE_RUNTIME runsc
    set_env .env MAX_CONTAINERS "$MAX_CONTAINERS"
    set_env .env SESSION_IDLE_TTL "$SESSION_IDLE_TTL"
    # Port 22 is still the admin SSH until go-live (and stays the honeypot's after).
    grep -q '^PROXY_PUBLISH_PORT=22$' .env || set_env .env PROXY_PUBLISH_PORT 2222
    docker network inspect honeypot-telemetry >/dev/null 2>&1 || docker network create honeypot-telemetry
    .venv/bin/python tools/build_nodes.py
    docker compose up -d --build
    # The proxy reads its key to the attacker nodes through a bind mount, which
    # keeps the host file's owner and mode. bootstrap.py ran as root and left it
    # 0600 root-only, so every attacker session closed as it opened. (Docker
    # Desktop on Windows hides this: files it mounts are readable by everyone.)
    chown "$(docker run --rm --entrypoint id honeypot/ssh-proxy:current -u)" secrets/backend_key

    say "Intelligence hub (every port on 127.0.0.1 only)"
    [[ -f "$HUB/.env" ]] || write_hub_env
    (cd "$HUB" && docker compose up -d --build)

    cat <<EOF

Prepared. Next, without closing this session:
  1. In the AWS security group, allow TCP $ADMIN_SSH_PORT from your IP, or from the
     Instance Connect Endpoint's security group if you connect through one.
  2. From a NEW terminal:  ssh -i <key.pem> -p $ADMIN_SSH_PORT ${SUDO_USER:-ubuntu}@<server address>
  3. In that new session:  cd $REPO && sudo bash deploy/server-setup.sh go-live
EOF
}

go_live() {
    [[ -n "$(ss -Htn state established "( sport = :$ADMIN_SSH_PORT )")" ]] \
        || die "nobody is logged in on port $ADMIN_SSH_PORT. Log in on it first, keep that session open, and run go-live from it -- otherwise moving SSH off 22 could lock you out."

    say "Moving admin SSH to port $ADMIN_SSH_PORT only"
    admin_ssh "$ADMIN_SSH_PORT"

    say "Putting the honeypot on port 22"
    cd "$HP"
    set_env .env PROXY_PUBLISH_PORT 22
    docker compose up -d

    check || true
    cat <<EOF

Live on port 22. Last step, in the AWS security group: change the port-22 rule
to allow 0.0.0.0/0 (the honeypot), and keep $ADMIN_SSH_PORT limited to your IP or
the Instance Connect Endpoint's security group.
Test it:  ssh -p 22 devuser@<server address>   (password dev@123), then run
check again -- it can verify gVisor and containment once a node container exists.
EOF
}

check() {
    local failures=0 node addr host port
    pass() { echo "  PASS  $*"; }
    fail() { echo "  FAIL  $*"; failures=$((failures + 1)); }
    note() { echo "  ....  $*"; }

    say "Only the honeypot (22) and admin SSH ($ADMIN_SSH_PORT) on public addresses"
    while read -r addr; do
        host="${addr%:*}" port="${addr##*:}"
        case "$host" in 127.*|"[::1]"|"[::ffff:127."*) continue ;; esac
        case "$port" in 22|"$ADMIN_SSH_PORT") pass "$addr" ;; *) fail "$addr is listening publicly" ;; esac
    done < <(ss -Hltn | awk '{print $4}' | sort -u)

    say "Sandbox and containment"
    if has_runsc; then
        pass "Docker has the gVisor runtime"
    else
        fail "Docker does not list runsc"
    fi
    if [[ "$(broker_runtime)" == *"runtime=runsc"* ]]; then
        pass "the broker starts attacker nodes under runsc"
    else
        fail "the broker is not using runsc (NODE_RUNTIME in $HP/.env)"
    fi
    # </dev/null: compose exec attaches stdin, and a stdin that never closes
    # (a script, a non-interactive ssh) would hang check() here.
    if (cd "$HP" && docker compose exec -T ssh-proxy test -r /run/secrets/backend_key) </dev/null 2>/dev/null; then
        pass "the proxy can read its key to the attacker nodes"
    else
        fail "the proxy cannot read secrets/backend_key, so every attacker session closes at once"
    fi
    node="$(docker ps -q --filter label=honeypot.role=node | head -1)"
    if [[ -z "$node" ]]; then
        note "no attacker container yet: log in once on port 22 and run check again"
    else
        [[ "$(docker inspect -f '{{.HostConfig.Runtime}}' "$node")" == runsc ]] \
            && pass "attacker container runs under gVisor" || fail "attacker container is not under gVisor"
        # Not a safety check, so a note rather than a failure. gVisor ignores
        # setuid and setgid bits unless runsc runs with --allow-suid, so inside
        # a node `sudo` says "effective uid is not 0" and `crontab` is denied.
        local sudo_out
        sudo_out="$(docker exec -u nobody "$node" /usr/bin/sudo -n true 2>&1 || true)"
        if [[ "$sudo_out" == *"effective uid is not 0"* ]]; then
            note "sudo and crontab cannot elevate in attacker containers (runsc without --allow-suid)"
        else
            pass "setuid works in attacker containers, so sudo behaves as on a real host"
        fi
        for target in "1.1.1.1 443 internet" "169.254.169.254 80 cloud-metadata"; do
            set -- $target
            if docker exec "$node" timeout 5 bash -c "echo > /dev/tcp/$1/$2" 2>/dev/null; then
                fail "an attacker container can reach the $3 ($1:$2)"
            else
                pass "an attacker container cannot reach the $3"
            fi
        done
    fi

    say "Hub and delivery"
    curl -fsS -m 5 http://127.0.0.1:8000/health >/dev/null && pass "hub answers on 127.0.0.1:8000" || fail "hub health check failed"
    if [[ "$(sidecar_401s)" -gt 0 ]]; then
        fail "the hub rejected sidecar events (HMAC_SECRET differs between the two .env files)"
    else
        pass "no rejected deliveries in the last hour"
    fi

    say "Cloud credentials an attacker could reach (AWS only)"
    local token role
    token="$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' || true)"
    if [[ -z "$token" ]]; then
        note "no instance metadata service found; skipping"
    else
        [[ "$(curl -s -o /dev/null -w '%{http_code}' -m 2 http://169.254.169.254/latest/meta-data/)" == 401 ]] \
            && pass "metadata requires IMDSv2 tokens" || fail "IMDSv1 is enabled: set metadata to IMDSv2-only"
        role="$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/ || true)"
        [[ -z "$role" || "$role" == *"Not Found"* ]] && pass "no IAM role attached" || fail "IAM role '$role' is attached: detach it"
    fi

    echo
    [[ $failures -eq 0 ]] && echo "All checks passed." || echo "$failures check(s) failed."
    return "$failures"
}

stop() {
    say "Stopping the honeypot, every attacker environment, and the hub"
    (cd "$HP" && docker compose down)
    local ids
    ids="$(docker ps -aq --filter label=honeypot.role=node)"
    [[ -z "$ids" ]] || docker rm -f $ids
    ids="$(docker network ls -q --filter label=honeypot.role)"
    [[ -z "$ids" ]] || docker network rm $ids >/dev/null
    (cd "$HUB" && docker compose down)
    echo "Stopped; data volumes are kept. Also remove the 0.0.0.0/0 port-22 rule in the security group."
}

[[ $EUID -eq 0 ]] || die "run with sudo"
case "${1:-}" in
    prepare) prepare ;;
    go-live) go_live ;;
    check) check ;;
    stop) stop ;;
    *) die "usage: sudo bash deploy/server-setup.sh prepare | go-live | check | stop" ;;
esac
