# The internet-facing process. It deliberately holds nothing worth stealing:
# no HMAC key (that is the sidecar's), no Docker socket (that is the broker's).
FROM python:3.11-slim

# iproute2 is required, not optional: the broker execs `ip addr add` in here
# to give the proxy the .21/.31 addresses on each attacker network. Without it
# the exec fails, the addresses are never claimed, and every pivot dies with
# "No route to host" -- which is exactly what happened, silently, because the
# claim was fire-and-forget.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2     && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY shared/ssh-proxy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/common/ /app/common/
COPY shared/ssh-proxy/ /app/

# NOT "proxy": that is a Debian system account (uid 13), and useradd refuses
# it with exit 9 — the same trap the node renderer hits with "backup".
RUN useradd --system --uid 10022 --no-create-home sshproxy \
    && mkdir -p /var/spool/honeypot/transcripts /var/lib/honeypot/hostkeys \
    && chown -R sshproxy:sshproxy /var/spool/honeypot /var/lib/honeypot

USER sshproxy
ENV PYTHONUNBUFFERED=1
EXPOSE 2222
CMD ["python", "proxy.py"]
