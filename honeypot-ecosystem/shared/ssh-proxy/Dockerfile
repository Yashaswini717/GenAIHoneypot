# The internet-facing process. It deliberately holds nothing worth stealing:
# no HMAC key (that is the sidecar's), no Docker socket (that is the broker's).
FROM python:3.11-slim

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
