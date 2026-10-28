# Running the hub on a Windows PC

Use this when the honeypot machine can't also run the hub. The honeypot
(SSH proxy, broker, sidecar, AI brain) stays where it is. Only the
intelligence hub moves to this PC: the API, the dashboard, Elasticsearch,
Postgres, Neo4j and Redis. The sidecar sends each signed event over the LAN
to port 8000 here.

```
honeypot machine (Kali)                          this PC (Windows)
ssh-proxy -> events -> sidecar --HTTP :8000-->   hub backend -> ES, Postgres, Neo4j, Redis
                                                 dashboard :5173
```

## What you need

- Docker Desktop with the WSL 2 backend, set to Linux containers.
- About 3 GB of RAM free for Docker. The stack is capped at about 2.8 GB.
- Both machines on the same network.

## Setup

1. Copy `hub-windows.zip` to this PC and extract it. Keep the zip private.
   Its `.env` holds the HMAC signing secret and the database passwords.
2. Open PowerShell with **Run as administrator**, `cd` into the extracted
   `intelligence_hub` folder, and run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1
   ```

   The firewall rule only lets in `192.168.0.15`, the honeypot machine's
   address when this was written. If that has changed, add
   `-HoneypotIp <its address>`.
3. When the script finishes it prints `HUB_URL=http://<this PC's IP>:8000`.
   On the honeypot machine, run:

   ```bash
   cd ~/Desktop/phase3/GenAIHoneypot/honeypot-ecosystem
   sed -i 's|^HUB_URL=.*|HUB_URL=http://<this PC IP>:8000|' .env
   docker compose up -d sidecar
   docker logs -f hp-sidecar
   ```

   Events held back while the hub was away drain first. After that,
   `delivered ...` lines follow each command as it is typed.

The dashboard works from either machine: `http://localhost:5173` on this PC,
or `http://<this PC's IP>:5173` from the honeypot machine.

## Everyday use

Run these from the `intelligence_hub` folder:

| What | Command |
|---|---|
| Stop (keeps the data) | `docker compose -f docker-compose.yml -f docker-compose.windows.yml down` |
| Start again | `docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d` |
| Backend logs | `docker compose -f docker-compose.yml -f docker-compose.windows.yml logs -f backend` |

## When the network changes

Joining a different network, such as the Wi-Fi in a review room, changes both
machines' addresses. Run the script again with the new `-HoneypotIp`, then
update `HUB_URL` on the honeypot machine again.

## Troubleshooting

Check `docker logs hp-sidecar` on the honeypot machine first.

| What the sidecar logs | Cause and fix |
|---|---|
| `hub unreachable: [Errno -2] Name or service not known` | `HUB_URL` still has the old name. Redo step 3. |
| `hub unreachable: ... timed out` | Windows Firewall is blocking it. Rerun the script and look for the Docker block-rule warning. To test from the honeypot machine: `curl http://<this PC IP>:8000/health` |
| `hub unreachable: ... Connection refused` | The hub isn't running, or it's still starting. Check with `docker compose -f docker-compose.yml -f docker-compose.windows.yml ps` |
| `hub rejected a batch: 401` | `HMAC_SECRET` differs between the two `.env` files. Don't retype it on this PC. Copy the honeypot's value over exactly. |

If the dashboard sits on "Loading intelligence data…" during the first start,
the backend is still waiting for Elasticsearch and Neo4j to pass their health
checks. Give it a few minutes.
