# SSH Honeypot — University Server Simulation

A research-grade SSH honeypot that mimics a university CS department server.
Designed to attract, observe, and log attacker behavior.

---

## Quick Start

```bash
# 1. Build and run
docker compose up -d --build

# 2. (Optional) Set Discord/Slack webhook for login alerts
export WEBHOOK_URL="https://discord.com/api/webhooks/YOUR/WEBHOOK"
docker compose up -d --build

# 3. Watch logs live
tail -f logs/sessions.log
```

Your honeypot is now listening on port **2222**.

---

## What's Included

| Feature | Details |
|---|---|
| **Fake root illusion** | `whoami`, `id`, `sudo` all return root |
| **Fixed sudo** | Actually executes commands under fake root env |
| **Fake netstat / ps** | Believable MySQL, Apache, sshd processes |
| **Fake git / mysql** | Realistic CLI responses |
| **Bait files** | `.credentials`, `.env`, `.ssh/id_rsa`, `todo_list.txt` |
| **Fake .bash_history** | Looks like an active developer machine |
| **Fake users** | `prof_davis`, `ta_miller`, `sysadmin` in `/etc/passwd` |
| **Realistic MOTD** | University branding, last login, system stats |
| **TTY session logging** | Full keystroke + timing logs via `script` |
| **Login alerting** | Webhook POST on every new session |
| **Resource limits** | CPU/memory capped via Docker |

---

## Log Files

All logs are written to `./logs/` on the host:

| File | Contents |
|---|---|
| `sessions.log` | One line per session: timestamp, IP, start/end |
| `session_<id>.log` | Full TTY output for each session |
| `timing_<id>.log` | Keystroke timing data (replay with `scriptreplay`) |

### Replay a session
```bash
scriptreplay logs/timing_<id>.log logs/session_<id>.log
```

---

## Egress Control (Recommended)

By default the container has outbound internet access. To block it:

**Option A** — Docker network (in `docker-compose.yml`):
```yaml
networks:
  honeypot-net:
    internal: true   # uncomment this line
```

**Option B** — iptables on host (allows logging, blocks attacker payloads):
```bash
# Get container IP
CONTAINER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-honeypot)

# Drop all outbound from container except DNS
iptables -I FORWARD -s $CONTAINER_IP ! -d 8.8.8.8 -j DROP
```

---

## Webhook Alerts

Set `WEBHOOK_URL` to any Discord, Slack, or generic webhook.

**Discord**: Server Settings → Integrations → Webhooks → Copy URL
**Slack**: Create an Incoming Webhook app in your workspace

Alert payload example:
```
🚨 Honeypot Login Detected
Time    : 2023-11-14 03:22:11 UTC
From IP : 185.220.101.45
Host    : dev-server
```

---

## Legal Notice

This honeypot is intended for **defensive security research only**.
Deploy only on infrastructure you own or have explicit permission to use.
Ensure compliance with local laws regarding network deception and data collection.
