# SSH Honeypot — University Server Simulation

A research-grade SSH honeypot that mimics a university CS department server.
Designed to attract, observe, and log attacker behavior.

---

## Quick Start

```bash
# 1. Build and run
docker compose up -d --build

# 3. Watch logs live
tail -f logs/sessions.log
```

