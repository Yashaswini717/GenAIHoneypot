# Local demo: attacker, AI brain, intent classification, intelligence hub

Everything below was run end to end on this PC on 2026-11-05, with the LLM on, in this order:
warm-up, reset, demo 1, demo 2, 3b, 3c, reset. The sample outputs are copied from that run.
Decoy action names vary between runs, because the brain chooses them by Thompson sampling.

Use **Git Bash** for all three terminals (Start menu → Git Bash), not Windows PowerShell.
PowerShell can't run several lines below: it rejects `&&` and the reset line, and it passes
`~` to Python without expanding it.

**Running order**

| Step | What | When |
|---|---|---|
| 0 | Docker, both stacks, warm-up login, reset | Before the panel arrives, about 5 minutes |
| 1 | Open terminals 2 and 3 and the dashboard | Before you start the attack |
| 2 | Demo 1: one host, 12 commands | Live |
| 3 | Demo 2: the attacker returns and pivots, 10 commands | Live, right after demo 1 |
| 3b | Show what the LLM wrote | After demo 2 |
| 3c | Zero trust | After 3b, within an hour of demo 2 |
| 4 | What to say if something looks different | Keep it open for questions |
| 5 | Reset, control arm back on, shut down | After the panel |

The panel brief (architecture, results, limits) is at https://claude.ai/artifact/BDTw7xNJvDvMJy569PPM1W.

---

## 0. Before the panel (about 5 minutes)

1. Start Docker Desktop and wait until it says it is running.
   If it shows an error dialog instead, **never click "Reset to factory defaults"**. That deletes
   every image, container and volume, the hub's data included.
   On 2026-11-03 the error was `initializing Secrets Engine ... docker-secrets-engine/engine.sock
   ... The file cannot be accessed by the system`. That is a socket file left behind by an unclean
   shutdown. Click **Quit**, move the folder aside in Git Bash, then start Docker Desktop again:
   ```bash
   mv "$LOCALAPPDATA/docker-secrets-engine" "$LOCALAPPDATA/docker-secrets-engine.stale-$(date +%Y%m%d%H%M%S)"
   ```

2. Check that both stacks are up:
   ```bash
   docker ps --format "{{.Names}}: {{.Status}}"
   ```
   You should see `gw-01`, `hp-session-broker`, `ai-brain`, `hp-sidecar`, and six `intelligence_hub-*` containers.
   If any are missing:
   ```bash
   cd ~/Desktop/capstone/GenAIHoneypot/honeypot-ecosystem && docker compose up -d
   cd ~/Desktop/capstone/GenAIHoneypot/intelligence_hub && docker compose up -d
   ```

3. **Warm up the hub, then reset the attacker environment.**
   First log in once and leave. After hours idle, the hub's first event can take over 15 s,
   and the first INTENT line comes that much later (see section 4):
   ```bash
   ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null devuser@localhost
   ```
   Type the password from demo 1, then `exit`.

   Then reset, so the decoys are planted fresh in front of the panel. Do this after every
   rehearsal too: an environment otherwise survives for 6 hours, and the brain then reports
   `already in ... environment; left as they left it` instead of planting.
   ```bash
   ids=$(docker ps -aq --filter label=honeypot.role=node); [ -n "$ids" ] && docker rm -f $ids; docker restart hp-session-broker
   ```
   You can confirm it worked with
   `docker logs hp-session-broker --since 1m | grep "broker up"`.
   It should say `adopted 0 existing environment(s)`, followed by how many departed
   attackers it cleaned up after (1 after the warm-up).

4. The control arm is off (`EXPERIMENT_CONTROL_RATIO=0` in `honeypot-ecosystem/.env`).
   Keep it off for the demo. Otherwise there is a 15% chance that your login lands in the
   control group and gets no generated decoys. Set it back to 0.15 after the demo.

---

## 1. Open the four windows

| Window | Command | What it shows |
|---|---|---|
| **Terminal 2: AI brain** | `python ~/Desktop/capstone/demo/watch.py brain` | Each adaptive decision (intent → decoy action, the Thompson sample and mean reward), each decoy it generates, the reward it learns, and honeytoken tripwires |
| **Terminal 3: intent classification** | `python ~/Desktop/capstone/demo/watch.py intent` | Every 2 commands, the sidecar classifies the last 3: intent, confidence, whether a rule or the ML model decided, then what was planted |
| **Browser: intelligence hub** | http://localhost:5173 | Open **Live Feed** first; it should say `● live`. Later: Alerts, Sessions, Overview |
| **Terminal 1: attacker** | started in demo 1 | The attacker's view |

Start terminals 2 and 3 **before** the attacker logs in. They show only what happens from then on.

---

## 2. Demo 1: one host, reconnaissance → privilege escalation → persistence

**Story:** an attacker logs in to `jump-01` with a weak password, looks around, finds a
deploy script that leaks a key path, uses sudo to steal the key, and plants persistence.

In **terminal 1**:
```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null devuser@localhost
```
The password is `dev@123`. Then type these one at a time, **in this order**:
```bash
w
ps aux | head
ls -la ~
cat /etc/passwd | tail -5
grep DEPLOY_KEY /opt/deploy/sync-erp.sh
sudo -l
```
When sudo asks for a password, type `dev@123`. Then:
```bash
sudo cp /home/ta_miller/.ssh/id_erp_deploy /tmp/k
sudo chown devuser /tmp/k
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoKeyOnly demo@attacker" >> ~/.ssh/authorized_keys
(crontab -l 2>/dev/null; echo "@reboot /home/devuser/.cache/sync.sh") | crontab -
cd ~
exit
```

**Why this order matters.** The sidecar classifies after every 2nd command, and the sudo
password you type counts as one. The final `cd ~` makes the persistence commands the newest
evidence in their window. If you end with `crontab -l` instead, that window is reconnaissance
(listing cron jobs), and the classifier is right to call it so.

**Terminal 3 (sample from the verified run):**
```
19:17:31  INTENT  reconnaissance        confidence 0.90  decided by rule  session b949b7  ->  decoy action: serve_minimal_banner
19:17:37  INTENT  reconnaissance        confidence 0.95  decided by rule  session b949b7  ->  decoy action: serve_minimal_banner
19:17:44  INTENT  privilege_escalation  confidence 0.70  decided by rule  session b949b7  ->  decoy action: plant_honeytoken_credentials
19:17:51  INTENT  privilege_escalation  confidence 0.90  decided by rule  session b949b7  ->  decoy action: plant_honeytoken_credentials
19:17:59  INTENT  persistence           confidence 0.70  decided by rule  session b949b7  ->  decoy action: populate_production_server
19:18:05  INTENT  persistence           confidence 0.75  decided by rule  session b949b7  ->  decoy action: simulate_cron_jobs
```
The first time an action comes up for this attacker, a `planted '<action>' for 172.21.0.1 (...)`
line follows. That is a small fixed decoy landing in the attacker's container at once. An action
that comes up again plants nothing new.

**Terminal 2 (sample):**
```
19:17:44  DECISION   intent privilege_escalation -> decoy action plant_honeytoken_credentials  (sampled 0.64, mean reward 0.60, chosen 8x so far)
19:17:51  LEARNED    plant_honeytoken_credentials for privilege_escalation: reward 0.4 (session_continued), mean reward now 0.56
19:17:59  LEARNED    plant_honeytoken_credentials for privilege_escalation: reward 0.7 (intent_escalated), mean reward now 0.58
19:20:46  GENERATED  7 decoy file(s) holding 2 honeytoken(s) for plant_honeytoken_credentials [production_server]
```
Each GENERATED line is the LLM finishing a whole set of decoy files. It comes 1 to 4 minutes
after its DECISION, usually during demo 2.

How the bandit is rewarded:

| Reward | When |
|---|---|
| 1.0 | The attacker uses a honeytoken |
| 0.7 | The attacker escalates |
| 0.4 | The attacker continues |
| 0.2 | The attacker de-escalates |
| 0.0 | The attacker leaves |

**Hub, Alerts page:** `credential_access 80` (the key copy) and `persistence 85` (the
authorized_keys line; the cron job lands on the same alert). Ordinary commands score 40
and raise no alert.

---

## 3. Demo 2: the attacker comes back and pivots, lateral movement → data exfiltration

**Story:** the same attacker returns and finds everything as they left it. They use the
stolen key to reach `erp-web`, read the app's settings, and pull data from the database
on `db-01` with the password they find. That password is a honeytoken.

In **terminal 1**:
```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null devuser@localhost
```
The password is `dev@123`. Then:
```bash
ls -la /tmp/k
crontab -l
chmod 600 /tmp/k
ssh -i /tmp/k -o StrictHostKeyChecking=no deploy@erp-web
hostname
cat /opt/erp/settings.py
set +H
mysql -h db-01 -u erp_admin -pTr3llis!84m -e "select count(*) from erp.students;"
exit
exit
```
`set +H` stops bash from treating the `!` in the password as a history command. The query
returns `240`.

**Terminal 3 (sample):**
```
19:19:02  INTENT  lateral_movement      confidence 0.70  decided by rule  session 3dee2f  ->  decoy action: expose_fake_internal_ips
19:19:31  WARN  TRIPWIRE session ac5611672ca4 (172.23.0.2): used decoy database_password
19:19:32  INTENT  data_exfiltration     confidence 0.70  decided by rule  session ac5611  ->  decoy action: populate_database_server
```
The session changes from `3dee2f` (on `jump-01`) to `ac5611`: that is the attacker's new session
on `erp-web`, coming from `jump-01`'s internal address, 172.23.0.2.

**Terminal 2 (sample), the climax:**
```
19:19:32  TRIPWIRE   the attacker used a planted honeytoken: database_password (use #4)
19:19:32  LEARNED    populate_developer_workstation for reconnaissance: reward 1.0 (honeytoken_triggered), mean reward now 0.60
```
The use number counts rehearsals too.

**Hub, Alerts page:** `lateral_movement 85` (the ssh pivot) and `data_exfiltration 90`
(the database query). Sessions shows the `erp-web` session coming from `172.23.0.2`, which
is `jump-01`'s internal address.

---

## 3b. Show the panel what the LLM wrote (after demo 2)

Each decision plants two kinds of decoy:
- **at once**, a small fixed file (terminal 3: `planted '<action>' ...`);
- **1 to 4 minutes later**, a whole set of files the LLM wrote (terminal 3:
  `planted generated <set> ...`).

In the verified run, demo 1's sets were all in place by the end of demo 2. `erp-web`'s two
sets landed about 3 minutes after demo 2. All 8 sets landed and none failed.

In terminal 1, back on your own PC:
```bash
c=$(docker ps --filter label=honeypot.role=node --format "{{.Names}}" | grep '^jump-01' | head -1)
docker diff "$c" | grep '^A /home/devuser'
```
That lists every file added to the attacker's machine since it was created. Which files are
there depends on the decoy actions the brain picked. Pick one from a set that terminal 3 says
has landed:

| Set in terminal 3 | A good file to show |
|---|---|
| `web_server` | `app/main.py` |
| `production_server` | `scripts/deploy.sh` or `app/docker-compose.yml` |
| `database_server` | `scripts/backup_db.py` |
| `developer_workstation` | `projects/app/README.md` |

For example, after a `web_server` set:
```bash
MSYS_NO_PATHCONV=1 docker exec "$c" head -20 /home/devuser/app/main.py
```
The files are backdated and owned by `devuser`, and so are the folders they land in, so to the
attacker they look like old work. To show the dates, run
`MSYS_NO_PATHCONV=1 docker exec "$c" ls -la /home/devuser/app`.

After demo 2, `erp-web` has its own decoys, in `deploy`'s home. For example, after a
`database_server` set (the verified run got one, and a `developer_workstation` set):
```bash
e=$(docker ps --format "{{.Names}}" | grep '^erp-web-' | head -1)
docker diff "$e" | grep '^A /home/deploy'
MSYS_NO_PATHCONV=1 docker exec "$e" head -20 /home/deploy/scripts/backup_db.py
```
If terminal 3 has no `planted generated ... for 172.23.0.2` line yet, `erp-web` has only its
fixed files. Do 3c first, then come back.

---

## 3c. Zero trust: the hub accepts only signed, fresh, first-time events (after demo 2, 1 minute)

**Story:** someone on the network between the honeypot and the hub tries to feed the hub
false intelligence. They can forge an event, alter a real one, or resend a real one they captured.
The hub refuses all of it.

First note how many events the hub holds. In terminal 1:
```bash
curl -s "http://127.0.0.1:8000/events/?limit=1" | grep -o '"total": *[0-9]*'
```
Then run the check. It runs inside the sidecar, the only process that holds the signing key, so
the key never leaves that container and nothing prints it:
```bash
docker exec -i hp-sidecar python - < ~/Desktop/capstone/demo/zero_trust.py
```
It takes the newest event the sidecar delivered and sends the hub four bad versions of it.
Output from the verified run:
```
Zero-trust check: requests the hub must refuse
  hub    http://intelligence-hub:8000/ingest/
  event  cowrie.session.closed from session 3dee2fee13c0, sent 1 min ago

1  Forged: a made-up root login, signed with the default key from the code
   -> 401 refused: Invalid HMAC signature
2  Tampered: a real signed event, its source address changed on the way
   -> 401 refused: Invalid HMAC signature
3  Replayed late: the real request, as if captured 10 minutes ago
   -> 401 refused: X-Timestamp is 600s from the hub's clock, outside the 300s window. Either a clock is wrong or this is a replay.
4  Replayed at once: the real request, sent a second time
   -> 409 refused: Event b21a8eb7a1478070367afe193a84b0d1 has already been ingested

All 4 refused before anything was stored. The dashboard is unchanged.
```
Run the `curl` line again: the total is the same (501 before and after in the verified run).

**What to say, line by line:**
1. Knowing the hub's address and the event format is not enough. Every event must carry an
   HMAC-SHA256 signature made with a key that only the sidecar and the hub hold. Nothing an
   attacker can reach has it, and the default key printed in the code (`dev`) gets nowhere.
2. The signature covers the exact bytes. Changing one field, here the source address to frame
   someone else, breaks it.
3. The timestamp is signed too. A captured request is worthless 5 minutes later.
4. Within those 5 minutes, the hub remembers every event id it has accepted for 24 hours, so a
   copy is refused. The sidecar's own retries rely on the same check: an event is stored once.

**If something looks different:**
- `Replay test skipped`: the newest event is over an hour old, so the hub may no longer remember
  it, and resending it could store it twice. Run it right after demo 2, or log in once and run it again.
- Line 4 says `accepted`: the sidecar had not delivered that event yet, so the check delivered it,
  once. Run it again.
- `hub unreachable`: the hub is down; see step 0.2.

---

## 4. Things the panel may see, and what to say

- **The first INTENT line can come late** if the hub has been idle for hours. On 2026-11-03,
  after 7 idle hours, the hub took over 15 s on its first event, and the first INTENT came about
  35 s after the commands. A duplicate-key error (`sessions_pkey`) made it worse; that is fixed
  now. The slow first event itself is not explained yet. The warm-up login in step 0.3 is
  there for this. In the 2026-11-05 run, after 2.5 idle hours and the warm-up, the first INTENT
  came right after the second command.

- **The LLM is on now: Mistral's free mode, model `ministral-8b-latest`.** Your Mistral key,
  the Mistral address and the model are in `honeypot-ecosystem/.env`. The sample outputs above
  come from a run with it on.
  - Rehearsed end to end on 2026-11-05. The 10 decisions produced 8 LLM sets: the two actions
    that came up twice did not get a second set. Each set landed 1 to 4 minutes after its
    decision, and none failed. None of the 31 files planted in the two home folders had LLM
    chatter or code fences in it.
  - Tested on 2026-11-04: one `developer_workstation` profile took 4 min 32 s and produced all
    10 files, with no failed steps. Each model call took 17 to 57 s. In a live attacker session
    the same day, a web-server set (`app/main.py`, `app/config.py`, `nginx.conf`,
    `logs/access.log`) landed 72 s after the decision, and the attacker saw it on their next login. Google's Flash-Lite did the
    same profile in 3 min 3 s, but its calls ranged from 3.5 s to 90 s, and its per-minute
    limit can't be read from its replies.
  - Mistral's free allowance for this model is 188 requests and 625,000 tokens a minute, so
    demo 1's several profiles at once should stay well under it. The monthly cap is shown only
    in the Mistral console (Admin › API › Limits). Free mode may use your requests for training
    unless you switch that off (Admin › Privacy).
  - The sidecar now waits up to 10 minutes for a profile (it was 5). Files land even after the
    attacker has logged out: in an earlier test, a profile arrived 3 minutes after logout. In
    terminal 3 a landing looks like
    `planted generated developer_workstation for 172.21.0.1 (7 of 10 file(s); the rest already existed; 3 tracked credential(s))`.
  - So expect GENERATED lines, and their `planted generated` lines, a few minutes after the
    DECISION. A profile slower than 10 minutes is dropped, and terminal 3 shows
    `WARN generation request failed for '<action>'`.
  - The scripted commands don't depend on generated files. The deploy key, the deploy script,
    the ERP settings and the database password are baked into the node images.
  - After every rehearsal, do the reset in step 0.3.
  - Some files read as LLM-written. In the verified run, the README had emoji headings. Show a
    script (`scripts/backup_db.py`, `app/main.py`) rather than a README. If asked, say this is
    the free 8B model's style.
    - The brain checks each file for words a security tool would write but a real server
      wouldn't. In that run it caught "Detected" and "suspicious" in generated logs and code.
    - It sent 11 generations back for another try, and deleted the offending lines from the
      one that still failed.
    - It doesn't judge style, so emoji get through.
  - Mistral's Medium and Small models aren't in the free plan (0 requests a minute). Ministral
    14B is free, but 3 of its 8 calls failed with server errors in testing.
  - To turn the LLM off, put `#` in front of `OPENAI_API_KEY` in `honeypot-ecosystem/.env`,
    then run `docker compose up -d ai-brain` in that folder.
  - Other free providers are set the same way (`OPENAI_API_KEY`, `OPENAI_BASE_URL`,
    `LLM_MODEL`, then the same command). Google AI Studio:
    `https://generativelanguage.googleapis.com/v1beta/openai/` with `gemini-3.5-flash-lite`, and
    never Gemma 4, which writes its reasoning into the decoy files. OpenRouter: no
    `OPENAI_BASE_URL` line, `nvidia/nemotron-3.5-lightning:free`, 50 requests a day.
- **Decoys on `erp-web` now (fixed 2026-11-04).** Terminal 3 shows lines like
  `planted 'serve_minimal_banner' for 172.23.0.2`: that is the `erp-web` session, whose source
  address is `jump-01`'s. They land in `deploy`'s home on this attacker's own `erp-web`. In the
  rehearsal that day, `~/scripts/backup_db.py`, `~/.pgpass`, `~/.aws/credentials` and
  `~/exports/customer_export.csv` were there within about a minute, backdated like everything else.
  Before the fix those plants ended in `no-active-session`.
- **Commands typed on `erp-web` are counted once (fixed 2026-11-05).** They also pass
  through the `jump-01` session, because the attacker's terminal is nested. That session's copy
  is now marked nested, so there is one TRIPWIRE and one `data_exfiltration` alert, both on
  `erp-web`. Live Feed still lists those lines under both sessions, because both carried them;
  only the `erp-web` copy is scored.
- **`dev@123` shows up in Live Feed.** The sudo password is recorded as typed input. That
  is by design: honeypots log typed passwords.
- **The bandit remembers its rehearsals (since 2026-11-05).** Its learning is on the
  `brain-state` volume, so it survives restarts, recreates and rebuilds. Terminal 2's
  `chosen Nx so far` and mean rewards therefore count every rehearsal as well as the panel
  run. Before, every `docker compose up -d` after a change to `.env` reset it to an old copy
  inside the image.

---

## 5. After the demo

After a rehearsal, do only step 1. Steps 2 and 3 are for after the panel.

1. Run the reset from step 0.3. In the verified run it removed all three of the attacker's
   machines (`jump-01`, `erp-web` and `db-01`).
2. Set `EXPERIMENT_CONTROL_RATIO=0.15` in `honeypot-ecosystem/.env`.
3. Run `docker compose up -d` in `honeypot-ecosystem`. The bandit keeps what it learned (see
   the last point of section 4).
4. To shut down, quit Docker Desktop from its tray icon (right-click → Quit Docker Desktop)
   before you shut Windows down. The 2026-11-03 start-up error in step 0.1 followed an unclean
   shutdown. Every service is set to `restart: unless-stopped`, so both stacks come back the
   next time Docker Desktop starts; step 0.2 checks that.
   Never run `docker compose down -v`. The `-v` deletes the volumes, which hold the hub's data
   and the bandit's learning.
