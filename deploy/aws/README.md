# Deploying on AWS

One EC2 server runs everything:

| Port | What answers | Who can reach it |
|---|---|---|
| 22 | the honeypot (ssh-proxy) | everyone, once live |
| 22022 | the server's real SSH, keys only | your IP only |
| everything else | nothing public; the hub listens on 127.0.0.1 only | you, through an SSH tunnel |

Attacker containers run under **gVisor** and sit on networks with no route out: they cannot reach the internet, the host, the hub, the brain or the cloud metadata service. That was tested on the local stack before this guide was written; `check` confirms it on the server.

`deploy/server-setup.sh` does the server work in two phases (`prepare`, `go-live`) so moving SSH off port 22 cannot lock you out.

## Before you start

- **Agree it with your supervisor or team.** A public honeypot records real people's IP addresses and commands, and AWS holds the account owner responsible for traffic from the instance.
- **Cost.** A t3.large (2 vCPU, 8 GiB) is roughly US$60–75 a month on demand, plus about $3–4 for a 40 GiB disk and about $3.60 for a public IPv4 address. Check the EC2 pricing page for your region. Stopping the instance stops the compute charge; the disk and the address are still billed.
- **Pick a region** close to you, for example Mumbai (`ap-south-1`).

## 1. Budget alert (2 min)

Billing and Cost Management → **Budgets** → Create budget → *Monthly cost budget*. Set an amount such as US$25 and your email.

- [ ] Budget created.

## 2. Key pair (2 min)

EC2 → **Key pairs** → Create key pair. Name it `honeypot`, type **ED25519**, format **.pem**. Save the file to `C:\Users\<you>\.ssh\honeypot.pem`.

Then restrict the file so SSH accepts it. In PowerShell:

```
icacls $env:USERPROFILE\.ssh\honeypot.pem /inheritance:r /grant:r "$($env:USERNAME):R"
```

- [ ] Key saved and restricted.

## 3. Security group (3 min)

EC2 → **Security groups** → Create security group. Name it `honeypot-sg`, in the default VPC.

Inbound rules, for now:

| Type | Port | Source |
|---|---|---|
| SSH | 22 | My IP |
| Custom TCP | 22022 | My IP |

Leave outbound as the default (all). The server needs it for packages and image builds. Attacker containers get no outbound access whatever this says.

- [ ] `honeypot-sg` saved with exactly these two inbound rules.

## 4. Launch the server (5 min)

EC2 → **Launch instance**:

| Setting | Value |
|---|---|
| Name | `genai-honeypot` |
| AMI | **Ubuntu Server 24.04 LTS**, 64-bit (x86) |
| Instance type | **t3.large** |
| Key pair | `honeypot` |
| Network | default VPC, **Auto-assign public IP: Enable**, security group **honeypot-sg** |
| Storage | **40 GiB gp3** |
| Advanced → IAM instance profile | **none** (no role) |
| Advanced → Metadata version | **V2 only (token required)** |
| Advanced → Metadata response hop limit | **1** |
| Advanced → Credit specification | **Standard** (no surprise charges when CPU is busy) |

The two metadata settings and having no IAM role mean nothing on the server has AWS credentials to steal.

Optional: **Elastic IPs** → Allocate → Associate with the instance, so the address stays the same across stop and start.

- [ ] Instance is running. Note its public IP; below it is `<ip>`.

## 5. Get the code onto the server (5 min)

In Git Bash on your laptop:

```bash
ssh -i ~/.ssh/honeypot.pem ubuntu@<ip>
```

On the server:

```bash
git clone https://github.com/Yashaswini717/GenAIHoneypot.git && cd GenAIHoneypot && git checkout classifier-rework-and-hardening
```

Use `main` instead once the branch is merged.

- [ ] You are in `~/GenAIHoneypot` on the server.

## 6. Prepare (15–25 min)

```bash
sudo bash deploy/server-setup.sh prepare
```

This installs Docker and gVisor, rotates Docker logs, adds the admin SSH port, generates fresh secrets, builds the node images, and starts the honeypot (still on port 2222, which the security group does not open) and the hub.

- [ ] It ends with `Prepared. Next, without closing this session:` and no `ERROR`.

## 7. Check the admin port (2 min)

**Keep the first session open.** From a **new** Git Bash window:

```bash
ssh -i ~/.ssh/honeypot.pem -p 22022 ubuntu@<ip>
```

- [ ] You get a shell. If you don't, fix it now: you still have the first session on port 22.

## 8. Go live (2 min)

In the **port-22022 session**:

```bash
cd ~/GenAIHoneypot && sudo bash deploy/server-setup.sh go-live
```

It refuses to run unless you are logged in on 22022. Then, in the AWS console, edit `honeypot-sg` and change the **port-22 rule's source to `0.0.0.0/0`** (add `::/0` too if the instance has IPv6). Leave 22022 on *My IP*.

- [ ] `go-live` printed `Live on port 22`.
- [ ] Port 22 is open to `0.0.0.0/0`, and 22022 only to your IP.

## 9. Verify (5 min)

From your laptop, be the first attacker:

```bash
ssh -p 22 devuser@<ip>
```

The password is `dev@123`. Run `hostname`, then `exit`.

- [ ] The hostname is `jump-01`.

On the server (22022 session):

```bash
sudo bash deploy/server-setup.sh check
```

- [ ] `All checks passed.` That covers:
  - only ports 22 and 22022 are public;
  - gVisor is registered, and the broker and your attacker container use it;
  - the container cannot reach the internet or the metadata service;
  - the hub is healthy, with no rejected deliveries;
  - IMDSv2 only, and no IAM role.

From PowerShell on your laptop, the hub's ports must be closed from outside:

```
foreach ($p in 5173,8000,9200,5432,6379,7474,7687) { Test-NetConnection <ip> -Port $p -InformationLevel Quiet }
```

- [ ] Every line prints `False`.

## 10. The dashboard, through a tunnel

**Stop the local hub first** if it is running on your laptop (`docker compose down` in `intelligence_hub`). The tunnel needs local ports 5173 and 8000, and the dashboard's Live Feed connects to `localhost:8000`.

```bash
ssh -i ~/.ssh/honeypot.pem -p 22022 -N -L 5173:127.0.0.1:5173 -L 8000:127.0.0.1:8000 ubuntu@<ip>
```

Leave it running and open http://localhost:5173.

- [ ] The dashboard loads, `backend • connected`, and your test login from step 9 is under **Sessions**.

## Running it

| Task | Command (on the server, in `~/GenAIHoneypot`) |
|---|---|
| Watch the brain decide | `cd honeypot-ecosystem && docker compose logs -f sidecar \| grep --line-buffered -E "intent=\|planted"` |
| Re-check everything | `sudo bash deploy/server-setup.sh check` |
| Update the code | `git pull && sudo bash deploy/server-setup.sh prepare` (safe once live: SSH stays on 22022) |
| **Kill switch** | `sudo bash deploy/server-setup.sh stop`, then remove the `0.0.0.0/0` rule on port 22 |
| Pause the bill | stop the instance in the console (disk and address still billed) |

**Real captures for holdout v4.** These are what this deployment is for. On the server:

```bash
cd ~/GenAIHoneypot/honeypot-ecosystem && docker compose cp sidecar:/var/spool/honeypot ~/telemetry
```

Then on your laptop:

```bash
scp -P 22022 -i ~/.ssh/honeypot.pem -r ubuntu@<ip>:telemetry ./telemetry
```

Run `captures extract ./telemetry` (see `ai-brain/.../captures.py`). On a real server the source addresses are real, so the default `--protocol` and private-address handling apply as written.

## Known limits at launch

- **gVisor shows if you look for it.** `dmesg`, `uname -r` and `/proc/version` reveal it to a careful human; bots do not check. This is the price of a much stronger sandbox.
- **Few accounts accept logins.** Only the accounts in `honeypot-ecosystem/secrets/credentials.yaml` work (`devuser`, `test`, `student`, `ubuntu`, `git`). Bots trying `root` or `admin` are refused, which is still recorded as brute force. Add common pairs there to see more sessions.
- **Open bugs:**
  - no decoys are planted after a pivot (the sidecar looks attackers up by address);
  - every command scores 100 on the Alerts page;
  - MySQL from node-02 to node-03 is not proxied, so "reached DB" stays at 0.
- **The control arm is back on.** It holds out 15% of attackers (`EXPERIMENT_CONTROL_RATIO=0.15` in the server's fresh `.env`), as the retention experiment needs.
