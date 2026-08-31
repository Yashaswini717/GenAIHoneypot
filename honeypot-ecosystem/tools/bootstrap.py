#!/usr/bin/env python3
"""One-time setup: generate the keys and derived config the stack needs.

Produces three things, none of which belong in git:

  secrets/backend_key(.pub)   the key the SSH proxy uses to reach backend
                              containers. Only the public half is baked into
                              the node image, so an attacker with root on a
                              node finds nothing to steal — and the key
                              authorises a shell on a throwaway container in
                              any case.

  .env                        environment for the stack, including a random
                              HMAC secret. The hub skips signature
                              verification when the secret is the literal
                              string "dev", so leaving the default in place
                              would silently disable the zero-trust check.

  nodes/*/sshd_policy.conf    the node's sshd_config policy block, generated
                              from the same module the proxy advertises from.
                              These must agree: an attacker who reads
                              sshd_config and finds a policy that contradicts
                              the handshake they just completed has found us.

Safe to re-run. Existing files are left alone unless --force is passed.
"""

from __future__ import annotations

import argparse
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRETS = ROOT / "secrets"
NODES = ROOT / "nodes"

#: The only node the SSH proxy fronts. Everything else is reached by pivoting.
ENTRY_NODE = "node-01-jump"


def generate_backend_key(force: bool) -> Path:
    SECRETS.mkdir(parents=True, exist_ok=True)
    private = SECRETS / "backend_key"
    public = SECRETS / "backend_key.pub"

    if private.exists() and not force:
        print(f"  keeping existing {private.relative_to(ROOT)}")
    else:
        for path in (private, public):
            path.unlink(missing_ok=True)
        subprocess.run(
            [
                "ssh-keygen",
                "-t", "ed25519",
                "-N", "",
                "-C", "deploy@ops",  # an innocuous comment; it lands in authorized_keys
                "-f", str(private),
            ],
            check=True,
            capture_output=True,
        )
        private.chmod(0o600)
        print(f"  generated {private.relative_to(ROOT)}")

    # Every node image needs the public half at build time.
    for node_dir in sorted(NODES.iterdir()):
        if node_dir.is_dir():
            shutil.copy2(public, node_dir / "backend_key.pub")
            print(f"  installed public key into {node_dir.name}/")
    return private


def generate_decoy_key(force: bool) -> None:
    """The key the attacker steals must be a REAL key.

    It was a random base64 blob wrapped in OPENSSH PRIVATE KEY armour, which
    looks right in `cat` and fails the moment anyone uses it: `ssh -i` cannot
    parse it, so the pivot dies at exactly the point the whole decoy chain
    exists to reach. An attacker who works for twenty minutes to find a key
    and then discovers it is not a key has learned more than if we had left
    nothing there at all.

    So it is a genuine ed25519 keypair. The private half is planted on node-01
    for them to find; the public half authorises the `deploy` account on the
    proxy and nothing else, so stealing it buys exactly the next hop we want
    them to take.
    """
    private = SECRETS / "decoy_deploy_key"
    public = SECRETS / "decoy_deploy_key.pub"

    if private.exists() and not force:
        print(f"  keeping existing {private.relative_to(ROOT)}")
    else:
        for path in (private, public):
            path.unlink(missing_ok=True)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "",
             "-C", "deploy@erp-web", "-f", str(private)],
            check=True, capture_output=True,
        )
        private.chmod(0o600)
        print(f"  generated {private.relative_to(ROOT)}")

    # The entry node plants the private half; only that node needs it.
    shutil.copy2(private, NODES / ENTRY_NODE / "decoy_deploy_key")
    print(f"  planted private half into {ENTRY_NODE}/")


def generate_sshd_policy(force: bool) -> None:
    sys.path.insert(0, str(ROOT / "shared" / "ssh-proxy"))
    import openssh_profile as profile

    # Fails loudly if the installed AsyncSSH cannot deliver the policy, rather
    # than writing a node config the proxy will not actually honour.
    try:
        profile.verify_profile()
    except ImportError:
        print("  (asyncssh not installed locally; skipping the deliverability check)")

    for node_dir in sorted(NODES.iterdir()):
        if not node_dir.is_dir():
            continue
        target = node_dir / "sshd_policy.conf"
        if target.exists() and not force:
            print(f"  keeping existing {target.relative_to(ROOT)}")
            continue
        # newline="" stops Windows translating \n to \r\n. A CRLF policy file
        # puts a stray \r into the algorithm lists sshd parses, which would
        # silently desync the node's advertised SSH policy from the proxy's.
        target.write_text(profile.SSHD_CONFIG_LINES + "\n", encoding="utf-8", newline="")
        print(f"  wrote {target.relative_to(ROOT)}")


def generate_credentials(force: bool) -> None:
    """Derive the proxy's accepted logins from each node's identity.yaml.

    These must not be maintained separately. The proxy decides who gets in;
    the node decides whose password `sudo` accepts. When those two lists were
    written independently the node's accounts ended up locked, so every login
    succeeded at the proxy and every `sudo` afterwards failed — which no real
    box does, and which dead-ended the decoy chain at its second step.

    One file, generated, so the password that logs you in is the password
    sudo takes.
    """
    import yaml

    target = SECRETS / "credentials.yaml"
    if target.exists() and not force:
        print(f"  keeping existing {target.relative_to(ROOT)}")
        return

    # ONLY the entry node's accounts. The proxy is the front door to node-01;
    # `deploy` and `dbadmin` belong to nodes reached by pivoting, and an
    # attacker who could log straight in as `deploy` at the perimeter would
    # never need to find the stolen key at all -- which is the entire chain.
    accounts: dict[str, str] = {}
    entry = NODES / ENTRY_NODE / "identity.yaml"
    if entry.exists():
        identity = yaml.safe_load(entry.read_text(encoding="utf-8"))
        for user in identity.get("users", []):
            if user.get("login") and user.get("password"):
                accounts[user["name"]] = user["password"]

    if not accounts:
        print("  no login accounts found in any identity.yaml — skipping")
        return

    body = "# Generated by tools/bootstrap.py from nodes/*/identity.yaml.\n"
    body += "# Edit identity.yaml, not this file, or sudo and login will disagree.\n"
    body += "".join(f"{name}: {password!r}\n" for name, password in sorted(accounts.items()))
    target.write_text(body, encoding="utf-8", newline="")
    print(f"  wrote {target.relative_to(ROOT)} ({len(accounts)} accounts)")


def generate_peer_credentials(force: bool) -> None:
    """Accounts that exist only on the pivot targets.

    Deliberately a separate file from the entry node's. `deploy` and `dbadmin`
    must not be accepted at the perimeter, or an attacker could skip the
    entire decoy chain by guessing a username.
    """
    import yaml

    target = SECRETS / "peer_credentials.yaml"
    if target.exists() and not force:
        print(f"  keeping existing {target.relative_to(ROOT)}")
        return

    accounts: dict[str, str] = {}
    for node_dir in sorted(NODES.iterdir()):
        if not node_dir.is_dir() or node_dir.name == ENTRY_NODE:
            continue
        identity_path = node_dir / "identity.yaml"
        if not identity_path.exists():
            continue
        identity = yaml.safe_load(identity_path.read_text(encoding="utf-8"))
        for user in identity.get("users", []):
            if user.get("login") and user.get("password"):
                accounts[user["name"]] = user["password"]

    body = (
        "# Generated from the non-entry nodes' identity.yaml.\n"
        "# These accounts are accepted ONLY by the pivot gateway, never at\n"
        "# the perimeter -- reaching them is supposed to require the chain.\n"
    )
    body += "".join(f"{n}: {p!r}\n" for n, p in sorted(accounts.items()))
    target.write_text(body, encoding="utf-8", newline="")
    print(f"  wrote {target.relative_to(ROOT)} ({len(accounts)} accounts)")


def generate_env(force: bool) -> None:
    env_path = ROOT / ".env"
    if env_path.exists() and not force:
        print(f"  keeping existing {env_path.name}")
        return

    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    example = example.replace("HMAC_SECRET=change-me", f"HMAC_SECRET={secrets.token_hex(32)}")
    env_path.write_text(example, encoding="utf-8", newline="")
    print(f"  wrote {env_path.name} with a fresh HMAC secret")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="regenerate files that already exist")
    args = parser.parse_args()

    print("backend key:")
    generate_backend_key(args.force)
    print("decoy key:")
    generate_decoy_key(args.force)
    print("sshd policy:")
    generate_sshd_policy(args.force)
    print("credentials:")
    generate_credentials(args.force)
    print("peer credentials:")
    generate_peer_credentials(args.force)
    print("environment:")
    generate_env(args.force)

    print(
        "\nReady. Next:\n"
        "  docker compose build\n"
        "  docker compose up -d\n"
        "  ssh -p 2222 test@localhost        # password: test123\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
