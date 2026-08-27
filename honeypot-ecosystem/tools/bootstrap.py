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
    print("sshd policy:")
    generate_sshd_policy(args.force)
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
