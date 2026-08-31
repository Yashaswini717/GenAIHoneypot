"""The SSH policy our front door presents, and why it is this policy.

An SSH library's default algorithm list is itself a fingerprint. AsyncSSH's
defaults differ from OpenSSH's in both membership and order, and order is part
of what HASSH hashes — so an attacker can HASSH us and see a server that
claims to be OpenSSH but negotiates like a Python library.

The obvious fix is to imitate OpenSSH 8.9p1's stock lists. We cannot: AsyncSSH
implements neither `sntrup761x25519-sha512@openssh.com` nor any of the four
`umac` MACs, and advertising an algorithm we cannot perform breaks the
handshake outright (negotiation takes the client's first match, and modern
OpenSSH clients put sntrup761 first). The residue would be a server claiming
stock OpenSSH while missing every umac yet still offering hmac-sha1 — an
incoherent profile no real administrator produces, and incoherence is exactly
what gets a host flagged.

So we imitate something else: a security-conscious administrator. The lists
below are a recognisable CIS / Mozilla-modern style hardening policy — ETM and
SHA-2 MACs only, AEAD-preferred ciphers, no NIST-curve host keys. Every entry
is inside AsyncSSH's capabilities, the set is internally consistent, and it is
the kind of config a university team that cares about its jump box would
actually deploy. There is no unexplainable hole left to find.

`SSHD_CONFIG_LINES` mirrors the same policy into the node's own
/etc/ssh/sshd_config, so an attacker who reads that file finds corroboration
rather than contradiction.

Check our work from outside with either of:

    nmap --script ssh2-enum-algos -p 22 <host>
    ssh-audit <host>
"""

from __future__ import annotations

from typing import Final, Iterable

#: Identification string. The *version claim* stays stock Ubuntu — only the
#: negotiated policy is hardened, which is exactly the shape of a real
#: hardened host. Must stay consistent with the node's /etc/os-release.
SERVER_VERSION: Final = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"

#: Order is preference order, and is part of the HASSH input. Keep it stable.
KEX_ALGS: Final[tuple[str, ...]] = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
)

#: AEAD first, then CTR. This is Mozilla's "modern" cipher list verbatim.
ENCRYPTION_ALGS: Final[tuple[str, ...]] = (
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
)

#: Encrypt-then-MAC, SHA-2 only. Unused when an AEAD cipher is negotiated,
#: which is most sessions — these only apply to the CTR ciphers above.
MAC_ALGS: Final[tuple[str, ...]] = (
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
)

#: OpenSSH's default (`Compression yes`) advertises exactly this pair.
COMPRESSION_ALGS: Final[tuple[str, ...]] = (
    "none",
    "zlib@openssh.com",
)

#: ed25519 preferred, RSA with SHA-2 as the compatibility fallback. Dropping
#: the NIST-curve host key is standard in the same hardening guides that
#: produce the MAC list above, so the omission reads as policy, not gap.
#:
#: Note this is *not* a server-side AsyncSSH option — a server advertises host
#: key algorithms derived from the keys it actually loads, filtered by
#: `signature_algs`. Load one ed25519 and one RSA host key and pass
#: SIGNATURE_ALGS, and the wire result matches this list. Omitting ssh-rsa
#: (SHA-1) from SIGNATURE_ALGS is what keeps that true.
SERVER_HOST_KEY_ALGS: Final[tuple[str, ...]] = (
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
)

SIGNATURE_ALGS: Final[tuple[str, ...]] = SERVER_HOST_KEY_ALGS

#: Which auth methods the server advertises, and in OpenSSH's order.
#:
#: Getting this wrong is a louder tell than any algorithm list, because every
#: client sees it without needing to enumerate anything. A real sshd always
#: offers `publickey` — a server that advertises only password auth does not
#: exist in the wild. Live testing against the OpenSSH client caught exactly
#: that: AsyncSSH defaults to keyboard-interactive plus password and no
#: publickey, which is a shape no real host produces.
#:
#: Disabling keyboard-interactive is consistent with the hardening policy
#: above, so the advertised set lands on `publickey,password` — what a
#: hardened Ubuntu 22.04 jump box looks like.
PUBKEY_AUTH: Final = True
KBDINT_AUTH: Final = False
PASSWORD_AUTH: Final = True

#: sshd's MaxAuthTries. Matching real behaviour matters: Cowrie's habit of
#: accepting the Nth guess regardless of its value is among the best known
#: honeypot tells, and an unlimited retry count is another. AsyncSSH has no
#: equivalent option, so the proxy's auth handler enforces this itself.
MAX_AUTH_TRIES: Final = 6

#: sshd's LoginGraceTime, in seconds. Maps to AsyncSSH's `login_timeout`.
LOGIN_GRACE_TIME: Final = 120

#: The same policy expressed for the node's /etc/ssh/sshd_config. Rendered in
#: by the node build so the file an attacker can read agrees with the
#: handshake they just completed.
SSHD_CONFIG_LINES: Final[str] = "\n".join(
    [
        "# Hardening policy - CIS Benchmark aligned",
        "# Reviewed: see /opt/deploy/CHANGELOG for last audit",
        f"KexAlgorithms {','.join(KEX_ALGS)}",
        f"Ciphers {','.join(ENCRYPTION_ALGS)}",
        f"MACs {','.join(MAC_ALGS)}",
        f"HostKeyAlgorithms {','.join(SERVER_HOST_KEY_ALGS)}",
        f"MaxAuthTries {MAX_AUTH_TRIES}",
        f"LoginGraceTime {LOGIN_GRACE_TIME}",
        "PermitRootLogin no",
        "PubkeyAuthentication yes",
        "PasswordAuthentication yes",
        "KbdInteractiveAuthentication no",
        "X11Forwarding no",
        "ClientAliveInterval 300",
        "ClientAliveCountMax 2",
    ]
)


def intersect_supported(
    preferred: Iterable[str],
    supported: Iterable[str],
) -> list[str]:
    """Keep our preference order, drop anything the local library cannot do.

    Advertising an algorithm we cannot actually perform breaks the handshake,
    so we filter — but never reorder, because order is HASSH input.

    With the hardened lists above this should be a no-op on AsyncSSH 2.24.
    `verify_profile` asserts exactly that at startup.
    """
    available = set(supported)
    return [alg for alg in preferred if alg in available]


def describe_gaps(
    preferred: Iterable[str],
    supported: Iterable[str],
) -> list[str]:
    """Anything we advertise but cannot perform — our residual fingerprint.

    Expected to be empty. If a dependency upgrade ever makes it non-empty,
    `verify_profile` fails loudly at startup rather than letting the node go
    live with a silently incoherent algorithm list.
    """
    available = set(supported)
    return [alg for alg in preferred if alg not in available]


def verify_profile() -> dict[str, list[str]]:
    """Fail fast if the local AsyncSSH cannot deliver the advertised policy.

    Called during proxy startup. A gap here is not cosmetic: it means the
    handshake we present no longer matches the policy the node's sshd_config
    claims, which is precisely the contradiction this module exists to avoid.

    Returns the per-category gaps (all empty on a healthy install).
    """
    from asyncssh.compression import get_compression_algs
    from asyncssh.encryption import get_encryption_algs
    from asyncssh.kex import get_kex_algs
    from asyncssh.mac import get_mac_algs

    def decoded(algs: Iterable[bytes | str]) -> list[str]:
        return [a.decode() if isinstance(a, bytes) else a for a in algs]

    gaps = {
        "kex": describe_gaps(KEX_ALGS, decoded(get_kex_algs())),
        "encryption": describe_gaps(ENCRYPTION_ALGS, decoded(get_encryption_algs())),
        "mac": describe_gaps(MAC_ALGS, decoded(get_mac_algs())),
        "compression": describe_gaps(COMPRESSION_ALGS, decoded(get_compression_algs())),
    }

    missing = {k: v for k, v in gaps.items() if v}
    if missing:
        raise RuntimeError(
            "SSH policy cannot be delivered by the installed AsyncSSH: "
            f"{missing}. The advertised handshake would no longer match the "
            "policy in the node's sshd_config. Pin AsyncSSH, or update both "
            "this module and the node's sshd_config together."
        )
    return gaps
