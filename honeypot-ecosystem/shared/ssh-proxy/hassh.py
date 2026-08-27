"""HASSH fingerprinting from the client's KEXINIT.

The intelligence hub has a HASSH correlation panel and its normalizer reads a
`hassh` field, but nothing was producing one. HASSH identifies the client
*implementation* rather than the host, so it survives IP rotation — the same
botnet hitting us from three hundred addresses shows up as one fingerprint.
That is what makes it worth the effort.

    hassh = md5(kex ; encryption_c2s ; mac_c2s ; compression_c2s)

with each element a comma-joined algorithm list, taken from the client's
KEXINIT in the order the client offered them.

KEXINIT travels in the clear, before key exchange completes, so we can read it
straight off the wire. We tee raw bytes out of asyncio's `data_received` — the
Protocol contract, not an AsyncSSH internal — so this keeps working across
AsyncSSH releases. Everything is wrapped defensively: if parsing fails we emit
no fingerprint, and the hub treats `hassh` as optional, so a failure here
degrades one field rather than dropping the session.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

SSH_MSG_KEXINIT = 20

#: Stop buffering after this much. A real KEXINIT arrives inside the first
#: couple of KB; anything larger is a malformed or hostile client and we would
#: rather drop the fingerprint than hold attacker-controlled bytes in memory.
_MAX_BUFFER = 16 * 1024


@dataclass
class ClientHandshake:
    """What we recovered from one client's pre-encryption bytes."""

    version: str | None = None
    hassh: str | None = None
    kex_algs: list[str] = field(default_factory=list)
    host_key_algs: list[str] = field(default_factory=list)
    encryption_algs: list[str] = field(default_factory=list)
    mac_algs: list[str] = field(default_factory=list)
    compression_algs: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.version is not None and self.hassh is not None


class HandshakeSniffer:
    """Accumulates raw client bytes and extracts the ident string and KEXINIT.

    Feed it with `feed()` for every chunk received from the peer. It stops
    consuming as soon as it has both the version line and the KEXINIT, so the
    steady-state cost after the handshake is a single boolean check.
    """

    def __init__(self) -> None:
        self.result = ClientHandshake()
        self._buf = bytearray()
        self._done = False
        self._version_offset: int | None = None

    @property
    def done(self) -> bool:
        """True once there is nothing further worth reading from the stream."""
        return self._done

    def feed(self, data: bytes) -> None:
        if self._done:
            return
        self._buf.extend(data)
        if len(self._buf) > _MAX_BUFFER:
            log.debug("hassh: buffer cap hit, abandoning fingerprint")
            self._done = True
            return
        try:
            self._parse()
        except Exception:  # never let fingerprinting break a session
            log.debug("hassh: parse failed, abandoning fingerprint", exc_info=True)
            self._done = True

    # -- parsing -----------------------------------------------------------

    def _parse(self) -> None:
        if self._version_offset is None and not self._read_version():
            return
        if self.result.hassh is None:
            self._read_kexinit()
        if self.result.complete:
            self._done = True
            self._buf = bytearray()

    def _read_version(self) -> bool:
        """RFC 4253 permits arbitrary lines before the SSH- ident line."""
        offset = 0
        view = bytes(self._buf)
        while True:
            end = view.find(b"\n", offset)
            if end == -1:
                return False
            line = view[offset:end].rstrip(b"\r")
            offset = end + 1
            if line.startswith(b"SSH-"):
                self.result.version = line.decode("utf-8", "replace")
                self._version_offset = offset
                return True
            if offset > 4096:  # runaway preamble
                raise ValueError("no SSH ident line in preamble")

    def _read_kexinit(self) -> None:
        assert self._version_offset is not None
        view = memoryview(self._buf)
        pos = self._version_offset

        while True:
            if len(view) - pos < 6:
                return  # need more bytes
            (packet_len,) = struct.unpack_from(">I", view, pos)
            if packet_len < 2 or packet_len > _MAX_BUFFER:
                raise ValueError(f"implausible packet length {packet_len}")
            total = 4 + packet_len
            if len(view) - pos < total:
                return  # packet still in flight

            padding_len = view[pos + 4]
            payload = bytes(view[pos + 5 : pos + total - padding_len])
            pos += total

            if payload and payload[0] == SSH_MSG_KEXINIT:
                self._decode_kexinit(payload)
                return

    def _decode_kexinit(self, payload: bytes) -> None:
        # byte msg_type, byte[16] cookie, then ten name-lists.
        pos = 1 + 16
        lists: list[list[str]] = []
        for _ in range(10):
            (length,) = struct.unpack_from(">I", payload, pos)
            pos += 4
            raw = payload[pos : pos + length].decode("utf-8", "replace")
            pos += length
            lists.append([item for item in raw.split(",") if item])

        (
            kex,
            host_key,
            enc_cs,
            _enc_sc,
            mac_cs,
            _mac_sc,
            comp_cs,
            _comp_sc,
            _lang_cs,
            _lang_sc,
        ) = lists

        self.result.kex_algs = kex
        self.result.host_key_algs = host_key
        self.result.encryption_algs = enc_cs
        self.result.mac_algs = mac_cs
        self.result.compression_algs = comp_cs
        self.result.hassh = compute_hassh(kex, enc_cs, mac_cs, comp_cs)


def compute_hassh(
    kex_algs: list[str],
    encryption_algs: list[str],
    mac_algs: list[str],
    compression_algs: list[str],
) -> str:
    """The HASSH digest, as defined by Salesforce's original implementation.

    MD5 is not a security choice here — it is the published algorithm, and
    changing it would make our fingerprints incomparable with every public
    HASSH dataset, which is the entire point of computing one.
    """
    payload = ";".join(
        [
            ",".join(kex_algs),
            ",".join(encryption_algs),
            ",".join(mac_algs),
            ",".join(compression_algs),
        ]
    )
    return hashlib.md5(payload.encode("utf-8")).hexdigest()  # noqa: S324
