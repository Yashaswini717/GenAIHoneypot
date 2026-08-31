"""Turning a raw PTY stream back into the commands that were run.

The proxy sits between the attacker's terminal and the backend node's shell,
so it sees two byte streams: keystrokes going in, terminal output coming back.
Neither is a list of commands, and recovering one is fiddlier than it looks.

Reading only the *input* stream loses accuracy. Tab completion means the bytes
typed are not the command that ran (`cd Doc<TAB>` executes `cd Documents/`),
and history recall means an up-arrow runs a command whose text was never typed
at all.

Reading only the *output* stream is closer to ground truth, because the shell
echoes the fully resolved line before running it — but it breaks the moment an
attacker changes PS1, and it never sees input that is not echoed, such as a
password typed at a sudo prompt.

So we use both. Keystrokes are tracked to know *when* a line was submitted and
what was typed; the echo is preferred as *what actually ran*; and the typed
buffer is the fallback when the echo cannot be resolved. Whatever happens, the
full raw transcript is written to disk, so a human can always replay the
session and see the truth regardless of what reconstruction decided.

The ANSI-stripping and backspace-replay logic follows the approach in Rohan's
original `parse_session.py`, moved from an after-the-fact batch parser into the
live stream.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from pathlib import Path

log = logging.getLogger(__name__)

#: OSC, then CSI, then single-character escapes — and the order is load-bearing.
#:
#: Alternation is first-match-wins, and the single-character class [@-Z\\-_]
#: contains `]` (0x5D). Putting it first meant `\x1b]` matched *it*, consuming
#: the escape but leaving the OSC body behind as literal text. Bash emits an
#: OSC title sequence in every single prompt, so that ordering leaked
#: `0;devuser@host: ~` into the front of every line — visible in the original
#: parse_session.py output too, where reports contain lines like
#: "0;devuser@dev-server: ~devuser@dev-server:~$ ls". A leading title fragment
#: also stops the prompt pattern from anchoring, which would silently disable
#: echo resolution and take tab completion down with it.
ANSI_RE = re.compile(rb"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])")

#: A shell prompt at the start of an echoed line: user@host:cwd$ or #.
PROMPT_RE = re.compile(r"^[\w.\-]+@[\w.\-]+:[^$#]*[$#]\s?")

#: Anything longer is not a command, it is a paste bomb or binary noise.
MAX_COMMAND_LEN = 4096

#: Control characters we interpret rather than store.
_BACKSPACE = {0x08, 0x7F}
_CTRL_C = 0x03
_CTRL_U = 0x15
_CTRL_W = 0x17
_ENTER = {0x0D, 0x0A}


def strip_ansi(data: bytes) -> bytes:
    return ANSI_RE.sub(b"", data)


class CommandReconstructor:
    """Recovers submitted commands from the two halves of a PTY stream."""

    def __init__(self) -> None:
        self._typed = bytearray()
        self._out_line = bytearray()
        self._out_col = 0
        self._pending: str | None = None
        self._pending_unreliable = False
        self._in_escape = False
        self._escape_buf = bytearray()

    # -- attacker -> shell -------------------------------------------------

    def feed_input(self, data: bytes) -> None:
        """Track keystrokes. Commands are emitted from the echo, not here."""
        for byte in data:
            if self._in_escape:
                self._escape_buf.append(byte)
                # CSI sequences end on a byte in the @-~ range.
                if 0x40 <= byte <= 0x7E:
                    self._end_escape()
                elif len(self._escape_buf) > 32:  # runaway, give up
                    self._end_escape()
                continue

            if byte == 0x1B:
                self._in_escape = True
                self._escape_buf = bytearray()
            elif byte in _ENTER:
                self._submit()
            elif byte in _BACKSPACE:
                if self._typed:
                    self._typed.pop()
            elif byte == _CTRL_C:
                self._typed.clear()
                self._pending = None
            elif byte == _CTRL_U:
                self._typed.clear()
            elif byte == _CTRL_W:
                self._delete_word()
            elif byte == 0x09:  # tab: the echo is now authoritative
                self._pending_unreliable = True
            elif byte >= 0x20:
                self._typed.append(byte)
            # other control bytes are ignored

    def _end_escape(self) -> None:
        # Arrow keys mean history recall or line editing; either way the typed
        # buffer no longer reflects what will run.
        if self._escape_buf[:1] == b"[" and self._escape_buf[-1:] in (b"A", b"B"):
            self._pending_unreliable = True
        self._in_escape = False
        self._escape_buf = bytearray()

    def _delete_word(self) -> None:
        while self._typed and self._typed[-1:] == b" ":
            self._typed.pop()
        while self._typed and self._typed[-1:] != b" ":
            self._typed.pop()

    def _submit(self) -> None:
        typed = self._typed.decode("utf-8", "replace").strip()
        self._typed.clear()
        self._pending = typed
        # Reset only after the echo has had its chance to resolve.

    # -- shell -> attacker -------------------------------------------------

    def feed_output(self, data: bytes) -> list[str]:
        """Track echoed output. Returns any commands resolved by this chunk.

        This models a real terminal line rather than appending blindly, which
        matters more than it sounds. A shell echoes Enter as CR-LF, and CR
        moves the cursor to column zero without erasing anything — so treating
        CR as "clear the line" would discard the echoed command a fraction of
        a byte before LF asks for it, defeating the entire point of reading
        the echo. Tab completion redraws the line the same way.

        So: CR moves the cursor, writes overwrite in place, and only LF ends
        the line.
        """
        commands: list[str] = []
        clean = strip_ansi(data)

        for byte in clean:
            if byte == 0x0A:  # line feed: the line is final
                resolved = self._resolve(bytes(self._out_line).rstrip())
                if resolved is not None:
                    commands.append(resolved)
                self._out_line.clear()
                self._out_col = 0
            elif byte == 0x0D:  # carriage return: cursor to column zero
                self._out_col = 0
            elif byte in _BACKSPACE:
                self._out_col = max(0, self._out_col - 1)
            elif byte >= 0x20 or byte == 0x09:
                if self._out_col < len(self._out_line):
                    self._out_line[self._out_col] = byte
                else:
                    self._out_line.append(byte)
                self._out_col += 1

        return commands

    def _resolve(self, line: bytes) -> str | None:
        """Decide what command, if any, this completed output line represents."""
        if self._pending is None:
            return None

        typed = self._pending
        unreliable = self._pending_unreliable
        self._pending = None
        self._pending_unreliable = False

        text = line.decode("utf-8", "replace")
        echoed = PROMPT_RE.sub("", text).strip() if PROMPT_RE.match(text) else None

        if echoed:
            command = echoed
        elif typed:
            # No prompt to strip: a custom PS1, or input that was never echoed
            # such as a password at a sudo prompt. The typed bytes are all we
            # have, and they are still worth recording.
            command = typed
        elif unreliable:
            # History recall whose echo we could not parse. Nothing to report
            # rather than something wrong.
            return None
        else:
            return None

        command = command.strip()
        if not command or len(command) > MAX_COMMAND_LEN:
            return None
        return command

    def flush(self) -> list[str]:
        """Emit anything still pending at session teardown."""
        if self._pending:
            command = self._pending.strip()
            self._pending = None
            if command and len(command) <= MAX_COMMAND_LEN:
                return [command]
        return []


class TranscriptWriter:
    """Writes the full raw PTY stream for later replay.

    Deliberately separate from the event stream: events go to the hub for
    scoring, transcripts stay local and are read by humans. Keeping the raw
    bytes means a reconstruction bug is recoverable after the fact instead of
    silently losing evidence.

    One JSON object per line: relative timestamp, direction, base64 payload.
    """

    def __init__(self, directory: Path, session_id: str) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self._path = directory / f"{session_id}.jsonl"
        self._started = time.monotonic()
        self._handle = self._path.open("a", encoding="utf-8")

    def write(self, direction: str, data: bytes) -> None:
        record = {
            "t": round(time.monotonic() - self._started, 4),
            "dir": direction,  # "i" attacker -> shell, "o" shell -> attacker
            "b64": base64.b64encode(data).decode("ascii"),
        }
        try:
            self._handle.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._handle.flush()
        except Exception:
            log.error("transcript write failed for %s", self._path, exc_info=True)

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:
            pass

    @property
    def path(self) -> Path:
        return self._path
