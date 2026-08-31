"""Command reconstruction tests.

Each case is a byte-level script of a real PTY exchange: 'i' is what the
attacker's terminal sent, 'o' is what the backend shell sent back. The cases
that matter most are the ones where the typed bytes and the executed command
differ — tab completion, history recall, and input that is never echoed at
all. Those are exactly the cases a naive keystroke logger gets wrong, and they
feed the intent classifier, so a wrong command here becomes a wrong intent
downstream.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "ssh-proxy"))

from recorder import CommandReconstructor, strip_ansi  # noqa: E402

#: A default Ubuntu bash prompt exactly as bash emits it: an OSC sequence that
#: sets the terminal title, then the colour escapes, then the prompt text.
#: The OSC half is the part naive parsers drop on the floor.
PROMPT = (
    b"\x1b]0;devuser@jump-01: ~\x07"
    b"\x1b[01;32mdevuser@jump-01\x1b[00m:\x1b[01;34m~\x1b[00m$ "
)
PLAIN = b"devuser@jump-01:~$ "


def replay(script: list[tuple[str, bytes]]) -> list[str]:
    reconstructor = CommandReconstructor()
    recovered: list[str] = []
    for direction, data in script:
        if direction == "i":
            reconstructor.feed_input(data)
        else:
            recovered.extend(reconstructor.feed_output(data))
    recovered.extend(reconstructor.flush())
    return recovered


CASES: list[tuple[str, list[tuple[str, bytes]], list[str]]] = [
    (
        "plain command with a coloured prompt",
        [
            ("o", PROMPT),
            ("i", b"ls"),
            ("o", b"ls"),
            ("i", b"\r"),
            ("o", b"\r\n"),
            ("o", b"Desktop  Documents\r\n"),
        ],
        ["ls"],
    ),
    (
        "tab completion: typed 'cd Doc', ran 'cd Documents/'",
        [
            ("o", PROMPT),
            ("i", b"cd Doc"),
            ("o", b"cd Doc"),
            ("i", b"\t"),
            ("o", b"uments/"),
            ("i", b"\r"),
            ("o", b"\r\n"),
        ],
        ["cd Documents/"],
    ),
    (
        "backspace correction",
        [
            ("o", PROMPT),
            ("i", b"lss"),
            ("o", b"lss"),
            ("i", b"\x7f"),
            ("o", b"\x08 \x08"),
            ("i", b"\r"),
            ("o", b"\r\n"),
        ],
        ["ls"],
    ),
    (
        "history recall: nothing typed, the echo is the only truth",
        [
            ("o", PROMPT),
            ("i", b"\x1b[A"),
            ("o", b"cat /etc/passwd"),
            ("i", b"\r"),
            ("o", b"\r\n"),
        ],
        ["cat /etc/passwd"],
    ),
    (
        "ctrl-C abandons the line without running it",
        [
            ("o", PROMPT),
            ("i", b"rm -rf /"),
            ("o", b"rm -rf /"),
            ("i", b"\x03"),
            ("o", b"^C\r\n"),
            ("o", PROMPT),
        ],
        [],
    ),
    (
        "sudo password is never echoed, so the typed bytes are all we have",
        [
            ("o", PROMPT),
            ("i", b"sudo -s"),
            ("o", b"sudo -s"),
            ("i", b"\r"),
            ("o", b"\r\n"),
            ("o", b"[sudo] password for devuser: "),
            ("i", b"hunter2\r"),
            ("o", b"\r\n"),
        ],
        ["sudo -s", "hunter2"],
    ),
    (
        "two commands back to back",
        [
            ("o", PROMPT),
            ("i", b"whoami"),
            ("o", b"whoami"),
            ("i", b"\r"),
            ("o", b"\r\n"),
            ("o", b"devuser\r\n"),
            ("o", PLAIN),
            ("i", b"id"),
            ("o", b"id"),
            ("i", b"\r"),
            ("o", b"\r\n"),
            ("o", b"uid=1000(devuser)\r\n"),
        ],
        ["whoami", "id"],
    ),
    (
        "ctrl-U clears the line, then a real command runs",
        [
            ("o", PROMPT),
            ("i", b"garbage"),
            ("o", b"garbage"),
            ("i", b"\x15"),
            ("o", b"\r" + PLAIN),
            ("i", b"uname -a"),
            ("o", b"uname -a"),
            ("i", b"\r"),
            ("o", b"\r\n"),
        ],
        ["uname -a"],
    ),
]


@pytest.mark.parametrize(
    ("script", "expected"),
    [(script, expected) for _, script, expected in CASES],
    ids=[name for name, _, _ in CASES],
)
def test_reconstruction(script: list[tuple[str, bytes]], expected: list[str]) -> None:
    assert replay(script) == expected


def test_carriage_return_does_not_erase_the_echoed_line() -> None:
    """Regression: CR moves the cursor, it does not clear the line.

    Treating CR as "clear" discarded the echoed command one byte before LF
    asked for it, which silently broke every tab-completion and history case.
    """
    recovered = replay(
        [
            ("o", PLAIN),
            ("i", b"cat /etc/shadow"),
            ("o", b"cat /etc/shadow"),
            ("i", b"\r"),
            ("o", b"\r\n"),
        ]
    )
    assert recovered == ["cat /etc/shadow"]


def test_overlong_input_is_dropped() -> None:
    """A paste bomb is not a command and must not reach the classifier."""
    payload = b"A" * 9000
    recovered = replay([("o", PLAIN), ("i", payload), ("o", payload), ("i", b"\r"), ("o", b"\r\n")])
    assert recovered == []


def test_strip_ansi_removes_csi_and_osc() -> None:
    assert strip_ansi(b"\x1b[01;32mhi\x1b[00m") == b"hi"
    assert strip_ansi(b"\x1b]0;title\x07text") == b"text"
