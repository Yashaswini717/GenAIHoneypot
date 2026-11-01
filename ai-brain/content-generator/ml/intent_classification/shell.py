"""Just enough shell parsing to tell what a command line actually runs.

The rules used to match substrings of the lowercased, newline-joined window,
and every substring test was a false positive waiting for the right command:

    "ssh "   matched `ls -la ~/.ssh`, because the join left a trailing space
    "nc "    matched `rsync -avz ...`
    "su "    never matched a bare `su root`, which starts the line
    "curl -f" matched `curl -fsSL` -- lowercasing turned "fail quietly" into
              "upload a form"

So commands are split into segments the way a shell would split them --
quotes respected, `;`, `&&`, `|` and parentheses as boundaries, redirections
pulled out -- and each segment is reduced to the program it runs, its
arguments, and the files it writes or reads. `sudo cp ...` runs `cp` with
`sudo` in front; `echo "x | sh"` runs `echo`, not `sh`.

This is a classifier's view of a shell, not a shell: it never expands
variables or globs, and unbalanced quotes fall back to splitting on
whitespace rather than failing.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

#: Programs that run another program. The one after them is what matters, but
#: the wrapper is kept too: `sudo` in front of anything is evidence by itself.
WRAPPERS = frozenset({
    "sudo", "doas", "nohup", "time", "nice", "ionice", "timeout", "stdbuf", "env",
    "proxychains", "proxychains4", "torsocks", "xargs", "busybox", "command",
    "exec", "strace", "watch",
})

#: Wrapper options that consume the next word as their value.
_OPTIONS_WITH_VALUE = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D"},
    "doas": {"-u", "-C"},
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "timeout": {"-s", "-k"},
    "xargs": {"-I", "-n", "-P", "-d", "-E", "-L", "-s"},
    "watch": {"-n", "-d"},
}

#: Shell keywords that can open a segment without being its program.
_KEYWORDS = frozenset({"do", "then", "else", "elif", "if", "while", "until", "!", "{", "}", "time"})

_BOUNDARY = re.compile(r"^[;&|()\n]+$")
_WRITE_OPS = frozenset({">", ">>", "&>", ">|", "&>>"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class Segment:
    """One simple command inside a command line."""

    words: list[str]
    program: str = ""
    args: list[str] = field(default_factory=list)
    wrappers: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    #: True when the segment's input is a pipe from the segment before it.
    piped_in: bool = False

    @property
    def text(self) -> str:
        return " ".join(self.words)

    def has_flag(self, *flags: str) -> bool:
        """True when any argument is one of `flags`, compared case-sensitively.

        Case matters on the command line: `curl -F` uploads a form, `curl -f`
        just fails quietly.
        """
        return any(arg in flags for arg in self.args)

    def has_short_flag(self, letter: str) -> bool:
        """True when a single-dash option cluster contains `letter`, e.g. `-zv` has `z`."""
        return any(
            arg.startswith("-") and not arg.startswith("--") and letter in arg[1:]
            for arg in self.args
        )


def tokens(command: str) -> list[str]:
    """Shell-style tokens: quotes removed, operators as separate tokens."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        # Unbalanced quotes -- usually a multi-line command the recorder only
        # saw the first line of. Whitespace splitting keeps the program names.
        return re.findall(r"[^\s;|&()<>]+|[;|&()<>]+", command.replace('"', " ").replace("'", " "))


def basename(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def _resolve_program(segment: Segment) -> None:
    words = segment.words
    i = 0
    while i < len(words) and (words[i] in _KEYWORDS or _ASSIGNMENT.match(words[i])):
        i += 1
    while i < len(words) and basename(words[i]) in WRAPPERS:
        wrapper = basename(words[i])
        segment.wrappers.append(wrapper)
        i += 1
        takes_value = _OPTIONS_WITH_VALUE.get(wrapper, set())
        while i < len(words) and (words[i].startswith("-") or _ASSIGNMENT.match(words[i])):
            i += 2 if words[i] in takes_value else 1
        if wrapper == "timeout" and i < len(words) and words[i][:1].isdigit():
            i += 1
    if i < len(words):
        segment.program = basename(words[i])
        segment.args = words[i + 1:]


def segments(command: str) -> list[Segment]:
    """Split one command line into the simple commands it runs."""
    result: list[Segment] = []
    current: list[str] = []
    writes: list[str] = []
    reads: list[str] = []
    piped_in = False
    pending: str | None = None

    def close(next_piped: bool) -> None:
        nonlocal current, writes, reads, piped_in
        if current or writes or reads:
            segment = Segment(words=current, writes=writes, reads=reads, piped_in=piped_in)
            _resolve_program(segment)
            result.append(segment)
        current, writes, reads = [], [], []
        piped_in = next_piped

    for token in tokens(command):
        if pending is not None:
            if pending in _WRITE_OPS:
                writes.append(token)
            elif pending == "<":
                reads.append(token)
            pending = None
            continue
        if token in _WRITE_OPS or token in {"<", "<<", "<<<", ">&", "<&"}:
            pending = token
            continue
        if _BOUNDARY.match(token):
            close(next_piped=token == "|")
            continue
        current.append(token)
    close(next_piped=False)
    return result


def programs(command: str) -> list[str]:
    """Every program a command line runs, wrappers included."""
    names: list[str] = []
    for segment in segments(command):
        names.extend(segment.wrappers)
        if segment.program:
            names.append(segment.program)
    return names
