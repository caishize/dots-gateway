"""Command, shell-syntax, and workspace path security policy enforcement."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .config import DEFAULT_AGY_READONLY_ROOTS, GatewayConfig


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    normalized_argv: Optional[List[str]] = None
    resolved_cwd: str = ""
    requires_shell: bool = False


_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.DOTALL)
_VERSIONED_TOOL_RE = re.compile(
    r"^(?:python3\.\d+|pip3\.\d+|gcc-\d+|g\+\+-\d+|clang-\d+|clang\+\+-\d+)$"
)
_SHELL_BUILTINS = {
    "cd",
    "export",
    "unset",
    "source",
    ".",
    "true",
    "false",
    "test",
    "[",
    "set",
}
_SHELL_PREFIX_KEYWORDS = {
    "if",
    "elif",
    "while",
    "until",
    "then",
    "else",
    "do",
    "!",
    "{",
}
_SHELL_CLOSE_KEYWORDS = {"fi", "done", "}"}
_FOR_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REDIR_PREFIX_RE = re.compile(r"^(?:\d+)?(?:>>?|<<?|[<>]&|&>>?|<>|>\|)(.+)$", re.DOTALL)
_WORD_BOUNDARY_PREDECESSORS = (" ", "\t", "\n", "\r", ";", "&", "|", "(", ")")

_AUDIT_SECRET_PREFIX_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}"
    r"|dots_(?:at|rt)\.[A-Za-z0-9._-]+|AIza[0-9A-Za-z_-]{20,})"
)
_AUDIT_BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s\"';&|]+")
_AUDIT_KV_SECRET_RE = re.compile(
    r"(?i)((?:api[_-]?key|token|secret|password|passwd|authorization|hmac[_-]?secret)"
    r"\s*[=:]\s*[\"']?)[^\s\"';&|]+"
)


def redact_for_audit_log(value: Any, max_len: int = 400) -> str:
    """Format a command/argument preview for single-line audit logs with secrets redacted."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = _AUDIT_SECRET_PREFIX_RE.sub("<REDACTED>", text)
    text = _AUDIT_BEARER_RE.sub(r"\1<REDACTED>", text)
    text = _AUDIT_KV_SECRET_RE.sub(r"\1<REDACTED>", text)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > max_len:
        text = text[:max_len] + "...(truncated)"
    return text


@dataclass
class _HeredocSpec:
    delimiter: str
    quoted: bool
    strip_tabs: bool
    body: str = ""


@dataclass
class _ParsedSegment:
    command: str
    heredocs: List[_HeredocSpec]


def _decode_ansi_c_string(content: str) -> str:
    """Decode Bash `$'...'` escape sequences so `shlex.split` sees exact token text."""
    out: List[str] = []
    i = 0
    n = len(content)
    simple = {
        "a": "\a",
        "b": "\b",
        "e": "\x1b",
        "E": "\x1b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
        "?": "?",
    }
    while i < n:
        ch = content[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = content[i + 1]
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
            continue
        if nxt == "x":
            m_hex = re.match(r"[0-9a-fA-F]{1,2}", content[i + 2 : i + 4])
            if m_hex:
                out.append(chr(int(m_hex.group(0), 16)))
                i += 2 + len(m_hex.group(0))
                continue
        if nxt in ("u", "U"):
            width = 4 if nxt == "u" else 8
            m_uni = re.match(rf"[0-9a-fA-F]{{1,{width}}}", content[i + 2 : i + 2 + width])
            if m_uni:
                codepoint = int(m_uni.group(0), 16)
                out.append(chr(codepoint) if codepoint <= 0x10FFFF else "\ufffd")
                i += 2 + len(m_uni.group(0))
                continue
        m_oct = re.match(r"[0-7]{1,3}", content[i + 1 : i + 4])
        if m_oct:
            out.append(chr(int(m_oct.group(0), 8) & 0xFF))
            i += 1 + len(m_oct.group(0))
            continue
        out.append("\\")
        out.append(nxt)
        i += 2
    return "".join(out)


def _parse_heredoc_delimiter(raw: str, start_idx: int) -> Tuple[str, bool, int]:
    """Parse heredoc delimiter starting right after `<<` or `<<-`.

    Returns `(delimiter_text, is_quoted, next_idx)`.
    """
    n = len(raw)
    j = start_idx
    while j < n:
        if raw[j] in (" ", "\t"):
            j += 1
        elif raw[j : j + 2] == "\\\n":
            j += 2
        else:
            break

    delim_chars: List[str] = []
    quoted = False
    in_single = False
    in_ansi = False
    in_double = False

    while j < n:
        c = raw[j]
        if in_single:
            if c == "'":
                in_single = False
            else:
                delim_chars.append(c)
            j += 1
        elif in_ansi:
            if c == "\\" and j + 1 < n:
                delim_chars.append(raw[j + 1])
                j += 2
            elif c == "'":
                in_ansi = False
                j += 1
            else:
                delim_chars.append(c)
                j += 1
        elif in_double:
            if c == '"':
                in_double = False
                j += 1
            elif c == "\\" and j + 1 < n:
                if raw[j + 1] == "\n":
                    j += 2
                elif raw[j + 1] in ('"', "\\", "$", "`"):
                    delim_chars.append(raw[j + 1])
                    j += 2
                else:
                    delim_chars.append(c)
                    delim_chars.append(raw[j + 1])
                    j += 2
            else:
                delim_chars.append(c)
                j += 1
        else:
            if c in (" ", "\t", "\n", ";", "&", "|", "<", ">", "(", ")"):
                break
            if c == "$" and j + 1 < n and raw[j + 1] == "'":
                quoted = True
                in_ansi = True
                j += 2
            elif c == "$" and j + 1 < n and raw[j + 1] == '"':
                quoted = True
                in_double = True
                j += 2
            elif c == "'":
                quoted = True
                in_single = True
                j += 1
            elif c == '"':
                quoted = True
                in_double = True
                j += 1
            elif c == "\\" and j + 1 < n:
                if raw[j + 1] == "\n":
                    j += 2
                else:
                    quoted = True
                    delim_chars.append(raw[j + 1])
                    j += 2
            else:
                delim_chars.append(c)
                j += 1

    if in_single or in_ansi or in_double:
        raise ValueError("No closing quotation in heredoc delimiter")
    delim = "".join(delim_chars)
    if not delim and not quoted:
        raise ValueError("Missing heredoc delimiter after '<<'")
    return delim, quoted, j


def _consume_heredocs(raw: str, start_idx: int, specs: Sequence[_HeredocSpec]) -> int:
    """Consume heredoc body lines starting right after `\n` for each queued `_HeredocSpec`."""
    pos = start_idx
    n = len(raw)
    for spec in specs:
        body_start = pos
        matched = False
        while pos <= n:
            if pos == n:
                break
            nl = raw.find("\n", pos)
            if nl == -1:
                line = raw[pos:n]
                next_pos = n
            else:
                line = raw[pos:nl]
                next_pos = nl + 1
            check_line = line.lstrip("\t") if spec.strip_tabs else line
            if check_line == spec.delimiter:
                spec.body = raw[body_start:pos]
                pos = next_pos
                matched = True
                break
            if nl == -1:
                break
            pos = next_pos
        if not matched:
            raise ValueError(
                f"Unclosed heredoc (missing closing delimiter {spec.delimiter!r})"
            )
    return pos


def _extract_balanced_parens(text: str, start_idx: int) -> Tuple[str, int]:
    """Given `start_idx` right after `$(`, return `(inner_cmd, next_idx_after_closing_paren)`."""
    depth = 1
    i = start_idx
    in_single = False
    in_ansi = False
    in_double = False
    pending_heredocs: List[_HeredocSpec] = []
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_ansi:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_ansi = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue

        # Unquoted context inside `$(...)`
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "'":
            in_ansi = True
            i += 2
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch == "#" and (i == start_idx or text[i - 1] in _WORD_BOUNDARY_PREDECESSORS):
            nl = text.find("\n", i + 1)
            i = n if nl == -1 else nl
            continue
        if (
            ch == "<"
            and i + 1 < n
            and text[i + 1] == "<"
            and (i + 2 >= n or text[i + 2] != "<")
        ):
            strip_tabs = i + 2 < n and text[i + 2] == "-"
            delim_start = i + (3 if strip_tabs else 2)
            delim, quoted, next_j = _parse_heredoc_delimiter(text, delim_start)
            pending_heredocs.append(
                _HeredocSpec(delimiter=delim, quoted=quoted, strip_tabs=strip_tabs)
            )
            i = next_j
            continue
        if ch == "\n" and pending_heredocs:
            i = _consume_heredocs(text, i + 1, pending_heredocs)
            pending_heredocs.clear()
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                if pending_heredocs:
                    raise ValueError(
                        f"Unclosed heredoc inside '$(' (missing delimiter {pending_heredocs[0].delimiter!r})"
                    )
                return text[start_idx:i], i + 1
        i += 1
    raise ValueError("Unbalanced command substitution '$('")


def _extract_backtick_substitution(text: str, start_idx: int) -> Tuple[str, int]:
    """Given `start_idx` right after opening `` ` ``, return `(inner_cmd, next_idx_after_closing_bt)`."""
    j = start_idx
    n = len(text)
    bt_buf: List[str] = []
    while j < n:
        ch = text[j]
        if ch == "\\" and j + 1 < n and text[j + 1] in ("\\", "`", "$", "\n"):
            if text[j + 1] != "\n":
                bt_buf.append(text[j + 1])
            j += 2
            continue
        if ch == "`":
            return "".join(bt_buf), j + 1
        bt_buf.append(ch)
        j += 1
    raise ValueError("Unclosed backtick command substitution")


def _extract_unquoted_heredoc_substitutions(body: str) -> List[str]:
    """Extract `$(...)` and `` `...` `` command substitutions inside an unquoted POSIX heredoc body.

    Per POSIX §2.7.4, single and double quotes are NOT special inside an unquoted heredoc body;
    only backslash escapes `$`, `` ` ``, `\\`, and newline.
    """
    subs: List[str] = []
    k = 0
    m = len(body)
    while k < m:
        ch = body[k]
        if ch == "\\" and k + 1 < m:
            k += 2
            continue
        if ch == "$" and k + 1 < m and body[k + 1] == "(":
            if k + 2 < m and body[k + 2] == "(":
                k += 3
                continue
            inner, next_k = _extract_balanced_parens(body, k + 2)
            subs.append(inner)
            k = next_k
            continue
        if ch == "`":
            inner_bt, next_k = _extract_backtick_substitution(body, k + 1)
            subs.append(inner_bt)
            k = next_k
            continue
        k += 1
    return subs


def _strip_trailing_io_number(buf: List[str]) -> None:
    """Strip an optional POSIX `IO_NUMBER` (e.g. `0` in `0<<'PY'`) immediately preceding `<<`."""
    idx = len(buf) - 1
    while idx >= 0 and buf[idx].isdigit():
        idx -= 1
    if idx == len(buf) - 1:
        return
    if idx < 0 or buf[idx] in _WORD_BOUNDARY_PREDECESSORS:
        del buf[idx + 1 :]


def _parse_shell_structure(raw: str) -> Tuple[List[_ParsedSegment], List[str], bool]:
    """Quote-, heredoc-, comment-, and escape-aware POSIX/Bash command structure parser."""
    parsed_segments: List[_ParsedSegment] = []
    substitutions: List[str] = []
    has_shell_syntax = False
    buf: List[str] = []
    current_seg_heredocs: List[_HeredocSpec] = []
    pending_line_heredocs: List[_HeredocSpec] = []

    def _flush_segment() -> None:
        seg = "".join(buf).strip()
        if seg or current_seg_heredocs:
            parsed_segments.append(
                _ParsedSegment(command=seg or "true", heredocs=list(current_seg_heredocs))
            )
        buf.clear()
        current_seg_heredocs.clear()

    in_single = False
    in_double = False
    paren_depth = 0
    i = 0
    n = len(raw)

    while i < n:
        ch = raw[i]

        if in_single:
            buf.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            if raw[i + 1] == "\n":
                # POSIX line continuation (`\\\n`): fold away completely
                has_shell_syntax = True
                i += 2
                continue
            buf.append(ch)
            buf.append(raw[i + 1])
            i += 2
            continue

        if in_double:
            if ch == '"':
                in_double = False
                buf.append(ch)
                i += 1
                continue
            if ch == "$" and i + 1 < n and raw[i + 1] == "(":
                has_shell_syntax = True
                if i + 2 < n and raw[i + 2] == "(":
                    buf.append("$((")
                    i += 3
                    continue
                inner, next_i = _extract_balanced_parens(raw, i + 2)
                substitutions.append(inner)
                buf.append(raw[i:next_i] if paren_depth > 0 else "__CMD_SUB__")
                i = next_i
                continue
            if ch == "`":
                has_shell_syntax = True
                inner_bt, next_i = _extract_backtick_substitution(raw, i + 1)
                substitutions.append(inner_bt)
                buf.append(raw[i:next_i] if paren_depth > 0 else "__CMD_SUB__")
                i = next_i
                continue
            buf.append(ch)
            i += 1
            continue

        # Unquoted context
        if ch == "$" and i + 1 < n and raw[i + 1] == "'":
            # Bash ANSI-C quoting `$'...'`
            has_shell_syntax = True
            j = i + 2
            ansi_closed = False
            while j < n:
                if raw[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if raw[j] == "'":
                    ansi_closed = True
                    break
                j += 1
            if not ansi_closed:
                raise ValueError("No closing quotation in ANSI-C string ($'...')")
            if paren_depth > 0:
                buf.append(raw[i : j + 1])
            else:
                decoded = _decode_ansi_c_string(raw[i + 2 : j])
                buf.append(shlex.quote(decoded))
            i = j + 1
            continue

        if ch == "'":
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            buf.append(ch)
            i += 1
            continue

        # POSIX `#` comment at token boundary: skip up to (but not including) `\n`
        if ch == "#" and (i == 0 or raw[i - 1] in _WORD_BOUNDARY_PREDECESSORS):
            has_shell_syntax = True
            nl = raw.find("\n", i + 1)
            i = n if nl == -1 else nl
            continue

        if ch == "$" and i + 1 < n and raw[i + 1] == "(":
            has_shell_syntax = True
            if i + 2 < n and raw[i + 2] == "(":
                buf.append("$((")
                i += 3
                continue
            inner, next_i = _extract_balanced_parens(raw, i + 2)
            substitutions.append(inner)
            buf.append(raw[i:next_i] if paren_depth > 0 else "__CMD_SUB__")
            i = next_i
            continue

        if ch == "`":
            has_shell_syntax = True
            inner_bt, next_i = _extract_backtick_substitution(raw, i + 1)
            substitutions.append(inner_bt)
            buf.append(raw[i:next_i] if paren_depth > 0 else "__CMD_SUB__")
            i = next_i
            continue

        # POSIX / Bash Here-Document (`<<` or `<<-`, excluding `<<<` here-string)
        if (
            ch == "<"
            and i + 1 < n
            and raw[i + 1] == "<"
            and (i + 2 >= n or raw[i + 2] != "<")
        ):
            has_shell_syntax = True
            strip_tabs = i + 2 < n and raw[i + 2] == "-"
            delim_start = i + (3 if strip_tabs else 2)
            delim, quoted, next_j = _parse_heredoc_delimiter(raw, delim_start)
            hspec = _HeredocSpec(delimiter=delim, quoted=quoted, strip_tabs=strip_tabs)
            pending_line_heredocs.append(hspec)
            if paren_depth > 0:
                buf.append(raw[i:next_j])
            else:
                _strip_trailing_io_number(buf)
                buf.append(" ")
                current_seg_heredocs.append(hspec)
            i = next_j
            continue

        if ch == "(":
            has_shell_syntax = True
            paren_depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            has_shell_syntax = True
            if paren_depth > 0:
                paren_depth -= 1
            buf.append(ch)
            i += 1
            continue

        if paren_depth > 0 and ch == "\n" and pending_line_heredocs:
            next_pos = _consume_heredocs(raw, i + 1, pending_line_heredocs)
            for hspec in pending_line_heredocs:
                if not hspec.quoted:
                    substitutions.extend(_extract_unquoted_heredoc_substitutions(hspec.body))
            pending_line_heredocs.clear()
            buf.append(raw[i:next_pos])
            i = next_pos
            continue

        if paren_depth == 0:
            # Two-char operators: &&, ||, |&
            two = raw[i : i + 2]
            if two in ("&&", "||", "|&"):
                has_shell_syntax = True
                _flush_segment()
                i += 2
                continue

            # Redirections `&>` or `>&` should NOT split segments
            if two == "&>":
                has_shell_syntax = True
                buf.append(two)
                i += 2
                continue

            if ch in (";", "\n", "|"):
                has_shell_syntax = True
                _flush_segment()
                if ch == "\n" and pending_line_heredocs:
                    next_pos = _consume_heredocs(raw, i + 1, pending_line_heredocs)
                    for hspec in pending_line_heredocs:
                        if not hspec.quoted:
                            substitutions.extend(
                                _extract_unquoted_heredoc_substitutions(hspec.body)
                            )
                    pending_line_heredocs.clear()
                    i = next_pos
                else:
                    i += 1
                continue

            if ch == "&":
                prev_ch = raw[i - 1] if i > 0 else ""
                if prev_ch in (">", "<"):
                    has_shell_syntax = True
                    buf.append(ch)
                    i += 1
                    continue
                has_shell_syntax = True
                _flush_segment()
                i += 1
                continue

            if ch in (">", "<"):
                has_shell_syntax = True

        buf.append(ch)
        i += 1

    if in_single or in_double:
        raise ValueError("No closing quotation in command string")
    if paren_depth != 0:
        raise ValueError("Unbalanced parentheses in command string")
    if pending_line_heredocs:
        raise ValueError(
            f"Unclosed heredoc (missing closing delimiter {pending_line_heredocs[0].delimiter!r})"
        )

    _flush_segment()
    return parsed_segments, substitutions, has_shell_syntax


def split_shell_commands(raw: str) -> Tuple[List[str], List[str], bool]:
    """Quote-, heredoc-, comment-, and escape-aware shell splitter.

    Returns `(segments, command_substitutions, has_shell_syntax)` without falsely splitting
    on `;`, `|`, or heredoc body lines.
    """
    parsed_segments, substitutions, has_shell_syntax = _parse_shell_structure(raw)
    return [seg.command for seg in parsed_segments], substitutions, has_shell_syntax


class CommandPolicy:
    """Enforces command allowlists, blocklists, protected paths, and workspace boundaries."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self._blocked_regexes = [
            re.compile(pat, re.IGNORECASE) for pat in config.blocked_patterns
        ]
        self._allowed_basenames = {
            os.path.basename(cmd) for cmd in config.allowed_commands
        }
        self._allowed_fullpaths = {
            cmd for cmd in config.allowed_commands if "/" in cmd
        }
        self._blocked_basenames = {
            os.path.basename(cmd) for cmd in config.blocked_commands
        }
        self._allowed_roots = [
            str(Path(r).expanduser().resolve()) for r in config.allowed_workdirs
        ]
        self._protected_roots = [
            str(Path(p).expanduser().resolve()) for p in config.protected_paths
        ]

    def is_protected_path(self, resolved_path: str) -> bool:
        for prot in self._protected_roots:
            if resolved_path == prot or resolved_path.startswith(prot + os.sep):
                return True
        return False

    def is_within_allowed_workdirs(self, resolved_path: str) -> bool:
        if not self._allowed_roots:
            return True
        for root in self._allowed_roots:
            if resolved_path == root or resolved_path.startswith(root + os.sep):
                return True
        return False

    def validate_path(
        self, target: str, base_cwd: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """Validate a filesystem path (for `/v1/files` or `cwd`) against allowed & protected roots."""
        try:
            raw_p = Path(target).expanduser()
            if not raw_p.is_absolute():
                anchor = Path(base_cwd or self.config.default_workdir).expanduser().resolve()
                raw_p = anchor / raw_p
            lexical_abs = os.path.abspath(str(raw_p))
            resolved = str(raw_p.resolve())
        except Exception as exc:
            return False, f"Invalid path '{target}': {exc}", ""

        if self.is_protected_path(lexical_abs) or self.is_protected_path(resolved):
            return False, f"Access to protected path '{target}' is forbidden by security policy", resolved

        if not self.is_within_allowed_workdirs(lexical_abs) or not self.is_within_allowed_workdirs(resolved):
            return (
                False,
                f"Path '{resolved}' is outside allowed roots {self.config.allowed_workdirs}",
                resolved,
            )
        return True, "", resolved

    def validate_workdir(self, cwd: Optional[str]) -> Tuple[bool, str, str]:
        target = cwd or self.config.default_workdir
        ok, err, resolved = self.validate_path(target)
        if not ok:
            return False, err.replace("Path ", "Working directory "), resolved
        return True, "", resolved

    def _check_single_executable(self, exe: str, resolved_cwd: str) -> Tuple[bool, str]:
        base = os.path.basename(exe)
        if base in self._blocked_basenames or exe in self.config.blocked_commands:
            return False, f"Command '{exe}' is explicitly blocked by security policy"

        # If path-qualified executable (e.g. ./scripts/build.sh, .venv/bin/pytest, /usr/bin/git)
        if "/" in exe:
            cand = Path(exe).expanduser()
            if not cand.is_absolute():
                cand = Path(resolved_cwd) / cand
            lex_abs = os.path.abspath(str(cand))

            try:
                real_str = str(cand.resolve())
                real_base = os.path.basename(real_str)
            except Exception:
                real_str = lex_abs
                real_base = base

            if real_base in self._blocked_basenames or real_str in self.config.blocked_commands:
                return False, f"Executable '{exe}' resolves to blocked binary '{real_base}'"

            if exe in self._allowed_fullpaths or real_str in self._allowed_fullpaths:
                return True, ""

            if self.is_protected_path(lex_abs) or self.is_protected_path(real_str):
                return False, f"Executable '{exe}' resides in a protected path"

            # Workspace-local script, compiled binary, or virtualenv entrypoint
            if self.is_within_allowed_workdirs(lex_abs):
                if not cand.exists() and not cand.is_symlink():
                    # Newly compiled binary in chained command (e.g. `gcc a.c -o ./app && ./app`)
                    return True, ""
                if self.is_within_allowed_workdirs(real_str):
                    return True, ""
                # Virtualenv interpreter symlink (e.g. `.venv/bin/python` -> `/usr/bin/python3.11`)
                if real_base in self._allowed_basenames or _VERSIONED_TOOL_RE.match(real_base):
                    return True, ""

        if self.config.enforce_allowlist:
            if (
                base not in self._allowed_basenames
                and exe not in self._allowed_fullpaths
                and not _VERSIONED_TOOL_RE.match(base)
            ):
                return (
                    False,
                    f"Command '{exe}' is not in the gateway allowed_commands list",
                )
        return True, ""

    def _check_dangerous_rm(self, tokens: Sequence[str]) -> Tuple[bool, str]:
        """Prevent catastrophic 'rm' targets such as '/', '/*', '/home', '/etc', etc."""
        if not tokens:
            return True, ""
        base = os.path.basename(tokens[0])
        if base != "rm":
            return True, ""

        critical_paths = {
            "/",
            "/*",
            "/home",
            str(Path.home()),
            "/etc",
            "/usr",
            "/var",
            "/boot",
            "/root",
            "~",
        }
        for tok in tokens[1:]:
            if tok == "--no-preserve-root":
                return False, "rm '--no-preserve-root' is forbidden"
            if tok.startswith("-"):
                continue
            cleaned = tok.rstrip("/") or "/"
            if tok in critical_paths or cleaned in critical_paths:
                return False, f"Refusing to run 'rm' on critical path '{tok}'"
        return True, ""

    def _check_protected_arguments(
        self,
        tokens: Sequence[str],
        resolved_cwd: str,
        _trusted_agy_argv: bool = False,
    ) -> Tuple[bool, str]:
        """Block CLI arguments targeting protected paths or escaping allowed_workdirs."""
        tok_list = list(tokens)
        for idx, tok in enumerate(tok_list[1:], start=1):
            if _trusted_agy_argv and tok.startswith("--settings={"):
                continue
            if (
                tok
                in (
                    "--no-sandbox",
                    "--sandbox=false",
                    "--sandbox=0",
                    "--sandbox=danger-full-access",
                    "-s=danger-full-access",
                    "--dangerously-bypass-approvals-and-sandbox",
                    "--dangerously-bypass-hook-trust",
                    "--remote-control",
                )
                or tok.startswith(("--settings=", "--remote-control="))
                or tok == "--settings"
            ):
                return False, f"Flag '{tok}' is forbidden in command execution"
            if tok in ("-s", "--sandbox") and idx + 1 < len(tok_list):
                if tok_list[idx + 1] == "danger-full-access":
                    return False, "Sandbox mode 'danger-full-access' is forbidden in command execution"
            if tok in ("-c", "--config") and idx + 1 < len(tok_list):
                if "danger-full-access" in tok_list[idx + 1].lower():
                    return False, "Sandbox mode 'danger-full-access' is forbidden in command execution"
            if idx > 1 and tok_list[idx - 1] in ("-c", "--config") and tok.startswith(
                "sandbox_workspace_write."
            ):
                continue
            if tok == "--add-dir":
                if idx + 1 >= len(tok_list):
                    return False, "Missing directory path after '--add-dir'"
                ok_ad, err_ad, _ = self.validate_workdir(tok_list[idx + 1])
                if not ok_ad:
                    return False, err_ad
                continue
            if tok.startswith("--add-dir="):
                ok_ad, err_ad, _ = self.validate_workdir(tok.split("=", 1)[1])
                if not ok_ad:
                    return False, err_ad
                continue
            candidates = [tok]
            m_redir = _REDIR_PREFIX_RE.match(tok)
            if m_redir:
                candidates.append(m_redir.group(1))
            if tok.startswith("-") and "=" in tok:
                candidates = [tok.split("=", 1)[1]]
            elif tok.startswith("-"):
                continue

            for val in candidates:
                if not val or "://" in val or val.startswith("git@"):
                    continue
                looks_like_path = (
                    "/" in val
                    or val.startswith("~")
                    or val in ("..", ".")
                    or any(
                        marker in val
                        for marker in (
                            "config.json",
                            "client.json",
                            "/certs",
                            ".ssh",
                            ".gnupg",
                            ".gemini",
                            ".codex",
                            ".config",
                            ".bashrc",
                            ".profile",
                        )
                    )
                )
                if not looks_like_path:
                    continue
                try:
                    p = Path(val).expanduser()
                    if not p.is_absolute():
                        p = Path(resolved_cwd) / p
                    lex = os.path.abspath(str(p))
                    res = str(p.resolve())
                except Exception:
                    continue

                if self.is_protected_path(lex) or self.is_protected_path(res):
                    return (
                        False,
                        f"Argument '{val}' targets a protected gateway/credential path",
                    )

                # Block home-directory, /root, or parent-traversal ('..') escapes outside allowed_workdirs
                is_escape_target = (
                    val == "~"
                    or val.startswith("~/")
                    or val.startswith("/home/")
                    or val == "/home"
                    or val.startswith("/root")
                    or val == ".."
                    or val.startswith("../")
                    or "/../" in val
                    or val.endswith("/..")
                )
                real_base = os.path.basename(res)
                is_allowed_toolchain_symlink = (
                    self.is_within_allowed_workdirs(lex)
                    and res.startswith(
                        (
                            "/usr/",
                            "/bin/",
                            "/opt/uv-python/",
                            "/opt/uv-tools/",
                            "/opt/flutter/",
                            "/opt/codex/",
                            "/opt/devtools/",
                        )
                    )
                    and (
                        real_base in self._allowed_basenames
                        or bool(_VERSIONED_TOOL_RE.match(real_base))
                    )
                )
                if (
                    is_escape_target
                    and not is_allowed_toolchain_symlink
                    and (
                        not self.is_within_allowed_workdirs(lex)
                        or not self.is_within_allowed_workdirs(res)
                    )
                ):
                    return (
                        False,
                        f"Argument '{val}' resolves outside allowed workspace roots {self.config.allowed_workdirs}",
                    )
        return True, ""

    def validate_command(
        self,
        command: Union[str, Sequence[str]],
        cwd: Optional[str] = None,
        _depth: int = 0,
        _trusted_agy_argv: bool = False,
    ) -> PolicyDecision:
        if _depth > 8:
            return PolicyDecision(False, reason="Excessive nested subshell depth")

        ok_cwd, cwd_err, resolved_cwd = self.validate_workdir(cwd)
        if not ok_cwd:
            return PolicyDecision(False, reason=cwd_err, resolved_cwd=resolved_cwd)

        requires_shell = False
        if isinstance(command, str):
            if not command or not command.strip():
                return PolicyDecision(False, reason="Empty command string")
            raw_str = command
            try:
                parsed_segments, substitutions, has_shell_syntax = _parse_shell_structure(raw_str)
            except ValueError as exc:
                return PolicyDecision(
                    False, reason=f"Malformed command syntax: {exc}", resolved_cwd=resolved_cwd
                )
            requires_shell = has_shell_syntax
            if requires_shell:
                argv = ["/bin/bash", "-c", raw_str]
            else:
                try:
                    argv = shlex.split(raw_str)
                except ValueError as exc:
                    return PolicyDecision(
                        False, reason=f"Malformed command syntax: {exc}", resolved_cwd=resolved_cwd
                    )
        elif isinstance(command, (list, tuple)):
            argv = [str(x) for x in command]
            if not argv:
                return PolicyDecision(False, reason="Empty command argv")
            raw_str = " ".join(shlex.quote(x) for x in argv)
            parsed_segments = [_ParsedSegment(command=raw_str, heredocs=[])]
            substitutions = []
        else:
            return PolicyDecision(False, reason="Command must be a string or list of strings")

        # Check blocked regex patterns against raw command string
        for rx in self._blocked_regexes:
            if rx.search(raw_str):
                return PolicyDecision(
                    False,
                    reason=f"Command matched blocked high-risk pattern: {rx.pattern}",
                    resolved_cwd=resolved_cwd,
                )

        # Recursively validate any `$(...)` or backtick command substitutions
        for sub_cmd in substitutions:
            if sub_cmd.strip():
                sub_dec = self.validate_command(sub_cmd, cwd=resolved_cwd, _depth=_depth + 1)
                if not sub_dec.allowed:
                    return sub_dec

        for pseg in parsed_segments:
            seg = pseg.command.strip()
            if not seg:
                continue

            # Unwrap outer subshell parentheses `(cd dir && make)`
            if seg.startswith("(") and seg.endswith(")"):
                inner_grp = seg[1:-1]
                if inner_grp.strip():
                    grp_dec = self.validate_command(inner_grp, cwd=resolved_cwd, _depth=_depth + 1)
                    if not grp_dec.allowed:
                        return grp_dec
                continue

            try:
                seg_tokens = shlex.split(seg)
            except ValueError:
                seg_tokens = seg.split()

            idx = 0
            # Strip leading POSIX shell control-flow keywords (`if`, `then`, `else`, `while`, `do`, `!`, `{`)
            while idx < len(seg_tokens) and seg_tokens[idx] in _SHELL_PREFIX_KEYWORDS:
                requires_shell = True
                idx += 1

            # Standalone closing keywords (`fi`, `done`, `}`), optionally with redirections
            if idx < len(seg_tokens) and seg_tokens[idx] in _SHELL_CLOSE_KEYWORDS:
                requires_shell = True
                if idx + 1 < len(seg_tokens):
                    ok_prot, prot_err = self._check_protected_arguments(
                        ["true"] + seg_tokens[idx + 1 :],
                        resolved_cwd,
                        _trusted_agy_argv=False,
                    )
                    if not ok_prot:
                        return PolicyDecision(False, reason=prot_err, resolved_cwd=resolved_cwd)
                continue

            # `for <var> [in <words...>]` header segment
            if idx < len(seg_tokens) and seg_tokens[idx] == "for":
                requires_shell = True
                if idx + 1 >= len(seg_tokens) or not _FOR_VAR_RE.match(seg_tokens[idx + 1]):
                    return PolicyDecision(
                        False,
                        reason="Malformed 'for' loop variable in shell command",
                        resolved_cwd=resolved_cwd,
                    )
                if idx + 2 < len(seg_tokens):
                    ok_prot, prot_err = self._check_protected_arguments(
                        ["for"] + seg_tokens[idx + 2 :],
                        resolved_cwd,
                        _trusted_agy_argv=False,
                    )
                    if not ok_prot:
                        return PolicyDecision(False, reason=prot_err, resolved_cwd=resolved_cwd)
                continue

            while idx < len(seg_tokens) and _ENV_ASSIGN_RE.match(seg_tokens[idx]):
                requires_shell = True
                idx += 1
            if idx >= len(seg_tokens):
                continue

            exe = seg_tokens[idx]
            if exe in _SHELL_BUILTINS:
                requires_shell = True

            ok_exe, exe_err = self._check_single_executable(exe, resolved_cwd)
            if not ok_exe:
                return PolicyDecision(False, reason=exe_err, resolved_cwd=resolved_cwd)

            ok_rm, rm_err = self._check_dangerous_rm(seg_tokens[idx:])
            if not ok_rm:
                return PolicyDecision(False, reason=rm_err, resolved_cwd=resolved_cwd)

            ok_prot, prot_err = self._check_protected_arguments(
                seg_tokens[idx:],
                resolved_cwd,
                _trusted_agy_argv=(_trusted_agy_argv and _depth == 0),
            )
            if not ok_prot:
                return PolicyDecision(False, reason=prot_err, resolved_cwd=resolved_cwd)

            # Unwrap `env` command wrapper (`env FOO=1 cmd ...`) so wrapped executable is validated
            effective_idx = idx
            if os.path.basename(exe) == "env" and idx + 1 < len(seg_tokens):
                e_idx = idx + 1
                while e_idx < len(seg_tokens):
                    etok = seg_tokens[e_idx]
                    if etok == "--":
                        e_idx += 1
                        break
                    if etok in ("-u", "--unset") and e_idx + 1 < len(seg_tokens):
                        e_idx += 2
                        continue
                    if etok in ("-C", "--chdir", "-S", "--split-string"):
                        if etok in ("-S", "--split-string"):
                            return PolicyDecision(
                                False,
                                reason=f"Flag '{etok}' on 'env' is forbidden by security policy",
                                resolved_cwd=resolved_cwd,
                            )
                        if e_idx + 1 >= len(seg_tokens):
                            return PolicyDecision(
                                False,
                                reason=f"Missing directory after 'env {etok}'",
                                resolved_cwd=resolved_cwd,
                            )
                        ok_cd, err_cd, _ = self.validate_workdir(seg_tokens[e_idx + 1])
                        if not ok_cd:
                            return PolicyDecision(False, reason=err_cd, resolved_cwd=resolved_cwd)
                        e_idx += 2
                        continue
                    if etok.startswith(("--chdir=", "--split-string=")):
                        if etok.startswith("--split-string="):
                            return PolicyDecision(
                                False,
                                reason="Flag '--split-string' on 'env' is forbidden by security policy",
                                resolved_cwd=resolved_cwd,
                            )
                        ok_cd, err_cd, _ = self.validate_workdir(etok.split("=", 1)[1])
                        if not ok_cd:
                            return PolicyDecision(False, reason=err_cd, resolved_cwd=resolved_cwd)
                        e_idx += 1
                        continue
                    if etok.startswith("-"):
                        e_idx += 1
                        continue
                    if _ENV_ASSIGN_RE.match(etok):
                        e_idx += 1
                        continue
                    break
                if e_idx < len(seg_tokens):
                    effective_idx = e_idx
                    sub_exe = seg_tokens[effective_idx]
                    ok_sub_exe, sub_exe_err = self._check_single_executable(sub_exe, resolved_cwd)
                    if not ok_sub_exe:
                        return PolicyDecision(False, reason=sub_exe_err, resolved_cwd=resolved_cwd)
                    ok_sub_rm, sub_rm_err = self._check_dangerous_rm(seg_tokens[effective_idx:])
                    if not ok_sub_rm:
                        return PolicyDecision(False, reason=sub_rm_err, resolved_cwd=resolved_cwd)

            # If invoking subshell `bash`/`sh` via `-c`/`-lc` or via heredoc (`bash <<'EOF'`), validate inner script
            effective_exe = seg_tokens[effective_idx]
            if os.path.basename(effective_exe) in ("bash", "sh"):
                b_idx = effective_idx + 1
                while b_idx < len(seg_tokens):
                    btok = seg_tokens[b_idx]
                    if btok == "--":
                        break
                    if btok in ("-o", "+o", "-O", "+O"):
                        b_idx += 2
                        continue
                    if btok.startswith("-") and not btok.startswith("--") and "c" in btok[1:]:
                        if b_idx + 1 < len(seg_tokens):
                            inner_cmd = seg_tokens[b_idx + 1]
                            inner_decision = self.validate_command(
                                inner_cmd, cwd=resolved_cwd, _depth=_depth + 1
                            )
                            if not inner_decision.allowed:
                                return inner_decision
                        break
                    if btok.startswith(("-", "+")):
                        b_idx += 1
                        continue
                    break

                for hspec in pseg.heredocs:
                    if hspec.body.strip():
                        hd_decision = self.validate_command(
                            hspec.body, cwd=resolved_cwd, _depth=_depth + 1
                        )
                        if not hd_decision.allowed:
                            return hd_decision

        # Resolve 'agy' / 'codex' binary paths automatically if the first token is 'agy' or 'codex'
        if argv and argv[0] == "agy" and os.path.exists(self.config.agy_binary):
            argv = [self.config.agy_binary] + argv[1:]
        elif argv and argv[0] == "codex" and os.path.exists(self.config.codex_binary):
            argv = [self.config.codex_binary] + argv[1:]

        return PolicyDecision(
            allowed=True,
            reason="ok",
            normalized_argv=argv,
            resolved_cwd=resolved_cwd,
            requires_shell=requires_shell,
        )

    def build_agy_argv(
        self,
        prompt: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: Optional[bool] = None,
        sandbox: Optional[bool] = None,
        print_mode: bool = True,
        output_format: Optional[str] = None,
        input_format: Optional[str] = None,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        mode: Optional[str] = None,
        conversation_id: Optional[str] = None,
        continue_last: bool = False,
        add_dirs: Optional[Sequence[str]] = None,
        cwd: Optional[str] = None,
    ) -> List[str]:
        """Construct a validated `agy` CLI invocation list confined to allowed_workdirs."""
        agy_bin = (
            self.config.agy_binary
            if os.path.exists(self.config.agy_binary)
            else "agy"
        )
        argv: List[str] = [agy_bin]

        use_skip = (
            self.config.agy_default_skip_permissions
            if skip_permissions is None
            else skip_permissions
        )
        use_sandbox = (
            self.config.agy_default_sandbox if sandbox is None else bool(sandbox)
        )
        extra = [str(a) for a in (args or [])]

        for raw_arg in extra:
            if raw_arg == "--add-dir" or raw_arg.startswith("--add-dir="):
                raise PermissionError(
                    "Raw '--add-dir' in args is forbidden; pass 'add_dirs' for workspace validation"
                )
            if raw_arg == "--settings" or raw_arg.startswith("--settings="):
                raise PermissionError(
                    "Raw '--settings' override in args is forbidden by gateway security policy"
                )
            if raw_arg == "--remote-control" or raw_arg.startswith("--remote-control="):
                raise PermissionError(
                    "Raw '--remote-control' flag in args is forbidden by gateway security policy"
                )
            if raw_arg in ("--no-sandbox", "--sandbox=false", "--sandbox=0"):
                raise PermissionError(
                    "Disabling '--sandbox' via raw args is forbidden by gateway security policy"
                )

        if use_skip and "--dangerously-skip-permissions" not in extra:
            argv.append("--dangerously-skip-permissions")
        if use_sandbox:
            if "--sandbox" not in extra:
                argv.append("--sandbox")
            agy_settings = self.build_agy_sandbox_settings(cwd=cwd, add_dirs=add_dirs)
            argv.append(f"--settings={json.dumps(agy_settings, separators=(',', ':'))}")

        if model and "--model" not in extra:
            argv.extend(["--model", model])
        if effort and "--effort" not in extra:
            argv.extend(["--effort", effort])
        if mode and "--mode" not in extra:
            argv.extend(["--mode", mode])
        if conversation_id and "--conversation" not in extra:
            argv.extend(["--conversation", conversation_id])
        elif continue_last and "--continue" not in extra and "-c" not in extra:
            argv.append("--continue")

        if add_dirs:
            for d in add_dirs:
                ok_dir, dir_err, resolved_dir = self.validate_workdir(str(d))
                if not ok_dir:
                    raise PermissionError(dir_err)
                argv.extend(["--add-dir", resolved_dir])

        if input_format and "--input-format" not in extra:
            argv.extend(["--input-format", input_format])
        if output_format and "--output-format" not in extra:
            argv.extend(["--output-format", output_format])

        argv.extend(extra)

        has_print_flag = any(
            a in ("--print", "-p", "--prompt", "--prompt-interactive", "-i")
            or a.startswith("--print=")
            or a.startswith("-p=")
            or a.startswith("--prompt=")
            for a in argv
        )

        if prompt is not None:
            if print_mode and not has_print_flag:
                argv.append(f"--print={prompt}")
            else:
                argv.append(prompt)
        elif (
            print_mode
            and input_format == "stream-json"
            and not has_print_flag
            and "--help" not in argv
            and "-h" not in argv
        ):
            argv.append("--print=")

        return argv

    def get_agy_writable_roots(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> List[str]:
        """Compute safe `write_file(...)` mount roots for `agy --sandbox`.

        Includes the validated session `cwd` explicitly (because `agy --sandbox`
        otherwise mounts an active sub-workspace read-only in default/enterprise
        mode even when a parent directory is writable), alongside all configured
        `allowed_workdirs`, `add_dirs`, Flutter SDK `bin/cache`, and isolated
        developer toolchain caches.
        """
        ok_cwd, cwd_err, resolved_cwd = self.validate_workdir(cwd)
        if not ok_cwd:
            raise PermissionError(cwd_err)

        roots: List[str] = []
        seen: set[str] = set()

        def _add(cand_path: str) -> None:
            norm = os.path.abspath(cand_path)
            if norm not in seen:
                seen.add(norm)
                roots.append(norm)

        _add(resolved_cwd)
        for root in self.get_codex_writable_roots(add_dirs=add_dirs):
            _add(root)
        return roots

    def get_agy_readonly_roots(self) -> List[str]:
        """Compute safe `read_file(...)` mount roots for `agy --sandbox`.

        `agy --sandbox` on Linux mounts standard OS system paths (`/usr`, `/etc`, etc.)
        by default, not `/opt`. Exposing read-only SDK/toolchain directories (`/opt/uv-python`,
        `/opt/uv-tools`, `/opt/devtools`, `/opt/flutter`, plus configured `agy_extra_readonly_roots`)
        via `read_file(...)` allows virtualenvs, `pytest`, `mypy`, `ruff`, Node/pnpm, Terraform,
        Trivy, and Flutter/Dart binaries to execute inside the sandbox while keeping SDK trees
        read-only.
        """
        roots: List[str] = []
        seen: set[str] = set()

        def _add_candidate(raw_cand: str) -> None:
            try:
                p = Path(str(raw_cand)).expanduser()
                lex = os.path.abspath(str(p))
                res = str(p.resolve())
            except OSError:
                return
            if self.is_protected_path(lex) or self.is_protected_path(res):
                return
            for cand in (lex, res):
                if ")" not in cand and os.path.isdir(cand) and cand not in seen:
                    seen.add(cand)
                    roots.append(cand)

        for default_ro in DEFAULT_AGY_READONLY_ROOTS:
            _add_candidate(default_ro)

        flutter_bin = shutil.which("flutter")
        if flutter_bin:
            try:
                fl_root = Path(flutter_bin).resolve().parent.parent
                _add_candidate(str(fl_root))
            except OSError:
                pass

        for raw_extra in self.config.agy_extra_readonly_roots:
            _add_candidate(raw_extra)

        return roots

    def get_agy_denied_rules(self) -> List[str]:
        """Compute `permissions.deny` rules enforced inside `agy` sessions.

        Blocks high-risk commands (`sudo`, `docker`, `shutdown`, etc.) via `command(...)`
        and blocks sensitive host/gateway paths via `read_file(...)` (which also implicitly
        denies `write_file(...)` in `agy`), while avoiding broad parent directories
        (`~/.gemini`, `~/.config`, `~/.local`) required by `agy`'s own runtime and plugins.
        """
        rules: List[str] = []
        seen: set[str] = set()

        def _emit(rule: str) -> None:
            if rule and rule not in seen:
                seen.add(rule)
                rules.append(rule)

        for raw_cmd in self.config.blocked_commands:
            cmd_str = str(raw_cmd).strip()
            if not cmd_str:
                continue
            base = os.path.basename(cmd_str)
            if (
                base
                and base not in _SHELL_PREFIX_KEYWORDS
                and base != "time"
                and ")" not in base
            ):
                _emit(f"command({base})")
            if "/" in cmd_str and ")" not in cmd_str:
                _emit(f"command({cmd_str})")

        home_lex = os.path.abspath(str(Path.home()))
        try:
            home_res = str(Path.home().resolve())
        except OSError:
            home_res = home_lex
        home_variants = {home_lex, home_res}

        agy_runtime_parents = {
            os.path.join(h, sub)
            for h in home_variants
            for sub in (".gemini", ".config", ".local")
        }

        for raw_prot in self.config.protected_paths:
            try:
                p = Path(str(raw_prot)).expanduser()
                lex_abs = os.path.abspath(str(p))
                res_abs = str(p.resolve())
            except OSError:
                continue
            if lex_abs in agy_runtime_parents or res_abs in agy_runtime_parents:
                continue
            if ")" not in lex_abs:
                _emit(f"read_file({lex_abs})")
            if res_abs != lex_abs and ")" not in res_abs:
                _emit(f"read_file({res_abs})")

        for sensitive_cfg_sub in ("dots-gateway", "tunnel-client", "systemd"):
            cfg_sub_path = os.path.join(home_res, ".config", sensitive_cfg_sub)
            if ")" not in cfg_sub_path:
                _emit(f"read_file({cfg_sub_path})")

        return rules

    def build_agy_sandbox_settings(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Build per-session `--settings` JSON for `agy --sandbox`.

        Configures `toolPermission` (default: `"proceed-in-sandbox"`, enabling headless
        command execution inside `agy --sandbox` even when `skip_permissions=False`),
        grants `read_file(...)` mounts for read-only `/opt` SDK toolchains (ordered before
        `write_file(...)` so writable child caches such as `/opt/flutter/bin/cache` stay
        writable), grants `write_file(...)` mounts for validated workspace/cache roots,
        and enforces `permissions.deny` (`deny > ask > allow`) on blocked commands and
        protected paths without mutating the user's global `settings.json`.
        """
        tool_perm = str(self.config.agy_sandbox_tool_permission or "").strip()
        if tool_perm not in ("proceed-in-sandbox", "request-review", "strict"):
            raise PermissionError(
                f"Invalid or forbidden agy_sandbox_tool_permission '{tool_perm}'; "
                "allowed: 'proceed-in-sandbox', 'request-review', 'strict'"
            )

        perms: Dict[str, Any] = {}
        settings_path = Path.home() / ".gemini" / "antigravity-cli" / "settings.json"
        try:
            if settings_path.is_file():
                raw = json.loads(settings_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and isinstance(raw.get("permissions"), dict):
                    for k, v in raw["permissions"].items():
                        if isinstance(v, list):
                            perms[k] = [str(x) for x in v]
        except Exception:
            pass

        writable_roots = self.get_agy_writable_roots(cwd=cwd, add_dirs=add_dirs)
        writable_set = set(writable_roots)

        allow_list: List[str] = []
        allow_seen: set[str] = set()

        def _emit_allow(rule: str) -> None:
            if rule and rule not in allow_seen:
                allow_seen.add(rule)
                allow_list.append(rule)

        for ro_root in self.get_agy_readonly_roots():
            if ro_root not in writable_set and ")" not in ro_root:
                _emit_allow(f"read_file({ro_root})")

        for existing_rule in perms.get("allow") or []:
            _emit_allow(str(existing_rule))

        for rw_root in writable_roots:
            if ")" not in rw_root:
                _emit_allow(f"write_file({rw_root})")

        perms["allow"] = allow_list

        deny_list: List[str] = list(perms.get("deny") or [])
        deny_seen = set(deny_list)
        for rule in self.get_agy_denied_rules():
            if rule not in deny_seen:
                deny_seen.add(rule)
                deny_list.append(rule)
        perms["deny"] = deny_list

        return {
            "toolPermission": tool_perm,
            "permissions": perms,
        }

    def get_codex_writable_roots(
        self, add_dirs: Optional[Sequence[str]] = None
    ) -> List[str]:
        """Compute safe `sandbox_workspace_write.writable_roots` for Codex CLI.

        Exposes all configured `allowed_workdirs` (so git worktrees can update shared
        `.git/worktrees/*` state), Flutter SDK's `bin/cache` (for `engine.stamp`,
        `engine.realm`, and `lockfile`), and isolated developer toolchain caches mounted
        by `sandbox.py`, while keeping SDK binaries, `~/gateway`, `~/.ssh`, `~/.codex`,
        `~/.gemini`, and `~/.config/dots-gateway` read-only or hidden.
        """
        roots: List[str] = []
        seen: set[str] = set()

        def _add(cand_path: str) -> None:
            norm = os.path.abspath(cand_path)
            if norm not in seen:
                seen.add(norm)
                roots.append(norm)

        for allowed in self._allowed_roots:
            _add(allowed)

        if add_dirs:
            for d in add_dirs:
                ok_dir, dir_err, resolved_dir = self.validate_workdir(str(d))
                if not ok_dir:
                    raise PermissionError(dir_err)
                _add(resolved_dir)

        flutter_cache_candidates: List[str] = ["/opt/flutter/bin/cache"]
        flutter_bin = shutil.which("flutter")
        if flutter_bin:
            try:
                fl_root = Path(flutter_bin).resolve().parent.parent
                flutter_cache_candidates.append(str(fl_root / "bin" / "cache"))
            except OSError:
                pass
        for fc in flutter_cache_candidates:
            if os.path.isdir(fc) and not self.is_protected_path(os.path.abspath(fc)):
                _add(fc)

        home_dir = str(Path.home().resolve())
        home_already_covered = any(
            home_dir == r or home_dir.startswith(r.rstrip("/") + "/")
            for r in self._allowed_roots
        )
        if not home_already_covered:
            for rel in (
                ".pub-cache",
                os.path.join(".config", "flutter"),
                ".dart-tool",
                ".dartServer",
                ".cache",
                ".npm",
                os.path.join(".local", "share"),
                os.path.join(".config", "gh"),
            ):
                abs_cache = os.path.join(home_dir, rel)
                if self.config.isolate_mount_namespace or os.path.isdir(abs_cache):
                    _add(abs_cache)

        for raw_extra in self.config.codex_extra_writable_roots:
            try:
                p = Path(raw_extra).expanduser()
                lex = os.path.abspath(str(p))
                res = str(p.resolve())
            except OSError:
                continue
            if self.is_protected_path(lex) or self.is_protected_path(res):
                continue
            if os.path.isdir(lex):
                _add(lex)

        return roots

    def build_codex_argv(
        self,
        prompt: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: Optional[bool] = None,
        sandbox_mode: Optional[str] = None,
        json_events: bool = False,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        search: bool = False,
        session_id: Optional[str] = None,
        continue_last: bool = False,
        review: bool = False,
        skip_git_repo_check: bool = True,
        ephemeral: bool = False,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> List[str]:
        """Construct a validated non-interactive `codex exec` invocation list confined to allowed_workdirs."""
        codex_bin = (
            self.config.codex_binary
            if os.path.exists(self.config.codex_binary)
            else "codex"
        )
        argv: List[str] = [codex_bin]

        use_skip = (
            self.config.codex_default_skip_permissions
            if skip_permissions is None
            else bool(skip_permissions)
        )
        eff_sandbox = (
            self.config.codex_default_sandbox
            if sandbox_mode is None
            else str(sandbox_mode).strip()
        )
        if eff_sandbox not in ("read-only", "workspace-write"):
            raise PermissionError(
                f"Invalid or forbidden codex sandbox_mode '{eff_sandbox}'; allowed: 'workspace-write', 'read-only'"
            )

        extra = [str(a) for a in (args or [])]
        for idx, raw_arg in enumerate(extra):
            if raw_arg == "--add-dir" or raw_arg.startswith("--add-dir="):
                raise PermissionError(
                    "Raw '--add-dir' in args is forbidden; pass 'add_dirs' for workspace validation"
                )
            if raw_arg in ("-C", "--cd") or raw_arg.startswith("--cd="):
                raise PermissionError(
                    "Raw '-C'/'--cd' in args is forbidden; pass 'cwd' for workspace validation"
                )
            if raw_arg in (
                "--dangerously-bypass-approvals-and-sandbox",
                "--dangerously-bypass-hook-trust",
                "--remote-control",
            ) or raw_arg.startswith("--remote-control="):
                raise PermissionError(
                    f"Raw '{raw_arg}' flag in args is forbidden by gateway security policy"
                )
            if raw_arg in ("-s", "--sandbox") or raw_arg.startswith(("-s=", "--sandbox=")):
                raise PermissionError(
                    "Raw '-s'/'--sandbox' in args is forbidden; pass 'sandbox_mode' parameter"
                )
            if raw_arg in ("-c", "--config") and idx + 1 < len(extra):
                cfg_kv = extra[idx + 1].lower()
                if "sandbox" in cfg_kv or "approval" in cfg_kv:
                    raise PermissionError(
                        "Overriding sandbox or approval policy via '-c/--config' is forbidden"
                    )
            if raw_arg.startswith(("-c=", "--config=")):
                cfg_kv = raw_arg.split("=", 1)[1].lower()
                if "sandbox" in cfg_kv or "approval" in cfg_kv:
                    raise PermissionError(
                        "Overriding sandbox or approval policy via '-c/--config' is forbidden"
                    )

        # Top-level Codex CLI options (placed before `exec` per codex-cli 0.166+ parser)
        if use_skip:
            argv.extend(["-a", "never"])
        argv.extend(["-s", eff_sandbox])

        if eff_sandbox == "workspace-write":
            net_bool = "true" if self.config.codex_sandbox_network_access else "false"
            writable_roots = self.get_codex_writable_roots(add_dirs=add_dirs)
            argv.extend(["-c", f"sandbox_workspace_write.network_access={net_bool}"])
            argv.extend(
                [
                    "-c",
                    f"sandbox_workspace_write.writable_roots={json.dumps(writable_roots)}",
                ]
            )

        if model and "-m" not in extra and "--model" not in extra:
            argv.extend(["-m", model])
        if effort:
            mapped_effort = "xhigh" if effort == "max" else str(effort).strip()
            if mapped_effort not in ("minimal", "low", "medium", "high", "xhigh"):
                raise ValueError(
                    f"Unsupported codex effort '{effort}'; expected minimal/low/medium/high/xhigh"
                )
            argv.extend(["-c", f'model_reasoning_effort="{mapped_effort}"'])
        if search and "--search" not in extra:
            argv.append("--search")

        if add_dirs:
            for d in add_dirs:
                ok_dir, dir_err, resolved_dir = self.validate_workdir(str(d))
                if not ok_dir:
                    raise PermissionError(dir_err)
                argv.extend(["--add-dir", resolved_dir])

        # Non-interactive `exec` subcommand (+ optional `review` or `resume`)
        argv.append("exec")
        if review:
            argv.append("review")
        elif session_id or continue_last:
            argv.append("resume")
            if session_id:
                argv.append(str(session_id))
            elif continue_last:
                argv.append("--last")

        if skip_git_repo_check and "--skip-git-repo-check" not in extra:
            argv.append("--skip-git-repo-check")
        if ephemeral and "--ephemeral" not in extra:
            argv.append("--ephemeral")
        if json_events and "--json" not in extra:
            argv.append("--json")

        argv.extend(extra)

        if prompt is not None:
            if prompt.startswith("-") and "--" not in extra:
                argv.append("--")
            argv.append(prompt)

        return argv
