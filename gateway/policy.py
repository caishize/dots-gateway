"""Command, shell-syntax, and workspace path security policy enforcement."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .config import (
    DEFAULT_AGY_READONLY_ROOTS,
    DOCKER_CLI_BASENAMES,
    GATEWAY_ROOT,
    GatewayConfig,
    agy_plugins_config_state,
    codex_plugins_config_state,
    docker_access_enabled,
    effective_plugin_state_dir,
    redact_diagnostic_text,
)
from .hook_jail import (
    WORKSPACE_HOOK_INJECTION_RELPATHS,
    WORKSPACE_READONLY_PROTECTED_RELPATHS,
    _expand_host_tilde_in_agy_rule,
    validate_plugin_hooks_manifest,
)
from .sandbox import SHARED_SANDBOX_PUB_CACHE_VFS, can_use_mount_namespace


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    normalized_argv: Optional[List[str]] = None
    resolved_cwd: str = ""
    requires_shell: bool = False


@dataclass(frozen=True)
class ValidatedAgyPlugin:
    name: str
    source_dir: str
    vfs_discovery_dir: str
    manifest: str
    hooks_relpath: Optional[str] = None

    @property
    def has_hooks(self) -> bool:
        return bool(self.hooks_relpath)


@dataclass(frozen=True)
class ValidatedCodexPlugin:
    name: str
    marketplace_name: str
    version: str
    source_dir: str
    vfs_discovery_dir: str
    hooks_relpath: Optional[str]
    manifest: str

    @property
    def has_hooks(self) -> bool:
        return bool(self.hooks_relpath)


_SAFE_AGY_PLUGIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_CODEX_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_READ_FILE_RULE_RE = re.compile(r"^read_file\((.+)\)$")
_WRITE_FILE_RULE_RE = re.compile(r"^write_file\((.+)\)$")


def _path_is_within(candidate: str, root: str) -> bool:
    c = candidate.rstrip("/") or "/"
    r = root.rstrip("/") or "/"
    if r == "/":
        return True
    return c == r or c.startswith(r + "/")


def _paths_overlap_any_direction(path_a: str, path_b: str) -> bool:
    return _path_is_within(path_a, path_b) or _path_is_within(path_b, path_a)


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
    "exit",
    "return",
    ":",
    "trap",
    "command",
    "type",
}
_SUBSHELL_STANDALONE_REDIR_RE = re.compile(r"^(?:\d+|&)?(?:>>|>\||<>|>&|<&|>|<)$")
_SUBSHELL_COMBINED_REDIR_RE = re.compile(r"^(?:\d+|&)?(?:>>|>\||<>|>&|<&|>|<).+$")
_SUBSHELL_PREFIX_KEYWORDS = ("!", "if", "elif", "else", "then", "do", "while", "until")


def _is_valid_subshell_redir_tail(trailing: str) -> bool:
    if not trailing:
        return True
    try:
        toks = shlex.split(trailing)
    except ValueError:
        return False
    i = 0
    while i < len(toks):
        tok = toks[i]
        if _SUBSHELL_STANDALONE_REDIR_RE.match(tok):
            if i + 1 >= len(toks):
                return False
            i += 2
            continue
        if _SUBSHELL_COMBINED_REDIR_RE.match(tok):
            i += 1
            continue
        return False
    return True


def _unwrap_subshell_with_redirs(seg: str) -> Optional[Tuple[str, str]]:
    """Unwrap `[prefix_kw...] ( inner ) [redirs...]` into `(inner, trailing_redirs)` if valid."""
    work = seg.strip()
    while work:
        matched_kw = False
        for kw in _SUBSHELL_PREFIX_KEYWORDS:
            if work == kw:
                return None
            if work.startswith(kw) and len(work) > len(kw) and work[len(kw)].isspace():
                work = work[len(kw) :].lstrip()
                matched_kw = True
                break
        if not matched_kw:
            break
    if not work.startswith("("):
        return None
    depth = 0
    in_sq = False
    in_dq = False
    escaped = False
    close_idx = -1
    for idx, ch in enumerate(work):
        if in_sq:
            if ch == "'":
                in_sq = False
            continue
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_dq:
            if ch == '"':
                in_dq = False
            continue
        if ch == "'":
            in_sq = True
        elif ch == '"':
            in_dq = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_idx = idx
                break
    if close_idx <= 0:
        return None
    inner = work[1:close_idx]
    trailing = work[close_idx + 1 :].strip()
    if not _is_valid_subshell_redir_tail(trailing):
        return None
    return inner, trailing
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

_BWRAP_FORBIDDEN_OPTS = frozenset({"--args", "--cap-add", "--userns", "--userns2", "--pidns"})
_BWRAP_INFO_ZERO_ARG_OPTS = frozenset({"--help", "--version"})
_BWRAP_ZERO_ARG_OPTS = frozenset(
    {
        "--level-prefix",
        "--unshare-all",
        "--share-net",
        "--unshare-user",
        "--unshare-user-try",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
        "--unshare-cgroup-try",
        "--disable-userns",
        "--assert-userns-disabled",
        "--clearenv",
        "--new-session",
        "--die-with-parent",
        "--as-pid-1",
    }
)
_BWRAP_ONE_ARG_OPTS = frozenset(
    {
        "--argv0",
        "--uid",
        "--gid",
        "--hostname",
        "--chdir",
        "--unsetenv",
        "--lock-file",
        "--sync-fd",
        "--remount-ro",
        "--overlay-src",
        "--tmp-overlay",
        "--ro-overlay",
        "--exec-label",
        "--file-label",
        "--proc",
        "--dev",
        "--tmpfs",
        "--mqueue",
        "--dir",
        "--seccomp",
        "--add-seccomp-fd",
        "--block-fd",
        "--userns-block-fd",
        "--info-fd",
        "--json-status-fd",
        "--cap-drop",
        "--perms",
        "--size",
    }
)
_BWRAP_TWO_ARG_OPTS = frozenset(
    {
        "--setenv",
        "--bind",
        "--bind-try",
        "--dev-bind",
        "--dev-bind-try",
        "--ro-bind",
        "--ro-bind-try",
        "--bind-fd",
        "--ro-bind-fd",
        "--file",
        "--bind-data",
        "--ro-bind-data",
        "--symlink",
        "--chmod",
    }
)
_BWRAP_THREE_ARG_OPTS = frozenset({"--overlay"})

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
        for op_bin in (config.agy_binary, config.codex_binary):
            if op_bin and ("/" in op_bin or str(op_bin).startswith("~")):
                try:
                    exp_bin = os.path.expanduser(str(op_bin).strip())
                    if exp_bin.startswith("/"):
                        self._allowed_fullpaths.add(os.path.abspath(exp_bin))
                        if os.path.exists(exp_bin):
                            self._allowed_fullpaths.add(os.path.realpath(exp_bin))
                except OSError:
                    pass
        self._blocked_basenames = {
            os.path.basename(cmd) for cmd in config.blocked_commands
        }
        self._allowed_roots = [
            str(Path(r).expanduser().resolve()) for r in config.allowed_workdirs
        ]
        prot_roots: List[str] = []
        for p in config.protected_paths:
            exp = Path(p).expanduser()
            lex_p = os.path.abspath(str(exp))
            if lex_p not in prot_roots:
                prot_roots.append(lex_p)
            try:
                res_p = str(exp.resolve())
            except OSError:
                res_p = ""
            if res_p and res_p not in prot_roots:
                prot_roots.append(res_p)
        self._protected_roots = prot_roots

    def is_protected_path(self, resolved_path: str) -> bool:
        for prot in self._protected_roots:
            if resolved_path == prot or resolved_path.startswith(prot + os.sep):
                return True
        return False

    @staticmethod
    def _collect_plugin_paths_from_candidates(raw_candidates: Sequence[str]) -> List[str]:
        home_lex = os.path.abspath(str(Path.home()))
        try:
            home_res = str(Path.home().resolve())
        except OSError:
            home_res = home_lex
        ignore_roots = {
            "/",
            "/bin",
            "/sbin",
            "/usr",
            "/usr/local",
            "/opt",
            "/var",
            "/etc",
            "/tmp",
            "/home",
            home_lex,
            home_res,
        }
        out: List[str] = []
        for raw in raw_candidates:
            try:
                exp = os.path.expanduser(str(raw).strip())
                if not exp.startswith("/"):
                    continue
                lex = os.path.abspath(exp)
                if lex not in ignore_roots and lex not in out:
                    out.append(lex)
                if os.path.exists(exp):
                    res = os.path.realpath(exp)
                    if res not in ignore_roots and res not in out:
                        out.append(res)
            except OSError:
                continue
        return out

    def get_configured_agy_plugin_paths(self) -> List[str]:
        """Return lexical and resolved paths of operator-configured AGY plugin directories (active or inactive)."""
        state = agy_plugins_config_state(self.config)
        raw_candidates: List[str] = list(state.get("raw_dirs") or [])
        cfg_dirs = getattr(self.config, "agy_plugin_dirs", None)
        if isinstance(cfg_dirs, (list, tuple)):
            for item in cfg_dirs:
                if isinstance(item, str) and item.strip():
                    raw_candidates.append(item.strip())
        return self._collect_plugin_paths_from_candidates(raw_candidates)

    def get_configured_codex_plugin_paths(self) -> List[str]:
        """Return lexical and resolved paths of operator-configured Codex plugin directories (active or inactive)."""
        state = codex_plugins_config_state(self.config)
        raw_candidates: List[str] = list(state.get("raw_dirs") or [])
        cfg_dirs = getattr(self.config, "codex_plugin_dirs", None)
        if isinstance(cfg_dirs, (list, tuple)):
            for item in cfg_dirs:
                if isinstance(item, str) and item.strip():
                    raw_candidates.append(item.strip())
        return self._collect_plugin_paths_from_candidates(raw_candidates)

    def is_agy_plugin_path(self, candidate_path: str) -> bool:
        """Return True if `candidate_path` lies within any configured AGY plugin directory."""
        if not candidate_path:
            return False
        for plg_root in self.get_configured_agy_plugin_paths():
            if _path_is_within(candidate_path, plg_root):
                return True
        return False

    def is_codex_plugin_path(self, candidate_path: str) -> bool:
        """Return True if `candidate_path` lies within any configured Codex plugin directory."""
        if not candidate_path:
            return False
        for plg_root in self.get_configured_codex_plugin_paths():
            if _path_is_within(candidate_path, plg_root):
                return True
        return False

    def is_plugin_state_path(self, candidate_path: str) -> bool:
        """Return True if `candidate_path` lies within `plugin_state_dir`, `plugin_bundles`, or `agent_runtime_home_root`."""
        if not candidate_path:
            return False
        guards: List[str] = []
        raw_state = effective_plugin_state_dir(self.config)
        if raw_state:
            try:
                exp_s = os.path.expanduser(str(raw_state).strip())
                if exp_s.startswith("/"):
                    guards.append(os.path.abspath(exp_s))
                    if os.path.exists(exp_s):
                        guards.append(os.path.realpath(exp_s))
            except OSError:
                pass
        raw_sb = getattr(self.config, "sandbox_state_dir", "")
        if raw_sb:
            try:
                exp_sb = os.path.expanduser(str(raw_sb).strip())
                if exp_sb.startswith("/") and exp_sb != "/":
                    for int_sub in ("plugin_bundles", "codex_home"):
                        sub_lex = os.path.join(os.path.abspath(exp_sb), int_sub)
                        guards.append(sub_lex)
                        if os.path.exists(exp_sb):
                            guards.append(os.path.join(os.path.realpath(exp_sb), int_sub))
                        if os.path.exists(sub_lex):
                            guards.append(os.path.realpath(sub_lex))
            except OSError:
                pass
        raw_rt = getattr(self.config, "agent_runtime_home_root", "/mnt/dots-agent-home")
        if raw_rt:
            try:
                exp_rt = os.path.expanduser(str(raw_rt).strip())
                if exp_rt.startswith("/") and exp_rt != "/":
                    guards.append(os.path.abspath(exp_rt))
                    if os.path.exists(exp_rt):
                        guards.append(os.path.realpath(exp_rt))
            except OSError:
                pass
        for g in guards:
            if g != "/" and _path_is_within(candidate_path, g):
                return True
        return False

    def is_within_allowed_workdirs(self, resolved_path: str) -> bool:
        if not self._allowed_roots:
            return True
        for root in self._allowed_roots:
            if resolved_path == root or resolved_path.startswith(root + os.sep):
                return True
        return False

    def is_workspace_hook_injection_path(self, candidate_path: str) -> bool:
        """Return True if `candidate_path` targets any repo-local hook or agent-config injection path."""
        norm_t = os.path.abspath(candidate_path)
        roots = list(self._allowed_roots)
        if not roots and self.config.default_workdir:
            try:
                roots.append(str(Path(self.config.default_workdir).expanduser().resolve()))
            except OSError:
                pass
        for ws_r in roots:
            if not _path_is_within(norm_t, ws_r):
                continue
            rel_posix = os.path.relpath(norm_t, ws_r).replace(os.sep, "/")
            if rel_posix in ("", "."):
                continue
            for rel_inj in WORKSPACE_HOOK_INJECTION_RELPATHS:
                inj_posix = rel_inj.replace(os.sep, "/").strip("/")
                if (
                    rel_posix == inj_posix
                    or rel_posix.startswith(f"{inj_posix}/")
                    or rel_posix.endswith(f"/{inj_posix}")
                    or f"/{inj_posix}/" in rel_posix
                ):
                    return True
        return False

    def validate_path(
        self,
        target: str,
        base_cwd: Optional[str] = None,
        *,
        for_write: bool = False,
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

        if self.is_agy_plugin_path(lexical_abs) or self.is_agy_plugin_path(resolved):
            return (
                False,
                f"Access to AGY plugin resource path '{target}' is forbidden outside AGY sessions",
                resolved,
            )

        if self.is_codex_plugin_path(lexical_abs) or self.is_codex_plugin_path(resolved):
            return (
                False,
                f"Access to Codex plugin resource path '{target}' is forbidden outside Codex sessions",
                resolved,
            )

        if self.is_plugin_state_path(lexical_abs) or self.is_plugin_state_path(resolved):
            return (
                False,
                f"Access to isolated plugin runtime/state path '{target}' is forbidden",
                resolved,
            )

        if not self.is_within_allowed_workdirs(lexical_abs) or not self.is_within_allowed_workdirs(resolved):
            return (
                False,
                f"Path '{resolved}' is outside allowed roots {self.config.allowed_workdirs}",
                resolved,
            )

        if for_write and (
            self.is_workspace_hook_injection_path(lexical_abs)
            or self.is_workspace_hook_injection_path(resolved)
        ):
            return (
                False,
                f"Modifying protected workspace hook/configuration path '{target}' is forbidden by security policy",
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
        # Docker CLI is unblocked only while gateway Docker access is ON (hot-reloaded); the
        # daemon is then reached exclusively through the policy-filtering proxy socket.
        if base in DOCKER_CLI_BASENAMES and docker_access_enabled(self.config):
            return True, ""
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

            if exe in self._allowed_fullpaths or real_str in self._allowed_fullpaths or lex_abs in self._allowed_fullpaths:
                return True, ""

            if self.is_protected_path(lex_abs) or self.is_protected_path(real_str):
                return False, f"Executable '{exe}' resides in a protected path"

            if self.is_agy_plugin_path(lex_abs) or self.is_agy_plugin_path(real_str):
                return False, f"Executable '{exe}' resides in an AGY-only plugin resource path"

            if self.is_codex_plugin_path(lex_abs) or self.is_codex_plugin_path(real_str):
                return False, f"Executable '{exe}' resides in a Codex-only plugin resource path"

            if self.is_plugin_state_path(lex_abs) or self.is_plugin_state_path(real_str):
                return False, f"Executable '{exe}' resides in an isolated plugin runtime/state path"

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

    _BLOCKED_SHELL_ENV_KEYS = frozenset(
        {
            "HOME",
            "PATH",
            "TMPDIR",
            "TMP",
            "TEMP",
            "BASH_ENV",
            "ENV",
            "PROMPT_COMMAND",
            "SHELLOPTS",
            "BASHOPTS",
            "IFS",
            "CDPATH",
            "GLIBC_TUNABLES",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "PYTHONPYCACHEPREFIX",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONINSPECT",
            "PYTHONUSERBASE",
            "NODE_OPTIONS",
            "NODE_PATH",
            "NODE_REPL_EXTERNAL_MODULE",
            "AGY_PLUGIN_ROOT",
            "AGY_PLUGIN_DIRS",
            "AGY_REGISTERED_PLUGINS",
            "CODEX_HOME",
            "CODEX_PLUGIN_ROOT",
            "CODEX_PLUGIN_DIRS",
            "CODEX_REGISTERED_PLUGINS",
            "PLUGIN_ROOT",
            "PLUGIN_DATA",
            "CLAUDE_PLUGIN_DATA",
            "CLAUDE_PLUGIN_ROOT",
            "CLAUDE_PROJECT_DIR",
            "AGY_PROJECT_DIR",
            "HARNESS_PROJECT_DIR",
            "OH_MY_AGENTS_ROOT",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "XDG_STATE_HOME",
            "GIT_SSH_COMMAND",
            "GIT_EXEC_PATH",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_COUNT",
            "GIT_TEMPLATE_DIR",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "CONTAINER_HOST",
            "NO_GCE_CHECK",
            "GCE_METADATA_HOST",
            "GCE_METADATA_ROOT",
            "GCE_METADATA_IP",
            "AWS_EC2_METADATA_DISABLED",
        }
    )

    @classmethod
    def _is_blocked_shell_env_key(cls, var_name: str) -> bool:
        k = var_name.strip()
        return (
            k in cls._BLOCKED_SHELL_ENV_KEYS
            or k.startswith("GATEWAY_")
            or k.startswith("LD_")
        )

    def _resolve_exec_candidate(
        self, exe_tok: str, resolved_cwd: Optional[str] = None
    ) -> Optional[str]:
        if not exe_tok:
            return None
        try:
            expanded = os.path.expanduser(exe_tok)
            if "/" in expanded:
                cand = (
                    expanded
                    if os.path.isabs(expanded)
                    else os.path.join(resolved_cwd or os.getcwd(), expanded)
                )
                return os.path.realpath(cand)
            found = shutil.which(expanded)
            if found:
                return os.path.realpath(found)
        except OSError:
            return None
        return None

    def _is_agy_executable_token(
        self, exe_tok: str, resolved_cwd: Optional[str] = None
    ) -> bool:
        if not exe_tok:
            return False
        if os.path.basename(exe_tok) == "agy":
            return True
        real_cand = self._resolve_exec_candidate(exe_tok, resolved_cwd)
        if real_cand and os.path.basename(real_cand) == "agy":
            return True
        if self.config.agy_binary:
            if exe_tok == self.config.agy_binary:
                return True
            try:
                cfg_exp = os.path.expanduser(self.config.agy_binary)
                cfg_abs = os.path.abspath(cfg_exp)
                cfg_real = os.path.realpath(cfg_exp)
                if "/" in exe_tok or exe_tok.startswith("~"):
                    tok_exp = os.path.expanduser(exe_tok)
                    tok_abs = (
                        os.path.abspath(tok_exp)
                        if os.path.isabs(tok_exp)
                        else os.path.abspath(
                            os.path.join(resolved_cwd or os.getcwd(), tok_exp)
                        )
                    )
                    if tok_abs in (cfg_abs, cfg_real):
                        return True
                if real_cand and real_cand in (cfg_abs, cfg_real):
                    return True
            except OSError:
                pass
        return False

    def _is_codex_executable_token(
        self, exe_tok: str, resolved_cwd: Optional[str] = None
    ) -> bool:
        if not exe_tok:
            return False
        if os.path.basename(exe_tok) == "codex":
            return True
        real_cand = self._resolve_exec_candidate(exe_tok, resolved_cwd)
        if real_cand and os.path.basename(real_cand) == "codex":
            return True
        if self.config.codex_binary:
            if exe_tok == self.config.codex_binary:
                return True
            try:
                cfg_exp = os.path.expanduser(self.config.codex_binary)
                cfg_abs = os.path.abspath(cfg_exp)
                cfg_real = os.path.realpath(cfg_exp)
                if "/" in exe_tok or exe_tok.startswith("~"):
                    tok_exp = os.path.expanduser(exe_tok)
                    tok_abs = (
                        os.path.abspath(tok_exp)
                        if os.path.isabs(tok_exp)
                        else os.path.abspath(
                            os.path.join(resolved_cwd or os.getcwd(), tok_exp)
                        )
                    )
                    if tok_abs in (cfg_abs, cfg_real):
                        return True
                if real_cand and real_cand in (cfg_abs, cfg_real):
                    return True
            except OSError:
                pass
        return False

    def _check_protected_arguments(
        self,
        tokens: Sequence[str],
        resolved_cwd: str,
        _trusted_agy_argv: bool = False,
        _trusted_codex_argv: bool = False,
    ) -> Tuple[bool, str]:
        """Block CLI arguments targeting protected paths or escaping allowed_workdirs."""
        tok_list = list(tokens)
        is_agy_bin = bool(
            tok_list and self._is_agy_executable_token(tok_list[0], resolved_cwd)
        )
        is_codex_bin = bool(
            tok_list and self._is_codex_executable_token(tok_list[0], resolved_cwd)
        )
        saw_trusted_settings = False
        saw_codex_exec = False
        after_double_dash = False
        _safe_zero_arg_before_dd = {
            "--help",
            "-h",
            "--version",
            "-v",
            "-V",
            "--continue",
            "-c",
            "--verbose",
            "--debug",
            "--sandbox",
            "--dangerously-skip-permissions",
            "--ide",
            "--no-ide",
            "--chrome",
            "--no-chrome",
        }
        for idx, tok in enumerate(tok_list[1:], start=1):
            if tok == "--":
                if _trusted_agy_argv:
                    prev_tok = tok_list[idx - 1] if idx > 1 else ""
                    if idx != len(tok_list) - 2 or (
                        prev_tok.startswith("-")
                        and "=" not in prev_tok
                        and prev_tok not in _safe_zero_arg_before_dd
                    ):
                        return (
                            False,
                            "Unexpected or option-swallowed '--' in agy arguments; pass prompt via the dedicated 'prompt' field",
                        )
                after_double_dash = True
                continue
            if _trusted_agy_argv:
                if (
                    not after_double_dash
                    and not saw_trusted_settings
                    and tok.startswith("--settings={")
                ):
                    saw_trusted_settings = True
                    continue
                if idx == len(tok_list) - 1 and (
                    tok.startswith("--print=")
                    or (after_double_dash and tok_list[-2] == "--")
                ):
                    continue
            if _trusted_codex_argv:
                if not after_double_dash and tok == "exec":
                    saw_codex_exec = True
                    continue
                if saw_codex_exec and idx == len(tok_list) - 1:
                    continue
            if not after_double_dash:
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
                        "--plugin-dir",
                        "--plugin-dirs",
                    )
                    or tok.startswith(
                        ("--settings=", "--remote-control=", "--plugin-dir=", "--plugin-dirs=")
                    )
                    or tok == "--settings"
                ):
                    return False, f"Flag '{tok}' is forbidden in command execution"
                if is_agy_bin:
                    if tok in ("--plugin", "--plugins") or tok.startswith(
                        ("--plugin=", "--plugins=")
                    ):
                        return False, f"Flag '{tok}' on 'agy' is forbidden by gateway security policy"
                    if tok in ("plugin", "plugins") and tok_list[idx - 1] not in (
                        "-p",
                        "--print",
                        "--prompt",
                        "--model",
                        "--effort",
                        "--mode",
                        "--conversation",
                        "--input-format",
                        "--output-format",
                    ):
                        return (
                            False,
                            f"Subcommand 'agy {tok}' is forbidden in task execution; manage plugins via 'dots-gateway agy-plugins'",
                        )
                if is_codex_bin:
                    if tok in ("--plugin", "--plugins") or tok.startswith(
                        ("--plugin=", "--plugins=")
                    ):
                        return False, f"Flag '{tok}' on 'codex' is forbidden by gateway security policy"
                    if tok in ("plugin", "plugins") and tok_list[idx - 1] not in (
                        "-m",
                        "--model",
                        "-c",
                        "--config",
                    ):
                        return (
                            False,
                            f"Subcommand 'codex {tok}' is forbidden in task execution; manage plugins via 'dots-gateway codex-plugins'",
                        )
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
            if not after_double_dash and tok.startswith("-") and "=" in tok:
                flag_name, flag_val = tok.split("=", 1)
                if flag_name in ("-v", "--volume") and ":" in flag_val:
                    candidates = [flag_val.split(":", 1)[0]]
                else:
                    candidates = [flag_val]
            elif not after_double_dash and tok.startswith("-"):
                continue
            elif idx > 1 and tok_list[idx - 1] in ("-v", "--volume") and ":" in tok:
                candidates = [tok.split(":", 1)[0]]

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

                if self.is_agy_plugin_path(lex) or self.is_agy_plugin_path(res):
                    return (
                        False,
                        f"Argument '{val}' targets an AGY-only plugin resource path",
                    )

                if self.is_codex_plugin_path(lex) or self.is_codex_plugin_path(res):
                    return (
                        False,
                        f"Argument '{val}' targets a Codex-only plugin resource path",
                    )

                if self.is_plugin_state_path(lex) or self.is_plugin_state_path(res):
                    return (
                        False,
                        f"Argument '{val}' targets an isolated plugin runtime/state path",
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
        _trusted_codex_argv: bool = False,
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

            # Unwrap subshell groups `[prefix_kw...] (cd dir && make) [> log 2>&1]`
            unwrapped_subshell = _unwrap_subshell_with_redirs(seg)
            if unwrapped_subshell is not None:
                requires_shell = True
                inner_grp, trailing_redirs = unwrapped_subshell
                if inner_grp.strip():
                    grp_dec = self.validate_command(inner_grp, cwd=resolved_cwd, _depth=_depth + 1)
                    if not grp_dec.allowed:
                        return grp_dec
                if trailing_redirs:
                    redir_dec = self.validate_command(
                        f": {trailing_redirs}", cwd=resolved_cwd, _depth=_depth + 1
                    )
                    if not redir_dec.allowed:
                        return redir_dec
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
                if self._is_blocked_shell_env_key(seg_tokens[idx + 1]):
                    return PolicyDecision(
                        False,
                        reason=f"Overriding protected environment variable '{seg_tokens[idx + 1]}' is forbidden",
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
                env_var = seg_tokens[idx].split("=", 1)[0]
                if self._is_blocked_shell_env_key(env_var):
                    return PolicyDecision(
                        False,
                        reason=f"Overriding protected environment variable '{env_var}' in command execution is forbidden",
                        resolved_cwd=resolved_cwd,
                    )
                requires_shell = True
                idx += 1
            if idx >= len(seg_tokens):
                continue

            exe = seg_tokens[idx]
            if exe in _SHELL_BUILTINS:
                requires_shell = True
            if exe in ("export", "unset"):
                for exp_tok in seg_tokens[idx + 1 :]:
                    if exp_tok.startswith("-"):
                        continue
                    exp_key = exp_tok.split("=", 1)[0].strip()
                    if self._is_blocked_shell_env_key(exp_key):
                        return PolicyDecision(
                            False,
                            reason=f"Modifying protected environment variable '{exp_key}' via '{exe}' is forbidden",
                            resolved_cwd=resolved_cwd,
                        )
            if exe == "trap":
                trap_args = list(seg_tokens[idx + 1 :])
                t_i = 0
                is_print_or_list = False
                while t_i < len(trap_args):
                    targ = trap_args[t_i]
                    if targ == "--":
                        t_i += 1
                        break
                    if targ == "-":
                        break
                    if targ in ("-p", "-l"):
                        is_print_or_list = True
                        t_i += 1
                        continue
                    if targ.startswith("-"):
                        return PolicyDecision(
                            False,
                            reason=f"Unsupported option '{targ}' for 'trap'",
                            resolved_cwd=resolved_cwd,
                        )
                    break
                rem_trap = trap_args[t_i:]
                if not is_print_or_list and rem_trap:
                    trap_action = rem_trap[0]
                    is_numeric_reset = len(rem_trap) == 1 and trap_action.isdigit()
                    if trap_action not in ("", "-") and not is_numeric_reset:
                        trap_dec = self.validate_command(
                            trap_action, cwd=resolved_cwd, _depth=_depth + 1
                        )
                        if not trap_dec.allowed:
                            return trap_dec

            ok_exe, exe_err = self._check_single_executable(exe, resolved_cwd)
            if not ok_exe:
                return PolicyDecision(False, reason=exe_err, resolved_cwd=resolved_cwd)

            ok_rm, rm_err = self._check_dangerous_rm(seg_tokens[idx:])
            if not ok_rm:
                return PolicyDecision(False, reason=rm_err, resolved_cwd=resolved_cwd)

            ok_prot, prot_err = self._check_protected_arguments(
                seg_tokens[idx:],
                resolved_cwd,
                _trusted_agy_argv=(_trusted_agy_argv and _depth == 0 and idx == 0),
                _trusted_codex_argv=(_trusted_codex_argv and _depth == 0 and idx == 0),
            )
            if not ok_prot:
                return PolicyDecision(False, reason=prot_err, resolved_cwd=resolved_cwd)

            # Unwrap command wrappers (`env`, `timeout`, `nohup`, `time`) in a loop so wrapped executables & args are validated
            effective_idx = idx
            while effective_idx < len(seg_tokens):
                w_base = os.path.basename(seg_tokens[effective_idx])
                next_idx: Optional[int] = None
                if w_base == "env" and effective_idx + 1 < len(seg_tokens):
                    e_idx = effective_idx + 1
                    while e_idx < len(seg_tokens):
                        etok = seg_tokens[e_idx]
                        if etok == "--":
                            e_idx += 1
                            break
                        if etok in ("-i", "--ignore-environment", "-0", "--null"):
                            if etok in ("-i", "--ignore-environment"):
                                return PolicyDecision(
                                    False,
                                    reason=f"Flag '{etok}' on 'env' is forbidden by security policy",
                                    resolved_cwd=resolved_cwd,
                                )
                            e_idx += 1
                            continue
                        if etok in ("-u", "--unset") and e_idx + 1 < len(seg_tokens):
                            if self._is_blocked_shell_env_key(seg_tokens[e_idx + 1]):
                                return PolicyDecision(
                                    False,
                                    reason=f"Unsetting protected environment variable '{seg_tokens[e_idx + 1]}' is forbidden",
                                    resolved_cwd=resolved_cwd,
                                )
                            e_idx += 2
                            continue
                        if etok.startswith("--unset="):
                            u_key = etok.split("=", 1)[1]
                            if self._is_blocked_shell_env_key(u_key):
                                return PolicyDecision(
                                    False,
                                    reason=f"Unsetting protected environment variable '{u_key}' is forbidden",
                                    resolved_cwd=resolved_cwd,
                                )
                            e_idx += 1
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
                            e_key = etok.split("=", 1)[0]
                            if self._is_blocked_shell_env_key(e_key):
                                return PolicyDecision(
                                    False,
                                    reason=f"Overriding protected environment variable '{e_key}' via 'env' is forbidden",
                                    resolved_cwd=resolved_cwd,
                                )
                            e_idx += 1
                            continue
                        break
                    if e_idx < len(seg_tokens):
                        next_idx = e_idx
                elif w_base == "timeout" and effective_idx + 1 < len(seg_tokens):
                    t_idx = effective_idx + 1
                    while t_idx < len(seg_tokens):
                        ttok = seg_tokens[t_idx]
                        if ttok == "--":
                            t_idx += 1
                            break
                        if ttok in ("-k", "--kill-after", "-s", "--signal") and t_idx + 1 < len(seg_tokens):
                            t_idx += 2
                            continue
                        if ttok.startswith(("--kill-after=", "--signal=", "-k", "-s")) and len(ttok) > 2:
                            t_idx += 1
                            continue
                        if ttok.startswith("-"):
                            t_idx += 1
                            continue
                        # Duration positional argument
                        t_idx += 1
                        break
                    if t_idx < len(seg_tokens):
                        next_idx = t_idx
                elif w_base in ("nohup", "time") and effective_idx + 1 < len(seg_tokens):
                    n_idx = effective_idx + 1
                    while n_idx < len(seg_tokens):
                        ntok = seg_tokens[n_idx]
                        if ntok == "--":
                            n_idx += 1
                            break
                        if ntok.startswith("-"):
                            if w_base == "time" and ntok in ("-o", "--output", "-f", "--format") and n_idx + 1 < len(seg_tokens):
                                n_idx += 2
                                continue
                            n_idx += 1
                            continue
                        break
                    if n_idx < len(seg_tokens):
                        next_idx = n_idx
                elif w_base == "xargs" and effective_idx + 1 < len(seg_tokens):
                    x_idx = effective_idx + 1
                    while x_idx < len(seg_tokens):
                        xtok = seg_tokens[x_idx]
                        if xtok == "--":
                            x_idx += 1
                            break
                        if xtok in (
                            "-I",
                            "-J",
                            "-L",
                            "-l",
                            "-n",
                            "-P",
                            "-s",
                            "-a",
                            "-d",
                            "-E",
                            "-e",
                            "--replace",
                            "--max-lines",
                            "--max-args",
                            "--max-procs",
                            "--max-chars",
                            "--arg-file",
                            "--delimiter",
                            "--eof",
                            "--process-slot-var",
                        ) and x_idx + 1 < len(seg_tokens):
                            x_idx += 2
                            continue
                        if xtok.startswith("-"):
                            x_idx += 1
                            continue
                        break
                    if x_idx < len(seg_tokens):
                        next_idx = x_idx
                elif w_base == "command" and effective_idx + 1 < len(seg_tokens):
                    c_idx = effective_idx + 1
                    is_lookup = False
                    while c_idx < len(seg_tokens):
                        ctok = seg_tokens[c_idx]
                        if ctok == "--":
                            c_idx += 1
                            break
                        if ctok in ("-v", "-V"):
                            is_lookup = True
                            c_idx += 1
                            continue
                        if ctok.startswith("-"):
                            return PolicyDecision(
                                False,
                                reason=f"Flag '{ctok}' on 'command' is forbidden by security policy",
                                resolved_cwd=resolved_cwd,
                            )
                        break
                    if not is_lookup and c_idx < len(seg_tokens):
                        next_idx = c_idx

                if next_idx is None or next_idx <= effective_idx or next_idx >= len(seg_tokens):
                    break
                effective_idx = next_idx
                sub_exe = seg_tokens[effective_idx]
                ok_sub_exe, sub_exe_err = self._check_single_executable(sub_exe, resolved_cwd)
                if not ok_sub_exe:
                    return PolicyDecision(False, reason=sub_exe_err, resolved_cwd=resolved_cwd)
                ok_sub_rm, sub_rm_err = self._check_dangerous_rm(seg_tokens[effective_idx:])
                if not ok_sub_rm:
                    return PolicyDecision(False, reason=sub_rm_err, resolved_cwd=resolved_cwd)
                ok_sub_prot, sub_prot_err = self._check_protected_arguments(
                    seg_tokens[effective_idx:],
                    resolved_cwd,
                    _trusted_agy_argv=False,
                )
                if not ok_sub_prot:
                    return PolicyDecision(False, reason=sub_prot_err, resolved_cwd=resolved_cwd)

            effective_exe = seg_tokens[effective_idx]
            if self._is_agy_executable_token(effective_exe, resolved_cwd) and not (
                _trusted_agy_argv and _depth == 0 and effective_idx == 0 and not requires_shell
            ):
                return PolicyDecision(
                    False,
                    reason="Direct invocation of 'agy' via exec_command is forbidden; use dedicated 'run_agy' so sandbox and plugin security policies are enforced",
                    resolved_cwd=resolved_cwd,
                )
            if self._is_codex_executable_token(effective_exe, resolved_cwd) and not (
                _trusted_codex_argv and _depth == 0 and effective_idx == 0 and not requires_shell
            ):
                return PolicyDecision(
                    False,
                    reason="Direct invocation of 'codex' via exec_command is forbidden; use dedicated 'run_codex' so sandbox and workspace policies are enforced",
                    resolved_cwd=resolved_cwd,
                )

            # If invoking `bwrap` (bubblewrap), validate wrapper flags and recursively validate inner command
            effective_exe = seg_tokens[effective_idx]
            if os.path.basename(effective_exe) == "bwrap":
                bw_decision = self._validate_bwrap_segment(
                    seg_tokens[effective_idx:],
                    resolved_cwd=resolved_cwd,
                    _depth=_depth,
                    heredocs=pseg.heredocs,
                )
                if not bw_decision.allowed:
                    return bw_decision

            # If invoking subshell `bash`/`sh` via `-c`/`-lc` or via heredoc (`bash <<'EOF'`), validate inner script
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

        # Resolve 'agy' / 'codex' / 'bwrap' binary paths automatically if the first token matches
        if argv and argv[0] == "agy" and os.path.exists(self.config.agy_binary):
            argv = [self.config.agy_binary] + argv[1:]
        elif argv and argv[0] == "codex" and os.path.exists(self.config.codex_binary):
            argv = [self.config.codex_binary] + argv[1:]
        elif argv and argv[0] == "bwrap" and os.path.exists(self.config.bwrap_binary):
            argv = [self.config.bwrap_binary] + argv[1:]

        return PolicyDecision(
            allowed=True,
            reason="ok",
            normalized_argv=argv,
            resolved_cwd=resolved_cwd,
            requires_shell=requires_shell,
        )

    def _validate_bwrap_segment(
        self,
        bwrap_tokens: Sequence[str],
        resolved_cwd: str,
        _depth: int,
        heredocs: Sequence[Any] = (),
    ) -> PolicyDecision:
        """Validate `bwrap` sandbox flags fail-closed and recursively validate wrapped command."""
        b_idx = 1
        saw_info_flag = False
        inner_cwd = resolved_cwd

        while b_idx < len(bwrap_tokens):
            btok = bwrap_tokens[b_idx]
            if btok == "--":
                b_idx += 1
                break
            if not btok.startswith("-") or btok == "-":
                break

            opt_name = btok.split("=", 1)[0] if "=" in btok else btok
            if opt_name in _BWRAP_FORBIDDEN_OPTS:
                return PolicyDecision(
                    False,
                    reason=f"Flag '{opt_name}' on 'bwrap' is forbidden by security policy",
                    resolved_cwd=resolved_cwd,
                )
            if "=" in btok:
                return PolicyDecision(
                    False,
                    reason=f"Unsupported '=' option syntax '{btok}' on 'bwrap'; pass flag and value as separate arguments",
                    resolved_cwd=resolved_cwd,
                )
            if btok in _BWRAP_INFO_ZERO_ARG_OPTS:
                saw_info_flag = True
                b_idx += 1
                continue
            if btok in _BWRAP_ZERO_ARG_OPTS:
                b_idx += 1
                continue
            if btok in _BWRAP_ONE_ARG_OPTS:
                if b_idx + 1 >= len(bwrap_tokens):
                    return PolicyDecision(
                        False,
                        reason=f"Missing argument after 'bwrap {btok}'",
                        resolved_cwd=resolved_cwd,
                    )
                arg_val = bwrap_tokens[b_idx + 1]
                if btok == "--chdir":
                    ok_cd, _, cand_cwd = self.validate_workdir(arg_val)
                    if ok_cd and cand_cwd:
                        inner_cwd = cand_cwd
                b_idx += 2
                continue
            if btok in _BWRAP_TWO_ARG_OPTS:
                if b_idx + 2 >= len(bwrap_tokens):
                    return PolicyDecision(
                        False,
                        reason=f"Missing arguments after 'bwrap {btok}'",
                        resolved_cwd=resolved_cwd,
                    )
                b_idx += 3
                continue
            if btok in _BWRAP_THREE_ARG_OPTS:
                if b_idx + 3 >= len(bwrap_tokens):
                    return PolicyDecision(
                        False,
                        reason=f"Missing arguments after 'bwrap {btok}'",
                        resolved_cwd=resolved_cwd,
                    )
                b_idx += 4
                continue

            return PolicyDecision(
                False,
                reason=f"Unsupported or unknown bwrap option '{btok}'",
                resolved_cwd=resolved_cwd,
            )

        inner_tokens = list(bwrap_tokens[b_idx:])
        if not inner_tokens:
            if saw_info_flag:
                return PolicyDecision(True, reason="ok", resolved_cwd=resolved_cwd)
            return PolicyDecision(
                False,
                reason="Missing target command after 'bwrap' options",
                resolved_cwd=resolved_cwd,
            )

        inner_decision = self.validate_command(
            inner_tokens, cwd=inner_cwd, _depth=_depth + 1
        )
        if not inner_decision.allowed:
            return inner_decision

        if os.path.basename(inner_tokens[0]) in ("bash", "sh"):
            for hspec in heredocs:
                if getattr(hspec, "body", "").strip():
                    hd_decision = self.validate_command(
                        hspec.body, cwd=inner_cwd, _depth=_depth + 1
                    )
                    if not hd_decision.allowed:
                        return hd_decision

        return PolicyDecision(True, reason="ok", resolved_cwd=resolved_cwd)

    def _use_agy_host_network_vfs_mode(self, use_sandbox: bool = True) -> bool:
        """Return True when AGY uses outer kernel VFS isolation with host-consistent network.

        Linux `agy --sandbox` unconditionally enters an isolated network namespace
        (`CLONE_NEWNET`) that cuts off host NIC routing and `/etc/resolv.conf` DNS. When
        `agy_sandbox_network_access=True` AND outer kernel user+mount namespace isolation
        (`isolate_mount_namespace=True` + `can_use_mount_namespace()`) is active, Gateway
        enforces VFS/hook/credential containment at the kernel mount layer + `--settings`
        permission rules while omitting inner `--sandbox` so AGY shares host network & DNS
        (matching `exec_command` and `codex_sandbox_network_access=True`).
        If outer mount-namespace isolation is disabled or unavailable, Gateway fails safe by
        keeping inner `agy --sandbox` enabled.
        """
        return bool(
            use_sandbox
            and self.config.agy_sandbox_network_access
            and self.config.isolate_mount_namespace
            and can_use_mount_namespace()
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
        _validated_plugins: Optional[Sequence[ValidatedAgyPlugin]] = None,
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
        ok_cwd_agy, cwd_err_agy, resolved_cwd_agy = self.validate_workdir(cwd)
        if not ok_cwd_agy:
            raise PermissionError(cwd_err_agy)

        extra = [str(a) for a in (args or [])]

        _agy_value_flags = {
            "--model",
            "-m",
            "--effort",
            "--mode",
            "--conversation",
            "--resume",
            "-r",
            "--input-format",
            "--output-format",
            "--print",
            "-p",
            "--prompt",
            "--prompt-interactive",
            "-i",
            "--system-prompt",
            "--append-system-prompt",
            "--max-turns",
            "--fallback-model",
            "--allowedTools",
            "--allowed-tools",
            "--disallowedTools",
            "--disallowed-tools",
            "--tools",
            "--mcp-config",
            "--permission-mode",
            "--betas",
            "--agent",
            "--agents",
            "--json-schema",
            "--file",
        }
        _agy_safe_trailing_zero_arg_flags = {
            "--help",
            "-h",
            "--version",
            "-v",
            "-V",
            "--continue",
            "-c",
            "--verbose",
            "--debug",
            "--sandbox",
            "--dangerously-skip-permissions",
            "--ide",
            "--no-ide",
            "--chrome",
            "--no-chrome",
        }

        for raw_arg in extra:
            if raw_arg == "--":
                raise PermissionError(
                    "Passing '--' in agy args is forbidden; pass prompt via the dedicated 'prompt' field"
                )
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
            if (
                raw_arg in ("--plugin", "--plugins", "--plugin-dir", "--plugin-dirs")
                or raw_arg.startswith(
                    ("--plugin=", "--plugins=", "--plugin-dir=", "--plugin-dirs=")
                )
                or raw_arg in ("plugin", "plugins")
            ):
                raise PermissionError(
                    "Declaring or managing AGY plugins per task via CLI args is forbidden; "
                    "register operator-approved plugins via 'dots-gateway agy-plugins'"
                )
            if prompt is not None and (
                raw_arg in ("--print", "-p", "--prompt", "--prompt-interactive", "-i")
                or raw_arg.startswith(
                    ("--print=", "-p=", "--prompt=", "--prompt-interactive=", "-i=")
                )
            ):
                raise PermissionError(
                    "Cannot combine 'prompt' with print/prompt flags in 'args'; pass prompt via 'prompt' only"
                )

        if extra and extra[-1] in _agy_value_flags:
            raise PermissionError(
                f"Trailing flag '{extra[-1]}' in agy args is missing its value"
            )
        if (
            prompt is not None
            and not print_mode
            and extra
            and extra[-1].startswith("-")
            and "=" not in extra[-1]
            and extra[-1] not in _agy_safe_trailing_zero_arg_flags
        ):
            raise PermissionError(
                f"Trailing flag '{extra[-1]}' in agy args cannot precede a positional prompt without an explicit '=value'"
            )

        ok_extra, err_extra = self._check_protected_arguments(
            [agy_bin, *extra], resolved_cwd_agy, _trusted_agy_argv=False
        )
        if not ok_extra:
            raise PermissionError(err_extra)

        plugins_state = agy_plugins_config_state(self.config)
        active_validated_plugins: Optional[Sequence[ValidatedAgyPlugin]] = _validated_plugins
        if plugins_state.get("config_error") or plugins_state.get("enabled"):
            if not use_sandbox:
                raise PermissionError(
                    "AGY plugins require '--sandbox' to stay synchronized with read-only VFS mounts"
                )
            if active_validated_plugins is None:
                active_validated_plugins = self.validate_agy_plugins(cwd=cwd, add_dirs=add_dirs)

        if use_skip and "--dangerously-skip-permissions" not in extra:
            argv.append("--dangerously-skip-permissions")
        if use_sandbox:
            host_net_vfs = self._use_agy_host_network_vfs_mode(use_sandbox=True)
            if not host_net_vfs and "--sandbox" not in extra:
                argv.append("--sandbox")
            agy_settings = self.build_agy_sandbox_settings(
                cwd=cwd,
                add_dirs=add_dirs,
                _validated_plugins=active_validated_plugins,
                _inner_sandbox_active=not host_net_vfs,
            )
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

        for resolved_dir in self.get_agy_workspace_dirs(cwd=cwd, add_dirs=add_dirs):
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
            if print_mode:
                argv.append(f"--print={prompt}")
            else:
                argv.extend(["--", prompt])
        elif (
            print_mode
            and input_format == "stream-json"
            and not has_print_flag
            and "--help" not in argv
            and "-h" not in argv
        ):
            argv.append("--print=")

        return argv

    def _raise_plugin_policy_error(self, message: str) -> None:
        raise PermissionError(redact_diagnostic_text(message, self.config))

    def _check_no_symlink_ancestors(self, abs_path: str, label: str) -> None:
        """Fail closed if any existing path component of `abs_path` is a symlink."""
        cur = "/"
        for part in [p for p in abs_path.split("/") if p]:
            cur = os.path.join(cur, part)
            if os.path.islink(cur):
                self._raise_plugin_policy_error(
                    f"{label} '{abs_path}' traverses symlink component '{cur}', which is forbidden"
                )

    def _build_plugin_boundary_sets(
        self,
        *,
        home_lex: str,
        home_res: str,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> Tuple[
        set[str],
        Tuple[str, ...],
        List[Tuple[str, str]],
        List[Tuple[str, str]],
    ]:
        forbidden_exact_roots = {
            "/",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/usr",
            "/usr/local",
            "/opt",
            "/var",
            "/srv",
            "/mnt",
            "/media",
            "/home",
            home_lex,
            home_res,
        }
        forbidden_system_trees = (
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/etc",
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/boot",
            "/root",
            "/tmp",
            "/var/tmp",
            "/opt/codex",
            "/opt/uv-python",
            "/opt/uv-tools",
            "/opt/devtools",
            "/opt/flutter",
        )

        protected_boundaries: List[Tuple[str, str]] = []

        def _register_boundary(
            target_list: List[Tuple[str, str]], raw_val: Optional[str], label: str
        ) -> None:
            if not raw_val:
                return
            s_val = str(raw_val).strip()
            if not s_val:
                return
            try:
                exp = os.path.expanduser(s_val)
                if not exp.startswith("/"):
                    exp = os.path.abspath(exp)
                lex = os.path.abspath(exp)
                target_list.append((lex, label))
                if os.path.exists(exp):
                    res = os.path.realpath(exp)
                    if res != lex:
                        target_list.append((res, label))
            except OSError:
                return

        _register_boundary(protected_boundaries, str(GATEWAY_ROOT), "gateway root")
        _register_boundary(protected_boundaries, str(GATEWAY_ROOT / "certs"), "gateway certs")
        for prot_p in self.config.protected_paths:
            _register_boundary(protected_boundaries, str(prot_p), "protected_paths")
        for cfg_attr, cfg_label in (
            ("agy_env_file", "agy_env_file"),
            ("agy_model_file", "agy_model_file"),
            ("agy_plugins_file", "agy_plugins_file"),
            ("codex_env_file", "codex_env_file"),
            ("codex_plugins_file", "codex_plugins_file"),
            ("docker_mode_file", "docker_mode_file"),
            ("docker_proxy_socket", "docker_proxy_socket"),
            ("docker_upstream_socket", "docker_upstream_socket"),
            ("session_state_dir", "session_state_dir"),
            ("tls_certfile", "tls_certfile"),
            ("tls_keyfile", "tls_keyfile"),
            ("tls_ca_file", "tls_ca_file"),
        ):
            _register_boundary(
                protected_boundaries, getattr(self.config, cfg_attr, None), cfg_label
            )
        for h_base in {home_lex, home_res}:
            for dot_sub, dot_label in (
                (".config", "runtime/tunnel/credential config (~/.config)"),
                (".gemini", "AGY login & state directory (~/.gemini)"),
                (".codex", "Codex credential directory (~/.codex)"),
                (".ssh", "SSH credential directory (~/.ssh)"),
                (".gnupg", "GPG credential directory (~/.gnupg)"),
                (".aliyun", "cloud credential directory (~/.aliyun)"),
                (".aws", "cloud credential directory (~/.aws)"),
                (".kube", "Kubernetes credential directory (~/.kube)"),
                (".docker", "Docker config directory (~/.docker)"),
                (".local", "user local runtime directory (~/.local)"),
            ):
                _register_boundary(
                    protected_boundaries, os.path.join(h_base, dot_sub), dot_label
                )
        if self.config.sandbox_state_dir:
            _register_boundary(
                protected_boundaries,
                os.path.join(str(self.config.sandbox_state_dir), "plugin_bundles"),
                "sandbox plugin_bundles staging",
            )
            _register_boundary(
                protected_boundaries,
                os.path.join(str(self.config.sandbox_state_dir), "codex_home"),
                "sandbox isolated codex_home backing",
            )

        writable_boundaries: List[Tuple[str, str]] = []
        for ws_p in self.config.allowed_workdirs:
            _register_boundary(writable_boundaries, str(ws_p), "allowed_workdirs")
        _register_boundary(
            writable_boundaries, self.config.default_workdir, "default_workdir"
        )
        for ex_ws in self.config.agy_extra_workspace_dirs:
            _register_boundary(
                writable_boundaries, str(ex_ws), "agy_extra_workspace_dirs"
            )
        for ex_cx in self.config.codex_extra_writable_roots:
            _register_boundary(
                writable_boundaries, str(ex_cx), "codex_extra_writable_roots"
            )
        for ex_dk in self.config.docker_extra_bind_roots:
            _register_boundary(
                writable_boundaries, str(ex_dk), "docker_extra_bind_roots"
            )
        _register_boundary(
            writable_boundaries, self.config.sandbox_state_dir, "sandbox_state_dir"
        )
        if self.config.sandbox_state_dir:
            _register_boundary(
                writable_boundaries,
                os.path.join(str(self.config.sandbox_state_dir), "plugin_bundles"),
                "sandbox plugin_bundles staging",
            )
            _register_boundary(
                writable_boundaries,
                os.path.join(str(self.config.sandbox_state_dir), "codex_home"),
                "sandbox isolated codex_home backing",
            )
        _register_boundary(
            writable_boundaries,
            effective_plugin_state_dir(self.config),
            "plugin_state_dir",
        )
        _register_boundary(
            writable_boundaries, "/opt/flutter/bin/cache", "writable SDK cache"
        )
        _register_boundary(
            writable_boundaries,
            "/opt/flutter/packages/flutter_tools/.dart_tool",
            "writable Flutter tools package_config",
        )
        _register_boundary(
            writable_boundaries,
            SHARED_SANDBOX_PUB_CACHE_VFS,
            "shared sandbox pub cache",
        )
        if cwd:
            _register_boundary(writable_boundaries, str(cwd), "session cwd")
        if add_dirs:
            for ad in add_dirs:
                _register_boundary(writable_boundaries, str(ad), "session add_dirs")
        for h_base in {home_lex, home_res}:
            for cache_sub in (".cache", ".npm", ".pub-cache", ".dart-tool", ".dartServer"):
                _register_boundary(
                    writable_boundaries,
                    os.path.join(h_base, cache_sub),
                    f"writable toolchain cache (~/{cache_sub})",
                )
        return (
            forbidden_exact_roots,
            forbidden_system_trees,
            protected_boundaries,
            writable_boundaries,
        )

    def validate_agent_runtime_home_root(
        self,
        *,
        home_lex: str,
        home_res: str,
        forbidden_exact_roots: set[str],
        forbidden_system_trees: Sequence[str],
        protected_boundaries: Sequence[Tuple[str, str]],
        writable_boundaries: Sequence[Tuple[str, str]],
    ) -> str:
        """Validate `agent_runtime_home_root` (default `/mnt/dots-agent-home`) fail-closed."""
        raw_rt = str(
            getattr(self.config, "agent_runtime_home_root", None)
            or "/mnt/dots-agent-home"
        ).strip()
        if not raw_rt or any(ch in raw_rt for ch in ("\x00", "\r", "\n", ")")):
            self._raise_plugin_policy_error(
                f"Invalid characters or empty agent_runtime_home_root '{raw_rt}'"
            )
        exp_rt = os.path.expanduser(raw_rt)
        if not exp_rt.startswith("/"):
            self._raise_plugin_policy_error(
                f"agent_runtime_home_root '{raw_rt}' must be an absolute path"
            )
        rt_root = os.path.abspath(exp_rt)
        if not re.match(r"^/[A-Za-z0-9._/-]+$", rt_root):
            self._raise_plugin_policy_error(
                f"agent_runtime_home_root '{rt_root}' contains unsupported characters; "
                "only ASCII letters, digits, '.', '_', '-', and '/' are permitted"
            )
        if (
            rt_root in forbidden_exact_roots
            or _path_is_within(home_lex, rt_root)
            or _path_is_within(home_res, rt_root)
        ):
            self._raise_plugin_policy_error(
                f"agent_runtime_home_root '{rt_root}' cannot be a top-level system or HOME root"
            )
        self._check_no_symlink_ancestors(rt_root, "agent_runtime_home_root")
        for sys_tree in (*forbidden_system_trees, "/opt", "/var", "/usr", "/srv"):
            if _paths_overlap_any_direction(rt_root, sys_tree):
                self._raise_plugin_policy_error(
                    f"agent_runtime_home_root '{rt_root}' overlaps forbidden or read-only system tree '{sys_tree}'"
                )
        for prot_root, prot_label in protected_boundaries:
            if _paths_overlap_any_direction(rt_root, prot_root):
                self._raise_plugin_policy_error(
                    f"agent_runtime_home_root '{rt_root}' overlaps protected {prot_label} ('{prot_root}'); "
                    "keep agent_runtime_home_root outside protected HOME and credential umbrellas"
                )
        for wr_root, wr_label in writable_boundaries:
            if _paths_overlap_any_direction(rt_root, wr_root):
                self._raise_plugin_policy_error(
                    f"agent_runtime_home_root '{rt_root}' overlaps writable {wr_label} ('{wr_root}')"
                )
        return rt_root

    def validate_plugin_state_dir(
        self,
        *,
        home_lex: str,
        home_res: str,
        rt_root: str,
        forbidden_exact_roots: set[str],
        forbidden_system_trees: Sequence[str],
        protected_boundaries: Sequence[Tuple[str, str]],
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> str:
        """Validate `plugin_state_dir` fail-closed against workspaces, credentials, and plugin code."""
        raw_st = effective_plugin_state_dir(self.config)
        if not raw_st or any(ch in raw_st for ch in ("\x00", "\r", "\n", ")")):
            self._raise_plugin_policy_error(
                f"Invalid characters or empty plugin_state_dir '{raw_st}'"
            )
        exp_st = os.path.expanduser(str(raw_st).strip())
        if not exp_st.startswith("/"):
            self._raise_plugin_policy_error(
                f"plugin_state_dir '{raw_st}' must be an absolute path"
            )
        st_dir = os.path.abspath(exp_st)
        if st_dir in forbidden_exact_roots or st_dir in ("/tmp", "/var/tmp"):
            self._raise_plugin_policy_error(
                f"plugin_state_dir '{st_dir}' cannot be a top-level system, temp, or HOME root"
            )
        self._check_no_symlink_ancestors(st_dir, "plugin_state_dir")
        if os.path.lexists(st_dir):
            try:
                st_info = os.lstat(st_dir)
            except OSError as exc:
                self._raise_plugin_policy_error(
                    f"Cannot inspect plugin_state_dir '{st_dir}': {exc}"
                )
            if stat.S_ISLNK(st_info.st_mode) or not stat.S_ISDIR(st_info.st_mode):
                self._raise_plugin_policy_error(
                    f"plugin_state_dir '{st_dir}' must be a regular non-symlink directory"
                )
            if st_info.st_mode & 0o002:
                self._raise_plugin_policy_error(
                    f"plugin_state_dir '{st_dir}' must not be world-writable"
                )
            if hasattr(os, "getuid") and st_info.st_uid not in (os.getuid(), 0):
                self._raise_plugin_policy_error(
                    f"plugin_state_dir '{st_dir}' is owned by untrusted uid {st_info.st_uid}"
                )
        if _paths_overlap_any_direction(st_dir, rt_root):
            self._raise_plugin_policy_error(
                f"plugin_state_dir '{st_dir}' cannot overlap agent_runtime_home_root '{rt_root}'"
            )
        for sys_tree in forbidden_system_trees:
            if sys_tree in ("/tmp", "/var/tmp"):
                continue
            if _paths_overlap_any_direction(st_dir, sys_tree):
                self._raise_plugin_policy_error(
                    f"plugin_state_dir '{st_dir}' overlaps forbidden system/SDK path '{sys_tree}'"
                )
        for prot_root, prot_label in protected_boundaries:
            # Allow default `~/.cache/dots-sandbox/plugin_state` when broad `$HOME` is in `protected_paths`
            # unless `home_covered` by `allowed_workdirs` (workspace check below still rejects workspace overlap).
            if prot_root in (home_lex, home_res) and st_dir not in (home_lex, home_res):
                continue
            if _paths_overlap_any_direction(st_dir, prot_root):
                self._raise_plugin_policy_error(
                    f"plugin_state_dir '{st_dir}' overlaps protected {prot_label} ('{prot_root}')"
                )

        ws_candidates: List[str] = [
            *self._allowed_roots,
            *[
                os.path.abspath(os.path.expanduser(str(x)))
                for x in (
                    *self.config.agy_extra_workspace_dirs,
                    *self.config.codex_extra_writable_roots,
                    *self.config.docker_extra_bind_roots,
                )
                if str(x).strip()
            ],
        ]
        if self.config.default_workdir:
            ws_candidates.append(
                os.path.abspath(os.path.expanduser(str(self.config.default_workdir)))
            )
        if cwd:
            ws_candidates.append(os.path.abspath(os.path.expanduser(str(cwd))))
        if add_dirs:
            for ad in add_dirs:
                ws_candidates.append(os.path.abspath(os.path.expanduser(str(ad))))
        for ws_c in ws_candidates:
            if ws_c in (home_lex, home_res):
                continue
            if _paths_overlap_any_direction(st_dir, ws_c):
                self._raise_plugin_policy_error(
                    f"plugin_state_dir '{st_dir}' overlaps project workspace '{ws_c}'; "
                    "keep plugin runtime state separate from task workspaces"
                )
        return st_dir

    def _validate_plugin_source_directory_tree(
        self,
        raw_dir: str,
        *,
        agent_label: str,
        home_lex: str,
        home_res: str,
        rt_root: str,
        st_dir: str,
        forbidden_exact_roots: set[str],
        forbidden_system_trees: Sequence[str],
        protected_boundaries: Sequence[Tuple[str, str]],
        writable_boundaries: Sequence[Tuple[str, str]],
        allow_internal_symlinks: bool = True,
    ) -> str:
        if any(ch in raw_dir for ch in ("\x00", "\r", "\n", ")")):
            self._raise_plugin_policy_error(
                f"Invalid characters in registered {agent_label} plugin path '{raw_dir}'"
            )
        expanded = os.path.expanduser(raw_dir.strip())
        if not expanded.startswith("/"):
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin path '{raw_dir}' must be an absolute path"
            )
        source_dir = os.path.abspath(expanded)

        if (
            source_dir in forbidden_exact_roots
            or _path_is_within(home_lex, source_dir)
            or _path_is_within(home_res, source_dir)
        ):
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin path '{source_dir}' cannot be a top-level system or HOME root"
            )

        if os.path.islink(source_dir):
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin path '{source_dir}' must be a real directory, not a symlink"
            )
        try:
            st_src = os.lstat(source_dir)
        except FileNotFoundError:
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin directory '{source_dir}' does not exist"
            )
        except OSError as exc:
            self._raise_plugin_policy_error(
                f"Cannot stat registered {agent_label} plugin directory '{source_dir}': {exc}"
            )

        if stat.S_ISLNK(st_src.st_mode) or not stat.S_ISDIR(st_src.st_mode):
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin path '{source_dir}' is not a directory"
            )
        if os.path.realpath(source_dir) != source_dir:
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin path '{source_dir}' traverses a symlinked parent directory "
                f"(resolves to '{os.path.realpath(source_dir)}'); use the canonical directory path"
            )
        if st_src.st_mode & 0o002:
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin directory '{source_dir}' must not be world-writable"
            )
        if hasattr(os, "getuid") and st_src.st_uid not in (os.getuid(), 0):
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin directory '{source_dir}' is owned by untrusted uid {st_src.st_uid}"
            )
        if not os.access(source_dir, os.R_OK | os.X_OK):
            self._raise_plugin_policy_error(
                f"Registered {agent_label} plugin directory '{source_dir}' is not readable/traversable by gateway user"
            )

        for sys_tree in forbidden_system_trees:
            if _paths_overlap_any_direction(source_dir, sys_tree):
                self._raise_plugin_policy_error(
                    f"Registered {agent_label} plugin directory '{source_dir}' overlaps forbidden system/temp/SDK path '{sys_tree}'"
                )

        for prot_root, prot_label in protected_boundaries:
            # When broad `$HOME` itself is in `protected_paths`, every credential/gateway/login
            # subdirectory (`~/gateway`, `~/.config`, `~/.gemini`, `~/.codex`, `~/.ssh`, `~/.local`,
            # etc.) and every explicit non-`$HOME` umbrella path is still enforced individually
            # in `protected_boundaries`, while plugin discovery runs outside `$HOME` under
            # `agent_runtime_home_root` without weakening `read_file($HOME)` in `permissions.deny`.
            if prot_root in (home_lex, home_res) and source_dir not in (home_lex, home_res):
                continue
            if _paths_overlap_any_direction(source_dir, prot_root):
                self._raise_plugin_policy_error(
                    f"Registered {agent_label} plugin directory '{source_dir}' overlaps protected {prot_label} "
                    f"('{prot_root}'); separate plugin resources from gateway/tunnel secrets and login state"
                )

        for wr_root, wr_label in [
            *writable_boundaries,
            (rt_root, "agent_runtime_home_root"),
            (st_dir, "plugin_state_dir"),
        ]:
            if _paths_overlap_any_direction(source_dir, wr_root):
                self._raise_plugin_policy_error(
                    f"Registered {agent_label} plugin directory '{source_dir}' overlaps writable {wr_label} "
                    f"('{wr_root}'); plugin resources must stay strictly read-only and disjoint from workspaces/caches"
                )

        entry_count = 0
        max_entries = 20000
        for walk_root, dirnames, filenames in os.walk(
            source_dir, topdown=True, followlinks=False
        ):
            for entry_name in list(dirnames) + list(filenames):
                entry_count += 1
                if entry_count > max_entries:
                    self._raise_plugin_policy_error(
                        f"{agent_label} plugin directory '{source_dir}' exceeds maximum file count ({max_entries})"
                    )
                entry_full = os.path.join(walk_root, entry_name)
                try:
                    est = os.lstat(entry_full)
                except OSError as exc:
                    self._raise_plugin_policy_error(
                        f"Cannot inspect plugin entry '{entry_full}': {exc}"
                    )
                if stat.S_ISLNK(est.st_mode):
                    if not allow_internal_symlinks:
                        self._raise_plugin_policy_error(
                            f"Symlink '{entry_full}' inside {agent_label} plugin '{source_dir}' is forbidden "
                            "(Codex plugin content hash verification rejects symlinks)"
                        )
                    if not os.path.exists(entry_full):
                        self._raise_plugin_policy_error(
                            f"Dangling symlink '{entry_full}' inside {agent_label} plugin '{source_dir}' is forbidden"
                        )
                    target_real = os.path.realpath(entry_full)
                    if not _path_is_within(target_real, source_dir):
                        self._raise_plugin_policy_error(
                            f"Symlink '{entry_full}' inside {agent_label} plugin '{source_dir}' escapes to "
                            f"'{target_real}', which is forbidden by security policy"
                        )
                elif stat.S_ISREG(est.st_mode):
                    if est.st_mode & 0o002:
                        self._raise_plugin_policy_error(
                            f"World-writable file '{entry_full}' inside {agent_label} plugin '{source_dir}' is forbidden"
                        )
                    if est.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        self._raise_plugin_policy_error(
                            f"Setuid/setgid file '{entry_full}' inside {agent_label} plugin '{source_dir}' is forbidden"
                        )
                elif stat.S_ISDIR(est.st_mode):
                    if est.st_mode & 0o002:
                        self._raise_plugin_policy_error(
                            f"World-writable subdirectory '{entry_full}' inside {agent_label} plugin '{source_dir}' is forbidden"
                        )
                else:
                    self._raise_plugin_policy_error(
                        f"Special device/socket/FIFO '{entry_full}' inside {agent_label} plugin '{source_dir}' is forbidden"
                    )
        return source_dir

    def validate_agy_plugins(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
        require_mount_ns_check: bool = False,
    ) -> List[ValidatedAgyPlugin]:
        """Validate operator-registered AGY plugin directories fail-closed.

        Enforces strict separation between:
        1. Read-only plugin resources (`skills/`, `hooks/`, `rules/`, scripts, `plugin.json`),
        2. Per-task writable project workspaces & isolated plugin runtime state, and
        3. Gateway/tunnel credentials & AGY login state (`~/.gemini`, `~/.config/*`, or broad `HOME`).

        Plugin discovery runs inside `agent_runtime_home_root/agy/.gemini/config/plugins/<name>`
        so parent `permissions.deny` rules on `$HOME` or credential directories are never deleted
        or weakened, and native hooks are validated for mandatory hook-jail wrapping.
        """
        state = agy_plugins_config_state(self.config)
        if state.get("config_error"):
            self._raise_plugin_policy_error(str(state["config_error"]))
        if not state.get("enabled"):
            return []

        raw_dirs = list(state.get("raw_dirs") or [])
        if not raw_dirs:
            self._raise_plugin_policy_error(
                "AGY plugins are enabled, but no plugin directories are registered "
                "(configure 'agy_plugin_dirs' or run 'dots-gateway agy-plugins add <DIR>')"
            )

        if not self.config.isolate_mount_namespace:
            self._raise_plugin_policy_error(
                "AGY plugins require isolate_mount_namespace=True so kernel VFS read-only mounts "
                "and AGY session permissions stay synchronized"
            )
        if not self.config.agy_default_sandbox:
            self._raise_plugin_policy_error(
                "AGY plugins require agy_default_sandbox=True so AGY '--sandbox' and '--settings' "
                "read-only rules stay enforced"
            )
        if require_mount_ns_check and not can_use_mount_namespace():
            self._raise_plugin_policy_error(
                "AGY plugins require unprivileged Linux user+mount namespaces, "
                "which are unavailable on this host"
            )

        home_lex = os.path.abspath(str(Path.home()))
        try:
            home_res = str(Path.home().resolve())
        except OSError:
            home_res = home_lex

        if os.path.islink(home_lex) or home_lex != home_res:
            self._raise_plugin_policy_error(
                f"AGY plugins require a non-symlink HOME directory (got '{home_lex}' -> '{home_res}')"
            )

        home_covered_by_ws = any(_path_is_within(home_res, r) for r in self._allowed_roots)
        gem_lex = os.path.join(home_res, ".gemini")
        if home_covered_by_ws and os.path.islink(gem_lex):
            self._raise_plugin_policy_error(
                "AGY plugins forbid symlinked '~/.gemini' when $HOME is covered by allowed_workdirs"
            )
        if os.path.islink(gem_lex) and not os.path.exists(gem_lex):
            self._raise_plugin_policy_error("Dangling symlink at '~/.gemini' is forbidden")
        if os.path.exists(gem_lex):
            gem_real = os.path.realpath(gem_lex)
            for sub_rel, sub_label in (
                ("config", "~/.gemini/config"),
                (os.path.join("config", "plugins"), "~/.gemini/config/plugins"),
                ("antigravity-cli", "~/.gemini/antigravity-cli"),
            ):
                sub_cand = os.path.join(gem_real, sub_rel)
                if os.path.islink(sub_cand):
                    self._raise_plugin_policy_error(
                        f"Symlink at '{sub_label}' is forbidden when AGY plugins are enabled"
                    )
                if os.path.exists(sub_cand) and not os.path.isdir(sub_cand):
                    self._raise_plugin_policy_error(
                        f"'{sub_label}' must be a directory when AGY plugins are enabled"
                    )

        (
            forbidden_exact_roots,
            forbidden_system_trees,
            protected_boundaries,
            writable_boundaries,
        ) = self._build_plugin_boundary_sets(
            home_lex=home_lex, home_res=home_res, cwd=cwd, add_dirs=add_dirs
        )
        rt_root = self.validate_agent_runtime_home_root(
            home_lex=home_lex,
            home_res=home_res,
            forbidden_exact_roots=forbidden_exact_roots,
            forbidden_system_trees=forbidden_system_trees,
            protected_boundaries=protected_boundaries,
            writable_boundaries=writable_boundaries,
        )
        st_dir = self.validate_plugin_state_dir(
            home_lex=home_lex,
            home_res=home_res,
            rt_root=rt_root,
            forbidden_exact_roots=forbidden_exact_roots,
            forbidden_system_trees=forbidden_system_trees,
            protected_boundaries=protected_boundaries,
            cwd=cwd,
            add_dirs=add_dirs,
        )

        settings_deny_rules: List[str] = []
        cli_dir = Path.home() / ".gemini" / "antigravity-cli"
        if cli_dir.is_symlink():
            self._raise_plugin_policy_error(
                f"Symlinked AGY settings directory '{cli_dir}' is forbidden"
            )
        settings_path = cli_dir / "settings.json"
        if settings_path.is_symlink():
            self._raise_plugin_policy_error(
                f"Symlinked AGY settings file '{settings_path}' is forbidden"
            )
        if settings_path.exists():
            if not settings_path.is_file():
                self._raise_plugin_policy_error(
                    f"AGY settings path '{settings_path}' must be a regular file"
                )
            try:
                raw_settings = json.loads(settings_path.read_text(encoding="utf-8"))
            except Exception as exc:
                self._raise_plugin_policy_error(
                    f"Cannot parse '{settings_path}' while validating AGY plugin deny rules: {exc}"
                )
            if isinstance(raw_settings, dict) and isinstance(
                raw_settings.get("permissions"), dict
            ):
                raw_deny = raw_settings["permissions"].get("deny")
                if isinstance(raw_deny, list):
                    settings_deny_rules = [
                        _expand_host_tilde_in_agy_rule(str(x), home_res)
                        for x in raw_deny
                    ]

        effective_deny_rules = list(self.get_agy_denied_rules())
        for s_rule in settings_deny_rules:
            if s_rule not in effective_deny_rules:
                effective_deny_rules.append(s_rule)

        denied_read_paths: List[Tuple[str, str]] = []
        for rule in effective_deny_rules:
            m_deny = _READ_FILE_RULE_RE.match(rule.strip())
            if not m_deny:
                continue
            raw_dp = m_deny.group(1).strip()
            if not raw_dp:
                continue
            try:
                dp_exp = (
                    home_res
                    if raw_dp == "~"
                    else (
                        os.path.join(home_res, raw_dp[2:])
                        if raw_dp.startswith("~/")
                        else os.path.expanduser(raw_dp)
                    )
                )
                dp_lex = os.path.abspath(dp_exp)
                denied_read_paths.append((dp_lex, rule))
                if os.path.exists(dp_exp):
                    dp_res = os.path.realpath(dp_exp)
                    if dp_res != dp_lex:
                        denied_read_paths.append((dp_res, rule))
            except OSError:
                continue

        validated: List[ValidatedAgyPlugin] = []
        seen_names: Dict[str, str] = {}

        for raw_dir in raw_dirs:
            source_dir = self._validate_plugin_source_directory_tree(
                raw_dir,
                agent_label="AGY",
                home_lex=home_lex,
                home_res=home_res,
                rt_root=rt_root,
                st_dir=st_dir,
                forbidden_exact_roots=forbidden_exact_roots,
                forbidden_system_trees=forbidden_system_trees,
                protected_boundaries=protected_boundaries,
                writable_boundaries=writable_boundaries,
            )

            dir_base = os.path.basename(source_dir)
            if not _SAFE_AGY_PLUGIN_NAME_RE.match(dir_base):
                self._raise_plugin_policy_error(
                    f"Invalid AGY plugin directory name '{dir_base}' at '{source_dir}'"
                )

            manifest_label = ""
            plugin_name = dir_base
            manifest_path = os.path.join(source_dir, "plugin.json")
            if os.path.lexists(manifest_path):
                try:
                    mst = os.lstat(manifest_path)
                except OSError as exc:
                    self._raise_plugin_policy_error(
                        f"Cannot inspect plugin manifest '{manifest_path}': {exc}"
                    )
                if stat.S_ISLNK(mst.st_mode) or not stat.S_ISREG(mst.st_mode):
                    self._raise_plugin_policy_error(
                        f"Plugin manifest '{manifest_path}' must be a regular non-symlink file"
                    )
                try:
                    manifest_data = json.loads(
                        Path(manifest_path).read_text(encoding="utf-8")
                    )
                except Exception as exc:
                    self._raise_plugin_policy_error(
                        f"Invalid JSON in plugin manifest '{manifest_path}': {exc}"
                    )
                if not isinstance(manifest_data, dict):
                    self._raise_plugin_policy_error(
                        f"Plugin manifest '{manifest_path}' must contain a JSON object"
                    )
                if manifest_data.get("disabled") is True:
                    self._raise_plugin_policy_error(
                        f"Plugin '{source_dir}' has 'disabled: true' in plugin.json"
                    )
                raw_mname = manifest_data.get("name")
                if raw_mname is not None:
                    if not isinstance(raw_mname, str) or not _SAFE_AGY_PLUGIN_NAME_RE.match(
                        raw_mname.strip()
                    ):
                        self._raise_plugin_policy_error(
                            f"Invalid 'name' field in '{manifest_path}'"
                        )
                    plugin_name = raw_mname.strip()
                raw_hooks_ref = manifest_data.get("hooks")
                if raw_hooks_ref is not None:
                    if not isinstance(raw_hooks_ref, str) or os.path.normpath(
                        raw_hooks_ref.strip()
                    ) not in ("hooks.json", os.path.join("hooks", "hooks.json")):
                        self._raise_plugin_policy_error(
                            f"Unsupported 'hooks' path '{raw_hooks_ref}' in '{manifest_path}'; "
                            "must be './hooks.json' or './hooks/hooks.json'"
                        )
                manifest_label = "plugin.json"

            hooks_relpath: Optional[str] = None
            if os.path.isfile(os.path.join(source_dir, "hooks.json")):
                hooks_relpath = "hooks.json"
            elif os.path.isfile(os.path.join(source_dir, "hooks", "hooks.json")):
                hooks_relpath = os.path.join("hooks", "hooks.json")
            has_hooks_json = hooks_relpath is not None
            has_component_dir = any(
                os.path.isdir(os.path.join(source_dir, comp))
                for comp in ("skills", "hooks", "rules")
            )
            if not (manifest_label or has_hooks_json or has_component_dir):
                self._raise_plugin_policy_error(
                    f"Directory '{source_dir}' is not a valid AGY plugin (missing plugin.json, hooks.json, skills/, hooks/, or rules/)"
                )
            if not manifest_label:
                manifest_label = "hooks.json" if has_hooks_json else "directory"

            if plugin_name in seen_names:
                self._raise_plugin_policy_error(
                    f"Duplicate AGY plugin name '{plugin_name}' between '{seen_names[plugin_name]}' and '{source_dir}'"
                )
            for prev in validated:
                if _paths_overlap_any_direction(source_dir, prev.source_dir):
                    self._raise_plugin_policy_error(
                        f"Registered AGY plugin directories '{prev.source_dir}' and '{source_dir}' overlap"
                    )

            vfs_discovery_dir = os.path.join(
                rt_root, "agy", ".gemini", "config", "plugins", plugin_name
            )
            if ")" in vfs_discovery_dir:
                self._raise_plugin_policy_error(
                    f"AGY plugin discovery path '{vfs_discovery_dir}' contains unsupported ')' character"
                )

            for hooks_cand_rel in ("hooks.json", os.path.join("hooks", "hooks.json")):
                hooks_cand_full = Path(source_dir) / hooks_cand_rel
                if hooks_cand_full.exists() or hooks_cand_full.is_symlink():
                    try:
                        validate_plugin_hooks_manifest(
                            hooks_cand_full,
                            agent="agy",
                            plugin_name=plugin_name,
                            source_dir=source_dir,
                            vfs_discovery_dir=vfs_discovery_dir,
                        )
                    except Exception as exc:
                        self._raise_plugin_policy_error(str(exc))

            for denied_p, deny_rule in denied_read_paths:
                if _path_is_within(vfs_discovery_dir, denied_p):
                    self._raise_plugin_policy_error(
                        f"AGY plugin discovery path '{vfs_discovery_dir}' is blocked by parent permissions.deny "
                        f"rule '{deny_rule}'; configure 'agent_runtime_home_root' outside denied paths"
                    )
                if denied_p in (home_lex, home_res) and source_dir not in (home_lex, home_res):
                    continue
                if _paths_overlap_any_direction(source_dir, denied_p):
                    self._raise_plugin_policy_error(
                        f"AGY plugin '{source_dir}' conflicts with permissions.deny rule '{deny_rule}' "
                        "(deny takes precedence over allow in AGY; move plugin resources outside protected parent directories)"
                    )

            seen_names[plugin_name] = source_dir
            validated.append(
                ValidatedAgyPlugin(
                    name=plugin_name,
                    source_dir=source_dir,
                    vfs_discovery_dir=vfs_discovery_dir,
                    manifest=manifest_label,
                    hooks_relpath=hooks_relpath,
                )
            )

        return validated

    def get_agy_plugins_info(self) -> Dict[str, Any]:
        """Return safe, secret-redacted diagnostic state for operator-registered AGY plugins."""
        state = agy_plugins_config_state(self.config)
        plugins_file_display = redact_diagnostic_text(
            str(self.config.agy_plugins_file or ""), self.config
        )
        rt_display = redact_diagnostic_text(
            str(self.config.agent_runtime_home_root or "/mnt/dots-agent-home"),
            self.config,
        )
        state_dir_display = redact_diagnostic_text(
            effective_plugin_state_dir(self.config), self.config
        )
        enabled = bool(state.get("enabled"))
        configured = bool(state.get("configured"))
        source = redact_diagnostic_text(str(state.get("source") or ""), self.config)
        raw_dirs = [
            redact_diagnostic_text(str(d), self.config)
            for d in (state.get("raw_dirs") or [])
        ]

        if state.get("config_error"):
            return {
                "enabled": True,
                "configured": True,
                "source": source,
                "plugins_file": plugins_file_display,
                "agent_runtime_home_root": rt_display,
                "plugin_state_dir": state_dir_display,
                "configured_dirs": raw_dirs,
                "valid": False,
                "status": "error",
                "plugins": [],
                "error": redact_diagnostic_text(str(state["config_error"]), self.config),
            }

        if not enabled:
            return {
                "enabled": False,
                "configured": configured,
                "source": source,
                "plugins_file": plugins_file_display,
                "agent_runtime_home_root": rt_display,
                "plugin_state_dir": state_dir_display,
                "configured_dirs": raw_dirs,
                "valid": True,
                "status": "disabled",
                "plugins": [],
                "error": None,
            }

        try:
            validated = self.validate_agy_plugins()
        except Exception as exc:
            return {
                "enabled": True,
                "configured": True,
                "source": source,
                "plugins_file": plugins_file_display,
                "agent_runtime_home_root": rt_display,
                "plugin_state_dir": state_dir_display,
                "configured_dirs": raw_dirs,
                "valid": False,
                "status": "error",
                "plugins": [],
                "error": redact_diagnostic_text(str(exc), self.config),
            }

        return {
            "enabled": True,
            "configured": True,
            "source": source,
            "plugins_file": plugins_file_display,
            "agent_runtime_home_root": rt_display,
            "plugin_state_dir": state_dir_display,
            "configured_dirs": raw_dirs,
            "mount_namespace_available": bool(can_use_mount_namespace()),
            "hook_jail_enforced": True,
            "valid": True,
            "status": "active",
            "plugins": [
                {
                    "name": p.name,
                    "source_dir": redact_diagnostic_text(p.source_dir, self.config),
                    "vfs_discovery_dir": redact_diagnostic_text(
                        p.vfs_discovery_dir, self.config
                    ),
                    "manifest": p.manifest,
                    "mode": "ro",
                }
                for p in validated
            ],
            "error": None,
        }

    def validate_codex_plugins(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
        require_mount_ns_check: bool = False,
    ) -> List[ValidatedCodexPlugin]:
        """Validate operator-registered Codex plugin directories fail-closed."""
        state = codex_plugins_config_state(self.config)
        if state.get("config_error"):
            self._raise_plugin_policy_error(str(state["config_error"]))
        if not state.get("enabled"):
            return []

        raw_dirs = list(state.get("raw_dirs") or [])
        if not raw_dirs:
            self._raise_plugin_policy_error(
                "Codex plugins are enabled, but no plugin directories are registered "
                "(configure 'codex_plugin_dirs' or run 'dots-gateway codex-plugins add <DIR>')"
            )

        if not self.config.isolate_mount_namespace:
            self._raise_plugin_policy_error(
                "Codex plugins require isolate_mount_namespace=True so kernel VFS read-only mounts "
                "and Codex hook-jail sandboxing stay enforced"
            )
        if self.config.codex_default_sandbox not in ("read-only", "workspace-write"):
            self._raise_plugin_policy_error(
                f"Codex plugins require codex_default_sandbox in ('read-only', 'workspace-write'), "
                f"got '{self.config.codex_default_sandbox}'"
            )
        if require_mount_ns_check and not can_use_mount_namespace():
            self._raise_plugin_policy_error(
                "Codex plugins require unprivileged Linux user+mount namespaces, "
                "which are unavailable on this host"
            )

        home_lex = os.path.abspath(str(Path.home()))
        try:
            home_res = str(Path.home().resolve())
        except OSError:
            home_res = home_lex

        if os.path.islink(home_lex) or home_lex != home_res:
            self._raise_plugin_policy_error(
                f"Codex plugins require a non-symlink HOME directory (got '{home_lex}' -> '{home_res}')"
            )

        codex_home_lex = os.path.join(home_res, ".codex")
        if os.path.islink(codex_home_lex):
            self._raise_plugin_policy_error(
                "Codex plugins forbid symlinked '~/.codex'"
            )

        (
            forbidden_exact_roots,
            forbidden_system_trees,
            protected_boundaries,
            writable_boundaries,
        ) = self._build_plugin_boundary_sets(
            home_lex=home_lex, home_res=home_res, cwd=cwd, add_dirs=add_dirs
        )
        rt_root = self.validate_agent_runtime_home_root(
            home_lex=home_lex,
            home_res=home_res,
            forbidden_exact_roots=forbidden_exact_roots,
            forbidden_system_trees=forbidden_system_trees,
            protected_boundaries=protected_boundaries,
            writable_boundaries=writable_boundaries,
        )
        st_dir = self.validate_plugin_state_dir(
            home_lex=home_lex,
            home_res=home_res,
            rt_root=rt_root,
            forbidden_exact_roots=forbidden_exact_roots,
            forbidden_system_trees=forbidden_system_trees,
            protected_boundaries=protected_boundaries,
            cwd=cwd,
            add_dirs=add_dirs,
        )

        validated: List[ValidatedCodexPlugin] = []
        seen_names: Dict[str, str] = {}

        for raw_dir in raw_dirs:
            source_dir = self._validate_plugin_source_directory_tree(
                raw_dir,
                agent_label="Codex",
                home_lex=home_lex,
                home_res=home_res,
                rt_root=rt_root,
                st_dir=st_dir,
                forbidden_exact_roots=forbidden_exact_roots,
                forbidden_system_trees=forbidden_system_trees,
                protected_boundaries=protected_boundaries,
                writable_boundaries=writable_boundaries,
                allow_internal_symlinks=False,
            )

            dir_base = os.path.basename(source_dir)
            if not _SAFE_AGY_PLUGIN_NAME_RE.match(dir_base):
                self._raise_plugin_policy_error(
                    f"Invalid Codex plugin directory name '{dir_base}' at '{source_dir}'"
                )

            plugin_name = dir_base
            plugin_version = "local"
            manifest_label = ""

            codex_manifest_p = Path(source_dir) / ".codex-plugin" / "plugin.json"
            fallback_manifest_p = Path(source_dir) / "plugin.json"
            active_manifest_p: Optional[Path] = None
            if codex_manifest_p.exists() or codex_manifest_p.is_symlink():
                active_manifest_p = codex_manifest_p
                manifest_label = ".codex-plugin/plugin.json"
            elif fallback_manifest_p.exists() or fallback_manifest_p.is_symlink():
                active_manifest_p = fallback_manifest_p
                manifest_label = "plugin.json"

            if active_manifest_p is not None:
                mst = os.lstat(active_manifest_p)
                if stat.S_ISLNK(mst.st_mode) or not stat.S_ISREG(mst.st_mode):
                    self._raise_plugin_policy_error(
                        f"Codex plugin manifest '{active_manifest_p}' must be a regular non-symlink file"
                    )
                try:
                    m_data = json.loads(active_manifest_p.read_text(encoding="utf-8"))
                except Exception as exc:
                    self._raise_plugin_policy_error(
                        f"Invalid JSON in Codex plugin manifest '{active_manifest_p}': {exc}"
                    )
                if not isinstance(m_data, dict):
                    self._raise_plugin_policy_error(
                        f"Codex plugin manifest '{active_manifest_p}' must contain a JSON object"
                    )
                if m_data.get("disabled") is True:
                    self._raise_plugin_policy_error(
                        f"Codex plugin '{source_dir}' has 'disabled: true' in '{manifest_label}'"
                    )
                raw_mname = m_data.get("name")
                if raw_mname is not None:
                    if not isinstance(raw_mname, str) or not _SAFE_AGY_PLUGIN_NAME_RE.match(
                        raw_mname.strip()
                    ):
                        self._raise_plugin_policy_error(
                            f"Invalid 'name' field in '{active_manifest_p}'"
                        )
                    plugin_name = raw_mname.strip()
                raw_ver = m_data.get("version")
                if raw_ver is not None:
                    if not isinstance(raw_ver, str) or not _SAFE_CODEX_VERSION_RE.match(
                        raw_ver.strip()
                    ):
                        self._raise_plugin_policy_error(
                            f"Invalid 'version' field in '{active_manifest_p}'"
                        )
                    plugin_version = raw_ver.strip()
                raw_hooks_ref = m_data.get("hooks")
                if raw_hooks_ref is not None:
                    if not isinstance(raw_hooks_ref, str) or os.path.normpath(
                        raw_hooks_ref.strip()
                    ) not in (os.path.join("hooks", "hooks.json"), "hooks.json"):
                        self._raise_plugin_policy_error(
                            f"Unsupported 'hooks' path '{raw_hooks_ref}' in '{active_manifest_p}'; "
                            "must be './hooks/hooks.json' or './hooks.json'"
                        )

            marketplace_name = f"dots-gateway-{plugin_name}"[:64]
            mkt_manifest_p = Path(source_dir) / ".agents" / "plugins" / "marketplace.json"
            if mkt_manifest_p.exists() or mkt_manifest_p.is_symlink():
                mk_st = os.lstat(mkt_manifest_p)
                if stat.S_ISLNK(mk_st.st_mode) or not stat.S_ISREG(mk_st.st_mode):
                    self._raise_plugin_policy_error(
                        f"Codex marketplace manifest '{mkt_manifest_p}' must be a regular non-symlink file"
                    )
                try:
                    mk_data = json.loads(mkt_manifest_p.read_text(encoding="utf-8"))
                except Exception as exc:
                    self._raise_plugin_policy_error(
                        f"Invalid JSON in '{mkt_manifest_p}': {exc}"
                    )
                if isinstance(mk_data, dict) and mk_data.get("name") is not None:
                    raw_mk = mk_data.get("name")
                    if not isinstance(raw_mk, str) or not _SAFE_AGY_PLUGIN_NAME_RE.match(
                        raw_mk.strip()
                    ):
                        self._raise_plugin_policy_error(
                            f"Invalid marketplace 'name' in '{mkt_manifest_p}'"
                        )
                    marketplace_name = raw_mk.strip()

            hooks_relpath: Optional[str] = None
            if (Path(source_dir) / "hooks" / "hooks.json").is_file():
                hooks_relpath = os.path.join("hooks", "hooks.json")
            elif (Path(source_dir) / "hooks.json").is_file():
                hooks_relpath = "hooks.json"

            has_skills = os.path.isdir(os.path.join(source_dir, "skills"))
            if not (manifest_label or hooks_relpath or has_skills):
                self._raise_plugin_policy_error(
                    f"Directory '{source_dir}' is not a valid Codex plugin "
                    "(missing .codex-plugin/plugin.json, skills/, or hooks/hooks.json)"
                )
            if not manifest_label:
                manifest_label = hooks_relpath or "directory"

            if plugin_name in seen_names:
                self._raise_plugin_policy_error(
                    f"Duplicate Codex plugin name '{plugin_name}' between '{seen_names[plugin_name]}' and '{source_dir}'"
                )
            for prev in validated:
                if _paths_overlap_any_direction(source_dir, prev.source_dir):
                    self._raise_plugin_policy_error(
                        f"Registered Codex plugin directories '{prev.source_dir}' and '{source_dir}' overlap"
                    )

            vfs_discovery_dir = os.path.join(
                rt_root,
                "codex",
                ".codex",
                "plugins",
                "cache",
                marketplace_name,
                plugin_name,
                plugin_version,
            )

            for hooks_cand_rel in (os.path.join("hooks", "hooks.json"), "hooks.json"):
                hooks_cand_full = Path(source_dir) / hooks_cand_rel
                if hooks_cand_full.exists() or hooks_cand_full.is_symlink():
                    try:
                        validate_plugin_hooks_manifest(
                            hooks_cand_full,
                            agent="codex",
                            plugin_name=plugin_name,
                            source_dir=source_dir,
                            vfs_discovery_dir=vfs_discovery_dir,
                        )
                    except Exception as exc:
                        self._raise_plugin_policy_error(str(exc))

            seen_names[plugin_name] = source_dir
            validated.append(
                ValidatedCodexPlugin(
                    name=plugin_name,
                    marketplace_name=marketplace_name,
                    version=plugin_version,
                    source_dir=source_dir,
                    vfs_discovery_dir=vfs_discovery_dir,
                    hooks_relpath=hooks_relpath,
                    manifest=manifest_label,
                )
            )

        return validated

    def get_codex_plugins_info(self) -> Dict[str, Any]:
        """Return safe, secret-redacted diagnostic state for operator-registered Codex plugins."""
        state = codex_plugins_config_state(self.config)
        plugins_file_display = redact_diagnostic_text(
            str(self.config.codex_plugins_file or ""), self.config
        )
        rt_display = redact_diagnostic_text(
            str(self.config.agent_runtime_home_root or "/mnt/dots-agent-home"),
            self.config,
        )
        state_dir_display = redact_diagnostic_text(
            effective_plugin_state_dir(self.config), self.config
        )
        enabled = bool(state.get("enabled"))
        configured = bool(state.get("configured"))
        source = redact_diagnostic_text(str(state.get("source") or ""), self.config)
        raw_dirs = [
            redact_diagnostic_text(str(d), self.config)
            for d in (state.get("raw_dirs") or [])
        ]

        if state.get("config_error"):
            return {
                "enabled": True,
                "configured": True,
                "source": source,
                "plugins_file": plugins_file_display,
                "agent_runtime_home_root": rt_display,
                "plugin_state_dir": state_dir_display,
                "configured_dirs": raw_dirs,
                "valid": False,
                "status": "error",
                "plugins": [],
                "error": redact_diagnostic_text(str(state["config_error"]), self.config),
            }

        if not enabled:
            return {
                "enabled": False,
                "configured": configured,
                "source": source,
                "plugins_file": plugins_file_display,
                "agent_runtime_home_root": rt_display,
                "plugin_state_dir": state_dir_display,
                "configured_dirs": raw_dirs,
                "valid": True,
                "status": "disabled",
                "plugins": [],
                "error": None,
            }

        try:
            validated = self.validate_codex_plugins()
        except Exception as exc:
            return {
                "enabled": True,
                "configured": True,
                "source": source,
                "plugins_file": plugins_file_display,
                "agent_runtime_home_root": rt_display,
                "plugin_state_dir": state_dir_display,
                "configured_dirs": raw_dirs,
                "valid": False,
                "status": "error",
                "plugins": [],
                "error": redact_diagnostic_text(str(exc), self.config),
            }

        return {
            "enabled": True,
            "configured": True,
            "source": source,
            "plugins_file": plugins_file_display,
            "agent_runtime_home_root": rt_display,
            "plugin_state_dir": state_dir_display,
            "configured_dirs": raw_dirs,
            "mount_namespace_available": bool(can_use_mount_namespace()),
            "hook_jail_enforced": True,
            "valid": True,
            "status": "active",
            "plugins": [
                {
                    "name": p.name,
                    "marketplace": p.marketplace_name,
                    "version": p.version,
                    "source_dir": redact_diagnostic_text(p.source_dir, self.config),
                    "vfs_discovery_dir": redact_diagnostic_text(
                        p.vfs_discovery_dir, self.config
                    ),
                    "hooks_relpath": p.hooks_relpath,
                    "manifest": p.manifest,
                    "mode": "ro",
                }
                for p in validated
            ],
            "error": None,
        }

    def get_agy_workspace_dirs(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> List[str]:
        """Compute validated `--add-dir` workspace paths for `agy`.

        Ensures `agy` (and `PreToolUse` hooks inspecting `workspacePaths`) approves
        validated `add_dirs`, configured `agy_extra_workspace_dirs`, configured
        `allowed_workdirs` (when `agy_include_allowed_workdirs` is enabled, covering
        sibling evidence folders under `~/workspaces`), and linked Git worktree
        metadata directories, without duplicating `resolved_cwd`.
        """
        ok_cwd, cwd_err, resolved_cwd = self.validate_workdir(cwd)
        if not ok_cwd:
            raise PermissionError(cwd_err)

        norm_cwd = os.path.abspath(resolved_cwd)
        dirs: List[str] = []
        seen: set[str] = {norm_cwd}

        def _append_valid(cand_path: str) -> None:
            norm = os.path.abspath(cand_path)
            if norm in seen or norm == "/":
                return
            if (
                self.is_protected_path(norm)
                or self.is_agy_plugin_path(norm)
                or self.is_codex_plugin_path(norm)
                or self.is_plugin_state_path(norm)
                or not self.is_within_allowed_workdirs(norm)
            ):
                return
            seen.add(norm)
            dirs.append(norm)

        if add_dirs:
            for d in add_dirs:
                ok_dir, dir_err, resolved_dir = self.validate_workdir(str(d))
                if not ok_dir:
                    raise PermissionError(dir_err)
                _append_valid(resolved_dir)

        for raw_extra in self.config.agy_extra_workspace_dirs:
            ok_ex, _, resolved_ex = self.validate_workdir(str(raw_extra))
            if ok_ex:
                _append_valid(resolved_ex)

        if self.config.agy_include_allowed_workdirs:
            for root in self._allowed_roots:
                _append_valid(root)

        git_rw_dirs, _ = self.resolve_codex_git_metadata_dirs(
            cwd=resolved_cwd, add_dirs=add_dirs
        )
        for git_dir in git_rw_dirs:
            _append_valid(git_dir)

        return dirs

    def get_agy_writable_roots(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> List[str]:
        """Compute safe `write_file(...)` mount roots for `agy --sandbox`.

        Includes the validated session `cwd` explicitly (because `agy --sandbox`
        otherwise mounts an active sub-workspace read-only in default/enterprise
        mode even when a parent directory is writable), alongside all validated
        `get_agy_workspace_dirs`, configured `allowed_workdirs`, Flutter SDK
        `bin/cache`, and isolated developer toolchain caches.
        """
        ok_cwd, cwd_err, resolved_cwd = self.validate_workdir(cwd)
        if not ok_cwd:
            raise PermissionError(cwd_err)

        roots: List[str] = []
        seen: set[str] = set()

        def _add(cand_path: str) -> None:
            norm = os.path.abspath(cand_path)
            if (
                norm not in seen
                and not self.is_agy_plugin_path(norm)
                and not self.is_codex_plugin_path(norm)
            ):
                seen.add(norm)
                roots.append(norm)

        _add(resolved_cwd)
        for ws_dir in self.get_agy_workspace_dirs(cwd=cwd, add_dirs=add_dirs):
            _add(ws_dir)
        for root in self.get_codex_writable_roots(add_dirs=add_dirs, cwd=cwd):
            _add(root)

        agy_state = agy_plugins_config_state(self.config)
        if agy_state.get("enabled") and not agy_state.get("config_error"):
            rt_root = os.path.abspath(
                os.path.expanduser(
                    str(
                        self.config.agent_runtime_home_root or "/mnt/dots-agent-home"
                    ).strip()
                )
            )
            iso_agy_home = os.path.join(rt_root, "agy")
            for rel in (
                ".pub-cache",
                os.path.join(".config", "flutter"),
                ".dart-tool",
                ".dartServer",
                ".cache",
                ".npm",
                os.path.join(".local", "share"),
                os.path.join(".config", "gh"),
                ".docker",
            ):
                _add(os.path.join(iso_agy_home, rel))
        return roots

    def get_agy_readonly_roots(
        self,
        _validated_plugins: Optional[Sequence[ValidatedAgyPlugin]] = None,
    ) -> List[str]:
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
            if (
                self.is_protected_path(lex)
                or self.is_protected_path(res)
                or self.is_agy_plugin_path(lex)
                or self.is_agy_plugin_path(res)
                or self.is_codex_plugin_path(lex)
                or self.is_codex_plugin_path(res)
                or self.is_plugin_state_path(lex)
                or self.is_plugin_state_path(res)
            ):
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

        plugins_state = agy_plugins_config_state(self.config)
        if plugins_state.get("enabled") and not plugins_state.get("config_error"):
            if _validated_plugins is not None:
                valid_plgs: Sequence[ValidatedAgyPlugin] = _validated_plugins
            else:
                try:
                    valid_plgs = self.validate_agy_plugins()
                except Exception:
                    valid_plgs = []
            for plg in valid_plgs:
                if plg.source_dir not in seen and ")" not in plg.source_dir:
                    seen.add(plg.source_dir)
                    roots.append(plg.source_dir)

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

        docker_on = docker_access_enabled(self.config)
        for raw_cmd in self.config.blocked_commands:
            cmd_str = str(raw_cmd).strip()
            if not cmd_str:
                continue
            base = os.path.basename(cmd_str)
            if docker_on and base in DOCKER_CLI_BASENAMES:
                continue
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
        _validated_plugins: Optional[Sequence[ValidatedAgyPlugin]] = None,
        _inner_sandbox_active: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Build per-session `--settings` JSON for `agy`.

        Configures `toolPermission` (default: `"proceed-in-sandbox"` when inner `agy --sandbox`
        is active, or `"always-proceed"` when outer kernel VFS isolation runs with host-consistent
        network `agy_sandbox_network_access=True` so headless commands run without TUI prompts
        even when `skip_permissions=False`),
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
        inner_sbx = (
            not self._use_agy_host_network_vfs_mode(
                use_sandbox=self.config.agy_default_sandbox
            )
            if _inner_sandbox_active is None
            else bool(_inner_sandbox_active)
        )
        eff_tool_perm = (
            "always-proceed"
            if (not inner_sbx and tool_perm == "proceed-in-sandbox")
            else tool_perm
        )

        plugins_state = agy_plugins_config_state(self.config)
        validated_plugins: List[ValidatedAgyPlugin] = []
        if _validated_plugins is not None:
            validated_plugins = list(_validated_plugins)
        elif plugins_state.get("config_error") or plugins_state.get("enabled"):
            validated_plugins = self.validate_agy_plugins(cwd=cwd, add_dirs=add_dirs)

        home_lex = os.path.abspath(str(Path.home()))
        try:
            home_res = str(Path.home().resolve())
        except OSError:
            home_res = home_lex

        perms: Dict[str, Any] = {}
        cli_dir = Path.home() / ".gemini" / "antigravity-cli"
        if cli_dir.is_symlink():
            self._raise_plugin_policy_error(
                f"Symlinked AGY settings directory '{cli_dir}' is forbidden"
            )
        settings_path = cli_dir / "settings.json"
        if settings_path.is_symlink():
            self._raise_plugin_policy_error(
                f"Symlinked AGY settings file '{settings_path}' is forbidden"
            )
        if settings_path.exists():
            if not settings_path.is_file():
                self._raise_plugin_policy_error(
                    f"AGY settings path '{settings_path}' must be a regular file"
                )
            try:
                raw = json.loads(settings_path.read_text(encoding="utf-8"))
            except Exception as exc:
                self._raise_plugin_policy_error(
                    f"Cannot parse AGY settings file '{settings_path}': {exc}"
                )
            if isinstance(raw, dict) and isinstance(raw.get("permissions"), dict):
                for k, v in raw["permissions"].items():
                    if isinstance(v, list):
                        perms[k] = [
                            _expand_host_tilde_in_agy_rule(str(x), home_res)
                            for x in v
                        ]

        writable_roots = self.get_agy_writable_roots(cwd=cwd, add_dirs=add_dirs)
        writable_set = set(writable_roots)

        rt_root = os.path.abspath(
            os.path.expanduser(
                str(
                    self.config.agent_runtime_home_root or "/mnt/dots-agent-home"
                ).strip()
            )
        )
        iso_agy_home = os.path.join(rt_root, "agy")
        iso_agy_plugins_root = os.path.join(iso_agy_home, ".gemini", "config", "plugins")

        ro_plugin_guards: List[str] = [
            os.path.join(home_lex, ".gemini", "config", "plugins"),
            os.path.join(home_res, ".gemini", "config", "plugins"),
            iso_agy_plugins_root,
            *self.get_configured_agy_plugin_paths(),
            *self.get_configured_codex_plugin_paths(),
        ]
        for plg in validated_plugins:
            for p_guard in (plg.source_dir, plg.vfs_discovery_dir):
                if p_guard not in ro_plugin_guards:
                    ro_plugin_guards.append(p_guard)

        allow_list: List[str] = []
        allow_seen: set[str] = set()

        def _emit_allow(rule: str) -> None:
            if rule and rule not in allow_seen:
                allow_seen.add(rule)
                allow_list.append(rule)

        for ro_root in self.get_agy_readonly_roots(_validated_plugins=validated_plugins):
            if ro_root not in writable_set and ")" not in ro_root:
                _emit_allow(f"read_file({ro_root})")

        host_gitconfig = os.path.join(home_res, ".gitconfig")
        gitconfig_allowed = os.path.isfile(host_gitconfig) and not self.is_protected_path(
            host_gitconfig
        )
        if validated_plugins:
            iso_local_bin = os.path.join(iso_agy_home, ".local", "bin")
            if ")" not in iso_local_bin:
                _emit_allow(f"read_file({iso_local_bin})")
            if gitconfig_allowed:
                iso_gitconfig = os.path.join(iso_agy_home, ".gitconfig")
                if ")" not in iso_gitconfig:
                    _emit_allow(f"read_file({iso_gitconfig})")
        else:
            host_local_bin = os.path.join(home_res, ".local", "bin")
            if os.path.isdir(host_local_bin) and ")" not in host_local_bin:
                _emit_allow(f"read_file({host_local_bin})")
            if gitconfig_allowed and ")" not in host_gitconfig:
                _emit_allow(f"read_file({host_gitconfig})")

        for plg in validated_plugins:
            if ")" not in plg.source_dir:
                _emit_allow(f"read_file({plg.source_dir})")
            if ")" not in plg.vfs_discovery_dir:
                _emit_allow(f"read_file({plg.vfs_discovery_dir})")

        active_plugin_allow_paths = {
            p_path
            for plg in validated_plugins
            for p_path in (plg.source_dir, plg.vfs_discovery_dir)
        }
        plugin_discovery_roots = (
            os.path.join(home_lex, ".gemini", "config", "plugins"),
            os.path.join(home_res, ".gemini", "config", "plugins"),
            iso_agy_plugins_root,
        )

        for existing_rule in perms.get("allow") or []:
            rule_str = str(existing_rule)
            m_wr = _WRITE_FILE_RULE_RE.match(rule_str.strip())
            if m_wr:
                try:
                    wr_cand = os.path.abspath(os.path.expanduser(m_wr.group(1).strip()))
                except OSError:
                    continue
                if any(
                    _paths_overlap_any_direction(wr_cand, guard)
                    for guard in ro_plugin_guards
                ):
                    continue
            m_rd = _READ_FILE_RULE_RE.match(rule_str.strip())
            if m_rd:
                try:
                    rd_cand = os.path.abspath(os.path.expanduser(m_rd.group(1).strip()))
                except OSError:
                    continue
                if self.is_agy_plugin_path(rd_cand) and rd_cand not in active_plugin_allow_paths:
                    continue
                if self.is_codex_plugin_path(rd_cand):
                    continue
                if (
                    any(
                        _path_is_within(rd_cand, disc_root)
                        for disc_root in plugin_discovery_roots
                    )
                    and rd_cand not in active_plugin_allow_paths
                ):
                    continue
            _emit_allow(rule_str)

        for rw_root in writable_roots:
            if ")" not in rw_root and not any(
                _paths_overlap_any_direction(rw_root, guard)
                for guard in ro_plugin_guards
            ):
                _emit_allow(f"write_file({rw_root})")

        perms["allow"] = allow_list

        deny_list: List[str] = list(perms.get("deny") or [])
        deny_seen = set(deny_list)

        def _emit_deny(rule: str) -> None:
            if rule and rule not in deny_seen:
                deny_seen.add(rule)
                deny_list.append(rule)

        for rule in self.get_agy_denied_rules():
            _emit_deny(rule)

        # Prevent task tools from modifying repo-local hook/settings injection paths while
        # keeping `.claude/signals`, `.claude/metrics`, and `docs/exec-plans` writable.
        ok_cwd, _, resolved_cwd = self.validate_workdir(cwd)
        seed_ws_roots: List[str] = []
        if ok_cwd:
            seed_ws_roots.append(resolved_cwd)
            for ws_d in self.get_agy_workspace_dirs(cwd=cwd, add_dirs=add_dirs):
                if ws_d not in seed_ws_roots:
                    seed_ws_roots.append(ws_d)
        for root_w in self._allowed_roots:
            if root_w not in seed_ws_roots:
                seed_ws_roots.append(root_w)
        session_ws_roots: List[str] = []
        for seed_r in seed_ws_roots:
            cur_r = os.path.abspath(seed_r)
            while self.is_within_allowed_workdirs(cur_r):
                if cur_r not in session_ws_roots:
                    session_ws_roots.append(cur_r)
                parent_r = os.path.dirname(cur_r)
                if parent_r == cur_r:
                    break
                cur_r = parent_r
        ro_prot_rel_set = frozenset(WORKSPACE_READONLY_PROTECTED_RELPATHS)
        for ws_r in session_ws_roots:
            for inj_rel in WORKSPACE_HOOK_INJECTION_RELPATHS:
                inj_abs = os.path.join(ws_r, inj_rel)
                if ")" not in inj_abs:
                    if inj_rel in ro_prot_rel_set:
                        _emit_deny(f"write_file({inj_abs})")
                    else:
                        _emit_deny(f"read_file({inj_abs})")

        perms["deny"] = deny_list

        return {
            "toolPermission": eff_tool_perm,
            "permissions": perms,
        }

    def resolve_codex_git_metadata_dirs(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> Tuple[List[str], List[str]]:
        """Resolve validated Git metadata (`commondir` & `gitdir`) and `hooks` paths for Codex.

        In `codex-cli 0.166+`, every writable workspace root automatically receives synthetic
        read-only submounts over `<root>/.git` and (for linked `git worktree` checkouts) the
        resolved `<main-repo>/.git/worktrees/<id>` directory, blocking `index.lock` creation
        even when the parent workspace root is in `writable_roots`.

        Returns `(git_writable_dirs, git_readonly_hook_dirs)` strictly confined to
        `allowed_workdirs` and excluding `protected_paths`, allowing `git add` / `git commit`
        inside standalone repositories, subdirectories, and linked `git worktree` checkouts
        while keeping `<wt>/.git` pointer files and `.git/hooks` read-only.
        """
        start_dirs: List[str] = []
        seen_starts: set[str] = set()

        def _push_start(raw_dir: str, strict: bool) -> None:
            ok_dir, dir_err, resolved_dir = self.validate_workdir(raw_dir)
            if not ok_dir:
                if strict:
                    raise PermissionError(dir_err)
                return
            if resolved_dir not in seen_starts:
                seen_starts.add(resolved_dir)
                start_dirs.append(resolved_dir)

        if cwd is not None:
            _push_start(str(cwd), strict=True)
        elif self.config.default_workdir:
            _push_start(str(self.config.default_workdir), strict=False)

        if add_dirs:
            for d in add_dirs:
                _push_start(str(d), strict=True)

        writable_git_dirs: List[str] = []
        seen_git_dirs: set[str] = set()
        readonly_hook_dirs: List[str] = []
        seen_hook_dirs: set[str] = set()

        def _has_git_metadata_markers(validated_gd: str) -> bool:
            gd_path = Path(validated_gd)
            for marker in ("HEAD", "commondir", "config", "objects"):
                cand_m = gd_path / marker
                if cand_m.exists() or cand_m.is_symlink():
                    return True
            return False

        def _inspect_git_hooks(validated_gd: str) -> None:
            hooks_cand = os.path.join(validated_gd, "hooks")
            if os.path.islink(hooks_cand):
                self._raise_plugin_policy_error(
                    f"Symlinked git hooks path '{hooks_cand}' is forbidden by security policy"
                )
            if os.path.isdir(hooks_cand):
                ok_hk, _, resolved_hk = self.validate_workdir(hooks_cand)
                if ok_hk and resolved_hk not in seen_hook_dirs:
                    seen_hook_dirs.add(resolved_hk)
                    readonly_hook_dirs.append(resolved_hk)

        def _record_git_dir(raw_cand: Path) -> Optional[str]:
            ok_gd, _, resolved_gd = self.validate_workdir(str(raw_cand))
            if not ok_gd:
                return None
            _inspect_git_hooks(resolved_gd)
            if not _has_git_metadata_markers(resolved_gd):
                return None
            if resolved_gd not in seen_git_dirs:
                seen_git_dirs.add(resolved_gd)
                writable_git_dirs.append(resolved_gd)
            return resolved_gd

        def _record_commondir_if_present(validated_git_dir: str) -> Optional[str]:
            common_file = Path(validated_git_dir) / "commondir"
            try:
                if common_file.is_symlink():
                    self._raise_plugin_policy_error(
                        f"Symlinked git commondir file '{common_file}' is forbidden by security policy"
                    )
                if (
                    common_file.is_file()
                    and common_file.stat().st_size <= 8192
                ):
                    lines = [
                        ln.strip()
                        for ln in common_file.read_text(
                            encoding="utf-8", errors="replace"
                        ).splitlines()
                        if ln.strip()
                    ]
                    if lines:
                        raw_common = lines[0]
                        cand_common = (
                            Path(raw_common)
                            if os.path.isabs(raw_common)
                            else (Path(validated_git_dir) / raw_common)
                        )
                        return _record_git_dir(cand_common)
            except PermissionError:
                raise
            except OSError:
                pass
            return None

        for start in start_dirs:
            cur = Path(start)
            while True:
                cur_str = str(cur)
                if not self.is_within_allowed_workdirs(cur_str) or self.is_protected_path(cur_str):
                    break
                dot_git = cur / ".git"
                dot_git_lex = os.path.abspath(str(dot_git))
                if not self.is_protected_path(dot_git_lex):
                    try:
                        if dot_git.is_symlink():
                            self._raise_plugin_policy_error(
                                f"Symlinked .git path '{dot_git_lex}' is forbidden by security policy"
                            )
                        if dot_git.is_dir():
                            ok_dg, _, prelim_gd = self.validate_workdir(str(dot_git))
                            if ok_dg:
                                _record_commondir_if_present(prelim_gd)
                                recorded_gd = _record_git_dir(Path(prelim_gd))
                                if recorded_gd is not None:
                                    break
                            else:
                                break
                        if (
                            dot_git.is_file()
                            and dot_git.stat().st_size <= 8192
                        ):
                            first_lines = [
                                ln.strip()
                                for ln in dot_git.read_text(
                                    encoding="utf-8", errors="replace"
                                ).splitlines()
                                if ln.strip()
                            ]
                            if first_lines and first_lines[0].startswith("gitdir:"):
                                raw_gitdir = first_lines[0][len("gitdir:") :].strip()
                                if raw_gitdir:
                                    cand_gd = (
                                        Path(raw_gitdir)
                                        if os.path.isabs(raw_gitdir)
                                        else (cur / raw_gitdir)
                                    )
                                    ok_gd, _, prelim_gd = self.validate_workdir(str(cand_gd))
                                    if ok_gd:
                                        _record_commondir_if_present(prelim_gd)
                                        _record_git_dir(Path(prelim_gd))
                            break
                    except PermissionError:
                        raise
                    except OSError:
                        break

                parent = cur.parent
                if parent == cur:
                    break
                cur = parent

        return writable_git_dirs, readonly_hook_dirs

    def get_codex_writable_roots(
        self,
        add_dirs: Optional[Sequence[str]] = None,
        cwd: Optional[str] = None,
    ) -> List[str]:
        """Compute safe `sandbox_workspace_write.writable_roots` for Codex CLI.

        Exposes all configured `allowed_workdirs`, validated Git `commondir` & worktree
        `gitdir` metadata directories for `cwd` / `add_dirs` (so `git add` & `git commit`
        succeed inside standalone repos and linked `git worktree` checkouts while `.git/hooks`
        is locked read-only by `sandbox.py`), `.codex/signals` and `.codex/metrics` inside
        project workspaces (so `oh-my-agents` verify contracts succeed even though `codex`
        mounts `<workspace>/.codex` read-only), Flutter SDK's `bin/cache`, and isolated
        developer toolchain caches mounted by `sandbox.py`, while keeping SDK binaries,
        plugin code directories, `~/gateway`, `~/.ssh`, `~/.codex`, `~/.gemini`, and
        `~/.config/dots-gateway` read-only or hidden.
        """
        roots: List[str] = []
        seen: set[str] = set()

        def _add(cand_path: str) -> None:
            norm = os.path.abspath(cand_path)
            if (
                norm not in seen
                and not self.is_agy_plugin_path(norm)
                and not self.is_codex_plugin_path(norm)
            ):
                seen.add(norm)
                roots.append(norm)

        ws_scan_dirs: List[str] = []
        for allowed in self._allowed_roots:
            _add(allowed)
            ws_scan_dirs.append(allowed)

        if cwd is not None:
            ok_cwd, cwd_err, resolved_cwd = self.validate_workdir(str(cwd))
            if not ok_cwd:
                raise PermissionError(cwd_err)
            if resolved_cwd not in ws_scan_dirs:
                ws_scan_dirs.append(resolved_cwd)

        if add_dirs:
            for d in add_dirs:
                ok_dir, dir_err, resolved_dir = self.validate_workdir(str(d))
                if not ok_dir:
                    raise PermissionError(dir_err)
                _add(resolved_dir)
                if resolved_dir not in ws_scan_dirs:
                    ws_scan_dirs.append(resolved_dir)

        git_writable_dirs, _ = self.resolve_codex_git_metadata_dirs(
            cwd=cwd, add_dirs=add_dirs
        )
        for gd in git_writable_dirs:
            _add(gd)

        # `codex-linux-sandbox` mounts `<workspace>/.codex` read-only when `<workspace>/.codex`
        # exists; explicitly re-expose existing non-symlink `.codex/signals` & `.codex/metrics`
        # subdirectories while `.codex/hooks.json` and `.codex/config.toml` remain masked.
        for ws_d in ws_scan_dirs:
            dot_codex = os.path.join(ws_d, ".codex")
            if os.path.islink(dot_codex):
                continue
            for meta_sub in ("signals", "metrics"):
                sub_p = os.path.join(dot_codex, meta_sub)
                if not os.path.islink(sub_p) and os.path.isdir(sub_p):
                    ok_sub, _, resolved_sub = self.validate_workdir(sub_p)
                    if ok_sub:
                        _add(resolved_sub)

        flutter_cache_candidates: List[str] = [
            "/opt/flutter/bin/cache",
            "/opt/flutter/packages/flutter_tools/.dart_tool",
        ]
        flutter_bin = shutil.which("flutter")
        if flutter_bin:
            try:
                fl_root = Path(flutter_bin).resolve().parent.parent
                flutter_cache_candidates.append(str(fl_root / "bin" / "cache"))
                flutter_cache_candidates.append(
                    str(fl_root / "packages" / "flutter_tools" / ".dart_tool")
                )
            except OSError:
                pass
        for fc in flutter_cache_candidates:
            if (
                not os.path.islink(fc)
                and os.path.isdir(fc)
                and not self.is_protected_path(os.path.abspath(fc))
            ):
                _add(fc)
        if self.config.isolate_mount_namespace or os.path.isdir(SHARED_SANDBOX_PUB_CACHE_VFS):
            if not self.is_protected_path(SHARED_SANDBOX_PUB_CACHE_VFS):
                _add(SHARED_SANDBOX_PUB_CACHE_VFS)

        home_dir = str(Path.home().resolve())
        home_already_covered = any(
            home_dir == r or home_dir.startswith(r.rstrip("/") + "/")
            for r in self._allowed_roots
        )
        cache_rels = (
            ".pub-cache",
            os.path.join(".config", "flutter"),
            ".dart-tool",
            ".dartServer",
            ".cache",
            ".npm",
            os.path.join(".local", "share"),
            os.path.join(".config", "gh"),
            # Isolated per-sandbox Docker CLI config (buildx state, registry logins)
            ".docker",
        )
        if not home_already_covered:
            for rel in cache_rels:
                abs_cache = os.path.join(home_dir, rel)
                if self.config.isolate_mount_namespace or os.path.isdir(abs_cache):
                    _add(abs_cache)
            if not self.config.isolate_mount_namespace and self.config.sandbox_state_dir:
                try:
                    sb_tmp = os.path.abspath(
                        str(Path(self.config.sandbox_state_dir).expanduser() / "tmp")
                    )
                    if not self.is_protected_path(sb_tmp) and os.path.isdir(sb_tmp):
                        _add(sb_tmp)
                except OSError:
                    pass

        codex_state = codex_plugins_config_state(self.config)
        if codex_state.get("enabled") and not codex_state.get("config_error"):
            rt_root = os.path.abspath(
                os.path.expanduser(
                    str(
                        self.config.agent_runtime_home_root or "/mnt/dots-agent-home"
                    ).strip()
                )
            )
            iso_codex_home = os.path.join(rt_root, "codex")
            for rel in cache_rels:
                _add(os.path.join(iso_codex_home, rel))
            _add(os.path.join(iso_codex_home, ".codex", "plugins", "data"))

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
        cwd: Optional[str] = None,
    ) -> List[str]:
        """Construct a validated non-interactive `codex exec` invocation list confined to allowed_workdirs."""
        ok_cwd, cwd_err, resolved_cwd_codex = self.validate_workdir(cwd)
        if not ok_cwd:
            raise PermissionError(cwd_err)

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
        forbidden_codex_cfg_tokens = (
            "sandbox",
            "approval",
            "permission",
            "plugin",
            "marketplace",
            "hook",
            "project",
            "mcp_server",
            "notify",
        )
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
                "--approve-for-me",
                "--remote-control",
                "-P",
                "--permission-profile",
                "--plugin",
                "--plugins",
                "--plugin-dir",
                "--plugin-dirs",
            ) or raw_arg.startswith(
                (
                    "--remote-control=",
                    "-P=",
                    "--permission-profile=",
                    "--plugin=",
                    "--plugins=",
                    "--plugin-dir=",
                    "--plugin-dirs=",
                )
            ):
                raise PermissionError(
                    f"Raw '{raw_arg}' flag in args is forbidden by gateway security policy"
                )
            if raw_arg in ("-s", "--sandbox") or raw_arg.startswith(("-s=", "--sandbox=")):
                raise PermissionError(
                    "Raw '-s'/'--sandbox' in args is forbidden; pass 'sandbox_mode' parameter"
                )
            if raw_arg in ("-c", "--config") and idx + 1 < len(extra):
                cfg_kv = extra[idx + 1].lower()
                if any(tok_k in cfg_kv for tok_k in forbidden_codex_cfg_tokens):
                    raise PermissionError(
                        "Overriding sandbox, approval, permission, plugin, or hook policy via '-c/--config' is forbidden"
                    )
            if raw_arg.startswith(("-c=", "--config=")):
                cfg_kv = raw_arg.split("=", 1)[1].lower()
                if any(tok_k in cfg_kv for tok_k in forbidden_codex_cfg_tokens):
                    raise PermissionError(
                        "Overriding sandbox, approval, permission, plugin, or hook policy via '-c/--config' is forbidden"
                    )

        ok_extra, err_extra = self._check_protected_arguments(
            [codex_bin, *extra], resolved_cwd_codex, _trusted_agy_argv=False
        )
        if not ok_extra:
            raise PermissionError(err_extra)

        codex_plg_state = codex_plugins_config_state(self.config)
        if codex_plg_state.get("config_error") or codex_plg_state.get("enabled"):
            self.validate_codex_plugins(cwd=cwd, add_dirs=add_dirs)

        # Top-level Codex CLI options (placed before `exec` per codex-cli 0.166+ parser)
        if use_skip:
            argv.extend(["-a", "never"])
        argv.extend(["-s", eff_sandbox])

        if eff_sandbox == "workspace-write":
            net_bool = "true" if self.config.codex_sandbox_network_access else "false"
            writable_roots = self.get_codex_writable_roots(add_dirs=add_dirs, cwd=cwd)
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
