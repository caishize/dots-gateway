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

from .config import GatewayConfig


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    normalized_argv: Optional[List[str]] = None
    resolved_cwd: str = ""
    requires_shell: bool = False


_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_VERSIONED_TOOL_RE = re.compile(
    r"^(?:python3\.\d+|pip3\.\d+|gcc-\d+|g\+\+-\d+|clang-\d+|clang\+\+-\d+)$"
)
_SHELL_BUILTINS = {"cd", "export", "unset", "source", ".", "true", "false", "test", "["}


def _extract_balanced_parens(text: str, start_idx: int) -> Tuple[str, int]:
    """Given `start_idx` right after `$(`, return `(inner_cmd, next_idx_after_closing_paren)`."""
    depth = 1
    i = start_idx
    in_single = False
    in_double = False
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
        else:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[start_idx:i], i + 1
        i += 1
    raise ValueError("Unbalanced command substitution '$('")


def split_shell_commands(raw: str) -> Tuple[List[str], List[str], bool]:
    """Quote- and escape-aware shell splitter.

    Returns `(segments, command_substitutions, has_shell_syntax)` without falsely splitting
    on `;` or `|` inside single or double quotes.
    """
    segments: List[str] = []
    substitutions: List[str] = []
    has_shell_syntax = False
    buf: List[str] = []

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
                inner, next_i = _extract_balanced_parens(raw, i + 2)
                substitutions.append(inner)
                buf.append(raw[i:next_i])
                i = next_i
                continue
            if ch == "`":
                has_shell_syntax = True
                end_bt = raw.find("`", i + 1)
                if end_bt == -1:
                    raise ValueError("Unclosed backtick command substitution")
                substitutions.append(raw[i + 1 : end_bt])
                buf.append(raw[i : end_bt + 1])
                i = end_bt + 1
                continue
            buf.append(ch)
            i += 1
            continue

        # Unquoted context
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

        if ch == "$" and i + 1 < n and raw[i + 1] == "(":
            has_shell_syntax = True
            inner, next_i = _extract_balanced_parens(raw, i + 2)
            substitutions.append(inner)
            buf.append(raw[i:next_i])
            i = next_i
            continue

        if ch == "`":
            has_shell_syntax = True
            end_bt = raw.find("`", i + 1)
            if end_bt == -1:
                raise ValueError("Unclosed backtick command substitution")
            substitutions.append(raw[i + 1 : end_bt])
            buf.append(raw[i : end_bt + 1])
            i = end_bt + 1
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

        if paren_depth == 0:
            # Two-char operators: &&, ||, |&
            two = raw[i : i + 2]
            if two in ("&&", "||", "|&"):
                has_shell_syntax = True
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf.clear()
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
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf.clear()
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
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf.clear()
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

    tail = "".join(buf).strip()
    if tail:
        segments.append(tail)

    return segments, substitutions, has_shell_syntax


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
            raw_str = command.strip()
            if not raw_str:
                return PolicyDecision(False, reason="Empty command string")
            try:
                segments, substitutions, has_shell_syntax = split_shell_commands(raw_str)
            except ValueError as exc:
                return PolicyDecision(
                    False, reason=f"Malformed command syntax: {exc}", resolved_cwd=resolved_cwd
                )
            requires_shell = has_shell_syntax
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
            segments = [raw_str]
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

        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue

            # Unwrap outer subshell parentheses `(cd dir && make)`
            if seg.startswith("(") and seg.endswith(")"):
                inner_grp = seg[1:-1].strip()
                grp_dec = self.validate_command(inner_grp, cwd=resolved_cwd, _depth=_depth + 1)
                if not grp_dec.allowed:
                    return grp_dec
                continue

            try:
                seg_tokens = shlex.split(seg)
            except ValueError:
                seg_tokens = seg.split()

            idx = 0
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

            # If invoking subshell bash -c / sh -c, recursively validate inner command
            if os.path.basename(exe) in ("bash", "sh") and "-c" in seg_tokens[idx + 1 :]:
                c_idx = seg_tokens.index("-c", idx + 1)
                if c_idx + 1 < len(seg_tokens):
                    inner_cmd = seg_tokens[c_idx + 1]
                    inner_decision = self.validate_command(
                        inner_cmd, cwd=resolved_cwd, _depth=_depth + 1
                    )
                    if not inner_decision.allowed:
                        return inner_decision

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

    def build_agy_sandbox_settings(
        self,
        cwd: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Build session `--settings` JSON granting `write_file` mounts inside `agy --sandbox`."""
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

        allow_list: List[str] = list(perms.get("allow") or [])
        allow_seen = set(allow_list)
        for root in self.get_agy_writable_roots(cwd=cwd, add_dirs=add_dirs):
            rule = f"write_file({root})"
            if rule not in allow_seen:
                allow_seen.add(rule)
                allow_list.append(rule)
        perms["allow"] = allow_list
        return {"permissions": perms}

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
