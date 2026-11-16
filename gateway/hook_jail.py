"""Unified native hook sandboxing and isolated plugin bundle staging for AGY & Codex.

Why this module exists:
- Both `agy` and `codex` execute plugin `hooks.json` command handlers directly as child
  processes of the outer agent process (outside `agy --sandbox` and `codex-linux-sandbox`).
- Without mandatory hook isolation, an auto-triggered plugin hook (or repo-planted hook)
  inherits the agent parent's login credentials (`oauth_creds.json`, `gcloud` ADC,
  `CODEX_HOME/auth.json`, `OPENAI_API_KEY`, `gh/hosts.yml`) and could read unauthorized paths
  or execute untrusted code inside a writable project workspace.
- Gateway stages a verified read-only view of each operator-registered plugin whose
  `hooks.json` / `hooks/hooks.json` rewrites every command handler to execute through
  `dots-hook-jail.py`:
    1. Scrubs all credential/token/API-key/loader environment variables.
    2. Redirects `HOME`, `TMPDIR`, and `PLUGIN_DATA` / `CLAUDE_PLUGIN_DATA` to an isolated
       per-plugin writable state directory (never the read-only plugin tree or real `HOME`).
    3. Rejects out-of-workspace `cwd`, symlink escapes in `PreToolUse` file targets, and any
       hook command attempting to invoke code from writable project directories.
    4. Enters a dedicated nested Linux user+mount namespace (`pivot_root`, W^X across the
       entire filesystem: plugin & system trees `ro`, authorized workspaces & state `/tmp`
       `rw,nosuid,nodev,noexec`, all credentials/HOME/gateway paths absent) and drops all
       capabilities (`--bounding-set=-all`).
    5. Fails closed (exit code 2 + deny JSON) if the runtime environment cannot enforce the
       nested mount-namespace jail.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .config import GatewayConfig, effective_plugin_state_dir, redact_diagnostic_text

# Test-only switch used strictly by unit tests running inside a container seccomp sandbox
# where nested `unshare --user` is unavailable on the CI VM. Production code never flips this,
# and no environment variable or CLI flag can enable passthrough.
_ALLOW_TEST_UNSHARE_PASSTHROUGH: bool = False

_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

AGY_KNOWN_HOOK_EVENTS: Tuple[str, ...] = (
    "SessionStart",
    "SessionEnd",
    "PreInvocation",
    "PostInvocation",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "UserPromptSubmit",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "Stop",
    "Notification",
)

CLAUDE_KNOWN_HOOK_EVENTS: Tuple[str, ...] = (
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "Notification",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "TeammateIdle",
    "TaskCompleted",
    "ConfigChange",
    "WorktreeCreate",
    "WorktreeRemove",
    "PreCompact",
    "PostCompact",
)

CODEX_HOOK_EVENT_KEY_LABELS: Dict[str, str] = {
    "PreModelRequest": "pre_model_request",
    "PostModelRequest": "post_model_request",
    "PreToolUse": "pre_tool_use",
    "PermissionRequest": "permission_request",
    "PostToolUse": "post_tool_use",
    "PreCompact": "pre_compact",
    "PostCompact": "post_compact",
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "UserPromptSubmit": "user_prompt_submit",
    "SubagentStart": "subagent_start",
    "SubagentStop": "subagent_stop",
    "Stop": "stop",
    "Interrupt": "interrupt",
}

CODEX_HOOK_EVENTS_WITH_MATCHERS = frozenset(
    {
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
    }
)

# Relative paths inside a writable project workspace that must NEVER be allowed to plant
# auto-triggered native hooks, repo-local agent settings, or repo-local plugin marketplaces.
# Note: `.claude/signals`, `.claude/metrics`, `.codex/signals`, and `.codex/metrics` remain
# writable so `oh-my-agents` verify signals & metrics ledgers work inside project workspaces.
WORKSPACE_HOOK_INJECTION_RELPATHS: Tuple[str, ...] = (
    os.path.join(".git", "hooks"),
    os.path.join(".claude", "settings.json"),
    os.path.join(".claude", "settings.local.json"),
    os.path.join(".claude", "hooks"),
    os.path.join(".gemini", "settings.json"),
    os.path.join(".gemini", "antigravity-cli"),
    os.path.join(".gemini", "config", "plugins"),
    os.path.join(".codex", "hooks.json"),
    os.path.join(".codex", "config.toml"),
    os.path.join(".agents", "plugins"),
)

# Subset of `WORKSPACE_HOOK_INJECTION_RELPATHS` that are NOT auto-loaded or executed by
# `agy`, `codex`, or `git`, and may legitimately be tracked in Git (e.g., `.claude/settings.json`
# and `.claude/hooks/*`). Existing regular files/directories at these paths are locked
# read-only + `noexec` with real content preserved so `git status`, `git diff`, `git merge`,
# and `git stash` stay clean and readable while all write/tamper attempts remain blocked.
WORKSPACE_READONLY_PROTECTED_RELPATHS: Tuple[str, ...] = (
    os.path.join(".claude", "settings.json"),
    os.path.join(".claude", "settings.local.json"),
    os.path.join(".claude", "hooks"),
)

_ALLOWED_HOOK_SYS_PREFIXES: Tuple[str, ...] = (
    "/usr/bin/",
    "/usr/local/bin/",
    "/bin/",
    "/sbin/",
    "/usr/sbin/",
    "/lib/",
    "/lib64/",
    "/opt/devtools/",
    "/opt/uv-tools/",
    "/opt/uv-python/",
)

_ALLOWED_BARE_INTERPRETERS = frozenset(
    {"python3", "python", "bash", "sh", "dash", "node", "nodejs", "ruby", "perl", "uv"}
)


@dataclass(frozen=True)
class StagedPluginHookBundle:
    """Host & VFS paths for a Gateway-synthesized read-only plugin bundle and its hook jail."""

    agent: str
    name: str
    source_dir: str
    vfs_discovery_dir: str
    hooks_relpath: Optional[str]
    host_rewritten_hooks_file: Optional[str]
    host_jail_config_dir: str
    vfs_jail_config_dir: str
    host_hook_tmp_dir: str
    vfs_hook_tmp_dir: str
    host_hook_data_dir: str
    vfs_hook_data_dir: str
    marketplace_name: str = ""
    plugin_version: str = ""
    vfs_data_dirs: Tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedAgentPluginRuntime:
    """Prepared host staging artifacts mounted into a single `agy`, `codex`, or `claude` VFS session."""

    agent: str
    isolated_home_dir: str
    host_runner_script: str
    vfs_runner_script: str
    bundles: Tuple[StagedPluginHookBundle, ...]
    host_sanitized_agy_settings: Optional[str] = None
    host_codex_config_toml: Optional[str] = None
    vfs_codex_home_dir: Optional[str] = None
    host_sanitized_claude_settings: Optional[str] = None
    host_sanitized_claude_json: Optional[str] = None
    vfs_claude_config_dir: Optional[str] = None
    cleanup_dir: Optional[str] = None


def _path_is_within(child: str, parent: str) -> bool:
    c = os.path.abspath(child)
    p = os.path.abspath(parent)
    if p == "/":
        return True
    return c == p or c.startswith(p.rstrip("/") + "/")


def _atomic_write_file(target: Path, content: bytes, mode: int = 0o600) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise PermissionError(f"Refusing to write through symlink '{target}'")
    tmp_p = target.parent / f".{target.name}.tmp.{os.getpid()}.{uuid.uuid4().hex[:10]}"
    try:
        if tmp_p.exists() or tmp_p.is_symlink():
            tmp_p.unlink()
        fd = os.open(str(tmp_p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        os.chmod(tmp_p, mode)
        os.replace(tmp_p, target)
    except BaseException:
        try:
            tmp_p.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _ensure_safe_dir(path: Path, mode: int = 0o700) -> None:
    if path.is_symlink():
        raise PermissionError(f"Symlinked plugin state/bundle directory '{path}' is forbidden")
    path.mkdir(parents=True, exist_ok=True)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"Expected real directory at '{path}'")
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _consume_plugin_root_macro(
    s: str,
    idx: int,
    *,
    plugin_name: str,
    vfs_discovery_dir: str,
) -> Tuple[str, int]:
    """Expand an allowlisted `$...` plugin-root macro at `s[idx] == '$'` or raise `PermissionError`."""
    rest = s[idx:]
    home_suffix = f"/.gemini/config/plugins/{plugin_name}"

    for braced_home in (f"${{HOME}}{home_suffix}", f"$HOME{home_suffix}"):
        if rest.startswith(braced_home):
            after_pos = idx + len(braced_home)
            if after_pos == len(s) or s[after_pos] in ("/", " ", "\t", '"', "'"):
                return vfs_discovery_dir, after_pos

    for root_var in ("CLAUDE_PLUGIN_ROOT", "PLUGIN_ROOT", "AGY_PLUGIN_ROOT"):
        exact_braced = f"${{{root_var}}}"
        if rest.startswith(exact_braced):
            return vfs_discovery_dir, idx + len(exact_braced)

        fallback_prefix = f"${{{root_var}:-"
        if rest.startswith(fallback_prefix):
            depth = 1
            pos = idx + len(fallback_prefix)
            while pos < len(s) and depth > 0:
                ch = s[pos]
                if ch == "`":
                    raise PermissionError(
                        f"Backtick command substitution inside '${{{root_var}:-...}}' in plugin '{plugin_name}' is forbidden"
                    )
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return vfs_discovery_dir, pos + 1
                pos += 1
            raise PermissionError(
                f"Unclosed '${{{root_var}:-...' macro in hook command for plugin '{plugin_name}'"
            )

        bare_macro = f"${root_var}"
        if rest.startswith(bare_macro):
            after_pos = idx + len(bare_macro)
            if after_pos == len(s) or not (s[after_pos].isalnum() or s[after_pos] == "_"):
                return vfs_discovery_dir, after_pos

    raise PermissionError(
        f"Unexpanded shell variable or command substitution near '{rest[:32]}' in plugin '{plugin_name}' hook command is forbidden"
    )


def _tokenize_hook_command_strict(
    raw_command: str,
    *,
    plugin_name: str,
    vfs_discovery_dir: str,
) -> List[str]:
    """Quote-aware hook command lexer rejecting all shell control/redirection operators and arbitrary `$` expansions."""
    if not isinstance(raw_command, str) or not raw_command.strip():
        raise PermissionError(f"Empty hook command in plugin '{plugin_name}'")
    if any(ch in raw_command for ch in ("\x00", "\r", "\n")):
        raise PermissionError(
            f"Control characters in hook command for plugin '{plugin_name}' are forbidden"
        )

    s = raw_command.strip()
    tokens: List[str] = []
    buf: List[str] = []
    in_token = False
    quote: Optional[str] = None
    tilde_home_prefix = f"~/.gemini/config/plugins/{plugin_name}"
    i = 0
    n = len(s)

    while i < n:
        ch = s[i]
        if quote is None:
            if ch in (" ", "\t"):
                if in_token:
                    tokens.append("".join(buf))
                    buf.clear()
                    in_token = False
                i += 1
                continue
            if ch in (";", "|", "&", ">", "<", "(", ")", "`"):
                raise PermissionError(
                    f"Shell operator '{ch}' in plugin '{plugin_name}' hook command is forbidden; "
                    "hook commands are executed directly without a shell"
                )
            if ch in ("'", '"'):
                quote = ch
                in_token = True
                i += 1
                continue
            if ch == "\\":
                if i + 1 >= n:
                    raise PermissionError(
                        f"Trailing backslash in hook command for plugin '{plugin_name}'"
                    )
                buf.append(s[i + 1])
                in_token = True
                i += 2
                continue
            if ch == "$":
                expanded, next_i = _consume_plugin_root_macro(
                    s, i, plugin_name=plugin_name, vfs_discovery_dir=vfs_discovery_dir
                )
                buf.append(expanded)
                in_token = True
                i = next_i
                continue
            if ch == "~" and not in_token:
                if s[i:].startswith(tilde_home_prefix):
                    after_pos = i + len(tilde_home_prefix)
                    if after_pos == n or s[after_pos] in ("/", " ", "\t", '"', "'"):
                        buf.append(vfs_discovery_dir)
                        in_token = True
                        i = after_pos
                        continue
                raise PermissionError(
                    f"Home tilde expansion near '{s[i:i+32]}' in plugin '{plugin_name}' hook command is forbidden"
                )
            buf.append(ch)
            in_token = True
            i += 1
        elif quote == "'":
            if ch == "'":
                quote = None
                i += 1
                continue
            if ch in ("$", "`"):
                raise PermissionError(
                    f"Single-quoted '{ch}' in plugin '{plugin_name}' hook command is forbidden"
                )
            buf.append(ch)
            i += 1
        else:  # quote == '"'
            if ch == '"':
                quote = None
                i += 1
                continue
            if ch == "`":
                raise PermissionError(
                    f"Backtick command substitution in plugin '{plugin_name}' hook command is forbidden"
                )
            if ch == "\\":
                if i + 1 >= n:
                    raise PermissionError(
                        f"Trailing backslash in double-quoted hook command for plugin '{plugin_name}'"
                    )
                nxt = s[i + 1]
                if nxt in ('"', "\\"):
                    buf.append(nxt)
                    i += 2
                    continue
                if nxt in ("$", "`"):
                    raise PermissionError(
                        f"Escaped '{nxt}' in plugin '{plugin_name}' hook command is forbidden"
                    )
                buf.append(ch)
                buf.append(nxt)
                i += 2
                continue
            if ch == "$":
                expanded, next_i = _consume_plugin_root_macro(
                    s, i, plugin_name=plugin_name, vfs_discovery_dir=vfs_discovery_dir
                )
                buf.append(expanded)
                i = next_i
                continue
            buf.append(ch)
            i += 1

    if quote is not None:
        raise PermissionError(
            f"Unclosed quote ({quote}) in hook command for plugin '{plugin_name}'"
        )
    if in_token:
        tokens.append("".join(buf))
    if not tokens:
        raise PermissionError(f"Empty parsed hook command in plugin '{plugin_name}'")
    return tokens


def _validate_and_rewrite_plugin_path_token(
    tok: str,
    *,
    plugin_name: str,
    source_dir: str,
    vfs_discovery_dir: str,
) -> str:
    """Validate a path-bearing token and rewrite plugin-relative/source paths to `vfs_discovery_dir`."""
    norm_parts = tok.replace("\\", "/").split("/")
    if ".." in norm_parts:
        raise PermissionError(
            f"Parent-directory traversal '{tok}' in plugin '{plugin_name}' hook command is forbidden"
        )
    if tok.startswith("./"):
        rel_sub = tok[2:]
        vfs_target = os.path.normpath(os.path.join(vfs_discovery_dir, rel_sub))
        host_target = os.path.normpath(os.path.join(source_dir, rel_sub))
        if not _path_is_within(vfs_target, vfs_discovery_dir) or not _path_is_within(
            host_target, source_dir
        ):
            raise PermissionError(
                f"Relative hook script path '{tok}' escapes plugin '{plugin_name}'"
            )
        if not os.path.exists(host_target):
            raise PermissionError(
                f"Hook script '{host_target}' referenced by plugin '{plugin_name}' does not exist"
            )
        real_target = os.path.realpath(host_target)
        if not _path_is_within(real_target, source_dir):
            raise PermissionError(
                f"Hook script '{host_target}' in plugin '{plugin_name}' resolves via symlink outside plugin root"
            )
        return vfs_target

    if _path_is_within(tok, vfs_discovery_dir):
        rel = os.path.relpath(os.path.abspath(tok), os.path.abspath(vfs_discovery_dir))
        host_target = os.path.abspath(os.path.join(source_dir, rel))
        if not _path_is_within(host_target, source_dir):
            raise PermissionError(
                f"Hook script path '{tok}' escapes plugin '{plugin_name}'"
            )
        if not os.path.exists(host_target):
            raise PermissionError(
                f"Hook script '{host_target}' referenced by plugin '{plugin_name}' does not exist"
            )
        real_target = os.path.realpath(host_target)
        if not _path_is_within(real_target, source_dir):
            raise PermissionError(
                f"Hook script '{host_target}' in plugin '{plugin_name}' resolves via symlink outside plugin root"
            )
        return os.path.abspath(tok)

    if _path_is_within(tok, source_dir):
        if not os.path.exists(tok):
            raise PermissionError(
                f"Hook script '{tok}' referenced by plugin '{plugin_name}' does not exist"
            )
        real_target = os.path.realpath(tok)
        if not _path_is_within(real_target, source_dir):
            raise PermissionError(
                f"Hook script '{tok}' in plugin '{plugin_name}' resolves outside plugin root"
            )
        rel = os.path.relpath(real_target, os.path.abspath(source_dir))
        return os.path.abspath(os.path.join(vfs_discovery_dir, rel))

    if any(os.path.abspath(tok).startswith(pfx) for pfx in _ALLOWED_HOOK_SYS_PREFIXES):
        return os.path.abspath(tok)
    if tok == "/dev/null":
        return tok

    raise PermissionError(
        f"Hook command in plugin '{plugin_name}' references unauthorized path '{tok}'; "
        "hooks may only execute read-only plugin files and system binaries"
    )


_SAFE_PYTHON_SHORT_FLAG_CHARS = frozenset({"I", "S", "B", "E", "s", "u", "O"})
_SAFE_SHELL_PRE_SCRIPT_FLAGS = frozenset({"-e", "-u", "-eu", "-ue", "--norc", "--noprofile"})
_SAFE_JS_PRE_SCRIPT_FLAGS = frozenset({"--no-warnings", "--no-deprecation"})
_SAFE_RUBY_PERL_PRE_SCRIPT_FLAGS = frozenset({"-w", "-T"})
_SAFE_UV_RUN_PRE_SCRIPT_FLAGS = frozenset(
    {"--no-project", "--isolated", "--offline", "--quiet", "-q", "--no-sync", "--script", "-s"}
)


def _validate_interpreter_script_target(
    argv: Sequence[str],
    *,
    plugin_name: str,
    vfs_discovery_dir: str,
) -> None:
    """Enforce a strict zero-arg flag allowlist before `<plugin_script>` and require `<plugin_script>` inside `vfs_discovery_dir`."""
    exe_tok = argv[0]
    if _path_is_within(exe_tok, vfs_discovery_dir):
        return

    exe_base = os.path.basename(exe_tok).lower()
    if exe_base == "env":
        raise PermissionError(
            f"'env' wrapper in plugin '{plugin_name}' hook command is forbidden; invoke the interpreter or plugin script directly"
        )

    is_python = exe_base in ("python", "python3") or exe_base.startswith("python3.")
    is_shell = exe_base in ("bash", "sh", "dash", "zsh")
    is_js = exe_base in ("node", "nodejs", "deno", "bun")
    is_ruby_perl = exe_base in ("ruby", "perl")
    is_uv = exe_base == "uv"

    if not (is_python or is_shell or is_js or is_ruby_perl or is_uv):
        if "/" not in exe_tok or not any(
            os.path.abspath(exe_tok).startswith(pfx) for pfx in _ALLOWED_HOOK_SYS_PREFIXES
        ):
            raise PermissionError(
                f"Hook command executable '{exe_tok}' in plugin '{plugin_name}' is not an authorized plugin script or interpreter"
            )
        return

    idx = 1
    uv_isolated = False
    if is_uv:
        if idx >= len(argv) or argv[idx] != "run":
            raise PermissionError(
                f"'uv' hook command in plugin '{plugin_name}' must use 'uv run --no-project <plugin_script>'"
            )
        idx += 1

    script_arg: Optional[str] = None
    while idx < len(argv):
        arg = argv[idx]
        if arg == "--":
            if idx + 1 < len(argv):
                script_arg = argv[idx + 1]
            break
        if arg == "-":
            raise PermissionError(
                f"Reading hook code from stdin ('-') in plugin '{plugin_name}' is forbidden"
            )
        if arg.startswith("-"):
            if is_python:
                if (
                    len(arg) >= 2
                    and not arg.startswith("--")
                    and all(ch in _SAFE_PYTHON_SHORT_FLAG_CHARS for ch in arg[1:])
                ):
                    idx += 1
                    continue
                raise PermissionError(
                    f"Disallowed Python interpreter flag '{arg}' before plugin script in '{plugin_name}' hook command"
                )
            if is_shell:
                if arg in _SAFE_SHELL_PRE_SCRIPT_FLAGS:
                    idx += 1
                    continue
                raise PermissionError(
                    f"Disallowed shell flag '{arg}' before plugin script in '{plugin_name}' hook command"
                )
            if is_js:
                if arg in _SAFE_JS_PRE_SCRIPT_FLAGS:
                    idx += 1
                    continue
                raise PermissionError(
                    f"Disallowed JS runtime flag '{arg}' before plugin script in '{plugin_name}' hook command"
                )
            if is_ruby_perl:
                if arg in _SAFE_RUBY_PERL_PRE_SCRIPT_FLAGS:
                    idx += 1
                    continue
                raise PermissionError(
                    f"Disallowed interpreter flag '{arg}' before plugin script in '{plugin_name}' hook command"
                )
            if is_uv:
                if arg in _SAFE_UV_RUN_PRE_SCRIPT_FLAGS:
                    if arg in ("--no-project", "--isolated"):
                        uv_isolated = True
                    idx += 1
                    continue
                raise PermissionError(
                    f"Disallowed 'uv run' flag '{arg}' before plugin script in '{plugin_name}' hook command"
                )
        script_arg = arg
        break

    if is_uv and not uv_isolated:
        raise PermissionError(
            f"'uv run' hook command in plugin '{plugin_name}' must include '--no-project' or '--isolated' before the plugin script"
        )

    if not script_arg or not _path_is_within(script_arg, vfs_discovery_dir):
        raise PermissionError(
            f"Interpreter '{exe_tok}' in plugin '{plugin_name}' hook command must execute a script inside "
            f"the read-only plugin directory (got '{script_arg or '<missing>'}')"
        )


def _resolve_hook_command_argv(
    raw_command: str,
    *,
    plugin_name: str,
    source_dir: str,
    vfs_discovery_dir: str,
) -> List[str]:
    """Tokenize, expand plugin-root macros, and validate a hook command into a direct `argv` list (no shell)."""
    tokens = _tokenize_hook_command_strict(
        raw_command,
        plugin_name=plugin_name,
        vfs_discovery_dir=vfs_discovery_dir,
    )

    if tokens[0] == "env" and len(tokens) >= 2 and not tokens[1].startswith("-"):
        tokens = tokens[1:]

    rewritten: List[str] = []
    for t_idx, tok in enumerate(tokens):
        if tok in ("..",) or tok.startswith("../") or "/../" in tok or tok.endswith("/.."):
            raise PermissionError(
                f"Parent-directory traversal '{tok}' in plugin '{plugin_name}' hook command is forbidden"
            )
        if t_idx == 0:
            if tok.startswith("./") or "/" in tok:
                rewritten.append(
                    _validate_and_rewrite_plugin_path_token(
                        tok,
                        plugin_name=plugin_name,
                        source_dir=source_dir,
                        vfs_discovery_dir=vfs_discovery_dir,
                    )
                )
            elif tok in _ALLOWED_BARE_INTERPRETERS or re.match(r"^python3\.[0-9]+$", tok):
                rewritten.append(tok)
            else:
                raise PermissionError(
                    f"Unauthorized bare executable '{tok}' in plugin '{plugin_name}' hook command"
                )
            continue

        if tok.startswith("-") and "=" in tok:
            opt_name, opt_val = tok.split("=", 1)
            if opt_val.startswith(("/", "./", "../", "~")):
                checked_val = _validate_and_rewrite_plugin_path_token(
                    opt_val,
                    plugin_name=plugin_name,
                    source_dir=source_dir,
                    vfs_discovery_dir=vfs_discovery_dir,
                )
                rewritten.append(f"{opt_name}={checked_val}")
                continue

        if tok.startswith("./") or ("/" in tok and not tok.startswith("-")):
            rewritten.append(
                _validate_and_rewrite_plugin_path_token(
                    tok,
                    plugin_name=plugin_name,
                    source_dir=source_dir,
                    vfs_discovery_dir=vfs_discovery_dir,
                )
            )
            continue

        rewritten.append(tok)

    _validate_interpreter_script_target(
        rewritten,
        plugin_name=plugin_name,
        vfs_discovery_dir=vfs_discovery_dir,
    )
    return rewritten


def _validate_hook_handler_metadata(
    handler: Mapping[str, Any],
    *,
    event_name: str,
    hooks_file: Path,
) -> None:
    """Validate optional `timeout`, `async`, `statusMessage`, and `additionalContextLimit` fields."""
    if "timeout" in handler and handler["timeout"] is not None:
        t_val = handler["timeout"]
        if isinstance(t_val, bool) or not isinstance(t_val, int) or t_val < 1:
            raise PermissionError(
                f"Field 'timeout' in '{event_name}' of '{hooks_file}' must be a positive integer"
            )
    if "async" in handler and handler["async"] is not None:
        if not isinstance(handler["async"], bool):
            raise PermissionError(
                f"Field 'async' in '{event_name}' of '{hooks_file}' must be a boolean"
            )
    if "statusMessage" in handler and handler["statusMessage"] is not None:
        if not isinstance(handler["statusMessage"], str):
            raise PermissionError(
                f"Field 'statusMessage' in '{event_name}' of '{hooks_file}' must be a string"
            )
    if "additionalContextLimit" in handler and handler["additionalContextLimit"] is not None:
        acl_val = handler["additionalContextLimit"]
        if isinstance(acl_val, bool) or not isinstance(acl_val, int) or acl_val < 1:
            raise PermissionError(
                f"Field 'additionalContextLimit' in '{event_name}' of '{hooks_file}' must be a positive integer"
            )


def _extract_hooks_events_mapping(
    parsed: Dict[str, Any],
    *,
    agent: str,
    plugin_name: str,
    hooks_file: Path,
) -> Tuple[Optional[str], Dict[str, Any]]:
    """Return `(wrapper_key, events_dict)` supporting `{\"hooks\": ...}`, `{\"<plugin_name>\": ...}`, or flat."""
    if "hooks" in parsed:
        events_obj = parsed.get("hooks")
        if not isinstance(events_obj, dict):
            raise PermissionError(f"Field 'hooks' in '{hooks_file}' must be an object")
        return "hooks", events_obj
    if (
        agent == "agy"
        and plugin_name in parsed
        and isinstance(parsed.get(plugin_name), dict)
        and set(parsed.keys()).issubset({plugin_name, "description", "$schema", "version"})
    ):
        return plugin_name, parsed[plugin_name]
    return None, parsed


def validate_plugin_hooks_manifest(
    hooks_file: Path,
    *,
    agent: str,
    plugin_name: str,
    source_dir: str,
    vfs_discovery_dir: str,
) -> Dict[str, Any]:
    """Validate `hooks.json` / `hooks/hooks.json` structure and all command handlers fail-closed."""
    try:
        st = os.lstat(hooks_file)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise PermissionError(f"Cannot inspect hooks manifest '{hooks_file}': {exc}") from exc

    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise PermissionError(
            f"Plugin hooks manifest '{hooks_file}' must be a regular non-symlink file"
        )
    if st.st_mode & 0o002:
        raise PermissionError(f"Plugin hooks manifest '{hooks_file}' must not be world-writable")

    try:
        parsed = json.loads(hooks_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PermissionError(f"Invalid JSON in '{hooks_file}': {exc}") from exc

    if not isinstance(parsed, dict):
        raise PermissionError(f"Hooks manifest '{hooks_file}' must contain a JSON object")

    wrapper_key, events_obj = _extract_hooks_events_mapping(
        parsed, agent=agent, plugin_name=plugin_name, hooks_file=hooks_file
    )

    allowed_events = (
        set(CODEX_HOOK_EVENT_KEY_LABELS.keys())
        if agent == "codex"
        else (set(CLAUDE_KNOWN_HOOK_EVENTS) if agent == "claude" else set(AGY_KNOWN_HOOK_EVENTS))
    )

    for event_name, groups in events_obj.items():
        if wrapper_key is None and event_name in ("description", "$schema", "version"):
            continue
        if event_name not in allowed_events:
            raise PermissionError(
                f"Unsupported hook event '{event_name}' in '{hooks_file}' for {agent}"
            )
        if not isinstance(groups, list):
            raise PermissionError(
                f"Hook event '{event_name}' in '{hooks_file}' must map to a list of matcher groups"
            )
        for g_idx, group in enumerate(groups):
            if not isinstance(group, dict):
                raise PermissionError(
                    f"Entry #{g_idx} for '{event_name}' in '{hooks_file}' must be an object"
                )
            if agent == "agy" and "hooks" not in group and "command" in group:
                h_type = str(group.get("type") or "command").strip()
                if h_type != "command":
                    raise PermissionError(
                        f"Unsupported hook handler type '{h_type}' in '{hooks_file}' "
                        "(only sandboxed 'command' hooks are permitted)"
                    )
                _validate_hook_handler_metadata(
                    group, event_name=event_name, hooks_file=hooks_file
                )
                _resolve_hook_command_argv(
                    str(group.get("command") or ""),
                    plugin_name=plugin_name,
                    source_dir=source_dir,
                    vfs_discovery_dir=vfs_discovery_dir,
                )
                continue

            matcher = group.get("matcher")
            if matcher is not None and not isinstance(matcher, str):
                raise PermissionError(
                    f"Matcher in '{event_name}' group #{g_idx} of '{hooks_file}' must be a string"
                )
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                raise PermissionError(
                    f"Field 'hooks' in '{event_name}' group #{g_idx} of '{hooks_file}' must be a list"
                )
            for h_idx, handler in enumerate(handlers):
                if not isinstance(handler, dict):
                    raise PermissionError(
                        f"Hook handler #{h_idx} in '{event_name}' of '{hooks_file}' must be an object"
                    )
                h_type = str(handler.get("type") or "command").strip()
                if h_type != "command":
                    raise PermissionError(
                        f"Unsupported hook handler type '{h_type}' in '{hooks_file}' "
                        "(only sandboxed 'command' hooks are permitted)"
                    )
                _validate_hook_handler_metadata(
                    handler, event_name=event_name, hooks_file=hooks_file
                )
                _resolve_hook_command_argv(
                    str(handler.get("command") or ""),
                    plugin_name=plugin_name,
                    source_dir=source_dir,
                    vfs_discovery_dir=vfs_discovery_dir,
                )

    return parsed


def compute_codex_hook_declaration_hash(
    event_name: str,
    matcher: Optional[str],
    command: str,
    timeout_sec: Optional[int],
    is_async: bool = False,
    status_message: Optional[str] = None,
    additional_context_limit: Optional[int] = None,
) -> str:
    """Compute exact `codex_config::version_for_toml` SHA-256 declaration hash for a Codex hook."""
    event_key = CODEX_HOOK_EVENT_KEY_LABELS[event_name]
    eff_matcher = matcher if (matcher and event_name in CODEX_HOOK_EVENTS_WITH_MATCHERS) else None
    if event_name in ("SessionEnd", "Interrupt"):
        eff_timeout = max(1, min(3, int(timeout_sec if timeout_sec is not None else 1)))
    else:
        eff_timeout = max(1, int(timeout_sec if timeout_sec is not None else 600))
    runs_async = bool(is_async and event_name != "SessionEnd")

    handler_obj: Dict[str, Any] = {
        "async": runs_async,
        "command": command,
        "timeout": eff_timeout,
        "type": "command",
    }
    if status_message is not None:
        handler_obj["statusMessage"] = status_message
    if (
        additional_context_limit is not None
        and additional_context_limit != 2500
        and event_name
        in ("PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "SubagentStart")
    ):
        handler_obj["additionalContextLimit"] = int(additional_context_limit)

    identity_obj: Dict[str, Any] = {
        "event_name": event_key,
        "hooks": [handler_obj],
    }
    if eff_matcher is not None:
        identity_obj["matcher"] = eff_matcher

    serialized = json.dumps(identity_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(serialized).hexdigest()}"


def compute_codex_plugin_content_hash(
    root_dir: Path,
    file_overrides: Optional[Mapping[str, bytes]] = None,
) -> str:
    """Compute exact `plugin_fingerprint::plugin_content_hash` (`codex-plugin-bundle-v1`)."""
    overrides = dict(file_overrides or {})
    root_resolved = root_dir.resolve()
    pending: List[Path] = [root_resolved]
    hasher = hashlib.sha256()
    hasher.update(b"codex-plugin-bundle-v1")

    while pending:
        cur = pending.pop()
        rel = cur.relative_to(root_resolved)
        rel_str = "" if str(rel) == "." else rel.as_posix()
        base_name = cur.name if rel_str else ""
        if base_name and (
            base_name in ("__pycache__", ".venv")
            or base_name.endswith(".pyc")
            or base_name.endswith(".egg-info")
        ):
            continue

        rel_bytes = os.fsencode(rel_str) if rel_str else b""
        hasher.update(len(rel_bytes).to_bytes(8, "little"))
        hasher.update(rel_bytes)

        if rel_str in overrides:
            data = overrides[rel_str]
            hasher.update(b"file")
            hasher.update(len(data).to_bytes(8, "little"))
            hasher.update(data)
            continue

        st = os.lstat(cur)
        if stat.S_ISDIR(st.st_mode):
            hasher.update(b"directory")
            children = sorted(cur.iterdir(), key=lambda p: os.fsencode(p.name))
            for child in reversed(children):
                pending.append(child)
        elif stat.S_ISREG(st.st_mode):
            hasher.update(b"file")
            data = cur.read_bytes()
            hasher.update(len(data).to_bytes(8, "little"))
            hasher.update(data)
        else:
            raise PermissionError(
                f"Unsupported non-regular/symlink entry '{cur}' while fingerprinting Codex plugin"
            )

    return f"sha256:{hasher.hexdigest()}"


def _toml_quote(val: str) -> str:
    escaped = (
        val.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _format_toml_scalar(val: Any) -> Optional[str]:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int) and not isinstance(val, bool):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    if isinstance(val, str):
        return _toml_quote(val)
    if isinstance(val, list):
        items: List[str] = []
        for item in val:
            rendered = _format_toml_scalar(item)
            if rendered is None:
                return None
            items.append(rendered)
        return "[" + ", ".join(items) + "]"
    return None


def build_isolated_codex_config_toml(
    host_codex_config_path: Optional[Path],
    *,
    plugins_spec: Sequence[Dict[str, Any]],
    hook_states: Mapping[str, Dict[str, Any]],
) -> str:
    """Synthesize a clean `$CODEX_HOME/config.toml` enabling ONLY operator-registered plugins.

    Strips untrusted `[hooks]`, `[projects]` (so repo-local `.codex/config.toml` and
    `.codex/hooks.json` stay untrusted/disabled), `[mcp_servers]`, `[marketplaces]`, `[plugins]`,
    and `notify` commands from any existing host `~/.codex/config.toml`.
    """
    safe_top_scalars: List[str] = [
        "# Auto-generated by dots-gateway for isolated Codex plugin & hook execution (read-only)",
    ]
    safe_scalar_keys = {
        "model",
        "model_provider",
        "model_context_window",
        "model_max_output_tokens",
        "model_reasoning_effort",
        "model_reasoning_summary",
        "model_verbosity",
        "oss_provider",
        "review_model",
    }
    if host_codex_config_path and host_codex_config_path.is_file() and not host_codex_config_path.is_symlink():
        try:
            parsed_toml = tomllib.loads(host_codex_config_path.read_text(encoding="utf-8"))
        except Exception:
            parsed_toml = {}
        if isinstance(parsed_toml, dict):
            for k in sorted(safe_scalar_keys):
                if k in parsed_toml:
                    rendered = _format_toml_scalar(parsed_toml[k])
                    if rendered is not None:
                        safe_top_scalars.append(f"{k} = {rendered}")

    sections: List[str] = ["\n".join(safe_top_scalars)]

    mkt_counts: Dict[str, int] = {}
    for p_spec in plugins_spec:
        m_key = str(p_spec["marketplace_name"])
        mkt_counts[m_key] = mkt_counts.get(m_key, 0) + 1

    seen_marketplaces: set[str] = set()
    for p_spec in plugins_spec:
        mkt = str(p_spec["marketplace_name"])
        disc_dir = str(p_spec["vfs_discovery_dir"])
        if mkt_counts.get(mkt, 0) > 1:
            mkt_src = os.path.dirname(os.path.dirname(os.path.abspath(disc_dir)))
        else:
            mkt_src = disc_dir
        if mkt not in seen_marketplaces:
            seen_marketplaces.add(mkt)
            sections.append(
                "\n".join(
                    [
                        f"[marketplaces.{_toml_quote(mkt)}]",
                        'source_type = "local"',
                        f"source = {_toml_quote(mkt_src)}",
                    ]
                )
            )
        plugin_id = f"{p_spec['name']}@{mkt}"
        sections.append(
            "\n".join(
                [
                    f"[plugins.{_toml_quote(plugin_id)}]",
                    "enabled = true",
                ]
            )
        )

    for state_key in sorted(hook_states.keys()):
        st_entry = hook_states[state_key]
        lines = [
            f"[hooks.state.{_toml_quote(state_key)}]",
            f"enabled = {'true' if st_entry.get('enabled', True) else 'false'}",
            f"trusted_hash = {_toml_quote(str(st_entry['trusted_hash']))}",
        ]
        if st_entry.get("trusted_content_hash"):
            lines.append(
                f"trusted_content_hash = {_toml_quote(str(st_entry['trusted_content_hash']))}"
            )
        sections.append("\n".join(lines))

    return "\n\n".join(sections) + "\n"


def render_hook_jail_runner_source() -> str:
    """Return standalone, zero-dependency Python 3 source for `dots-hook-jail.py`."""
    ws_relpaths_json = json.dumps(list(WORKSPACE_HOOK_INJECTION_RELPATHS))
    ws_ro_relpaths_json = json.dumps(list(WORKSPACE_READONLY_PROTECTED_RELPATHS))
    return f'''#!/usr/bin/env python3
"""Standalone fail-closed native hook sandbox runner generated by dots-gateway."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

WORKSPACE_HOOK_INJECTION_RELPATHS = tuple({ws_relpaths_json})
WORKSPACE_READONLY_PROTECTED_RELPATHS = frozenset({ws_ro_relpaths_json})
MAX_HOOK_STDIN_BYTES = 8 * 1024 * 1024

SAFE_PASSTHROUGH_ENV_KEYS = ("LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "CLAUDE_SESSION_ID", "CODEX_THREAD_ID")

PURE_READONLY_TOOLS = frozenset(
    {{
        "read",
        "read_file",
        "view_file",
        "view_file_outline",
        "view_code_item",
        "grep",
        "grep_search",
        "ripgrep",
        "glob",
        "find_by_name",
        "list_dir",
        "ls",
    }}
)

ALLOWED_SYS_EXEC_ROOTS = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt/devtools",
    "/opt/uv-tools",
    "/opt/uv-python",
)


def _within(child: str, parent: str) -> bool:
    c = os.path.abspath(child)
    p = os.path.abspath(parent)
    if p == "/":
        return True
    return c == p or c.startswith(p.rstrip("/") + "/")


_DIAG_SECRET_RE = re.compile(
    r"(?i)(bearer\\s+\\S+|sk-[A-Za-z0-9_-]{{8,}}|gh[pousr]_[A-Za-z0-9_]{{8,}}|AIza[0-9A-Za-z_-]{{12,}}|(?:token|secret|password|apikey|api_key)\\s*[=:]\\s*\\S+)"
)


def _redact_diag_msg(raw: str, masked_paths: list[str] | None = None) -> str:
    text = _DIAG_SECRET_RE.sub("[REDACTED]", str(raw or ""))
    for mp in masked_paths or ():
        if mp and mp not in ("/", "/home", "/etc", "/var", "/opt", "/usr"):
            text = text.replace(mp, "<protected>")
    return " ".join(text.splitlines())[:400]


def _append_jail_diag_log(
    hook_tmp_dir: str,
    event_name: str,
    detail: str,
    masked_paths: list[str] | None = None,
) -> None:
    if not hook_tmp_dir or os.path.islink(hook_tmp_dir) or not os.path.isdir(hook_tmp_dir):
        return
    log_path = os.path.join(hook_tmp_dir, ".dots-hook-jail-diag.log")
    try:
        try:
            st = os.lstat(log_path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                return
            if st.st_size > 65536:
                os.unlink(log_path)
        except FileNotFoundError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(log_path, flags, 0o600)
        try:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            redacted = _redact_diag_msg(detail, masked_paths)
            line = f"{{ts}} event={{event_name}} {{redacted}}\\n".encode("utf-8", errors="replace")
            os.write(fd, line)
        finally:
            os.close(fd)
    except OSError:
        pass


def _emit_fail_closed(event_name: str, reason: str) -> "None":
    msg = f"[dots-hook-jail] {{reason}}"
    sys.stderr.write(msg + "\\n")
    sys.stderr.flush()
    if event_name in ("PreToolUse", "PermissionRequest", "PreInvocation", "UserPromptSubmit"):
        payload = {{
            "decision": "deny",
            "reason": msg,
            "hookSpecificOutput": {{
                "hookEventName": event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": msg,
            }},
        }}
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\\n")
        sys.stdout.flush()
    raise SystemExit(2)


def _find_sys_bin(name: str) -> str:
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"):
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    found = shutil.which(name)
    return found or ""


def _select_stage_dir(avoid_paths: list[str]) -> str:
    for cand in ("/media", "/mnt", "/srv", "/dev/shm"):
        if not os.path.isdir(cand) or os.path.islink(cand):
            continue
        conflict = False
        for raw in avoid_paths:
            if not raw:
                continue
            ap = os.path.abspath(raw)
            if _within(ap, cand) or _within(cand, ap):
                conflict = True
                break
        if not conflict:
            return cand
    return "/dev/shm"


def _extract_patch_paths(patch_text: str) -> list[str]:
    paths: list[str] = []
    for raw_line in patch_text.splitlines():
        for prefix in (
            "*** Add File: ",
            "*** Update File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ):
            if raw_line.startswith(prefix):
                val = raw_line[len(prefix) :].strip()
                if val:
                    paths.append(val)
        for udiff_prefix in ("+++ b/", "--- a/"):
            if raw_line.startswith(udiff_prefix):
                val = raw_line[len(udiff_prefix) :].split("\\t", 1)[0].strip()
                if val and val != "/dev/null":
                    paths.append(val)
    return paths


def _matches_workspace_relpaths(target_abs: str, allowed_roots: list[str], relpaths) -> bool:
    norm_t = os.path.abspath(target_abs)
    for ws_r in allowed_roots:
        if not _within(norm_t, ws_r):
            continue
        rel_posix = os.path.relpath(norm_t, ws_r).replace(os.sep, "/")
        if rel_posix in ("", "."):
            continue
        for rel_p in relpaths:
            p_posix = rel_p.replace(os.sep, "/").strip("/")
            if (
                rel_posix == p_posix
                or rel_posix.startswith(f"{{p_posix}}/")
                or rel_posix.endswith(f"/{{p_posix}}")
                or f"/{{p_posix}}/" in rel_posix
            ):
                return True
    return False


def _is_workspace_hook_injection_target(target_abs: str, allowed_roots: list[str]) -> bool:
    return _matches_workspace_relpaths(target_abs, allowed_roots, WORKSPACE_HOOK_INJECTION_RELPATHS)


def _is_workspace_readonly_protected_target(target_abs: str, allowed_roots: list[str]) -> bool:
    return _matches_workspace_relpaths(target_abs, allowed_roots, WORKSPACE_READONLY_PROTECTED_RELPATHS)


def _is_workspace_active_hook_injection_target(target_abs: str, allowed_roots: list[str]) -> bool:
    return _is_workspace_hook_injection_target(
        target_abs, allowed_roots
    ) and not _is_workspace_readonly_protected_target(target_abs, allowed_roots)


def _check_workspace_no_symlinked_hook_paths(
    allowed_workspaces: list[str],
    cwd_real: str,
    readonly_subpaths: list[str],
    event_name: str,
) -> None:
    top_ws: list[str] = []
    for ws_c in sorted(set(allowed_workspaces), key=lambda p: (len(p), p)):
        if os.path.islink(ws_c):
            _emit_fail_closed(event_name, f"Symlinked workspace root '{{ws_c}}' is forbidden")
        if os.path.isdir(ws_c) and not any(_within(ws_c, ex) for ex in top_ws):
            top_ws.append(ws_c)

    ws_dirs: list[str] = []
    for seed_w in [*allowed_workspaces, cwd_real]:
        cur_w = os.path.abspath(seed_w)
        while any(_within(cur_w, tw) for tw in top_ws):
            if cur_w not in ws_dirs:
                ws_dirs.append(cur_w)
            parent_w = os.path.dirname(cur_w)
            if parent_w == cur_w:
                break
            cur_w = parent_w

    for ws_dir in ws_dirs:
        for rel_inj in WORKSPACE_HOOK_INJECTION_RELPATHS:
            cur_chk = ws_dir
            for part in Path(rel_inj).parts:
                cur_chk = os.path.join(cur_chk, part)
                if os.path.islink(cur_chk):
                    _emit_fail_closed(
                        event_name,
                        f"Symlinked workspace hook/configuration path '{{cur_chk}}' is forbidden",
                    )

    for ro_sub in readonly_subpaths:
        if os.path.islink(ro_sub):
            _emit_fail_closed(
                event_name,
                f"Symlinked read-only workspace subpath '{{ro_sub}}' is forbidden",
            )


def _validate_path_no_symlink_escape(
    raw_p: str,
    *,
    effective_base_cwd: str,
    permitted_targets: list[str],
    effective_masked: list[str],
    event_name: str,
) -> tuple[str, str]:
    abs_p = (
        os.path.abspath(raw_p)
        if os.path.isabs(raw_p)
        else os.path.abspath(os.path.join(effective_base_cwd, raw_p))
    )
    probe = Path(abs_p)
    cur = Path("/")
    for part in probe.parts[1:]:
        cur = cur / part
        if os.path.islink(str(cur)):
            resolved_cur = os.path.realpath(str(cur))
            if not any(_within(resolved_cur, root) for root in permitted_targets) or any(
                _within(resolved_cur, mp) for mp in effective_masked
            ):
                _emit_fail_closed(
                    event_name,
                    f"Symlink escape blocked in '{{raw_p}}' ('{{cur}}' -> '{{resolved_cur}}')",
                )
    resolved_full = os.path.realpath(abs_p)
    if not any(_within(resolved_full, root) for root in permitted_targets):
        _emit_fail_closed(
            event_name,
            f"Path '{{raw_p}}' resolves outside authorized workspaces ('{{resolved_full}}')",
        )
    if any(_within(abs_p, mp) or _within(resolved_full, mp) for mp in effective_masked):
        _emit_fail_closed(
            event_name,
            f"Path '{{raw_p}}' targets a protected gateway path ('{{resolved_full}}')",
        )
    return abs_p, resolved_full


_SHELL_REDIR_OPS = ("1>>", "2>>", "&>>", ">>", ">|", "1>", "2>", "&>", "<>", ">", "<")
_SHELL_MUTATING_BINS = frozenset(
    {{"rm", "mv", "cp", "chmod", "chown", "truncate", "tee", "ln", "touch", "install", "dd"}}
)
_SHELL_READONLY_INSPECT_BINS = frozenset(
    {{
        "ls",
        "dir",
        "vdir",
        "stat",
        "file",
        "readlink",
        "realpath",
        "basename",
        "dirname",
        "pwd",
        "cat",
        "head",
        "tail",
        "nl",
        "wc",
        "cksum",
        "sha256sum",
        "sha1sum",
        "md5sum",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "tree",
        "du",
        "df",
        "diff",
        "cmp",
        "comm",
        "uniq",
        "cut",
        "tr",
        "jq",
        "yq",
        "test",
        "[",
        "echo",
        "printf",
    }}
)
_SHELL_READONLY_GIT_SUBCMDS = frozenset(
    {{
        "status",
        "diff",
        "log",
        "show",
        "ls-files",
        "ls-tree",
        "cat-file",
        "rev-parse",
        "check-ignore",
        "blame",
        "grep",
        "branch",
        "tag",
    }}
)
_FIND_UNSAFE_FLAGS = frozenset(
    {{
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-delete",
        "-fls",
        "-fprint",
        "-fprint0",
        "-fprintf",
    }}
)


def _split_shell_segments_simple(cmd_text: str):
    segments = []
    cur = []
    in_sq = False
    in_dq = False
    escaped = False
    n = len(cmd_text)
    i = 0
    while i < n:
        ch = cmd_text[i]
        nxt = cmd_text[i + 1] if i + 1 < n else ""
        if in_sq:
            if ch == "'":
                in_sq = False
            cur.append(ch)
            i += 1
            continue
        if escaped:
            cur.append(ch)
            escaped = False
            i += 1
            continue
        if ch == chr(92):
            escaped = True
            cur.append(ch)
            i += 1
            continue
        if in_dq:
            if ch == "`" or (ch == "$" and nxt == "(") or ch in (chr(10), chr(13)):
                return None
            if ch == '"':
                in_dq = False
            cur.append(ch)
            i += 1
            continue
        if ch == "'":
            in_sq = True
            cur.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dq = True
            cur.append(ch)
            i += 1
            continue
        if ch in (chr(10), chr(13), "`", "<", ">", "(", ")", "{{", "}}"):
            return None
        if ch == "$" and nxt == "(":
            return None
        if ch == ";":
            seg = "".join(cur).strip()
            if seg:
                segments.append(seg)
            cur = []
            i += 1
            continue
        if ch == "|":
            seg = "".join(cur).strip()
            if seg:
                segments.append(seg)
            cur = []
            i += 2 if nxt == "|" else 1
            continue
        if ch == "&":
            if nxt != "&":
                return None
            seg = "".join(cur).strip()
            if seg:
                segments.append(seg)
            cur = []
            i += 2
            continue
        cur.append(ch)
        i += 1
    if in_sq or in_dq or escaped:
        return None
    tail = "".join(cur).strip()
    if tail:
        segments.append(tail)
    return segments or None


def _is_pure_readonly_segment(seg_text: str) -> bool:
    try:
        toks = shlex.split(seg_text)
    except ValueError:
        return False
    idx = 0
    while idx < len(toks):
        tok = toks[idx]
        if "=" in tok and not tok.startswith("-"):
            var_name = tok.split("=", 1)[0]
            if var_name.isidentifier():
                idx += 1
                continue
        break
    if idx >= len(toks):
        return False
    cmd_bin = os.path.basename(toks[idx]).lower()
    args = toks[idx + 1 :]
    if cmd_bin == "cd":
        return True
    if cmd_bin == "find":
        for a in args:
            if a.split("=", 1)[0] in _FIND_UNSAFE_FLAGS:
                return False
        return True
    if cmd_bin == "git":
        j = 0
        while j < len(args):
            a = args[j]
            if a in ("--no-pager", "-p", "--paginate", "--bare"):
                j += 1
                continue
            if a in ("-C", "--git-dir", "--work-tree"):
                j += 2
                continue
            if a.startswith("--git-dir=") or a.startswith("--work-tree="):
                j += 1
                continue
            if a.startswith("-"):
                return False
            break
        if j >= len(args):
            return False
        subcmd = args[j]
        if subcmd not in _SHELL_READONLY_GIT_SUBCMDS:
            return False
        for rem in args[j + 1 :]:
            if rem == "--ext-diff" or rem == "-o" or rem == "--output" or rem.startswith("--output="):
                return False
        return True
    if cmd_bin not in _SHELL_READONLY_INSPECT_BINS:
        return False
    if cmd_bin == "rg":
        for a in args:
            if a == "--pre" or a.startswith("--pre="):
                return False
    return True


def _is_pure_readonly_command(cmd_text: str) -> bool:
    segs = _split_shell_segments_simple(cmd_text)
    if not segs:
        return False
    return all(_is_pure_readonly_segment(seg) for seg in segs)


def _inspect_shell_command_paths(
    cmd_text: str,
    *,
    effective_base_cwd: str,
    allowed_roots: list[str],
    readonly_plugin_roots: list[str],
    permitted_targets: list[str],
    effective_masked: list[str],
    event_name: str,
) -> None:
    try:
        sh_tokens = shlex.split(cmd_text)
    except ValueError:
        sh_tokens = cmd_text.split()
    safe_sys_roots = [*permitted_targets, "/tmp", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/dev", "/proc"]
    first_bin = os.path.basename(sh_tokens[0]).lower() if sh_tokens else ""
    is_mutating_cmd = first_bin in _SHELL_MUTATING_BINS or (
        first_bin == "sed" and any(t == "-i" or t.startswith("-i") for t in sh_tokens[1:])
    )
    is_pure_readonly_cmd = _is_pure_readonly_command(cmd_text)
    if _is_workspace_active_hook_injection_target(
        effective_base_cwd, allowed_roots
    ) or _is_workspace_active_hook_injection_target(
        os.path.realpath(effective_base_cwd), allowed_roots
    ):
        _emit_fail_closed(
            event_name,
            f"Command working directory references protected workspace hook/agent configuration path '{{effective_base_cwd}}'",
        )
    if (
        _is_workspace_readonly_protected_target(effective_base_cwd, allowed_roots)
        or _is_workspace_readonly_protected_target(
            os.path.realpath(effective_base_cwd), allowed_roots
        )
    ) and not (is_pure_readonly_cmd and not is_mutating_cmd):
        _emit_fail_closed(
            event_name,
            f"Command working directory references protected workspace hook/agent configuration path '{{effective_base_cwd}}'",
        )
    prev_was_out_redir = False
    prev_was_cd = False
    scan_cwd = effective_base_cwd
    for raw_tok in sh_tokens:
        if raw_tok in (";", "&&", "||", "|"):
            prev_was_out_redir = False
            prev_was_cd = False
            continue
        if raw_tok in _SHELL_REDIR_OPS:
            prev_was_out_redir = ">" in raw_tok
            prev_was_cd = False
            continue
        tok = raw_tok
        is_out_redir = prev_was_out_redir
        prev_was_out_redir = False
        for rop in _SHELL_REDIR_OPS:
            if tok.startswith(rop) and len(tok) > len(rop):
                if ">" in rop:
                    is_out_redir = True
                tok = tok[len(rop) :]
                break
        if prev_was_cd and tok == "--":
            continue
        if not tok or "://" in tok or tok.startswith(("s/", "y/", "-")):
            prev_was_cd = raw_tok == "cd"
            continue
        was_cd_target = prev_was_cd
        prev_was_cd = raw_tok == "cd"
        if tok.startswith(("/dev/", "/proc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/etc/", "/opt/", "/tmp/")):
            abs_sys = os.path.abspath(tok)
            if any(_within(abs_sys, mp) for mp in effective_masked):
                _emit_fail_closed(
                    event_name,
                    f"Command references protected gateway path '{{tok}}'",
                )
            if (is_out_redir or is_mutating_cmd) and any(
                _within(abs_sys, pr) or _within(os.path.realpath(abs_sys), pr)
                for pr in readonly_plugin_roots
            ):
                _emit_fail_closed(
                    event_name,
                    f"Modifying read-only plugin directory via '{{tok}}' is forbidden",
                )
            if was_cd_target:
                scan_cwd = abs_sys
            continue
        if tok == "/tmp":
            if was_cd_target:
                scan_cwd = "/tmp"
            continue
        rel_base_c = (
            os.path.abspath(tok)
            if os.path.isabs(tok)
            else os.path.abspath(os.path.join(effective_base_cwd, tok))
        )
        rel_scan_c = (
            rel_base_c
            if os.path.isabs(tok)
            else os.path.abspath(os.path.join(scan_cwd, tok))
        )
        if (
            is_out_redir
            or was_cd_target
            or tok.startswith(("/", "./", "../"))
            or "/" in tok
            or os.path.islink(os.path.join(effective_base_cwd, tok))
            or os.path.islink(os.path.join(scan_cwd, tok))
            or _is_workspace_hook_injection_target(rel_base_c, allowed_roots)
            or _is_workspace_hook_injection_target(rel_scan_c, allowed_roots)
        ):
            check_abs_list = [rel_base_c] if rel_scan_c == rel_base_c else [rel_base_c, rel_scan_c]
            for abs_c in check_abs_list:
                if any(_within(abs_c, mp) for mp in effective_masked):
                    _emit_fail_closed(
                        event_name,
                        f"Command references protected gateway path '{{tok}}'",
                    )
                cur = Path("/")
                for part in Path(abs_c).parts[1:]:
                    cur = cur / part
                    if os.path.islink(str(cur)):
                        resolved_cur = os.path.realpath(str(cur))
                        if not any(_within(resolved_cur, r) for r in safe_sys_roots) or any(
                            _within(resolved_cur, mp) for mp in effective_masked
                        ):
                            _emit_fail_closed(
                                event_name,
                                f"Symlink escape blocked in command path '{{tok}}' ('{{cur}}' -> '{{resolved_cur}}')",
                            )
                resolved_c = os.path.realpath(abs_c)
                if _is_workspace_active_hook_injection_target(
                    abs_c, allowed_roots
                ) or _is_workspace_active_hook_injection_target(resolved_c, allowed_roots):
                    _emit_fail_closed(
                        event_name,
                        f"Command references protected workspace hook/agent configuration path '{{tok}}'",
                    )
                if (
                    _is_workspace_readonly_protected_target(abs_c, allowed_roots)
                    or _is_workspace_readonly_protected_target(resolved_c, allowed_roots)
                ) and not (is_pure_readonly_cmd and not is_out_redir and not is_mutating_cmd):
                    _emit_fail_closed(
                        event_name,
                        f"Command references protected workspace hook/agent configuration path '{{tok}}'",
                    )
                if (is_out_redir or is_mutating_cmd) and any(
                    _within(abs_c, pr) or _within(resolved_c, pr) for pr in readonly_plugin_roots
                ):
                    _emit_fail_closed(
                        event_name,
                        f"Modifying read-only plugin directory via '{{tok}}' is forbidden",
                    )
            if was_cd_target:
                scan_cwd = rel_scan_c


def _check_symlink_escape_in_payload(
    stdin_bytes: bytes,
    event_name: str,
    allowed_roots: list[str],
    readonly_plugin_roots: list[str],
    allowed_artifact_roots: list[str],
    masked_paths: list[str],
    cwd_real: str,
) -> None:
    if not stdin_bytes or not stdin_bytes.strip():
        if event_name in ("PreToolUse", "PermissionRequest", "PreInvocation"):
            _emit_fail_closed(event_name, f"Empty hook stdin payload on {{event_name}}")
        return
    try:
        payload = json.loads(stdin_bytes.decode("utf-8"))
    except Exception as exc:
        _emit_fail_closed(event_name, f"Malformed JSON in hook stdin payload: {{exc}}")
    if not isinstance(payload, dict):
        _emit_fail_closed(event_name, "Hook stdin payload must be a JSON object")

    permitted_targets = [*allowed_roots, *readonly_plugin_roots, *allowed_artifact_roots]
    effective_masked = [
        mp
        for mp in masked_paths
        if not any(_within(keep_d, mp) for keep_d in permitted_targets)
    ]

    raw_cwd = payload.get("cwd")
    if isinstance(raw_cwd, str) and raw_cwd.strip():
        _validate_path_no_symlink_escape(
            raw_cwd.strip(),
            effective_base_cwd=cwd_real,
            permitted_targets=permitted_targets,
            effective_masked=effective_masked,
            event_name=event_name,
        )

    raw_ws_paths = payload.get("workspacePaths")
    if isinstance(raw_ws_paths, list):
        for ws_item in raw_ws_paths:
            if isinstance(ws_item, str) and ws_item.strip():
                _validate_path_no_symlink_escape(
                    ws_item.strip(),
                    effective_base_cwd=cwd_real,
                    permitted_targets=permitted_targets,
                    effective_masked=effective_masked,
                    event_name=event_name,
                )

    if event_name not in ("PreToolUse", "PermissionRequest", "PreInvocation", "PostToolUse"):
        return

    candidate_paths: list[str] = []
    shell_commands: list[str] = []
    tool_name = str(payload.get("tool_name") or "")
    effective_base_cwd = cwd_real
    if isinstance(raw_cwd, str) and raw_cwd.strip() and os.path.isabs(raw_cwd.strip()):
        effective_base_cwd = os.path.realpath(os.path.abspath(raw_cwd.strip()))
    elif isinstance(raw_ws_paths, list) and raw_ws_paths and isinstance(raw_ws_paths[0], str) and os.path.isabs(raw_ws_paths[0]):
        effective_base_cwd = os.path.realpath(os.path.abspath(raw_ws_paths[0]))

    tool_input = payload.get("tool_input")
    if isinstance(tool_input, str):
        if "patch" in tool_name.lower() or "*** " in tool_input:
            candidate_paths.extend(_extract_patch_paths(tool_input))
    elif isinstance(tool_input, dict):
        for wd_key in ("workdir", "cwd", "directory", "Cwd", "DirectoryPath"):
            raw_wd = tool_input.get(wd_key)
            if isinstance(raw_wd, str) and raw_wd.strip():
                _, resolved_wd = _validate_path_no_symlink_escape(
                    raw_wd.strip(),
                    effective_base_cwd=effective_base_cwd,
                    permitted_targets=permitted_targets,
                    effective_masked=effective_masked,
                    event_name=event_name,
                )
                effective_base_cwd = resolved_wd

        for key in (
            "file_path",
            "path",
            "TargetFile",
            "AbsolutePath",
            "filePath",
            "notebook_path",
            "destination",
            "source",
            "to_path",
            "from_path",
        ):
            val = tool_input.get(key)
            if isinstance(val, str) and val.strip():
                candidate_paths.append(val.strip())
        edits = tool_input.get("edits")
        if isinstance(edits, list):
            for ed in edits:
                if isinstance(ed, dict):
                    for ek in ("file_path", "path", "TargetFile"):
                        if isinstance(ed.get(ek), str) and ed[ek].strip():
                            candidate_paths.append(ed[ek].strip())

        for patch_key in ("patch", "input", "diff", "raw_patch", "command"):
            pval = tool_input.get(patch_key)
            if isinstance(pval, str) and (
                tool_name == "apply_patch" or patch_key != "command" or "*** " in pval
            ):
                candidate_paths.extend(_extract_patch_paths(pval))
            elif isinstance(pval, list) and patch_key == "command":
                joined_cmd = " ".join(str(x) for x in pval)
                if tool_name == "apply_patch" or "apply_patch" in joined_cmd or "*** " in joined_cmd:
                    for elem in pval:
                        if isinstance(elem, str):
                            candidate_paths.extend(_extract_patch_paths(elem))

        if tool_name in ("Bash", "run_command", "exec_command", "shell_command", "shell"):
            raw_sh = (
                tool_input.get("command")
                or tool_input.get("cmd")
                or tool_input.get("CommandLine")
                or tool_input.get("command_line")
            )
            if isinstance(raw_sh, str) and raw_sh.strip():
                shell_commands.append(raw_sh)
            elif isinstance(raw_sh, list):
                shell_commands.append(" ".join(shlex.quote(str(x)) for x in raw_sh))

    tool_call = payload.get("toolCall")
    if isinstance(tool_call, dict):
        if not tool_name and isinstance(tool_call.get("name"), str):
            tool_name = tool_call["name"]
        tc_args = tool_call.get("args")
        if isinstance(tc_args, dict):
            for tc_wd_key in ("Cwd", "DirectoryPath"):
                if isinstance(tc_args.get(tc_wd_key), str) and tc_args[tc_wd_key].strip():
                    _, resolved_tc_wd = _validate_path_no_symlink_escape(
                        tc_args[tc_wd_key].strip(),
                        effective_base_cwd=effective_base_cwd,
                        permitted_targets=permitted_targets,
                        effective_masked=effective_masked,
                        event_name=event_name,
                    )
                    if tc_wd_key == "Cwd":
                        effective_base_cwd = resolved_tc_wd
            for key in (
                "Path",
                "TargetFile",
                "AbsolutePath",
                "file_path",
                "path",
                "SearchPath",
                "Directory",
                "DirectoryPath",
            ):
                val = tc_args.get(key)
                if isinstance(val, str) and val.strip():
                    candidate_paths.append(val.strip())
            for list_key in ("SearchPaths", "Paths"):
                lval = tc_args.get(list_key)
                if isinstance(lval, list):
                    for item in lval:
                        if isinstance(item, str) and item.strip():
                            candidate_paths.append(item.strip())
            chunks = tc_args.get("ReplacementChunks")
            if isinstance(chunks, list):
                for ch in chunks:
                    if isinstance(ch, dict) and isinstance(ch.get("TargetFile"), str) and ch["TargetFile"].strip():
                        candidate_paths.append(ch["TargetFile"].strip())
            if isinstance(tc_args.get("CommandLine"), str) and tc_args["CommandLine"].strip():
                shell_commands.append(tc_args["CommandLine"].strip())

    for sh_cmd in shell_commands:
        _inspect_shell_command_paths(
            sh_cmd,
            effective_base_cwd=effective_base_cwd,
            allowed_roots=allowed_roots,
            readonly_plugin_roots=readonly_plugin_roots,
            permitted_targets=permitted_targets,
            effective_masked=effective_masked,
            event_name=event_name,
        )

    is_mutating_tool = tool_name.strip().lower() not in PURE_READONLY_TOOLS
    for raw_p in candidate_paths:
        abs_p, resolved_full = _validate_path_no_symlink_escape(
            raw_p,
            effective_base_cwd=effective_base_cwd,
            permitted_targets=permitted_targets,
            effective_masked=effective_masked,
            event_name=event_name,
        )
        if is_mutating_tool and any(_within(resolved_full, p_root) for p_root in readonly_plugin_roots):
            _emit_fail_closed(
                event_name,
                f"Modifying read-only plugin directory via '{{raw_p}}' is forbidden",
            )
        if is_mutating_tool and (
            _is_workspace_hook_injection_target(abs_p, allowed_roots)
            or _is_workspace_hook_injection_target(resolved_full, allowed_roots)
        ):
            _emit_fail_closed(
                event_name,
                f"Modifying protected hook/agent configuration path '{{raw_p}}' inside workspace is forbidden",
            )


_SAFE_PY_FLAG_CHARS = frozenset({{"I", "S", "B", "E", "s", "u", "O"}})
_SAFE_SH_FLAGS = frozenset({{"-e", "-u", "-eu", "-ue", "--norc", "--noprofile"}})
_SAFE_JS_FLAGS = frozenset({{"--no-warnings", "--no-deprecation"}})
_SAFE_RP_FLAGS = frozenset({{"-w", "-T"}})
_SAFE_UV_FLAGS = frozenset(
    {{"--no-project", "--isolated", "--offline", "--quiet", "-q", "--no-sync", "--script", "-s"}}
)


def _validate_argv_not_in_workspace(
    resolved_argv: list[str],
    event_name: str,
    allowed_workspaces: list[str],
    plugin_roots: list[str],
) -> None:
    if not isinstance(resolved_argv, list) or not resolved_argv:
        _emit_fail_closed(event_name, "Empty or invalid hook argv")
    for tok in resolved_argv:
        if not isinstance(tok, str) or not tok or any(ch in tok for ch in ("\\x00", "\\r", "\\n")):
            _emit_fail_closed(event_name, "Malformed token in hook argv")

    exe_tok = resolved_argv[0]
    exe_base = os.path.basename(exe_tok).lower()
    if "/" not in exe_tok:
        resolved_exe = _find_sys_bin(exe_tok)
        if not resolved_exe or not any(_within(resolved_exe, sr) for sr in ALLOWED_SYS_EXEC_ROOTS):
            _emit_fail_closed(
                event_name,
                f"Hook executable '{{exe_tok}}' could not be resolved inside trusted system directories",
            )

    is_py = exe_base in ("python", "python3") or exe_base.startswith("python3.")
    is_sh = exe_base in ("bash", "sh", "dash", "zsh")
    is_js = exe_base in ("node", "nodejs", "deno", "bun")
    is_rp = exe_base in ("ruby", "perl")
    is_uv = exe_base == "uv"
    if (is_py or is_sh or is_js or is_rp or is_uv) and not any(
        _within(exe_tok, pr) for pr in plugin_roots
    ):
        idx = 1
        uv_isolated = False
        if is_uv:
            if len(resolved_argv) <= 1 or resolved_argv[1] != "run":
                _emit_fail_closed(event_name, "'uv' hook must invoke 'uv run --no-project <plugin_script>'")
            idx = 2
        script_target = ""
        while idx < len(resolved_argv):
            a = resolved_argv[idx]
            if a == "--":
                if idx + 1 < len(resolved_argv):
                    script_target = resolved_argv[idx + 1]
                break
            if a == "-":
                _emit_fail_closed(event_name, "Hook interpreter stdin ('-') is forbidden")
            if a.startswith("-"):
                if is_py and len(a) >= 2 and not a.startswith("--") and all(ch in _SAFE_PY_FLAG_CHARS for ch in a[1:]):
                    idx += 1
                    continue
                if is_sh and a in _SAFE_SH_FLAGS:
                    idx += 1
                    continue
                if is_js and a in _SAFE_JS_FLAGS:
                    idx += 1
                    continue
                if is_rp and a in _SAFE_RP_FLAGS:
                    idx += 1
                    continue
                if is_uv and a in _SAFE_UV_FLAGS:
                    if a in ("--no-project", "--isolated"):
                        uv_isolated = True
                    idx += 1
                    continue
                _emit_fail_closed(event_name, f"Disallowed interpreter flag '{{a}}' before plugin script")
            script_target = a
            break
        if is_uv and not uv_isolated:
            _emit_fail_closed(
                event_name,
                "'uv run' hook must include '--no-project' or '--isolated' before plugin script",
            )
        if not script_target or not os.path.isabs(script_target) or not any(
            _within(script_target, pr) for pr in plugin_roots
        ):
            _emit_fail_closed(
                event_name,
                f"Hook interpreter '{{exe_tok}}' must target an absolute script inside read-only plugin roots (got '{{script_target}}')",
            )

    for tok in resolved_argv:
        cand_paths: list[str] = []
        if tok.startswith("-") and "=" in tok:
            _, opt_v = tok.split("=", 1)
            if opt_v.startswith(("/", "./", "../")):
                cand_paths.append(opt_v)
        elif "/" in tok and not tok.startswith("-"):
            cand_paths.append(tok)
        for cp in cand_paths:
            abs_tok = os.path.abspath(cp)
            real_tok = os.path.realpath(abs_tok)
            for ws in allowed_workspaces:
                if _within(abs_tok, ws) or _within(real_tok, ws):
                    _emit_fail_closed(
                        event_name,
                        f"Executing code from writable workspace ('{{cp}}') inside a hook is forbidden",
                    )
            if not any(
                _within(abs_tok, p_root)
                for p_root in [*plugin_roots, *ALLOWED_SYS_EXEC_ROOTS, "/dev/null"]
            ):
                _emit_fail_closed(
                    event_name,
                    f"Hook command references unauthorized path '{{cp}}'",
                )


def _build_sanitized_env(
    plugin_vfs_dir: str,
    hook_tmp_inside: str,
    hook_home_inside: str,
    hook_data_inside: str,
) -> dict[str, str]:
    env: dict[str, str] = {{}}
    for k in SAFE_PASSTHROUGH_ENV_KEYS:
        val = os.environ.get(k)
        if val:
            env[k] = val
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("TERM", "dumb")

    path_dirs = ["/usr/local/bin", "/usr/bin", "/bin"]
    for opt_bin in ("/opt/devtools/bin", "/opt/uv-tools/bin", "/opt/uv-python/bin"):
        if os.path.isdir(opt_bin):
            path_dirs.append(opt_bin)
    env["PATH"] = ":".join(path_dirs)

    env["HOME"] = hook_home_inside
    env["TMPDIR"] = hook_tmp_inside
    env["TMP"] = hook_tmp_inside
    env["TEMP"] = hook_tmp_inside
    env["PLUGIN_ROOT"] = plugin_vfs_dir
    env["CLAUDE_PLUGIN_ROOT"] = plugin_vfs_dir
    env["AGY_PLUGIN_ROOT"] = plugin_vfs_dir
    env["PLUGIN_DATA"] = hook_data_inside
    env["CLAUDE_PLUGIN_DATA"] = hook_data_inside

    env["PYTHONSAFEPATH"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["NO_GCE_CHECK"] = "true"
    env["GCE_METADATA_HOST"] = "127.0.0.1:1"
    env["GCE_METADATA_ROOT"] = "127.0.0.1:1"
    env["AWS_EC2_METADATA_DISABLED"] = "true"

    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/false"
    env["GIT_SSH_COMMAND"] = "/bin/false"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_COUNT"] = "5"
    env["GIT_CONFIG_KEY_0"] = "core.fsmonitor"
    env["GIT_CONFIG_VALUE_0"] = "false"
    env["GIT_CONFIG_KEY_1"] = "core.hooksPath"
    env["GIT_CONFIG_VALUE_1"] = "/dev/null"
    env["GIT_CONFIG_KEY_2"] = "core.sshCommand"
    env["GIT_CONFIG_VALUE_2"] = "/bin/false"
    env["GIT_CONFIG_KEY_3"] = "diff.external"
    env["GIT_CONFIG_VALUE_3"] = ""
    env["GIT_CONFIG_KEY_4"] = "protocol.allow"
    env["GIT_CONFIG_VALUE_4"] = "never"
    return env


def _build_nested_jail_argv(
    cfg: dict,
    *,
    cwd_real: str,
    resolved_argv: list[str],
    hook_tmp_dir: str,
    hook_data_dir: str,
    allowed_artifact_roots: list[str],
    ready_fd: int | None = None,
) -> tuple[list[str], str]:
    unshare_bin = _find_sys_bin("unshare")
    mount_bin = _find_sys_bin("mount")
    umount_bin = _find_sys_bin("umount")
    pivot_bin = _find_sys_bin("pivot_root")
    setpriv_bin = _find_sys_bin("setpriv")
    if not all((unshare_bin, mount_bin, umount_bin, pivot_bin, setpriv_bin)):
        return [], "Required Linux namespace binaries (unshare/mount/umount/pivot_root/setpriv) are missing"

    plugin_vfs_dir = os.path.abspath(str(cfg["plugin_vfs_dir"]))
    plugin_source_dir = os.path.abspath(str(cfg["plugin_source_dir"]))
    active_plugin_src = plugin_vfs_dir if os.path.isdir(plugin_vfs_dir) else plugin_source_dir
    allowed_workspaces = [os.path.abspath(str(x)) for x in (cfg.get("allowed_workspaces") or [])]
    masked_paths = [os.path.abspath(str(x)) for x in (cfg.get("masked_paths") or []) if str(x).strip()]
    readonly_subpaths = [os.path.abspath(str(x)) for x in (cfg.get("readonly_subpaths") or []) if str(x).strip()]

    stage_dir = _select_stage_dir(
        [
            plugin_vfs_dir,
            plugin_source_dir,
            hook_tmp_dir,
            hook_data_dir,
            cwd_real,
            *allowed_workspaces,
            *allowed_artifact_roots,
        ]
    )
    q_stage = shlex.quote(stage_dir)
    q_mount = shlex.quote(mount_bin)
    q_umount = shlex.quote(umount_bin)
    q_pivot = shlex.quote(pivot_bin)
    q_setpriv = shlex.quote(setpriv_bin)

    lines: list[str] = [
        "set -euo pipefail",
        f"{{q_mount}} -t tmpfs -o size=32m,mode=0755,nosuid,nodev tmpfs {{q_stage}}",
    ]
    if stage_dir == "/dev/shm":
        lines.extend(
            [
                f"mkdir -p {{shlex.quote(f'{{stage_dir}}/dev')}}",
                f"{{q_mount}} --rbind /dev {{shlex.quote(f'{{stage_dir}}/dev')}}",
                f"{{q_mount}} -t tmpfs -o size=16m,mode=1777,nosuid,nodev,noexec tmpfs {{shlex.quote(f'{{stage_dir}}/dev/shm')}}",
                "for d in usr bin sbin lib lib64 etc var opt proc sys run; do",
            ]
        )
    else:
        lines.append("for d in usr bin sbin lib lib64 etc var opt proc dev sys run; do")

    lines.extend(
        [
            '  if [ -L "/$d" ]; then',
            f'    ln -s "$(readlink "/$d")" "{{stage_dir}}/$d"',
            '  elif [ -d "/$d" ]; then',
            f'    mkdir -p "{{stage_dir}}/$d"',
            f'    {{q_mount}} --rbind "/$d" "{{stage_dir}}/$d"',
            "  fi",
            "done",
            f'if [ -d "/opt" ] && [ -d "{{stage_dir}}/opt" ]; then',
            f'  {{q_mount}} -o remount,bind,ro,nosuid,nodev "{{stage_dir}}/opt" 2>/dev/null || {{q_mount}} -o remount,bind,ro "{{stage_dir}}/opt" 2>/dev/null || {{q_mount}} -o bind,remount,ro "{{stage_dir}}/opt"',
            "fi",
            f'if [ -d "{{stage_dir}}/run/user" ]; then',
            f'  {{q_mount}} -t tmpfs -o size=1m,mode=0555,ro,nosuid,nodev,noexec tmpfs {{shlex.quote(f"{{stage_dir}}/run/user")}}',
            "fi",
            "for sock in /run/docker.sock /var/run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock; do",
            f'  if [ -e "{{stage_dir}}$sock" ] && [ ! -d "{{stage_dir}}$sock" ]; then {{q_mount}} --bind /dev/null "{{stage_dir}}$sock"; fi',
            "done",
            f"mkdir -p {{shlex.quote(f'{{stage_dir}}/home')}} {{shlex.quote(f'{{stage_dir}}/tmp')}} {{shlex.quote(f'{{stage_dir}}/mnt')}} {{shlex.quote(f'{{stage_dir}}/media')}}",
        ]
    )

    keep_roots_for_mask = [plugin_vfs_dir, plugin_source_dir, *allowed_workspaces, *allowed_artifact_roots]

    # Mask any protected paths outside /home (e.g. /etc/..., /var/..., /opt/...)
    for mp in masked_paths:
        if mp in ("/", "/usr", "/bin", "/lib", "/lib64", "/etc", "/var", "/opt", "/home"):
            continue
        if any(_within(kr, mp) for kr in keep_roots_for_mask):
            continue
        q_mp = shlex.quote(f"{{stage_dir}}{{mp}}")
        lines.append(
            f"if [ -d {{q_mp}} ]; then {{q_mount}} -t tmpfs -o size=4k,mode=0555,ro,nosuid,nodev,noexec tmpfs {{q_mp}}; "
            f"elif [ -e {{q_mp}} ]; then {{q_mount}} --bind /dev/null {{q_mp}}; fi"
        )

    # Mount isolated per-plugin writable /tmp, HOME (/tmp/dots-hook-home), and PLUGIN_DATA (/tmp/plugin-data) with noexec!
    q_htmp = shlex.quote(hook_tmp_dir)
    q_dst_tmp = shlex.quote(f"{{stage_dir}}/tmp")
    q_hdata = shlex.quote(hook_data_dir)
    q_dst_data = shlex.quote(f"{{stage_dir}}/tmp/plugin-data")
    q_dst_home = shlex.quote(f"{{stage_dir}}/tmp/dots-hook-home")
    lines.extend(
        [
            f"[ ! -L {{q_htmp}} ] && [ -d {{q_htmp}} ]",
            f"{{q_mount}} --rbind {{q_htmp}} {{q_dst_tmp}}",
            f"mkdir -p {{q_dst_home}} {{q_dst_data}}",
            f"{{q_mount}} -o remount,bind,rw,nosuid,nodev,noexec {{q_dst_tmp}} 2>/dev/null || {{q_mount}} -o bind,remount,rw,nosuid,nodev,noexec {{q_dst_tmp}}",
            f"[ ! -L {{q_hdata}} ] && [ -d {{q_hdata}} ]",
            f"{{q_mount}} --rbind {{q_hdata}} {{q_dst_data}}",
            f"{{q_mount}} -o remount,bind,rw,nosuid,nodev,noexec {{q_dst_data}} 2>/dev/null || {{q_mount}} -o bind,remount,rw,nosuid,nodev,noexec {{q_dst_data}}",
        ]
    )

    # Mount ONLY the active plugin read-only at its isolated discovery path (all credentials under agent_runtime_home_root stay absent!).
    # Must use `--rbind` (not `--bind`) because the outer VFS mounts a read-only `hooks.json` submount inside
    # `active_plugin_src` and `plugin_source_dir`; in a nested user+mount namespace, Linux `do_loopback()`
    # marks that child submount `MNT_LOCKED` and rejects non-recursive `--bind` with `EINVAL` (exit status 32).
    q_psrc = shlex.quote(active_plugin_src)
    q_pdst = shlex.quote(f"{{stage_dir}}{{plugin_vfs_dir}}")
    lines.extend(
        [
            f"[ ! -L {{q_psrc}} ] && [ -d {{q_psrc}} ]",
            f"mkdir -p {{q_pdst}}",
            f"{{q_mount}} --rbind {{q_psrc}} {{q_pdst}}",
            f"{{q_mount}} -o remount,bind,ro,nosuid,nodev {{q_pdst}} 2>/dev/null || {{q_mount}} -o remount,bind,ro {{q_pdst}} 2>/dev/null || {{q_mount}} -o bind,remount,ro {{q_pdst}}",
        ]
    )
    if os.path.isdir(plugin_source_dir) and plugin_source_dir != plugin_vfs_dir:
        q_csrc = shlex.quote(plugin_source_dir)
        q_cdst = shlex.quote(f"{{stage_dir}}{{plugin_source_dir}}")
        lines.extend(
            [
                f"mkdir -p {{q_cdst}}",
                f"{{q_mount}} --rbind {{q_csrc}} {{q_cdst}}",
                f"{{q_mount}} -o remount,bind,ro,nosuid,nodev {{q_cdst}} 2>/dev/null || {{q_mount}} -o remount,bind,ro {{q_cdst}} 2>/dev/null || {{q_mount}} -o bind,remount,ro {{q_cdst}}",
            ]
        )

    # For AGY only, bind conversation artifact/transcript brain directories read-only+noexec if present
    # (oauth_creds.json, google_accounts.json, gcloud ADC, etc. remain 100% unmounted and absent).
    for art_root in allowed_artifact_roots:
        if os.path.isdir(art_root) and not os.path.islink(art_root):
            q_asrc = shlex.quote(art_root)
            q_adst = shlex.quote(f"{{stage_dir}}{{art_root}}")
            lines.extend(
                [
                    f"mkdir -p {{q_adst}}",
                    f"{{q_mount}} --rbind {{q_asrc}} {{q_adst}}",
                    f"{{q_mount}} -o remount,bind,ro,nosuid,nodev,noexec {{q_adst}} 2>/dev/null || {{q_mount}} -o bind,remount,ro {{q_adst}}",
                ]
            )

    # Mount non-overlapping top-level session workspaces parent-first (rw,nosuid,nodev,noexec)
    # so parent `--rbind` never overmounts child masks or submounts!
    top_workspaces: list[str] = []
    for ws_cand in sorted(set(allowed_workspaces), key=lambda p: (len(p), p)):
        if not os.path.isdir(ws_cand) or os.path.islink(ws_cand):
            continue
        if any(_within(ws_cand, existing) for existing in top_workspaces):
            continue
        top_workspaces.append(ws_cand)

    for ws in top_workspaces:
        q_ws = shlex.quote(ws)
        q_wdst = shlex.quote(f"{{stage_dir}}{{ws}}")
        lines.extend(
            [
                f"mkdir -p {{q_wdst}}",
                f"{{q_mount}} --rbind {{q_ws}} {{q_wdst}}",
                f"{{q_mount}} -o remount,bind,rw,nosuid,nodev,noexec {{q_wdst}} 2>/dev/null || {{q_mount}} -o bind,remount,rw,nosuid,nodev,noexec {{q_wdst}}",
            ]
        )

    ws_mask_dirs: list[str] = []
    for seed_ws in [*allowed_workspaces, cwd_real]:
        cur_w = os.path.abspath(seed_ws)
        while any(_within(cur_w, tw) for tw in top_workspaces):
            if cur_w not in ws_mask_dirs:
                ws_mask_dirs.append(cur_w)
            parent_w = os.path.dirname(cur_w)
            if parent_w == cur_w:
                break
            cur_w = parent_w

    for ws_dir in ws_mask_dirs:
        for rel_inj in WORKSPACE_HOOK_INJECTION_RELPATHS:
            parts = [pt for pt in rel_inj.split("/") if pt]
            cur_p = ws_dir
            for pt in parts:
                cur_p = os.path.join(cur_p, pt)
                if os.path.islink(cur_p):
                    return [], f"Symlinked workspace hook/settings path '{{cur_p}}' is forbidden"
            inj_host = os.path.join(ws_dir, rel_inj)
            q_inj_dst = shlex.quote(f"{{stage_dir}}{{inj_host}}")
            if rel_inj in WORKSPACE_READONLY_PROTECTED_RELPATHS:
                q_inj_src = shlex.quote(os.path.realpath(inj_host))
                if os.path.isdir(inj_host):
                    lines.extend(
                        [
                            f"if [ ! -L {{q_inj_src}} ] && [ -d {{q_inj_src}} ] && [ -d {{q_inj_dst}} ]; then",
                            f"  {{q_mount}} --rbind {{q_inj_src}} {{q_inj_dst}}",
                            f"  {{q_mount}} -o remount,bind,ro,nosuid,nodev,noexec {{q_inj_dst}} 2>/dev/null || {{q_mount}} -o bind,remount,ro {{q_inj_dst}}",
                            "fi",
                        ]
                    )
                elif os.path.isfile(inj_host):
                    lines.extend(
                        [
                            f"if [ ! -L {{q_inj_src}} ] && [ -f {{q_inj_src}} ] && [ -f {{q_inj_dst}} ]; then",
                            f"  {{q_mount}} --bind {{q_inj_src}} {{q_inj_dst}}",
                            f"  {{q_mount}} -o remount,bind,ro,nosuid,nodev,noexec {{q_inj_dst}} 2>/dev/null || {{q_mount}} -o bind,remount,ro {{q_inj_dst}}",
                            "fi",
                        ]
                    )
            elif os.path.isdir(inj_host):
                lines.append(
                    f"if [ -d {{q_inj_dst}} ]; then {{q_mount}} -t tmpfs -o size=4k,mode=0555,ro,nosuid,nodev,noexec tmpfs {{q_inj_dst}}; fi"
                )
            elif os.path.isfile(inj_host):
                lines.append(
                    f"if [ -f {{q_inj_dst}} ]; then {{q_mount}} --bind /dev/null {{q_inj_dst}}; fi"
                )

    for mp in masked_paths:
        if mp in ("/", "/usr", "/bin", "/lib", "/lib64", "/etc", "/var", "/opt", "/home"):
            continue
        if any(_within(kr, mp) for kr in keep_roots_for_mask):
            continue
        if any(_within(mp, ws) for ws in allowed_workspaces):
            q_mp = shlex.quote(f"{{stage_dir}}{{mp}}")
            lines.append(
                f"if [ -d {{q_mp}} ]; then {{q_mount}} -t tmpfs -o size=4k,mode=0555,ro,nosuid,nodev,noexec tmpfs {{q_mp}}; "
                f"elif [ -e {{q_mp}} ]; then {{q_mount}} --bind /dev/null {{q_mp}}; fi"
            )

    for ro_sub in readonly_subpaths:
        if os.path.islink(ro_sub):
            return [], f"Symlinked readonly_subpath '{{ro_sub}}' is forbidden"
        if os.path.isdir(ro_sub):
            q_ros = shlex.quote(ro_sub)
            q_rod = shlex.quote(f"{{stage_dir}}{{ro_sub}}")
            lines.extend(
                [
                    f"if [ -d {{q_rod}} ]; then",
                    f"  {{q_mount}} --rbind {{q_ros}} {{q_rod}}",
                    f"  {{q_mount}} -o remount,bind,ro,nosuid,nodev,noexec {{q_rod}} 2>/dev/null || {{q_mount}} -o bind,remount,ro {{q_rod}}",
                    "fi",
                ]
            )

    active_cwd = cwd_real
    if active_cwd == plugin_source_dir and not os.path.isdir(plugin_source_dir) and os.path.isdir(plugin_vfs_dir):
        active_cwd = plugin_vfs_dir

    lines.extend(
        [
            f"mkdir -p {{shlex.quote(f'{{stage_dir}}/.oldroot')}}",
            f"cd {{q_stage}}",
            f"{{q_pivot}} . .oldroot",
            f"{{q_umount}} -l /.oldroot",
            "rmdir /.oldroot",
            f"cd {{shlex.quote(active_cwd)}}",
        ]
    )
    if ready_fd is not None:
        lines.extend(
            [
                f"printf 'READY' >&{{int(ready_fd)}}",
                f"exec {{int(ready_fd)}}>&-",
            ]
        )
    lines.append(
        f'exec {{q_setpriv}} --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- "$@"'
    )
    script = "\\n".join(lines)
    return [
        unshare_bin,
        "--user",
        "--map-current-user",
        "--keep-caps",
        "--mount",
        "/bin/bash",
        "-c",
        script,
        "--",
        *resolved_argv,
    ], ""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cfg_path = ""
    i = 0
    while i < len(args):
        if args[i] == "--config" and i + 1 < len(args):
            cfg_path = args[i + 1]
            i += 2
            continue
        i += 1

    if not cfg_path:
        _emit_fail_closed("PreToolUse", "Missing required --config for dots-hook-jail")

    try:
        st = os.lstat(cfg_path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            _emit_fail_closed("PreToolUse", f"Hook jail config '{{cfg_path}}' is not a regular file")
        cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    except SystemExit:
        raise
    except Exception as exc:
        _emit_fail_closed("PreToolUse", f"Cannot load hook jail config '{{cfg_path}}': {{exc}}")

    event_name = str(cfg.get("event_name") or "PreToolUse")
    agent_kind = str(cfg.get("agent") or "")
    plugin_vfs_dir = os.path.abspath(str(cfg.get("plugin_vfs_dir") or ""))
    plugin_source_dir = os.path.abspath(str(cfg.get("plugin_source_dir") or ""))
    vfs_hook_tmp = str(cfg.get("vfs_hook_tmp_dir") or "").strip()
    host_hook_tmp = str(cfg.get("hook_tmp_dir") or "").strip()
    vfs_hook_data = str(cfg.get("vfs_hook_data_dir") or "").strip()
    host_hook_data = str(cfg.get("hook_data_dir") or "").strip()
    hook_tmp_dir = os.path.abspath(vfs_hook_tmp if (vfs_hook_tmp and os.path.isdir(vfs_hook_tmp)) else host_hook_tmp)
    hook_data_dir = os.path.abspath(vfs_hook_data if (vfs_hook_data and os.path.isdir(vfs_hook_data)) else host_hook_data)
    raw_resolved_argv = cfg.get("resolved_argv")
    resolved_argv: list[str] = []
    if isinstance(raw_resolved_argv, list):
        for item in raw_resolved_argv:
            if not isinstance(item, str) or not item.strip():
                resolved_argv = []
                break
            resolved_argv.append(item)
    allowed_workspaces = [os.path.abspath(str(x)) for x in (cfg.get("allowed_workspaces") or []) if str(x).strip()]
    masked_paths = [os.path.abspath(str(x)) for x in (cfg.get("masked_paths") or []) if str(x).strip()]
    readonly_subpaths = [os.path.abspath(str(x)) for x in (cfg.get("readonly_subpaths") or []) if str(x).strip()]
    runtime_home_root = os.path.abspath(str(cfg.get("agent_runtime_home_root") or "/mnt/dots-agent-home"))
    allowed_artifact_roots: list[str] = []
    if agent_kind == "agy":
        allowed_artifact_roots.extend(
            [
                os.path.join(runtime_home_root, "agy", ".gemini", "antigravity", "brain"),
                os.path.join(runtime_home_root, "agy", ".gemini", "jetski", "brain"),
            ]
        )
    require_mount_ns = bool(cfg.get("require_mount_ns", True))

    if not plugin_vfs_dir or not resolved_argv or not hook_tmp_dir or not hook_data_dir:
        _emit_fail_closed(event_name, "Incomplete hook jail configuration")

    for state_d in (hook_tmp_dir, hook_data_dir):
        if os.path.islink(state_d):
            _emit_fail_closed(event_name, f"Symlinked hook state directory '{{state_d}}' is forbidden")
        os.makedirs(state_d, mode=0o700, exist_ok=True)
        if _within(state_d, plugin_vfs_dir) or _within(state_d, plugin_source_dir):
            _emit_fail_closed(event_name, "Hook state directory overlaps read-only plugin directory")

    try:
        cwd_real = os.path.realpath(os.getcwd())
    except OSError as exc:
        _emit_fail_closed(event_name, f"Cannot resolve hook working directory: {{exc}}")

    readonly_plugin_roots = [p for p in (plugin_vfs_dir, plugin_source_dir) if p]
    if not any(_within(cwd_real, r) for r in [*allowed_workspaces, *readonly_plugin_roots]):
        _emit_fail_closed(
            event_name,
            f"Hook working directory '{{cwd_real}}' is outside authorized session workspaces",
        )

    _check_workspace_no_symlinked_hook_paths(
        allowed_workspaces, cwd_real, readonly_subpaths, event_name
    )

    stdin_bytes = sys.stdin.buffer.read(MAX_HOOK_STDIN_BYTES + 1)
    if len(stdin_bytes) > MAX_HOOK_STDIN_BYTES:
        _emit_fail_closed(
            event_name,
            f"Hook stdin payload exceeds maximum allowed size ({{MAX_HOOK_STDIN_BYTES}} bytes)",
        )
    _check_symlink_escape_in_payload(
        stdin_bytes,
        event_name,
        allowed_workspaces,
        readonly_plugin_roots,
        allowed_artifact_roots,
        masked_paths,
        cwd_real,
    )
    _validate_argv_not_in_workspace(
        resolved_argv,
        event_name,
        allowed_workspaces,
        readonly_plugin_roots,
    )

    if require_mount_ns:
        sanitized_env = _build_sanitized_env(
            plugin_vfs_dir=plugin_vfs_dir,
            hook_tmp_inside="/tmp",
            hook_home_inside="/tmp/dots-hook-home",
            hook_data_inside="/tmp/plugin-data",
        )

        def _run_nested_attempt() -> tuple[subprocess.CompletedProcess[bytes], bool, str]:
            r_fd, w_fd = os.pipe()
            try:
                j_argv, j_err = _build_nested_jail_argv(
                    cfg,
                    cwd_real=cwd_real,
                    resolved_argv=resolved_argv,
                    hook_tmp_dir=hook_tmp_dir,
                    hook_data_dir=hook_data_dir,
                    allowed_artifact_roots=allowed_artifact_roots,
                    ready_fd=w_fd,
                )
                if not j_argv:
                    return subprocess.CompletedProcess([], 2, b"", b""), False, j_err
                try:
                    cp = subprocess.run(
                        j_argv,
                        input=stdin_bytes,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=sanitized_env,
                        cwd=cwd_real,
                        pass_fds=(w_fd,),
                    )
                finally:
                    try:
                        os.close(w_fd)
                    except OSError:
                        pass
                    w_fd = -1
                marker = os.read(r_fd, 16)
                return cp, (marker == b"READY"), ""
            finally:
                if w_fd >= 0:
                    try:
                        os.close(w_fd)
                    except OSError:
                        pass
                try:
                    os.close(r_fd)
                except OSError:
                    pass

        proc, jail_ready, err_msg = _run_nested_attempt()
        if err_msg:
            _append_jail_diag_log(hook_tmp_dir, event_name, f"stage=build_argv err={{err_msg}}", masked_paths)
            _emit_fail_closed(event_name, err_msg)
        if proc.returncode != 0 and not jail_ready:
            time.sleep(0.05)
            proc, jail_ready, err_msg = _run_nested_attempt()
            if err_msg:
                _append_jail_diag_log(hook_tmp_dir, event_name, f"stage=build_argv_retry err={{err_msg}}", masked_paths)
                _emit_fail_closed(event_name, err_msg)
        if proc.returncode != 0 and (not jail_ready or proc.returncode in (126, 127)):
            raw_err = proc.stderr.decode("utf-8", errors="replace").strip() or f"rc={{proc.returncode}}"
            detail = _redact_diag_msg(raw_err, masked_paths)
            _append_jail_diag_log(
                hook_tmp_dir,
                event_name,
                f"stage=jail_setup rc={{proc.returncode}} ready={{jail_ready}} err={{detail}}",
                masked_paths,
            )
            _emit_fail_closed(
                event_name,
                f"Kernel mount-namespace hook isolation is required but unavailable ({{detail}})",
            )
    else:
        jail_ready = True
        hook_home_host = os.path.join(hook_tmp_dir, "dots-hook-home")
        os.makedirs(hook_home_host, mode=0o700, exist_ok=True)
        active_root = plugin_vfs_dir if os.path.isdir(plugin_vfs_dir) else plugin_source_dir
        exec_argv = [
            (
                os.path.join(active_root, os.path.relpath(tok, plugin_vfs_dir))
                if (active_root != plugin_vfs_dir and _within(tok, plugin_vfs_dir))
                else tok
            )
            for tok in resolved_argv
        ]
        sanitized_env = _build_sanitized_env(
            plugin_vfs_dir=active_root,
            hook_tmp_inside=hook_tmp_dir,
            hook_home_inside=hook_home_host,
            hook_data_inside=hook_data_dir,
        )
        proc = subprocess.run(
            exec_argv,
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=sanitized_env,
            cwd=cwd_real,
        )

    if proc.returncode not in (0, 2):
        raw_err = proc.stderr.decode("utf-8", errors="replace").strip() or f"rc={{proc.returncode}}"
        detail = _redact_diag_msg(raw_err, masked_paths)
        _append_jail_diag_log(
            hook_tmp_dir,
            event_name,
            f"stage=hook_exec rc={{proc.returncode}} err={{detail}}",
            masked_paths,
        )
        if event_name in ("PreToolUse", "PermissionRequest", "PreInvocation", "UserPromptSubmit"):
            _emit_fail_closed(
                event_name,
                f"Hook script exited unexpectedly with status {{proc.returncode}} ({{detail}})",
            )

    if proc.stdout:
        sys.stdout.buffer.write(proc.stdout)
        sys.stdout.buffer.flush()
    if proc.stderr:
        sys.stderr.buffer.write(proc.stderr)
        sys.stderr.buffer.flush()
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _prepare_single_plugin_bundle(
    *,
    agent: str,
    plugin_name: str,
    source_dir: str,
    vfs_discovery_dir: str,
    hooks_relpath: Optional[str],
    bundles_root: Path,
    state_root: Path,
    agent_runtime_home_root: str,
    vfs_runner_script: str,
    allowed_workspaces: Sequence[str],
    masked_paths: Sequence[str],
    readonly_subpaths: Sequence[str],
    marketplace_name: str = "",
    plugin_version: str = "",
    vfs_data_dirs: Tuple[str, ...] = (),
) -> Tuple[StagedPluginHookBundle, Optional[bytes], Dict[str, Dict[str, Any]]]:
    """Build rewritten `hooks.json`, per-handler jail configs, and Codex hook trust states."""
    bundle_dir = bundles_root / agent / plugin_name
    jail_cfg_dir = bundle_dir / "jail-configs"
    _ensure_safe_dir(bundle_dir, mode=0o700)
    _ensure_safe_dir(jail_cfg_dir, mode=0o700)

    plugin_state_base = state_root / agent / plugin_name
    hook_tmp_dir = plugin_state_base / "tmp"
    hook_data_dir = plugin_state_base / "data"
    _ensure_safe_dir(plugin_state_base, mode=0o700)
    _ensure_safe_dir(hook_tmp_dir, mode=0o700)
    _ensure_safe_dir(hook_data_dir, mode=0o700)

    vfs_jail_cfg_dir = os.path.join(agent_runtime_home_root, "hook-jail", agent, plugin_name)
    vfs_hook_state_base = os.path.join(agent_runtime_home_root, "hook-state", agent, plugin_name)
    vfs_hook_tmp_dir = os.path.join(vfs_hook_state_base, "tmp")
    vfs_hook_data_dir = os.path.join(vfs_hook_state_base, "data")
    python_bin = shutil.which("python3") or sys.executable or "/usr/bin/python3"
    if not os.path.isabs(python_bin):
        python_bin = "/usr/bin/python3"
    # Use canonical /usr/bin/python3 when available so host venv symlinks never fail inside VFS
    if os.path.isfile("/usr/bin/python3") and os.access("/usr/bin/python3", os.X_OK):
        python_bin = "/usr/bin/python3"

    host_rewritten_hooks_path: Optional[str] = None
    rewritten_hooks_bytes: Optional[bytes] = None
    codex_hook_states: Dict[str, Dict[str, Any]] = {}

    if hooks_relpath:
        src_hooks_file = Path(source_dir) / hooks_relpath
        if src_hooks_file.exists() or src_hooks_file.is_symlink():
            parsed_hooks = validate_plugin_hooks_manifest(
                src_hooks_file,
                agent=agent,
                plugin_name=plugin_name,
                source_dir=source_dir,
                vfs_discovery_dir=vfs_discovery_dir,
            )
            wrapper_key, raw_events_map = _extract_hooks_events_mapping(
                parsed_hooks,
                agent=agent,
                plugin_name=plugin_name,
                hooks_file=src_hooks_file,
            )
            events_map = dict(raw_events_map)
            new_events_map: Dict[str, Any] = {}

            for event_name, groups in events_map.items():
                if wrapper_key is None and event_name in ("description", "$schema", "version"):
                    new_events_map[event_name] = groups
                    continue
                new_groups: List[Dict[str, Any]] = []
                for g_idx, group in enumerate(groups):
                    is_direct_handler = (
                        agent == "agy" and "hooks" not in group and "command" in group
                    )
                    raw_handlers = [group] if is_direct_handler else list(group.get("hooks") or [])
                    new_handlers: List[Dict[str, Any]] = []
                    for h_idx, handler in enumerate(raw_handlers):
                        resolved_argv = _resolve_hook_command_argv(
                            str(handler.get("command") or ""),
                            plugin_name=plugin_name,
                            source_dir=source_dir,
                            vfs_discovery_dir=vfs_discovery_dir,
                        )
                        cfg_filename = f"{event_name}-{g_idx}-{h_idx}.json"
                        host_hcfg = jail_cfg_dir / cfg_filename
                        vfs_hcfg = os.path.join(vfs_jail_cfg_dir, cfg_filename)
                        hcfg_payload = {
                            "schema_version": 1,
                            "agent": agent,
                            "plugin_name": plugin_name,
                            "event_name": event_name,
                            "original_command": str(handler.get("command") or ""),
                            "resolved_argv": resolved_argv,
                            "plugin_vfs_dir": vfs_discovery_dir,
                            "plugin_source_dir": source_dir,
                            "agent_runtime_home_root": agent_runtime_home_root,
                            "hook_tmp_dir": str(hook_tmp_dir),
                            "vfs_hook_tmp_dir": vfs_hook_tmp_dir,
                            "hook_data_dir": str(hook_data_dir),
                            "vfs_hook_data_dir": vfs_hook_data_dir,
                            "allowed_workspaces": [os.path.abspath(x) for x in allowed_workspaces],
                            "masked_paths": [os.path.abspath(x) for x in masked_paths],
                            "readonly_subpaths": [os.path.abspath(x) for x in readonly_subpaths],
                            "require_mount_ns": (not _ALLOW_TEST_UNSHARE_PASSTHROUGH),
                        }
                        _atomic_write_file(
                            host_hcfg,
                            (json.dumps(hcfg_payload, indent=2, ensure_ascii=False) + "\n").encode(
                                "utf-8"
                            ),
                            mode=0o644,
                        )
                        wrapped_cmd = (
                            f"{shlex.quote(python_bin)} -I "
                            f"{shlex.quote(vfs_runner_script)} --config {shlex.quote(vfs_hcfg)}"
                        )
                        new_handler = dict(handler)
                        new_handler["type"] = "command"
                        new_handler["command"] = wrapped_cmd
                        new_handlers.append(new_handler)

                        if agent == "codex" and marketplace_name:
                            plugin_id = f"{plugin_name}@{marketplace_name}"
                            event_key = CODEX_HOOK_EVENT_KEY_LABELS[event_name]
                            state_key = f"{plugin_id}:{hooks_relpath}:{event_key}:{g_idx}:{h_idx}"
                            decl_hash = compute_codex_hook_declaration_hash(
                                event_name=event_name,
                                matcher=group.get("matcher"),
                                command=wrapped_cmd,
                                timeout_sec=(
                                    int(handler["timeout"])
                                    if handler.get("timeout") is not None
                                    else None
                                ),
                                is_async=bool(handler.get("async", False)),
                                status_message=handler.get("statusMessage"),
                                additional_context_limit=handler.get("additionalContextLimit"),
                            )
                            codex_hook_states[state_key] = {
                                "enabled": True,
                                "trusted_hash": decl_hash,
                            }
                    if is_direct_handler:
                        new_groups.append(new_handlers[0])
                    else:
                        new_group = dict(group)
                        new_group["hooks"] = new_handlers
                        new_groups.append(new_group)
                new_events_map[event_name] = new_groups

            if wrapper_key is not None:
                rewritten_doc = dict(parsed_hooks)
                rewritten_doc[wrapper_key] = new_events_map
            else:
                rewritten_doc = new_events_map

            rewritten_hooks_bytes = (
                json.dumps(rewritten_doc, indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8")
            out_hooks_file = bundle_dir / "hooks.json"
            _atomic_write_file(out_hooks_file, rewritten_hooks_bytes, mode=0o644)
            host_rewritten_hooks_path = str(out_hooks_file)

    return (
        StagedPluginHookBundle(
            agent=agent,
            name=plugin_name,
            source_dir=source_dir,
            vfs_discovery_dir=vfs_discovery_dir,
            hooks_relpath=hooks_relpath if host_rewritten_hooks_path else None,
            host_rewritten_hooks_file=host_rewritten_hooks_path,
            host_jail_config_dir=str(jail_cfg_dir),
            vfs_jail_config_dir=vfs_jail_cfg_dir,
            host_hook_tmp_dir=str(hook_tmp_dir),
            vfs_hook_tmp_dir=vfs_hook_tmp_dir,
            host_hook_data_dir=str(hook_data_dir),
            vfs_hook_data_dir=vfs_hook_data_dir,
            marketplace_name=marketplace_name,
            plugin_version=plugin_version,
            vfs_data_dirs=vfs_data_dirs,
        ),
        rewritten_hooks_bytes,
        codex_hook_states,
    )


def _expand_host_tilde_in_agy_rule(rule_str: str, host_home: str) -> str:
    """Expand leading `~` in `read_file(...)` / `write_file(...)` rules against the real host HOME."""
    s = str(rule_str).strip()
    for prefix in ("read_file(", "write_file("):
        if s.startswith(prefix) and s.endswith(")"):
            inner = s[len(prefix) : -1].strip()
            if inner == "~":
                expanded = host_home
            elif inner.startswith("~/"):
                expanded = os.path.join(host_home, inner[2:])
            else:
                return rule_str
            if ")" not in expanded:
                return f"{prefix}{expanded})"
    return rule_str


def sanitize_host_agy_settings_file(
    cfg: Optional[GatewayConfig],
    out_path: Path,
    *,
    expand_tilde: bool = True,
    only_if_hooks_present: bool = False,
    content_addressed: bool = False,
) -> Optional[str]:
    """Fail-closed inspect `~/.gemini/antigravity-cli/settings.json` and write a hook-stripped copy."""
    cli_dir = Path.home() / ".gemini" / "antigravity-cli"
    if cli_dir.is_symlink():
        raise PermissionError(
            redact_diagnostic_text(
                f"Symlinked AGY settings directory '{cli_dir}' is forbidden by security policy",
                cfg,
            )
        )
    host_settings = cli_dir / "settings.json"
    if host_settings.is_symlink():
        raise PermissionError(
            redact_diagnostic_text(
                f"Symlinked AGY settings file '{host_settings}' is forbidden by security policy",
                cfg,
            )
        )
    if not host_settings.exists():
        return None
    if not host_settings.is_file():
        raise PermissionError(
            redact_diagnostic_text(
                f"AGY settings path '{host_settings}' must be a regular file",
                cfg,
            )
        )
    try:
        s_data = json.loads(host_settings.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PermissionError(
            redact_diagnostic_text(f"Cannot parse '{host_settings}': {exc}", cfg)
        ) from exc
    if not isinstance(s_data, dict):
        raise PermissionError(
            redact_diagnostic_text(
                f"AGY settings file '{host_settings}' must contain a JSON object",
                cfg,
            )
        )
    if only_if_hooks_present and "hooks" not in s_data:
        return None

    cleaned = {k: v for k, v in s_data.items() if k != "hooks"}
    if expand_tilde:
        host_home_res = os.path.abspath(str(Path.home().resolve()))
        raw_perms = cleaned.get("permissions")
        if isinstance(raw_perms, dict):
            expanded_perms: Dict[str, Any] = {}
            for p_key, p_val in raw_perms.items():
                if isinstance(p_val, list):
                    expanded_perms[p_key] = [
                        _expand_host_tilde_in_agy_rule(str(item), host_home_res)
                        for item in p_val
                    ]
                else:
                    expanded_perms[p_key] = p_val
            cleaned["permissions"] = expanded_perms

    rendered_bytes = (json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _ensure_safe_dir(out_path.parent, mode=0o700)
    target_file = out_path
    if content_addressed:
        digest = hashlib.sha256(rendered_bytes).hexdigest()[:16]
        target_file = out_path.parent / f"settings_{digest}.json"
        if target_file.is_symlink():
            raise PermissionError(f"Refusing symlinked sanitized settings file '{target_file}'")
        try:
            if target_file.is_file() and target_file.read_bytes() == rendered_bytes:
                return str(target_file)
        except OSError:
            pass
    _atomic_write_file(
        target_file,
        rendered_bytes,
        mode=0o600,
    )
    if content_addressed:
        try:
            siblings = [
                p
                for p in out_path.parent.glob("settings_*.json")
                if p != target_file and not p.is_symlink()
            ]
            if len(siblings) > 3:
                siblings.sort(key=lambda p: p.stat().st_mtime)
                for stale_p in siblings[:-3]:
                    stale_p.unlink(missing_ok=True)
        except OSError:
            pass
    return str(target_file)


_SAFE_SESSION_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


def _prepare_session_bundle_root(bundles_root: Path, session_tag: Optional[str]) -> Path:
    """Create a per-session staging directory under `<bundles_root>/sessions/<tag>`."""
    sessions_dir = bundles_root / "sessions"
    _ensure_safe_dir(sessions_dir, mode=0o700)
    raw_tag = str(session_tag or "").strip()
    safe_tag = (
        raw_tag
        if (raw_tag and _SAFE_SESSION_TAG_RE.match(raw_tag))
        else f"rt_{uuid.uuid4().hex[:16]}"
    )
    session_root = sessions_dir / safe_tag
    _ensure_safe_dir(session_root, mode=0o700)
    return session_root


def cleanup_prepared_plugin_runtime(runtime: Optional[PreparedAgentPluginRuntime]) -> None:
    """Best-effort cleanup of per-session staged hook configs/settings after a session exits."""
    if runtime is None or not runtime.cleanup_dir:
        return
    cand = Path(runtime.cleanup_dir)
    if cand.is_symlink() or not cand.exists():
        return
    if cand.parent.name != "sessions" or cand.parent.parent.name != "plugin_bundles":
        return
    shutil.rmtree(cand, ignore_errors=True)


_CACHED_HOOK_JAIL_RUNNER_BYTES: Optional[bytes] = None


def _ensure_hook_jail_runner_binary(bin_dir: Path) -> Path:
    """Ensure `<bin_dir>/dots-hook-jail.py` exists with exact current bytes and `0755` mode."""
    global _CACHED_HOOK_JAIL_RUNNER_BYTES
    if _CACHED_HOOK_JAIL_RUNNER_BYTES is None:
        _CACHED_HOOK_JAIL_RUNNER_BYTES = render_hook_jail_runner_source().encode("utf-8")
    host_runner = bin_dir / "dots-hook-jail.py"
    if host_runner.is_symlink():
        raise PermissionError(f"Refusing symlinked hook jail runner '{host_runner}'")
    try:
        if host_runner.is_file():
            st_r = host_runner.lstat()
            if (
                stat.S_IMODE(st_r.st_mode) == 0o755
                and st_r.st_size == len(_CACHED_HOOK_JAIL_RUNNER_BYTES)
                and host_runner.read_bytes() == _CACHED_HOOK_JAIL_RUNNER_BYTES
            ):
                return host_runner
    except OSError:
        pass
    _atomic_write_file(host_runner, _CACHED_HOOK_JAIL_RUNNER_BYTES, mode=0o755)
    return host_runner


def prepare_agy_plugin_runtime(
    cfg: GatewayConfig,
    *,
    validated_plugins: Sequence[Any],
    sandbox_state_root: Path,
    allowed_workspaces: Sequence[str],
    masked_paths: Sequence[str],
    readonly_subpaths: Sequence[str],
    session_tag: Optional[str] = None,
) -> PreparedAgentPluginRuntime:
    """Prepare isolated runtime staging for an `agy` session with registered plugins."""
    runtime_root = os.path.abspath(str(cfg.agent_runtime_home_root or "/mnt/dots-agent-home").strip())
    isolated_agy_home = os.path.join(runtime_root, "agy")
    bundles_root = sandbox_state_root / "plugin_bundles"
    bin_dir = bundles_root / "_bin"
    _ensure_safe_dir(bundles_root, mode=0o700)
    _ensure_safe_dir(bin_dir, mode=0o755)
    session_bundle_root = _prepare_session_bundle_root(bundles_root, session_tag)

    state_root = Path(os.path.abspath(os.path.expanduser(effective_plugin_state_dir(cfg))))
    _ensure_safe_dir(state_root, mode=0o700)

    host_runner = _ensure_hook_jail_runner_binary(bin_dir)
    vfs_runner = os.path.join(runtime_root, "bin", "dots-hook-jail.py")

    staged_bundles: List[StagedPluginHookBundle] = []
    for plg in validated_plugins:
        hooks_rel: Optional[str] = None
        if (Path(plg.source_dir) / "hooks.json").exists() or (
            Path(plg.source_dir) / "hooks.json"
        ).is_symlink():
            hooks_rel = "hooks.json"
        elif (Path(plg.source_dir) / "hooks" / "hooks.json").exists() or (
            Path(plg.source_dir) / "hooks" / "hooks.json"
        ).is_symlink():
            hooks_rel = os.path.join("hooks", "hooks.json")

        bundle, _, _ = _prepare_single_plugin_bundle(
            agent="agy",
            plugin_name=plg.name,
            source_dir=plg.source_dir,
            vfs_discovery_dir=plg.vfs_discovery_dir,
            hooks_relpath=hooks_rel,
            bundles_root=session_bundle_root,
            state_root=state_root,
            agent_runtime_home_root=runtime_root,
            vfs_runner_script=vfs_runner,
            allowed_workspaces=allowed_workspaces,
            masked_paths=masked_paths,
            readonly_subpaths=readonly_subpaths,
        )
        staged_bundles.append(bundle)

    # Sanitize global `~/.gemini/antigravity-cli/settings.json` (fail closed on symlink, strip any
    # unmanaged `hooks` block, and expand leading `~` against real host HOME)
    out_s = session_bundle_root / "agy" / "_sanitized_settings.json"
    sanitized_settings_path = sanitize_host_agy_settings_file(
        cfg, out_s, expand_tilde=True, only_if_hooks_present=False
    )

    return PreparedAgentPluginRuntime(
        agent="agy",
        isolated_home_dir=isolated_agy_home,
        host_runner_script=str(host_runner),
        vfs_runner_script=vfs_runner,
        bundles=tuple(staged_bundles),
        host_sanitized_agy_settings=sanitized_settings_path,
        cleanup_dir=str(session_bundle_root),
    )


def prepare_codex_plugin_runtime(
    cfg: GatewayConfig,
    *,
    validated_plugins: Sequence[Any],
    sandbox_state_root: Path,
    allowed_workspaces: Sequence[str],
    masked_paths: Sequence[str],
    readonly_subpaths: Sequence[str],
    session_tag: Optional[str] = None,
) -> PreparedAgentPluginRuntime:
    """Prepare isolated `$CODEX_HOME`, jailed `hooks/hooks.json`, and exact trust hashes for `codex`."""
    runtime_root = os.path.abspath(str(cfg.agent_runtime_home_root or "/mnt/dots-agent-home").strip())
    isolated_codex_home_user = os.path.join(runtime_root, "codex")
    vfs_codex_home = os.path.join(isolated_codex_home_user, ".codex")
    bundles_root = sandbox_state_root / "plugin_bundles"
    bin_dir = bundles_root / "_bin"
    _ensure_safe_dir(bundles_root, mode=0o700)
    _ensure_safe_dir(bin_dir, mode=0o755)
    session_bundle_root = _prepare_session_bundle_root(bundles_root, session_tag)

    state_root = Path(os.path.abspath(os.path.expanduser(effective_plugin_state_dir(cfg))))
    _ensure_safe_dir(state_root, mode=0o700)

    host_runner = _ensure_hook_jail_runner_binary(bin_dir)
    vfs_runner = os.path.join(runtime_root, "bin", "dots-hook-jail.py")

    staged_bundles: List[StagedPluginHookBundle] = []
    plugins_toml_specs: List[Dict[str, Any]] = []
    all_hook_states: Dict[str, Dict[str, Any]] = {}

    for plg in validated_plugins:
        hooks_rel: Optional[str] = plg.hooks_relpath
        # Compute both Codex data root conventions (`<name>-<mkt>` and `agent-plugins/<sha256_32>`)
        id_digest = hashlib.sha256()
        id_digest.update(plg.marketplace_name.encode("utf-8"))
        id_digest.update(b"\x00")
        id_digest.update(plg.name.encode("utf-8"))
        agent_plg_hash = id_digest.hexdigest()[:32]
        vfs_data_1 = os.path.join(
            vfs_codex_home, "plugins", "data", f"{plg.name}-{plg.marketplace_name}"
        )
        vfs_data_2 = os.path.join(
            vfs_codex_home, "plugins", "data", "agent-plugins", agent_plg_hash
        )

        bundle, rewritten_bytes, hook_states = _prepare_single_plugin_bundle(
            agent="codex",
            plugin_name=plg.name,
            source_dir=plg.source_dir,
            vfs_discovery_dir=plg.vfs_discovery_dir,
            hooks_relpath=hooks_rel,
            bundles_root=session_bundle_root,
            state_root=state_root,
            agent_runtime_home_root=runtime_root,
            vfs_runner_script=vfs_runner,
            allowed_workspaces=allowed_workspaces,
            masked_paths=masked_paths,
            readonly_subpaths=readonly_subpaths,
            marketplace_name=plg.marketplace_name,
            plugin_version=plg.version,
            vfs_data_dirs=(vfs_data_1, vfs_data_2),
        )
        overrides: Dict[str, bytes] = {}
        if hooks_rel and rewritten_bytes is not None:
            overrides[Path(hooks_rel).as_posix()] = rewritten_bytes
        content_hash = compute_codex_plugin_content_hash(Path(plg.source_dir), overrides)
        for st_entry in hook_states.values():
            st_entry["trusted_content_hash"] = content_hash
        all_hook_states.update(hook_states)
        plugins_toml_specs.append(
            {
                "name": plg.name,
                "marketplace_name": plg.marketplace_name,
                "vfs_discovery_dir": plg.vfs_discovery_dir,
            }
        )
        staged_bundles.append(bundle)

    host_codex_cfg = Path.home() / ".codex" / "config.toml"
    if host_codex_cfg.is_symlink():
        raise PermissionError(
            redact_diagnostic_text(
                f"Symlinked Codex config file '{host_codex_cfg}' is forbidden by security policy",
                cfg,
            )
        )
    synthesized_toml = build_isolated_codex_config_toml(
        host_codex_cfg if host_codex_cfg.exists() else None,
        plugins_spec=plugins_toml_specs,
        hook_states=all_hook_states,
    )
    out_codex_toml = session_bundle_root / "codex" / "_isolated_config.toml"
    _atomic_write_file(out_codex_toml, synthesized_toml.encode("utf-8"), mode=0o600)

    return PreparedAgentPluginRuntime(
        agent="codex",
        isolated_home_dir=isolated_codex_home_user,
        host_runner_script=str(host_runner),
        vfs_runner_script=vfs_runner,
        bundles=tuple(staged_bundles),
        host_codex_config_toml=str(out_codex_toml),
        vfs_codex_home_dir=vfs_codex_home,
        cleanup_dir=str(session_bundle_root),
    )


def sanitize_host_claude_settings_file(
    cfg: Optional[GatewayConfig],
    out_path: Path,
    *,
    only_if_hooks_present: bool = False,
    content_addressed: bool = False,
) -> Optional[str]:
    """Fail-closed inspect `~/.claude/settings.json` and write a hook/mcp-stripped copy."""
    claude_dir = Path.home() / ".claude"
    if claude_dir.is_symlink():
        raise PermissionError(
            redact_diagnostic_text(
                f"Symlinked Claude config directory '{claude_dir}' is forbidden by security policy",
                cfg,
            )
        )
    host_settings = claude_dir / "settings.json"
    if host_settings.is_symlink():
        raise PermissionError(
            redact_diagnostic_text(
                f"Symlinked Claude settings file '{host_settings}' is forbidden by security policy",
                cfg,
            )
        )
    if not host_settings.exists():
        return None
    if not host_settings.is_file():
        raise PermissionError(
            redact_diagnostic_text(
                f"Claude settings path '{host_settings}' must be a regular file",
                cfg,
            )
        )
    try:
        s_data = json.loads(host_settings.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PermissionError(
            redact_diagnostic_text(f"Cannot parse '{host_settings}': {exc}", cfg)
        ) from exc
    if not isinstance(s_data, dict):
        raise PermissionError(
            redact_diagnostic_text(
                f"Claude settings file '{host_settings}' must contain a JSON object",
                cfg,
            )
        )
    if only_if_hooks_present and "hooks" not in s_data and "mcpServers" not in s_data:
        return None

    cleaned = {
        k: v
        for k, v in s_data.items()
        if k not in ("hooks", "mcpServers", "statusLine", "apiKeyHelper", "awsAuthRefresh")
    }
    rendered_bytes = (json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _ensure_safe_dir(out_path.parent, mode=0o700)
    target_file = out_path
    if content_addressed:
        digest = hashlib.sha256(rendered_bytes).hexdigest()[:16]
        target_file = out_path.parent / f"claude_settings_{digest}.json"
        if target_file.is_symlink():
            raise PermissionError(f"Refusing symlinked sanitized Claude settings file '{target_file}'")
        try:
            if target_file.is_file() and target_file.read_bytes() == rendered_bytes:
                return str(target_file)
        except OSError:
            pass
    _atomic_write_file(target_file, rendered_bytes, mode=0o600)
    return str(target_file)


def sanitize_host_claude_json_file(
    cfg: Optional[GatewayConfig],
    out_path: Path,
) -> str:
    """Synthesize a clean `.claude.json` (`hasCompletedOnboarding=True`) with untrusted MCP/hooks stripped."""
    base_data: Dict[str, Any] = {}
    for cand_p in (Path.home() / ".claude" / ".claude.json", Path.home() / ".claude.json"):
        if cand_p.is_symlink():
            raise PermissionError(
                redact_diagnostic_text(
                    f"Symlinked Claude state file '{cand_p}' is forbidden by security policy",
                    cfg,
                )
            )
        if cand_p.is_file():
            try:
                parsed = json.loads(cand_p.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    base_data = parsed
                    break
            except Exception:
                continue

    cleaned: Dict[str, Any] = {}
    for safe_k in ("oauthAccount", "userID", "theme", "hasCompletedOnboarding", "numStartups"):
        if safe_k in base_data:
            cleaned[safe_k] = base_data[safe_k]
    cleaned["hasCompletedOnboarding"] = True
    rendered = (json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _ensure_safe_dir(out_path.parent, mode=0o700)
    _atomic_write_file(out_path, rendered, mode=0o600)
    return str(out_path)


def prepare_claude_plugin_runtime(
    cfg: GatewayConfig,
    *,
    validated_plugins: Sequence[Any],
    sandbox_state_root: Path,
    allowed_workspaces: Sequence[str],
    masked_paths: Sequence[str],
    readonly_subpaths: Sequence[str],
    session_tag: Optional[str] = None,
) -> PreparedAgentPluginRuntime:
    """Prepare isolated `CLAUDE_CONFIG_DIR`, jailed `hooks/hooks.json`, and read-only plugin mounts for `claude`."""
    runtime_root = os.path.abspath(str(cfg.agent_runtime_home_root or "/mnt/dots-agent-home").strip())
    isolated_claude_home_user = os.path.join(runtime_root, "claude")
    vfs_claude_cfg_dir = os.path.join(isolated_claude_home_user, ".claude")
    bundles_root = sandbox_state_root / "plugin_bundles"
    bin_dir = bundles_root / "_bin"
    _ensure_safe_dir(bundles_root, mode=0o700)
    _ensure_safe_dir(bin_dir, mode=0o755)
    session_bundle_root = _prepare_session_bundle_root(bundles_root, session_tag)

    state_root = Path(os.path.abspath(os.path.expanduser(effective_plugin_state_dir(cfg))))
    _ensure_safe_dir(state_root, mode=0o700)

    host_runner = _ensure_hook_jail_runner_binary(bin_dir)
    vfs_runner = os.path.join(runtime_root, "bin", "dots-hook-jail.py")

    staged_bundles: List[StagedPluginHookBundle] = []
    for plg in validated_plugins:
        hooks_rel: Optional[str] = plg.hooks_relpath
        vfs_data_1 = os.path.join(vfs_claude_cfg_dir, "plugins", "data", plg.name)
        bundle, _, _ = _prepare_single_plugin_bundle(
            agent="claude",
            plugin_name=plg.name,
            source_dir=plg.source_dir,
            vfs_discovery_dir=plg.vfs_discovery_dir,
            hooks_relpath=hooks_rel,
            bundles_root=session_bundle_root,
            state_root=state_root,
            agent_runtime_home_root=runtime_root,
            vfs_runner_script=vfs_runner,
            allowed_workspaces=allowed_workspaces,
            masked_paths=masked_paths,
            readonly_subpaths=readonly_subpaths,
            plugin_version=getattr(plg, "version", "local"),
            vfs_data_dirs=(vfs_data_1,),
        )
        staged_bundles.append(bundle)

    out_settings = session_bundle_root / "claude" / "_sanitized_settings.json"
    sanitized_settings = sanitize_host_claude_settings_file(
        cfg, out_settings, only_if_hooks_present=False
    )
    out_cjson = session_bundle_root / "claude" / "_sanitized_claude.json"
    sanitized_cjson = sanitize_host_claude_json_file(cfg, out_cjson)

    return PreparedAgentPluginRuntime(
        agent="claude",
        isolated_home_dir=isolated_claude_home_user,
        host_runner_script=str(host_runner),
        vfs_runner_script=vfs_runner,
        bundles=tuple(staged_bundles),
        host_sanitized_claude_settings=sanitized_settings,
        host_sanitized_claude_json=sanitized_cjson,
        vfs_claude_config_dir=vfs_claude_cfg_dir,
        cleanup_dir=str(session_bundle_root),
    )

