"""Model Context Protocol (MCP) Server Engine for the Dots Gateway.

Implements MCP specification revisions 2024-11-05, 2025-03-26, 2025-06-18, and 2026-07-28:
- JSON-RPC 2.0 single & batch message dispatch
- Stateful (`Mcp-Session-Id`) and stateless (`2026-07-28` / restart-resilient) operation
- Streamable HTTP SSE progress notifications (`notifications/progress`) & NAT keepalives
- Curated software engineering tools (`fs_*`, `exec_command`, `run_agy`, `session_*`),
  MCP Resources (`gateway://status`, `gateway://policy`, `file://{path}`), and Prompts
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import json
import logging
import math
import secrets
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from . import __version__
from .config import (
    GatewayConfig,
    effective_plugin_state_dir,
    redact_diagnostic_text,
    resolve_effective_stream_mode,
    stream_mode_state,
)
from .executor import ExecutionSession, SessionManager
from .files import FileService
from .policy import CommandPolicy, redact_for_audit_log

logger = logging.getLogger("dots_gateway")

_FORBIDDEN_TASK_PLUGIN_KEYS = (
    "plugin_dirs",
    "agy_plugin_dirs",
    "codex_plugin_dirs",
    "claude_plugin_dirs",
    "plugins",
    "codex_plugins",
    "claude_plugins",
    "plugin_root",
    "agy_plugins_enabled",
    "codex_plugins_enabled",
    "claude_plugins_enabled",
    "agy_plugins_file",
    "codex_plugins_file",
    "claude_plugins_file",
    "agent_runtime_home_root",
    "plugin_state_dir",
)


def _reject_task_plugin_overrides(payload: Any) -> None:
    if isinstance(payload, dict):
        for key in _FORBIDDEN_TASK_PLUGIN_KEYS:
            if key in payload:
                raise PermissionError(
                    f"Task-level '{key}' declaration is forbidden by security policy; "
                    "register trusted AGY/Codex/Claude plugins via operator configuration only"
                )


SUPPORTED_PROTOCOL_VERSIONS: Tuple[str, ...] = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2026-07-28",
)
DEFAULT_PROTOCOL_VERSION = "2025-06-18"
MAX_MCP_SESSIONS = 1024

EmitCallback = Callable[[Optional[Dict[str, Any]]], Awaitable[None]]


SERVER_INSTRUCTIONS = (
    "Connected to the user's remote development machine via Dots Gateway. "
    "Prefer `fs_read`, `fs_write`, `fs_patch`, and `fs_list` for fast, atomic file operations "
    "without shell-escaping issues. Use `exec_command` for allowlisted shell commands, builds, "
    "linters, and git workflows. Use `run_agy` (local Antigravity CLI), `run_codex` (local "
    "OpenAI Codex CLI `codex exec`), or `run_claude` (local Anthropic Claude Code CLI `claude -p`) "
    "to delegate multi-file feature implementation, refactoring, cross-model code review, or "
    "autonomous debugging. "
    "Use `session_start`, `session_poll`, `session_input`, and `session_signal` for background "
    "tasks or interactive multi-turn processes."
)


TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "list_agy_models",
        "title": "List Available Antigravity (agy) Models",
        "description": (
            "List model IDs available to `run_agy` under the gateway's current agy auth "
            "profile (ADC or OAuth), plus the gateway default model used when `model` is "
            "omitted. Results are cached briefly; pass `refresh=true` to re-query."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "refresh": {
                    "type": "boolean",
                    "description": "Bypass the cache and re-run `agy models`.",
                    "default": False,
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "gateway_status",
        "title": "Check Remote Gateway Status & Policy",
        "description": (
            "Return live health diagnostics, uptime, active sessions, default working directory, "
            "allowed workspace roots, and command policy (including `allowed_commands` and "
            "`blocked_commands`) of the remote development gateway."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "exec_command",
        "title": "Execute Remote Development Command",
        "description": (
            "Execute an allowlisted command, compound shell pipeline, or multi-line heredoc script "
            "(e.g., `git status`, `pytest -v`, `cd ~/proj && npm test`, "
            "`python3 - <<'PY'\\nimport sys\\nprint(sys.version)\\nPY`, or `./scripts/build.sh`) "
            "on the remote machine and return stdout, stderr, and exit code. When gateway Docker "
            "access is ON (see `gateway_status` -> `docker.enabled`), `docker` / `docker compose` "
            "work via a policy-filtering proxy (workspace-only bind mounts, no privileged/host "
            "namespaces, ports bound to 127.0.0.1)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Shell command string or argv array to execute.",
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory inside allowed workspace roots.",
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Optional extra environment variables for this command.",
                },
                "stdin": {
                    "type": "string",
                    "description": "Optional standard input text to feed to the command.",
                },
                "use_pty": {
                    "type": "boolean",
                    "description": "Allocate a pseudo-terminal (PTY) if required by CLI tools.",
                    "default": False,
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Timeout in seconds (default: 21600 [6h], max: 86400 [24h]).",
                },
                "stream": {
                    "type": "boolean",
                    "description": "Per-call streaming toggle override (true -> 'summary', false -> 'off'). Omit to follow gateway default.",
                },
                "stream_mode": {
                    "type": "string",
                    "enum": ["off", "summary", "raw"],
                    "description": "Per-call streaming granularity override ('off', 'summary', or 'raw'). Overrides 'stream' and gateway default.",
                },
                "background": {
                    "type": "boolean",
                    "default": False,
                    "description": "Start asynchronously and return `session_id` + `progress` immediately without waiting for completion.",
                },
                "detach_after_seconds": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Optional auto-detach threshold in seconds (disabled by default). If still running after this duration, returns `detached=true`, `session_id`, and live `progress`.",
                },
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "run_agy",
        "title": "Run Local Antigravity Agent (agy)",
        "description": (
            "Invoke Google Antigravity CLI (`agy --sandbox`) on the remote development machine "
            "to autonomously write code, refactor, debug, and run tests inside the jailed workspace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Detailed engineering task instruction for local Antigravity (`agy`).",
                },
                "cwd": {
                    "type": "string",
                    "description": "Target project repository / working directory on the remote host.",
                },
                "skip_permissions": {
                    "type": "boolean",
                    "description": (
                        "Pass `--dangerously-skip-permissions` (default: true). When false, `agy` "
                        "still executes sandboxed commands unattended via session "
                        "`toolPermission='proceed-in-sandbox'` while enforcing `permissions.deny`."
                    ),
                    "default": True,
                },
                "model": {
                    "type": "string",
                    "description": (
                        "Optional model override for `agy` (e.g. `gemini-2.5-pro`, "
                        "`claude-sonnet-4-5`). Call `list_agy_models` for valid IDs. When "
                        "omitted, the gateway default (`dots-gateway agy-model`) is used."
                    ),
                },
                "effort": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "xhigh", "max"],
                    "description": "Optional reasoning effort level.",
                },
                "mode": {
                    "type": "string",
                    "description": "Optional execution mode override.",
                },
                "conversation_id": {
                    "type": "string",
                    "description": "Optional existing `agy` conversation ID to resume.",
                },
                "continue_last": {
                    "type": "boolean",
                    "description": "Continue the most recent `agy` conversation in `cwd`.",
                    "default": False,
                },
                "output_format": {
                    "type": "string",
                    "enum": ["text", "json", "stream-json"],
                    "description": "Optional explicit CLI output format override (`text`, `json`, or `stream-json`).",
                },
                "add_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional workspace directories to grant `agy` access to.",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional raw CLI flags passed directly to `agy`.",
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Timeout in seconds (default: 28800 [8h], max: 86400 [24h]).",
                },
                "stream": {
                    "type": "boolean",
                    "description": "Per-call streaming toggle override (true -> 'summary', false -> 'off'). Omit to follow gateway default.",
                },
                "stream_mode": {
                    "type": "string",
                    "enum": ["off", "summary", "raw"],
                    "description": "Per-call streaming granularity override ('off', 'summary', or 'raw'). Overrides 'stream' and gateway default.",
                },
                "background": {
                    "type": "boolean",
                    "default": False,
                    "description": "Start asynchronously and return `session_id` + `progress` immediately for tracking via `session_poll`.",
                },
                "detach_after_seconds": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Optional auto-detach threshold in seconds (disabled by default). If still running after this duration, returns `detached=true`, `session_id`, and live `progress`.",
                },
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "run_codex",
        "title": "Run Local OpenAI Codex Agent (codex)",
        "description": (
            "Invoke OpenAI Codex CLI (`codex -a never -s workspace-write exec`) on the remote "
            "development machine to autonomously implement features, refactor, run code reviews, "
            "debug, and verify tests inside the jailed workspace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Detailed engineering or review task instruction for local `codex`.",
                },
                "cwd": {
                    "type": "string",
                    "description": "Target project repository / working directory on the remote host.",
                },
                "skip_permissions": {
                    "type": "boolean",
                    "description": "Pass `-a never` for unattended execution without approval prompts (default: true).",
                    "default": True,
                },
                "sandbox_mode": {
                    "type": "string",
                    "enum": ["workspace-write", "read-only"],
                    "default": "workspace-write",
                    "description": "Codex sandbox policy ('workspace-write' for coding or 'read-only' for review/audit).",
                },
                "model": {
                    "type": "string",
                    "description": "Optional model override for `codex`.",
                },
                "effort": {
                    "type": "string",
                    "enum": ["minimal", "low", "medium", "high", "xhigh", "max"],
                    "description": "Optional reasoning effort override.",
                },
                "search": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable Codex native web search (`--search`).",
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional existing Codex session UUID/name to resume (`codex exec resume <ID>`).",
                },
                "continue_last": {
                    "type": "boolean",
                    "default": False,
                    "description": "Resume the most recent Codex session in `cwd` (`codex exec resume --last`).",
                },
                "review": {
                    "type": "boolean",
                    "default": False,
                    "description": "Run non-interactive `codex exec review` against the repository.",
                },
                "json_events": {
                    "type": "boolean",
                    "description": "Explicitly enable or disable raw JSONL events on stdout (`--json`).",
                },
                "add_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional allowed workspace directories to grant writable access to.",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional extra validated flags passed to `codex exec` (e.g. `['--uncommitted']` with `review=true`).",
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Timeout in seconds (default: 28800 [8h], max: 86400 [24h]).",
                },
                "stream": {
                    "type": "boolean",
                    "description": "Per-call streaming toggle override (true -> 'summary', false -> 'off'). Omit to follow gateway default.",
                },
                "stream_mode": {
                    "type": "string",
                    "enum": ["off", "summary", "raw"],
                    "description": "Per-call streaming granularity override ('off', 'summary', or 'raw'). Overrides 'stream' and gateway default.",
                },
                "background": {
                    "type": "boolean",
                    "default": False,
                    "description": "Start asynchronously and return `session_id` + `progress` immediately for tracking via `session_poll`.",
                },
                "detach_after_seconds": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Optional auto-detach threshold in seconds (disabled by default). If still running after this duration, returns `detached=true`, `session_id`, and live `progress`.",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "run_claude",
        "title": "Run Local Anthropic Claude Code Agent (claude)",
        "description": (
            "Invoke Anthropic Claude Code CLI (`claude -p`) on the remote development machine "
            "to autonomously implement features, refactor, run architectural/code reviews, "
            "debug, and verify tests inside the jailed workspace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Detailed engineering, refactoring, or review task instruction for local `claude`.",
                },
                "cwd": {
                    "type": "string",
                    "description": "Target project repository / working directory on the remote host.",
                },
                "skip_permissions": {
                    "type": "boolean",
                    "default": True,
                    "description": (
                        "Pass `--dangerously-skip-permissions` for unattended execution inside "
                        "the gateway mount-namespace sandbox (default: true)."
                    ),
                },
                "permission_mode": {
                    "type": "string",
                    "enum": [
                        "default",
                        "acceptEdits",
                        "plan",
                        "auto",
                        "dontAsk",
                        "bypassPermissions",
                    ],
                    "description": (
                        "Optional Claude Code `--permission-mode` when `skip_permissions=false` "
                        "(e.g. `'plan'` for read-only planning/audit or `'acceptEdits'`)."
                    ),
                },
                "model": {
                    "type": "string",
                    "description": (
                        "Optional model override for `claude` (e.g. `sonnet`, `opus`, "
                        "`claude-sonnet-4-6`). When omitted, the gateway default "
                        "(`dots-gateway claude-model`) is used."
                    ),
                },
                "effort": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "max"],
                    "description": "Optional reasoning effort level (`--effort`).",
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional existing Claude Code session UUID to resume (`--resume <ID>`).",
                },
                "continue_last": {
                    "type": "boolean",
                    "default": False,
                    "description": "Continue the most recent Claude Code conversation in `cwd` (`--continue`).",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["text", "json", "stream-json"],
                    "description": (
                        "Optional output format (`text` by default; `json` returns structured JSON "
                        "including `session_id`; `stream-json` emits NDJSON events)."
                    ),
                },
                "add_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional validated workspace directories to grant access to (`--add-dir`).",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional extra validated CLI flags passed to `claude` (e.g. `['--max-turns', '25']`).",
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Timeout in seconds (default: 28800 [8h], max: 86400 [24h]).",
                },
                "stream": {
                    "type": "boolean",
                    "description": "Per-call streaming toggle override (true -> 'summary', false -> 'off'). Omit to follow gateway default.",
                },
                "stream_mode": {
                    "type": "string",
                    "enum": ["off", "summary", "raw"],
                    "description": "Per-call streaming granularity override ('off', 'summary', or 'raw'). Overrides 'stream' and gateway default.",
                },
                "background": {
                    "type": "boolean",
                    "default": False,
                    "description": "Start asynchronously and return `session_id` + `progress` immediately for tracking via `session_poll`.",
                },
                "detach_after_seconds": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Optional auto-detach threshold in seconds (disabled by default). If still running after this duration, returns `detached=true`, `session_id`, and live `progress`.",
                },
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "session_start",
        "title": "Start Background or Interactive Session",
        "description": (
            "Start a non-blocking background command (`type='exec'`), multi-turn interactive "
            "`agy` session (`type='agy'`), multi-turn interactive `claude` session (`type='claude'`), "
            "or background `codex` run (`type='codex'`) and immediately return its `session_id`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["exec", "agy", "codex", "claude"],
                    "default": "exec",
                    "description": "Session type: 'exec' for shell/CLI commands, 'agy' for Antigravity, 'codex' for OpenAI Codex, or 'claude' for Anthropic Claude Code.",
                },
                "command": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Command to execute when `type='exec'`.",
                },
                "prompt": {
                    "type": "string",
                    "description": "Initial prompt when `type='agy'`, `type='codex'`, or `type='claude'`.",
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory on the remote machine.",
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "use_pty": {
                    "type": "boolean",
                    "default": False,
                },
                "close_stdin": {
                    "type": "boolean",
                    "default": False,
                    "description": "Close stdin immediately after starting (default false for interactive sessions).",
                },
                "skip_permissions": {
                    "type": "boolean",
                    "default": True,
                },
                "permission_mode": {
                    "type": "string",
                    "enum": [
                        "default",
                        "acceptEdits",
                        "plan",
                        "auto",
                        "dontAsk",
                        "bypassPermissions",
                    ],
                    "description": "Optional Claude Code `--permission-mode` when `type='claude'` and `skip_permissions=false`.",
                },
                "sandbox_mode": {
                    "type": "string",
                    "enum": ["workspace-write", "read-only"],
                },
                "model": {"type": "string"},
                "effort": {"type": "string"},
                "mode": {
                    "type": "string",
                    "description": "Optional execution mode override when `type='agy'`.",
                },
                "conversation_id": {
                    "type": "string",
                    "description": "Optional existing `agy` conversation ID to resume when `type='agy'`.",
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional existing Codex or Claude Code session ID to resume when `type='codex'` or `type='claude'`.",
                },
                "continue_last": {
                    "type": "boolean",
                    "default": False,
                    "description": "Resume the most recent `agy`, `codex`, or `claude` session in `cwd`.",
                },
                "search": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable Codex native web search when `type='codex'`.",
                },
                "review": {
                    "type": "boolean",
                    "default": False,
                    "description": "Run `codex exec review` when `type='codex'`.",
                },
                "add_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional validated workspace directories to grant access to (`agy`, `codex`, or `claude`).",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional validated CLI flags passed to `agy`, `codex`, or `claude`.",
                },
                "stdin": {
                    "type": "string",
                    "description": "Optional standard input text to feed when `type='exec'`.",
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Timeout in seconds (default: 28800 [8h] for agy/codex/claude, 21600 [6h] for exec; max: 86400 [24h]).",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["text", "json", "stream-json"],
                    "description": "Optional explicit CLI output format override for `type='agy'` or `type='claude'`.",
                },
                "json_events": {
                    "type": "boolean",
                    "description": "Optional explicit `--json` toggle for `type='codex'`.",
                },
                "stream": {
                    "type": "boolean",
                    "description": "Per-session streaming mode toggle override (true -> 'summary', false -> 'off').",
                },
                "stream_mode": {
                    "type": "string",
                    "enum": ["off", "summary", "raw"],
                    "description": "Per-session streaming granularity override ('off', 'summary', or 'raw').",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "session_poll",
        "title": "Poll Background Session Output & Status",
        "description": (
            "Fetch current status, `process_alive` (/proc kernel identity check), structured `progress`, "
            "stdout/stderr, and incremental events (`after_seq`) of a background or pre-restart persisted session, "
            "optionally waiting up to `wait_seconds` for new output. Use `view='progress'` for lightweight "
            "progress polling without repeating full accumulated output."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Target `session_id` returned by `session_start` or a background/detached task.",
                },
                "after_seq": {
                    "type": "integer",
                    "default": 0,
                    "description": "Only return events/activities with sequence number > `after_seq`.",
                },
                "wait_seconds": {
                    "type": "number",
                    "default": 0,
                    "description": "Optional long-poll wait duration (0-60s) if no new events are ready yet.",
                },
                "wait_for_exit": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, wait up to `wait_seconds` for the session to finish completely.",
                },
                "view": {
                    "type": "string",
                    "enum": ["full", "progress", "delta"],
                    "default": "full",
                    "description": (
                        "'full' (default) returns full stdout/stderr + progress + events; "
                        "'progress' returns lightweight structured progress + new activities + output tail; "
                        "'delta' returns only incremental stdout/stderr & events since `after_seq`."
                    ),
                },
                "tail_chars": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 2000,
                    "description": "Maximum trailing characters in `stdout_tail` when `view='progress'`.",
                },
                "include_events": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include event stream items in the response (set false when paging raw stdout/stderr).",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Character offset into `stdout` and `stderr` when slicing large session outputs.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Optional maximum characters per stream (`stdout`/`stderr`) starting at `offset`.",
                },
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "session_input",
        "title": "Send Input or Follow-Up Turn to Session",
        "description": (
            "Write stdin text (`data`) to a running `exec` session, or send a follow-up user turn "
            "(`prompt`) to a multi-turn `agy` or `claude` session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "data": {
                    "type": "string",
                    "description": "Raw text to write to process stdin (include trailing `\\n` if needed).",
                },
                "prompt": {
                    "type": "string",
                    "description": "Follow-up user message for an interactive `agy` or `claude` session.",
                },
                "close_stdin": {
                    "type": "boolean",
                    "default": False,
                    "description": "Close stdin after writing.",
                },
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "session_signal",
        "title": "Signal or Terminate Running Session",
        "description": "Send a POSIX signal (`SIGINT`, `SIGTERM`, `SIGKILL`, `SIGHUP`) to a session's process group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "signal": {
                    "type": "string",
                    "enum": ["SIGINT", "SIGTERM", "SIGKILL", "SIGHUP"],
                    "default": "SIGTERM",
                },
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "session_list",
        "title": "List Active & Recent Sessions",
        "description": (
            "List all active, recently completed, and restart-reconciled execution sessions on the gateway "
            "(including `process_alive` and `agent_conversation_id` when available)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Maximum number of sessions to return (most recent first).",
                },
                "cwd": {
                    "type": "string",
                    "description": "Filter sessions whose `cwd` matches or sits under this directory path.",
                },
                "status": {
                    "type": "string",
                    "description": "Filter by session status (e.g. `running`, `completed`, `failed`, `timeout`).",
                },
                "session_kind": {
                    "type": "string",
                    "enum": ["exec", "agy", "codex", "claude"],
                    "description": "Filter by session kind (`exec`, `agy`, `codex`, or `claude`).",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "fs_stat",
        "title": "Inspect Remote File or Directory Metadata",
        "description": "Check existence, file type, size, permissions, and mtime of a remote workspace path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Target file or directory path."},
                "cwd": {"type": "string", "description": "Base working directory for relative paths."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "fs_list",
        "title": "List Remote Workspace Directory",
        "description": "List files and subdirectories inside an allowed workspace directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list (defaults to gateway default workdir).",
                },
                "cwd": {"type": "string"},
                "recursive": {"type": "boolean", "default": False},
                "max_entries": {"type": "integer", "default": 500},
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "fs_read",
        "title": "Read Remote Workspace File",
        "description": "Read a UTF-8 text or Base64 binary file from the remote workspace with optional byte offset/limit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read."},
                "cwd": {"type": "string"},
                "encoding": {
                    "type": "string",
                    "enum": ["utf-8", "base64"],
                    "default": "utf-8",
                },
                "offset": {"type": "integer", "default": 0, "description": "Byte offset."},
                "limit": {"type": "integer", "description": "Maximum bytes to read."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "fs_write",
        "title": "Write Remote Workspace File",
        "description": "Atomically create, overwrite, or append to a file on the remote workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Destination file path."},
                "content": {"type": "string", "description": "UTF-8 text or Base64-encoded content."},
                "cwd": {"type": "string"},
                "encoding": {
                    "type": "string",
                    "enum": ["utf-8", "base64"],
                    "default": "utf-8",
                },
                "append": {"type": "boolean", "default": False},
                "mkdir_parents": {"type": "boolean", "default": True},
                "mode": {
                    "type": "string",
                    "description": "Optional octal file permissions, e.g. '0755' or '0644'.",
                },
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "fs_patch",
        "title": "Patch Remote Workspace File",
        "description": "Apply one or more exact search-and-replace edits atomically to an existing remote file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Target file path to modify."},
                "cwd": {"type": "string"},
                "edits": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Exact substring to find in the file.",
                            },
                            "replacement": {
                                "type": "string",
                                "description": "Replacement text.",
                            },
                            "replace_all": {
                                "type": "boolean",
                                "default": False,
                                "description": (
                                    "Replace all occurrences when target appears multiple times "
                                    "(default: false, which requires a unique match)."
                                ),
                            },
                        },
                        "required": ["target", "replacement"],
                        "additionalProperties": False,
                    },
                    "minItems": 1,
                },
            },
            "required": ["path", "edits"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "fs_delete",
        "title": "Delete Remote File or Empty Directory",
        "description": "Delete a file, symlink, or empty directory inside an allowed remote workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "cwd": {"type": "string"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
]

TOOL_MAP: Dict[str, Dict[str, Any]] = {t["name"]: t for t in TOOL_DEFINITIONS}


PROMPT_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "delegate_to_agy",
        "title": "Delegate Feature or Refactor to Local Antigravity (agy)",
        "description": "Orchestrate local `agy --dangerously-skip-permissions` to implement a task and verify with tests.",
        "arguments": [
            {"name": "task", "description": "Engineering task to implement", "required": True},
            {"name": "cwd", "description": "Remote project path", "required": False},
            {"name": "test_command", "description": "Verification command (e.g. pytest -v)", "required": False},
        ],
    },
    {
        "name": "delegate_to_codex",
        "title": "Delegate Feature or Code Review to Local OpenAI Codex (codex)",
        "description": "Orchestrate local `codex exec` to implement a feature or perform an independent code review.",
        "arguments": [
            {"name": "task", "description": "Engineering or review task for Codex", "required": True},
            {"name": "cwd", "description": "Remote project path", "required": False},
            {"name": "test_command", "description": "Verification command (e.g. pytest -v)", "required": False},
        ],
    },
    {
        "name": "delegate_to_claude",
        "title": "Delegate Feature or Review to Local Anthropic Claude Code (claude)",
        "description": "Orchestrate local `claude -p` to implement a feature, refactor, or perform an independent review.",
        "arguments": [
            {"name": "task", "description": "Engineering or review task for Claude Code", "required": True},
            {"name": "cwd", "description": "Remote project path", "required": False},
            {"name": "test_command", "description": "Verification command (e.g. pytest -v)", "required": False},
        ],
    },
    {
        "name": "remote_tdd_loop",
        "title": "Remote Test-Driven Development Loop",
        "description": "Inspect code, write/patch tests and implementation on the remote host, and run test verification.",
        "arguments": [
            {"name": "goal", "description": "Bug fix or feature goal", "required": True},
            {"name": "cwd", "description": "Remote project path", "required": False},
        ],
    },
]


def _jsonrpc_result(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _tool_success(data: Dict[str, Any], summary_text: Optional[str] = None) -> Dict[str, Any]:
    text = summary_text if summary_text is not None else json.dumps(data, indent=2, ensure_ascii=False)
    return {
        "isError": False,
        "content": [{"type": "text", "text": text}],
        "structuredContent": data,
    }


def _tool_error(message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {"error": message, **(details or {})}
    res: Dict[str, Any] = {
        "isError": True,
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}],
    }
    if details is not None:
        res["structuredContent"] = payload
    return res


class MCPHandler:
    """Zero-dependency MCP JSON-RPC 2.0 dispatcher backed by Dots Gateway services."""

    def __init__(
        self,
        config: GatewayConfig,
        policy: CommandPolicy,
        files: FileService,
        sessions: SessionManager,
        started_at: Optional[float] = None,
    ) -> None:
        self.config = config
        self.policy = policy
        self.files = files
        self.sessions = sessions
        self._started_at = started_at or time.time()
        self._mcp_sessions: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._active_request_sessions: Dict[Tuple[Optional[str], Any], str] = {}

    def _allocate_session(self, protocol_version: str, client_info: Dict[str, Any]) -> str:
        sid = f"mcp_{secrets.token_urlsafe(24)}"
        self._mcp_sessions[sid] = {
            "protocol_version": protocol_version,
            "client_info": client_info,
            "created_at": time.time(),
            "last_seen": time.time(),
        }
        self._mcp_sessions.move_to_end(sid)
        while len(self._mcp_sessions) > MAX_MCP_SESSIONS:
            self._mcp_sessions.popitem(last=False)
        return sid

    def touch_session(self, session_id: Optional[str]) -> Optional[str]:
        if session_id and session_id in self._mcp_sessions:
            self._mcp_sessions[session_id]["last_seen"] = time.time()
            self._mcp_sessions.move_to_end(session_id)
            return session_id
        return session_id

    def delete_session(self, session_id: Optional[str]) -> bool:
        if session_id and session_id in self._mcp_sessions:
            self._mcp_sessions.pop(session_id, None)
            return True
        return False

    def should_stream_sse(self, payload: Any) -> bool:
        """Return True if payload contains a long-running tool call with streaming enabled."""
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("method") != "tools/call":
                continue
            params = item.get("params") or {}
            if not isinstance(params, dict):
                continue
            name = params.get("name")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                args = {}
            if name in ("exec_command", "run_agy", "run_codex", "run_claude"):
                if bool(args.get("background", False)):
                    continue
                try:
                    eff_mode, _ = resolve_effective_stream_mode(
                        self.config,
                        stream=args.get("stream"),
                        stream_mode=args.get("stream_mode"),
                    )
                except ValueError:
                    continue
                if eff_mode != "off":
                    return True
            if name == "session_poll":
                try:
                    wait_sec = float(args.get("wait_seconds") or 0)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(wait_sec) and wait_sec > 0:
                    if stream_mode_state(self.config)["mode"] != "off":
                        return True
        return False

    async def handle_payload(
        self,
        payload: Any,
        session_id: Optional[str] = None,
        emit_event: Optional[EmitCallback] = None,
    ) -> Tuple[Optional[Any], Dict[str, str]]:
        """Process a decoded JSON-RPC message or batch.

        Returns `(response_payload_or_None, extra_http_headers)`.
        When `response_payload_or_None` is `None`, the input consisted solely of
        JSON-RPC notifications/responses and HTTP callers MUST return `202 Accepted` with empty body.
        """
        resp_headers: Dict[str, str] = {}
        active_sid = self.touch_session(session_id)
        if active_sid:
            resp_headers["Mcp-Session-Id"] = active_sid

        if isinstance(payload, list):
            if not payload:
                return _jsonrpc_error(None, -32600, "Invalid Request: empty batch"), resp_headers
            responses: List[Dict[str, Any]] = []
            for item in payload:
                res, item_hdrs = await self._handle_single(
                    item, emit_event=emit_event, mcp_session_id=active_sid
                )
                resp_headers.update(item_hdrs)
                if res is not None:
                    responses.append(res)
            return (responses if responses else None), resp_headers

        return await self._handle_single(
            payload,
            existing_headers=resp_headers,
            emit_event=emit_event,
            mcp_session_id=active_sid,
        )

    async def _handle_single(
        self,
        msg: Any,
        existing_headers: Optional[Dict[str, str]] = None,
        emit_event: Optional[EmitCallback] = None,
        mcp_session_id: Optional[str] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, str]]:
        headers = dict(existing_headers or {})
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return _jsonrpc_error(
                msg.get("id") if isinstance(msg, dict) else None,
                -32600,
                "Invalid Request: expected JSON-RPC 2.0 object",
            ), headers

        method = msg.get("method")
        has_id = "id" in msg
        req_id = msg.get("id")

        # JSON-RPC responses or notifications (no `id`) yield no response object
        if not method:
            if not has_id:
                return None, headers
            return _jsonrpc_error(req_id, -32600, "Invalid Request: missing 'method'"), headers

        if not isinstance(method, str):
            return _jsonrpc_error(req_id, -32600, "Invalid Request: 'method' must be a string"), headers

        params = msg.get("params")
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            if not has_id:
                return None, headers
            return _jsonrpc_error(req_id, -32602, "Invalid params: expected object"), headers

        # Notifications (`notifications/initialized`, `notifications/cancelled`, etc.)
        if not has_id:
            if method == "notifications/cancelled":
                # Support both standard MCP `requestId` mapping (scoped by MCP session) and explicit `sessionId`
                cancel_sid: Optional[str] = None
                cancel_req_id = params.get("requestId")
                if isinstance(cancel_req_id, (str, int)) and not isinstance(cancel_req_id, bool):
                    cancel_sid = self._active_request_sessions.get((mcp_session_id, cancel_req_id))
                    if cancel_sid is None and mcp_session_id is None:
                        matches = [
                            sid
                            for (_, rid), sid in self._active_request_sessions.items()
                            if rid == cancel_req_id
                        ]
                        if len(matches) == 1:
                            cancel_sid = matches[0]
                if not cancel_sid and isinstance(params.get("sessionId"), str):
                    cancel_sid = str(params["sessionId"])
                if cancel_sid:
                    sess = self.sessions.get_session(cancel_sid)
                    if sess is not None:
                        await sess.send_signal("SIGTERM")
            return None, headers

        # Standard MCP Requests
        if method == "initialize":
            requested_ver = str(params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION)
            negotiated = (
                requested_ver
                if requested_ver in SUPPORTED_PROTOCOL_VERSIONS
                else DEFAULT_PROTOCOL_VERSION
            )
            client_info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
            new_sid = self._allocate_session(negotiated, client_info)
            headers["Mcp-Session-Id"] = new_sid
            headers["MCP-Protocol-Version"] = negotiated
            return (
                _jsonrpc_result(
                    req_id,
                    {
                        "protocolVersion": negotiated,
                        "capabilities": {
                            "tools": {"listChanged": False},
                            "resources": {"subscribe": False, "listChanged": False},
                            "prompts": {"listChanged": False},
                            "logging": {},
                        },
                        "serverInfo": {
                            "name": "dots-gateway",
                            "title": "Dots Remote Development & Antigravity Gateway",
                            "version": __version__,
                        },
                        "instructions": SERVER_INSTRUCTIONS,
                    },
                ),
                headers,
            )

        if method == "ping":
            return _jsonrpc_result(req_id, {}), headers

        if method == "logging/setLevel":
            return _jsonrpc_result(req_id, {}), headers

        if method == "tools/list":
            return _jsonrpc_result(req_id, {"tools": TOOL_DEFINITIONS}), headers

        if method == "tools/call":
            meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            progress_token = meta.get("progressToken")
            res = await self._handle_tool_call(
                req_id=req_id,
                params=params,
                progress_token=progress_token,
                emit_event=emit_event,
                mcp_session_id=mcp_session_id,
            )
            return res, headers

        if method == "resources/list":
            return (
                _jsonrpc_result(
                    req_id,
                    {
                        "resources": [
                            {
                                "uri": "gateway://status",
                                "name": "Gateway Runtime Status",
                                "description": "Live health, active session count, and TLS/auth configuration summary.",
                                "mimeType": "application/json",
                            },
                            {
                                "uri": "gateway://policy",
                                "name": "Gateway Security & Command Policy",
                                "description": "Allowed commands, blocked commands, and allowed workspace directories.",
                                "mimeType": "application/json",
                            },
                        ]
                    },
                ),
                headers,
            )

        if method == "resources/templates/list":
            return (
                _jsonrpc_result(
                    req_id,
                    {
                        "resourceTemplates": [
                            {
                                "uriTemplate": "file://{path}",
                                "name": "Remote Workspace File",
                                "description": "Read a UTF-8 file inside an allowed workspace directory on the remote host.",
                                "mimeType": "text/plain",
                            }
                        ]
                    },
                ),
                headers,
            )

        if method == "resources/read":
            res = await self._handle_resource_read(req_id, params)
            return res, headers

        if method == "prompts/list":
            return _jsonrpc_result(req_id, {"prompts": PROMPT_DEFINITIONS}), headers

        if method == "prompts/get":
            return self._handle_prompt_get(req_id, params), headers

        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}"), headers

    def _resolve_detach_after(self, args: Dict[str, Any]) -> Optional[float]:
        """Validate optional per-call `detach_after_seconds` (or server default, disabled by default)."""
        raw = args.get("detach_after_seconds")
        if raw is None:
            default_det = getattr(self.config, "default_detach_after_seconds", None)
            return float(default_det) if (default_det is not None and float(default_det) > 0) else None
        try:
            val = float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid detach_after_seconds value: {raw!r}") from exc
        if not math.isfinite(val) or val <= 0:
            raise ValueError("detach_after_seconds must be a positive finite number")
        return val

    @staticmethod
    def _build_detached_result(
        session: ExecutionSession,
        *,
        stream_mode: str,
        detach_after_seconds: float,
    ) -> Dict[str, Any]:
        return {
            "session_id": session.session_id,
            "session_kind": (
                "agy"
                if session.is_agy
                else ("codex" if session.is_codex else ("claude" if session.is_claude else "exec"))
            ),
            "status": session.status,
            "process_alive": session.status in ("queued", "starting", "running"),
            "detached": True,
            "detach_after_seconds": detach_after_seconds,
            "stream_mode": stream_mode,
            "cwd": session.cwd,
            "last_seq": session._seq,
            "agent_conversation_id": session.agent_conversation_id,
            "progress": session.get_progress(after_seq=0),
            "stdout_tail": session.get_stdout_tail(2000),
            "stderr_tail": session.get_stderr_tail(1000),
            "message": (
                f"Session '{session.session_id}' is still {session.status} after {detach_after_seconds}s "
                "and continues running in the background. Call `session_poll` with "
                f"`session_id='{session.session_id}'`, `after_seq={session._seq}`, `view='progress'` to track it."
            ),
        }

    async def _watch_session_with_progress(
        self,
        session: ExecutionSession,
        progress_token: Any,
        emit_event: Optional[EmitCallback],
        *,
        req_id: Any = None,
        mcp_session_id: Optional[str] = None,
        stream_mode: str = "summary",
        detach_after_seconds: Optional[float] = None,
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        """Wait for `session` to finish (or auto-detach) while emitting MCP progress notifications.

        Returns `(summary_or_None, detached_bool)`.
        `notifications/progress` is emitted ONLY when `progress_token is not None` and `stream_mode != 'off'`.
        """
        req_key: Optional[Tuple[Optional[str], Any]] = (
            (mcp_session_id, req_id)
            if (isinstance(req_id, (str, int)) and not isinstance(req_id, bool))
            else None
        )
        if req_key is not None:
            self._active_request_sessions[req_key] = session.session_id
        try:
            can_emit_progress = (
                emit_event is not None
                and progress_token is not None
                and stream_mode != "off"
            )
            if emit_event is None or stream_mode == "off":
                if detach_after_seconds is not None:
                    try:
                        await asyncio.wait_for(session._done_event.wait(), timeout=detach_after_seconds)
                    except asyncio.TimeoutError:
                        if session.status in ("queued", "starting", "running"):
                            return None, True
                return (await session.wait()), False

            step = 0
            interval = max(0.05, float(getattr(self.config, "stream_progress_interval_seconds", 1.0)))
            keepalive_sec = max(0.2, float(self.config.sse_keepalive_seconds))
            deadline = (
                time.monotonic() + detach_after_seconds
                if detach_after_seconds is not None
                else None
            )
            hb_sec = (
                min(keepalive_sec, max(0.05, min(0.25, detach_after_seconds / 2.0)))
                if detach_after_seconds is not None
                else keepalive_sec
            )
            last_keepalive_mono = time.monotonic()
            last_emit_mono = 0.0
            last_sent_msg = ""
            pending_msg: Optional[str] = None

            async def _send_progress(msg: str) -> None:
                nonlocal step, last_emit_mono, last_sent_msg
                clean = msg.strip()
                if not clean or clean == last_sent_msg:
                    return
                step += 1
                last_emit_mono = time.monotonic()
                last_sent_msg = clean
                await emit_event(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {
                            "progressToken": progress_token,
                            "progress": step,
                            "message": clean,
                        },
                    }
                )

            async for ev in session.subscribe_with_heartbeat(
                after_seq=0, heartbeat_seconds=hb_sec
            ):
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    if session.status in ("queued", "starting", "running"):
                        if can_emit_progress and pending_msg:
                            await _send_progress(pending_msg)
                            pending_msg = None
                        return None, True

                if ev is None:
                    if can_emit_progress and pending_msg and (now - last_emit_mono) >= interval:
                        await _send_progress(pending_msg)
                        pending_msg = None
                    if (now - last_keepalive_mono) >= keepalive_sec:
                        last_keepalive_mono = now
                        await emit_event(None)
                    continue

                if not can_emit_progress:
                    continue

                if stream_mode == "raw":
                    if ev.type not in ("queued", "stdout", "stderr", "agy_event", "started", "error"):
                        continue
                    if ev.type == "stdout" and session.stream_json:
                        stripped = str(ev.data or "").strip()
                        if stripped.startswith("{") and stripped.endswith("}"):
                            try:
                                json.loads(stripped)
                                continue
                            except json.JSONDecodeError:
                                pass
                    snippet = (
                        ev.data if isinstance(ev.data, str) else json.dumps(ev.data, ensure_ascii=False)
                    )
                    if len(snippet) > 400:
                        snippet = snippet[:400] + "..."
                    await _send_progress(f"[{ev.type}] {snippet.strip()}")
                    continue

                # stream_mode == "summary": semantic, deduplicated, throttled progress
                formatted = session.format_progress_event(ev)
                if formatted is None:
                    continue
                summary_text, is_milestone = formatted
                if is_milestone:
                    pending_msg = None
                    await _send_progress(summary_text)
                else:
                    if (now - last_emit_mono) >= interval:
                        pending_msg = None
                        await _send_progress(summary_text)
                    else:
                        pending_msg = summary_text

            if can_emit_progress and pending_msg:
                await _send_progress(pending_msg)
            return (await session.wait()), False
        finally:
            if req_key is not None and self._active_request_sessions.get(req_key) == session.session_id:
                self._active_request_sessions.pop(req_key, None)

    async def _handle_tool_call(
        self,
        req_id: Any,
        params: Dict[str, Any],
        progress_token: Any = None,
        emit_event: Optional[EmitCallback] = None,
        mcp_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or tool_name not in TOOL_MAP:
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name!r}")

        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return _jsonrpc_error(req_id, -32602, "Tool 'arguments' must be an object")

        try:
            if tool_name in ("exec_command", "run_agy", "run_codex", "run_claude", "session_start"):
                _reject_task_plugin_overrides(args)

            if tool_name == "gateway_status":
                data = {
                    "ok": True,
                    "service": "dots-gateway",
                    "version": __version__,
                    "uptime_seconds": round(time.time() - self._started_at, 2),
                    "active_sessions": self.sessions.active_count(),
                    "active_agy_sessions": self.sessions.active_agy_count(),
                    "queued_agy_sessions": self.sessions.queued_agy_count(),
                    "active_codex_sessions": self.sessions.active_codex_count(),
                    "queued_codex_sessions": self.sessions.queued_codex_count(),
                    "active_claude_sessions": self.sessions.active_claude_count(),
                    "queued_claude_sessions": self.sessions.queued_claude_count(),
                    "max_concurrent_agy": self.config.max_concurrent_agy,
                    "max_concurrent_codex": self.config.max_concurrent_codex,
                    "max_concurrent_claude": self.config.max_concurrent_claude,
                    "default_timeout_seconds": self.config.default_timeout_seconds,
                    "agent_default_timeout_seconds": self.config.agent_default_timeout_seconds,
                    "max_timeout_seconds": self.config.max_timeout_seconds,
                    "agy_queue_timeout_seconds": self.config.agy_queue_timeout_seconds,
                    "default_workdir": self.config.default_workdir,
                    "allowed_workdirs": self.config.allowed_workdirs,
                    "isolate_mount_namespace": self.config.isolate_mount_namespace,
                    "sandbox_state_dir": self.config.sandbox_state_dir,
                    "agent_runtime_home_root": self.config.agent_runtime_home_root,
                    "plugin_state_dir": redact_diagnostic_text(
                        effective_plugin_state_dir(self.config), self.config
                    ),
                    "sandbox_lifecycle": self.sessions.get_sandbox_lifecycle_info(),
                    "enforce_allowlist": self.config.enforce_allowlist,
                    "allowed_commands_count": len(self.config.allowed_commands),
                    "allowed_commands": list(self.config.allowed_commands),
                    "blocked_commands": list(self.config.blocked_commands),
                    "agy_binary": self.config.agy_binary,
                    "agy_default_skip_permissions": self.config.agy_default_skip_permissions,
                    "agy_default_sandbox": self.config.agy_default_sandbox,
                    "agy_sandbox_network_access": self.config.agy_sandbox_network_access,
                    "agy_sandbox_tool_permission": self.config.agy_sandbox_tool_permission,
                    "agy_include_allowed_workdirs": self.config.agy_include_allowed_workdirs,
                    "agy_readonly_roots": self.policy.get_agy_readonly_roots(),
                    "agy_writable_roots": self.policy.get_agy_writable_roots(),
                    "agy_auth": self.sessions.get_agy_auth_info(),
                    "agy_plugins": self.policy.get_agy_plugins_info(),
                    "docker": self.sessions.get_docker_info(),
                    "streaming": self.sessions.get_stream_info(),
                    "codex_binary": self.config.codex_binary,
                    "codex_default_skip_permissions": self.config.codex_default_skip_permissions,
                    "codex_default_sandbox": self.config.codex_default_sandbox,
                    "codex_sandbox_network_access": self.config.codex_sandbox_network_access,
                    "codex_writable_roots": self.policy.get_codex_writable_roots(),
                    "codex_auth_configured": self.sessions.has_codex_auth(),
                    "codex_plugins": self.policy.get_codex_plugins_info(),
                    "claude_binary": self.config.claude_binary,
                    "claude_default_skip_permissions": self.config.claude_default_skip_permissions,
                    "claude_default_permission_mode": self.config.claude_default_permission_mode,
                    "claude_auth": self.sessions.get_claude_auth_info(),
                    "claude_plugins": self.policy.get_claude_plugins_info(),
                    "tls_enabled": bool(self.config.tls_certfile and self.config.tls_keyfile),
                    "mtls_required": self.config.tls_require_client_cert,
                }
                return _jsonrpc_result(req_id, _tool_success(data))

            if tool_name == "exec_command":
                command = args.get("command")
                if not command:
                    return _jsonrpc_result(req_id, _tool_error("Missing required argument 'command'"))
                eff_stream_mode, _ = resolve_effective_stream_mode(
                    self.config, stream=args.get("stream"), stream_mode=args.get("stream_mode")
                )
                background = bool(args.get("background", False))
                detach_after = None if background else self._resolve_detach_after(args)
                session = await self.sessions.create_session(
                    command=command,
                    cwd=args.get("cwd"),
                    env=args.get("env"),
                    use_pty=bool(args.get("use_pty", False)),
                    timeout=args.get("timeout"),
                    initial_stdin=args.get("stdin"),
                    close_stdin=True,
                    stream_mode=eff_stream_mode,
                )
                if background:
                    bg_data = {
                        **session.to_summary(include_output=False),
                        "background": True,
                        "progress": session.get_progress(after_seq=0),
                    }
                    return _jsonrpc_result(req_id, _tool_success(bg_data))
                summary, detached = await self._watch_session_with_progress(
                    session,
                    progress_token,
                    emit_event,
                    req_id=req_id,
                    mcp_session_id=mcp_session_id,
                    stream_mode=eff_stream_mode,
                    detach_after_seconds=detach_after,
                )
                if detached or summary is None:
                    assert detach_after is not None
                    return _jsonrpc_result(
                        req_id,
                        _tool_success(
                            self._build_detached_result(
                                session,
                                stream_mode=eff_stream_mode,
                                detach_after_seconds=detach_after,
                            )
                        ),
                    )
                result_data = {
                    "session_id": summary["session_id"],
                    "status": summary["status"],
                    "returncode": summary["returncode"],
                    "cwd": summary["cwd"],
                    "duration_seconds": summary["duration_seconds"],
                    "stream_mode": eff_stream_mode,
                    "stdout": summary["stdout"],
                    "stderr": summary["stderr"],
                    "stdout_truncated": summary["stdout_truncated"],
                    "stderr_truncated": summary["stderr_truncated"],
                    "progress": summary.get("progress"),
                }
                if summary["returncode"] != 0:
                    return _jsonrpc_result(
                        req_id,
                        _tool_error(
                            f"Command exited with code {summary['returncode']} ({summary['status']})",
                            result_data,
                        ),
                    )
                return _jsonrpc_result(req_id, _tool_success(result_data))

            if tool_name == "list_agy_models":
                try:
                    data = await self.sessions.list_agy_models(
                        refresh=bool(args.get("refresh", False))
                    )
                except RuntimeError as exc:
                    return _jsonrpc_result(
                        req_id, _tool_error(redact_diagnostic_text(str(exc), self.config))
                    )
                return _jsonrpc_result(req_id, _tool_success(data))

            if tool_name == "run_agy":
                prompt = args.get("prompt")
                extra_args = args.get("args") or []
                if not prompt and not extra_args:
                    return _jsonrpc_result(req_id, _tool_error("Provide 'prompt' or 'args' for run_agy"))
                eff_stream_mode, _ = resolve_effective_stream_mode(
                    self.config, stream=args.get("stream"), stream_mode=args.get("stream_mode")
                )
                background = bool(args.get("background", False))
                detach_after = None if background else self._resolve_detach_after(args)
                caller_fmt = args.get("output_format")
                has_raw_fmt = any(
                    str(a) == "--output-format" or str(a).startswith("--output-format=")
                    for a in extra_args
                )
                explicit_stream_req = args.get("stream") is True or args.get("stream_mode") in (
                    "summary",
                    "raw",
                )
                auto_structured = (
                    eff_stream_mode != "off"
                    and caller_fmt is None
                    and not has_raw_fmt
                    and (
                        progress_token is not None
                        or background
                        or detach_after is not None
                        or explicit_stream_req
                    )
                )
                eff_output_format = "stream-json" if auto_structured else caller_fmt
                session = await self.sessions.create_agy_session(
                    prompt=prompt,
                    cwd=args.get("cwd"),
                    env=args.get("env"),
                    args=extra_args,
                    skip_permissions=args.get("skip_permissions"),
                    print_mode=True,
                    output_format=eff_output_format,
                    model=args.get("model"),
                    effort=args.get("effort"),
                    mode=args.get("mode"),
                    conversation_id=args.get("conversation_id"),
                    continue_last=bool(args.get("continue_last", False)),
                    add_dirs=args.get("add_dirs"),
                    timeout=args.get("timeout"),
                    close_stdin=True,
                    stream_mode=eff_stream_mode,
                )
                if background:
                    bg_data = {
                        **session.to_summary(include_output=False),
                        "background": True,
                        "progress": session.get_progress(after_seq=0),
                    }
                    return _jsonrpc_result(req_id, _tool_success(bg_data))
                summary, detached = await self._watch_session_with_progress(
                    session,
                    progress_token,
                    emit_event,
                    req_id=req_id,
                    mcp_session_id=mcp_session_id,
                    stream_mode=eff_stream_mode,
                    detach_after_seconds=detach_after,
                )
                if detached or summary is None:
                    assert detach_after is not None
                    return _jsonrpc_result(
                        req_id,
                        _tool_success(
                            self._build_detached_result(
                                session,
                                stream_mode=eff_stream_mode,
                                detach_after_seconds=detach_after,
                            )
                        ),
                    )
                clean_final = summary.get("final_output", summary["stdout"])
                out_stdout = (
                    clean_final
                    if (auto_structured and eff_stream_mode != "raw")
                    else summary["stdout"]
                )
                result_data = {
                    "session_id": summary["session_id"],
                    "agent_conversation_id": summary.get("agent_conversation_id"),
                    "status": summary["status"],
                    "returncode": summary["returncode"],
                    "cwd": summary["cwd"],
                    "duration_seconds": summary["duration_seconds"],
                    "stream_mode": eff_stream_mode,
                    "stdout": out_stdout,
                    "stderr": summary["stderr"],
                    "final_output": clean_final,
                    "progress": summary.get("progress"),
                }
                if summary["returncode"] != 0:
                    return _jsonrpc_result(
                        req_id,
                        _tool_error(
                            f"agy exited with code {summary['returncode']} ({summary['status']})",
                            result_data,
                        ),
                    )
                return _jsonrpc_result(req_id, _tool_success(result_data))

            if tool_name == "run_codex":
                prompt = args.get("prompt")
                extra_args = args.get("args") or []
                review = bool(args.get("review", False))
                if not prompt and not extra_args and not review:
                    return _jsonrpc_result(
                        req_id,
                        _tool_error("Provide 'prompt', 'review=true', or 'args' for run_codex"),
                    )
                eff_stream_mode, _ = resolve_effective_stream_mode(
                    self.config, stream=args.get("stream"), stream_mode=args.get("stream_mode")
                )
                background = bool(args.get("background", False))
                detach_after = None if background else self._resolve_detach_after(args)
                caller_json_events = args.get("json_events")
                has_raw_json = "--json" in [str(a) for a in extra_args]
                explicit_stream_req = args.get("stream") is True or args.get("stream_mode") in (
                    "summary",
                    "raw",
                )
                auto_structured = (
                    eff_stream_mode != "off"
                    and caller_json_events is None
                    and not has_raw_json
                    and (
                        progress_token is not None
                        or background
                        or detach_after is not None
                        or explicit_stream_req
                    )
                )
                eff_json_events = (
                    True if auto_structured else bool(caller_json_events or False)
                )
                session = await self.sessions.create_codex_session(
                    prompt=prompt,
                    cwd=args.get("cwd"),
                    env=args.get("env"),
                    args=extra_args,
                    skip_permissions=args.get("skip_permissions"),
                    sandbox_mode=args.get("sandbox_mode"),
                    json_events=eff_json_events,
                    model=args.get("model"),
                    effort=args.get("effort"),
                    search=bool(args.get("search", False)),
                    session_id=args.get("session_id"),
                    continue_last=bool(args.get("continue_last", False)),
                    review=review,
                    add_dirs=args.get("add_dirs"),
                    timeout=args.get("timeout"),
                    close_stdin=True,
                    stream_mode=eff_stream_mode,
                )
                if background:
                    bg_data = {
                        **session.to_summary(include_output=False),
                        "background": True,
                        "progress": session.get_progress(after_seq=0),
                    }
                    return _jsonrpc_result(req_id, _tool_success(bg_data))
                summary, detached = await self._watch_session_with_progress(
                    session,
                    progress_token,
                    emit_event,
                    req_id=req_id,
                    mcp_session_id=mcp_session_id,
                    stream_mode=eff_stream_mode,
                    detach_after_seconds=detach_after,
                )
                if detached or summary is None:
                    assert detach_after is not None
                    return _jsonrpc_result(
                        req_id,
                        _tool_success(
                            self._build_detached_result(
                                session,
                                stream_mode=eff_stream_mode,
                                detach_after_seconds=detach_after,
                            )
                        ),
                    )
                clean_final = summary.get("final_output", summary["stdout"])
                out_stdout = (
                    clean_final
                    if (auto_structured and eff_stream_mode != "raw")
                    else summary["stdout"]
                )
                result_data = {
                    "session_id": summary["session_id"],
                    "agent_conversation_id": summary.get("agent_conversation_id"),
                    "status": summary["status"],
                    "returncode": summary["returncode"],
                    "cwd": summary["cwd"],
                    "duration_seconds": summary["duration_seconds"],
                    "stream_mode": eff_stream_mode,
                    "stdout": out_stdout,
                    "stderr": summary["stderr"],
                    "final_output": clean_final,
                    "progress": summary.get("progress"),
                }
                if summary["returncode"] != 0:
                    return _jsonrpc_result(
                        req_id,
                        _tool_error(
                            f"codex exited with code {summary['returncode']} ({summary['status']})",
                            result_data,
                        ),
                    )
                return _jsonrpc_result(req_id, _tool_success(result_data))

            if tool_name == "run_claude":
                prompt = args.get("prompt")
                extra_args = args.get("args") or []
                if not prompt and not extra_args:
                    return _jsonrpc_result(
                        req_id, _tool_error("Provide 'prompt' or 'args' for run_claude")
                    )
                eff_stream_mode, _ = resolve_effective_stream_mode(
                    self.config, stream=args.get("stream"), stream_mode=args.get("stream_mode")
                )
                background = bool(args.get("background", False))
                detach_after = None if background else self._resolve_detach_after(args)
                caller_fmt = args.get("output_format")
                has_raw_fmt = any(
                    str(a) == "--output-format" or str(a).startswith("--output-format=")
                    for a in extra_args
                )
                explicit_stream_req = args.get("stream") is True or args.get("stream_mode") in (
                    "summary",
                    "raw",
                )
                auto_structured = (
                    eff_stream_mode != "off"
                    and caller_fmt is None
                    and not has_raw_fmt
                    and (
                        progress_token is not None
                        or background
                        or detach_after is not None
                        or explicit_stream_req
                    )
                )
                eff_output_format = "stream-json" if auto_structured else caller_fmt
                session = await self.sessions.create_claude_session(
                    prompt=prompt,
                    cwd=args.get("cwd"),
                    env=args.get("env"),
                    args=extra_args,
                    skip_permissions=args.get("skip_permissions"),
                    permission_mode=args.get("permission_mode"),
                    print_mode=True,
                    output_format=eff_output_format,
                    model=args.get("model"),
                    effort=args.get("effort"),
                    session_id=args.get("session_id"),
                    continue_last=bool(args.get("continue_last", False)),
                    add_dirs=args.get("add_dirs"),
                    timeout=args.get("timeout"),
                    close_stdin=True,
                    stream_mode=eff_stream_mode,
                )
                if background:
                    bg_data = {
                        **session.to_summary(include_output=False),
                        "background": True,
                        "progress": session.get_progress(after_seq=0),
                    }
                    return _jsonrpc_result(req_id, _tool_success(bg_data))
                summary, detached = await self._watch_session_with_progress(
                    session,
                    progress_token,
                    emit_event,
                    req_id=req_id,
                    mcp_session_id=mcp_session_id,
                    stream_mode=eff_stream_mode,
                    detach_after_seconds=detach_after,
                )
                if detached or summary is None:
                    assert detach_after is not None
                    return _jsonrpc_result(
                        req_id,
                        _tool_success(
                            self._build_detached_result(
                                session,
                                stream_mode=eff_stream_mode,
                                detach_after_seconds=detach_after,
                            )
                        ),
                    )
                clean_final = summary.get("final_output", summary["stdout"])
                out_stdout = (
                    clean_final
                    if (auto_structured and eff_stream_mode != "raw")
                    else summary["stdout"]
                )
                result_data = {
                    "session_id": summary["session_id"],
                    "agent_conversation_id": summary.get("agent_conversation_id"),
                    "status": summary["status"],
                    "returncode": summary["returncode"],
                    "cwd": summary["cwd"],
                    "duration_seconds": summary["duration_seconds"],
                    "stream_mode": eff_stream_mode,
                    "stdout": out_stdout,
                    "stderr": summary["stderr"],
                    "final_output": clean_final,
                    "progress": summary.get("progress"),
                }
                if summary["returncode"] != 0:
                    return _jsonrpc_result(
                        req_id,
                        _tool_error(
                            f"claude exited with code {summary['returncode']} ({summary['status']})",
                            result_data,
                        ),
                    )
                return _jsonrpc_result(req_id, _tool_success(result_data))

            if tool_name == "session_start":
                stype = str(args.get("type", "exec"))
                eff_stream_mode, _ = resolve_effective_stream_mode(
                    self.config, stream=args.get("stream"), stream_mode=args.get("stream_mode")
                )
                if stype == "agy":
                    caller_fmt = args.get("output_format")
                    close_stdin_arg = bool(args.get("close_stdin", False))
                    if eff_stream_mode == "off" and caller_fmt is None and args.get("prompt") and close_stdin_arg:
                        session = await self.sessions.create_agy_session(
                            prompt=str(args["prompt"]),
                            cwd=args.get("cwd"),
                            env=args.get("env"),
                            args=args.get("args"),
                            skip_permissions=args.get("skip_permissions"),
                            print_mode=True,
                            output_format="text",
                            input_format=None,
                            model=args.get("model"),
                            effort=args.get("effort"),
                            mode=args.get("mode"),
                            conversation_id=args.get("conversation_id"),
                            continue_last=bool(args.get("continue_last", False)),
                            add_dirs=args.get("add_dirs"),
                            use_pty=bool(args.get("use_pty", False)),
                            timeout=args.get("timeout"),
                            close_stdin=True,
                            stream_mode=eff_stream_mode,
                        )
                    else:
                        out_fmt = caller_fmt or "stream-json"
                        session = await self.sessions.create_agy_session(
                            prompt=None,
                            cwd=args.get("cwd"),
                            env=args.get("env"),
                            args=args.get("args"),
                            skip_permissions=args.get("skip_permissions"),
                            print_mode=True,
                            output_format=out_fmt,
                            input_format="stream-json",
                            model=args.get("model"),
                            effort=args.get("effort"),
                            mode=args.get("mode"),
                            conversation_id=args.get("conversation_id"),
                            continue_last=bool(args.get("continue_last", False)),
                            add_dirs=args.get("add_dirs"),
                            use_pty=bool(args.get("use_pty", False)),
                            timeout=args.get("timeout"),
                            close_stdin=False,
                            stream_mode=eff_stream_mode,
                        )
                        if args.get("prompt"):
                            await session.send_agy_turn(str(args["prompt"]), close_after=close_stdin_arg)
                elif stype == "codex":
                    prompt = args.get("prompt")
                    extra_args = args.get("args") or []
                    review = bool(args.get("review", False))
                    if not prompt and not extra_args and not review:
                        return _jsonrpc_result(
                            req_id,
                            _tool_error(
                                "Provide 'prompt', 'review=true', or 'args' for session_start(type='codex')"
                            ),
                        )
                    caller_json = args.get("json_events")
                    eff_json = (eff_stream_mode != "off") if caller_json is None else bool(caller_json)
                    session = await self.sessions.create_codex_session(
                        prompt=str(prompt) if prompt is not None else None,
                        cwd=args.get("cwd"),
                        env=args.get("env"),
                        args=extra_args,
                        skip_permissions=args.get("skip_permissions"),
                        sandbox_mode=args.get("sandbox_mode"),
                        json_events=eff_json,
                        model=args.get("model"),
                        effort=args.get("effort"),
                        search=bool(args.get("search", False)),
                        session_id=args.get("session_id"),
                        continue_last=bool(args.get("continue_last", False)),
                        review=review,
                        add_dirs=args.get("add_dirs"),
                        use_pty=bool(args.get("use_pty", False)),
                        timeout=args.get("timeout"),
                        close_stdin=True,
                        stream_mode=eff_stream_mode,
                    )
                elif stype == "claude":
                    caller_fmt = args.get("output_format")
                    close_stdin_arg = bool(args.get("close_stdin", False))
                    if eff_stream_mode == "off" and caller_fmt is None and args.get("prompt") and close_stdin_arg:
                        session = await self.sessions.create_claude_session(
                            prompt=str(args["prompt"]),
                            cwd=args.get("cwd"),
                            env=args.get("env"),
                            args=args.get("args"),
                            skip_permissions=args.get("skip_permissions"),
                            permission_mode=args.get("permission_mode"),
                            print_mode=True,
                            output_format="text",
                            input_format=None,
                            model=args.get("model"),
                            effort=args.get("effort"),
                            session_id=args.get("session_id"),
                            continue_last=bool(args.get("continue_last", False)),
                            add_dirs=args.get("add_dirs"),
                            use_pty=bool(args.get("use_pty", False)),
                            timeout=args.get("timeout"),
                            close_stdin=True,
                            stream_mode=eff_stream_mode,
                        )
                    else:
                        out_fmt = caller_fmt or "stream-json"
                        session = await self.sessions.create_claude_session(
                            prompt=None,
                            cwd=args.get("cwd"),
                            env=args.get("env"),
                            args=args.get("args"),
                            skip_permissions=args.get("skip_permissions"),
                            permission_mode=args.get("permission_mode"),
                            print_mode=True,
                            output_format=out_fmt,
                            input_format="stream-json",
                            model=args.get("model"),
                            effort=args.get("effort"),
                            session_id=args.get("session_id"),
                            continue_last=bool(args.get("continue_last", False)),
                            add_dirs=args.get("add_dirs"),
                            use_pty=bool(args.get("use_pty", False)),
                            timeout=args.get("timeout"),
                            close_stdin=False,
                            stream_mode=eff_stream_mode,
                        )
                        if args.get("prompt"):
                            await session.send_agy_turn(str(args["prompt"]), close_after=close_stdin_arg)
                else:
                    command = args.get("command")
                    if not command:
                        return _jsonrpc_result(
                            req_id, _tool_error("Missing 'command' for session_start(type='exec')")
                        )
                    session = await self.sessions.create_session(
                        command=command,
                        cwd=args.get("cwd"),
                        env=args.get("env"),
                        use_pty=bool(args.get("use_pty", False)),
                        timeout=args.get("timeout"),
                        initial_stdin=args.get("stdin"),
                        close_stdin=bool(args.get("close_stdin", False)),
                        stream_mode=eff_stream_mode,
                    )
                start_data = {
                    **session.to_summary(include_output=False),
                    "progress": session.get_progress(after_seq=0),
                }
                return _jsonrpc_result(req_id, _tool_success(start_data))

            if tool_name == "session_poll":
                sid = str(args.get("session_id", ""))
                session = self.sessions.get_session(sid)
                if session is None:
                    return _jsonrpc_result(req_id, _tool_error(f"Session '{sid}' not found"))
                try:
                    after_seq = int(args.get("after_seq") or 0)
                    raw_wait = float(args.get("wait_seconds") or 0.0)
                    if not math.isfinite(raw_wait):
                        raise ValueError("wait_seconds must be finite")
                    wait_seconds = min(max(0.0, raw_wait), 60.0)
                    tail_chars = max(
                        0, int(args.get("tail_chars") if args.get("tail_chars") is not None else 2000)
                    )
                    offset_raw = args.get("offset")
                    limit_raw = args.get("limit")
                    offset = max(0, int(offset_raw)) if offset_raw is not None else 0
                    limit = max(0, int(limit_raw)) if limit_raw is not None else None
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Invalid numeric parameter in session_poll: {exc}") from exc
                wait_for_exit = bool(args.get("wait_for_exit", False))
                view = str(args.get("view") or "full").strip().lower()
                if view not in ("full", "progress", "delta"):
                    return _jsonrpc_result(
                        req_id,
                        _tool_error(f"Invalid view {view!r}; expected 'full', 'progress', or 'delta'"),
                    )
                include_events = bool(args.get("include_events", True))

                if wait_seconds > 0 and session.status in (
                    "queued",
                    "starting",
                    "running",
                    "orphaned_running",
                ):
                    deadline = time.monotonic() + wait_seconds
                    keepalive_sec = max(0.2, float(self.config.sse_keepalive_seconds))
                    hb_sec = min(keepalive_sec, max(0.05, min(0.5, wait_seconds)))
                    last_keepalive_mono = time.monotonic()
                    async for ev in session.subscribe_with_heartbeat(
                        after_seq=after_seq,
                        heartbeat_seconds=hb_sec,
                    ):
                        now = time.monotonic()
                        if ev is None:
                            if emit_event is not None and (now - last_keepalive_mono) >= keepalive_sec:
                                last_keepalive_mono = now
                                await emit_event(None)
                        elif not wait_for_exit:
                            # Allow a tiny coalescing window so immediate burst lines arrive together
                            coalesce = min(0.05, max(0.0, deadline - now))
                            if coalesce > 0:
                                await asyncio.sleep(coalesce)
                            break
                        if now >= deadline:
                            break

                if view == "progress":
                    meta_summary = session.to_summary(include_output=False, after_seq=after_seq)
                    progress_data: Dict[str, Any] = {
                        **meta_summary,
                        "view": "progress",
                        "progress": session.get_progress(after_seq=after_seq),
                        "stdout_tail": session.get_stdout_tail(tail_chars),
                        "stderr_tail": session.get_stderr_tail(min(1000, tail_chars)),
                    }
                    if session.status not in ("queued", "starting", "running", "orphaned_running"):
                        progress_data["final_output"] = session.get_final_output()
                    return _jsonrpc_result(req_id, _tool_success(progress_data))

                if view == "delta":
                    summary = session.to_summary(include_output=False, after_seq=after_seq)
                    out_delta, err_delta = session.get_delta_output(after_seq=after_seq)
                    summary["view"] = "delta"
                    summary["stdout"] = out_delta
                    summary["stderr"] = err_delta
                    summary["progress"] = session.get_progress(after_seq=after_seq)
                    if include_events:
                        summary["events"] = session.get_events(after_seq=after_seq)
                    if session.status not in ("queued", "starting", "running", "orphaned_running"):
                        summary["final_output"] = session.get_final_output()
                    return _jsonrpc_result(req_id, _tool_success(summary))

                summary = session.to_summary(include_output=True, after_seq=after_seq)
                if not include_events:
                    summary.pop("events", None)
                if offset > 0 or limit is not None:
                    summary.pop("final_output", None)
                    full_stdout = str(summary.get("stdout") or "")
                    full_stderr = str(summary.get("stderr") or "")
                    total_out = len(full_stdout)
                    total_err = len(full_stderr)
                    end_out = offset + limit if limit is not None else total_out
                    end_err = offset + limit if limit is not None else total_err
                    summary["stdout"] = full_stdout[offset:end_out]
                    summary["stderr"] = full_stderr[offset:end_err]
                    summary["output_offset"] = offset
                    summary["output_limit"] = limit
                    summary["stdout_total_chars"] = total_out
                    summary["stderr_total_chars"] = total_err
                    summary["stdout_has_more"] = end_out < total_out
                    summary["stderr_has_more"] = end_err < total_err
                return _jsonrpc_result(req_id, _tool_success(summary))

            if tool_name == "session_input":
                sid = str(args.get("session_id", ""))
                session = self.sessions.get_session(sid)
                if session is None:
                    return _jsonrpc_result(req_id, _tool_error(f"Session '{sid}' not found"))
                close_stdin = bool(args.get("close_stdin", False))
                if "prompt" in args and args["prompt"] is not None:
                    await session.send_agy_turn(str(args["prompt"]), close_after=close_stdin)
                elif "data" in args and args["data"] is not None:
                    await session.write_stdin(str(args["data"]), close_after=close_stdin)
                else:
                    return _jsonrpc_result(
                        req_id, _tool_error("Provide either 'data' or 'prompt' in session_input")
                    )
                return _jsonrpc_result(
                    req_id,
                    _tool_success(
                        {"ok": True, "session_id": sid, "status": session.status, "last_seq": session._seq}
                    ),
                )

            if tool_name == "session_signal":
                sid = str(args.get("session_id", ""))
                session = self.sessions.get_session(sid)
                if session is None:
                    return _jsonrpc_result(req_id, _tool_error(f"Session '{sid}' not found"))
                sig_name = str(args.get("signal", "SIGTERM"))
                await session.send_signal(sig_name)
                return _jsonrpc_result(
                    req_id,
                    _tool_success({"ok": True, "session_id": sid, "signal": sig_name, "status": session.status}),
                )

            if tool_name == "session_list":
                limit_arg = args.get("limit")
                limit_val = max(1, int(limit_arg)) if limit_arg is not None else None
                sessions_out = self.sessions.list_sessions(
                    limit=limit_val,
                    cwd=args.get("cwd"),
                    status=args.get("status"),
                    session_kind=args.get("session_kind"),
                )
                return _jsonrpc_result(req_id, _tool_success({"sessions": sessions_out}))

            if tool_name == "fs_stat":
                res = await asyncio.to_thread(self.files.stat, str(args["path"]), args.get("cwd"))
                return _jsonrpc_result(req_id, _tool_success(res))

            if tool_name == "fs_list":
                target = str(args.get("path") or self.config.default_workdir)
                res = await asyncio.to_thread(
                    self.files.list_dir,
                    target,
                    args.get("cwd"),
                    bool(args.get("recursive", False)),
                    int(args.get("max_entries", 500)),
                )
                return _jsonrpc_result(req_id, _tool_success(res))

            if tool_name == "fs_read":
                limit_val = int(args["limit"]) if args.get("limit") is not None else None
                res = await asyncio.to_thread(
                    self.files.read,
                    str(args["path"]),
                    args.get("cwd"),
                    str(args.get("encoding", "utf-8")),
                    int(args.get("offset", 0)),
                    limit_val,
                )
                return _jsonrpc_result(req_id, _tool_success(res))

            if tool_name == "fs_write":
                res = await asyncio.to_thread(
                    self.files.write,
                    str(args["path"]),
                    str(args["content"]),
                    args.get("cwd"),
                    str(args.get("encoding", "utf-8")),
                    bool(args.get("append", False)),
                    bool(args.get("mkdir_parents", True)),
                    args.get("mode"),
                )
                return _jsonrpc_result(req_id, _tool_success(res))

            if tool_name == "fs_patch":
                res = await asyncio.to_thread(
                    self.files.patch,
                    str(args["path"]),
                    list(args.get("edits") or []),
                    args.get("cwd"),
                )
                return _jsonrpc_result(req_id, _tool_success(res))

            if tool_name == "fs_delete":
                res = await asyncio.to_thread(
                    self.files.delete,
                    str(args["path"]),
                    args.get("cwd"),
                )
                return _jsonrpc_result(req_id, _tool_success(res))

        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            preview = redact_for_audit_log(
                args.get("command")
                if "command" in args
                else (args.get("path") or args.get("args") or args.get("add_dirs"))
            )
            logger.warning(
                "MCP policy rejection: tool=%s cwd=%r reason=%s preview=%s",
                tool_name,
                args.get("cwd"),
                safe_err,
                preview,
            )
            return _jsonrpc_result(req_id, _tool_error(safe_err))
        except (FileNotFoundError, ValueError, RuntimeError, OSError) as exc:
            return _jsonrpc_result(
                req_id, _tool_error(redact_diagnostic_text(str(exc), self.config))
            )

        return _jsonrpc_error(req_id, -32602, f"Unhandled tool: {tool_name}")

    async def _handle_resource_read(self, req_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = str(params.get("uri") or "")
        if not uri:
            return _jsonrpc_error(req_id, -32602, "Missing 'uri' parameter")

        if uri == "gateway://status":
            text = json.dumps(
                {
                    "service": "dots-gateway",
                    "version": __version__,
                    "uptime_seconds": round(time.time() - self._started_at, 2),
                    "active_sessions": self.sessions.active_count(),
                    "active_agy_sessions": self.sessions.active_agy_count(),
                    "queued_agy_sessions": self.sessions.queued_agy_count(),
                    "active_codex_sessions": self.sessions.active_codex_count(),
                    "queued_codex_sessions": self.sessions.queued_codex_count(),
                    "active_claude_sessions": self.sessions.active_claude_count(),
                    "queued_claude_sessions": self.sessions.queued_claude_count(),
                    "max_concurrent_agy": self.config.max_concurrent_agy,
                    "max_concurrent_codex": self.config.max_concurrent_codex,
                    "max_concurrent_claude": self.config.max_concurrent_claude,
                    "default_timeout_seconds": self.config.default_timeout_seconds,
                    "agent_default_timeout_seconds": self.config.agent_default_timeout_seconds,
                    "max_timeout_seconds": self.config.max_timeout_seconds,
                    "agy_queue_timeout_seconds": self.config.agy_queue_timeout_seconds,
                    "agy_auth": self.sessions.get_agy_auth_info(),
                    "agy_plugins": self.policy.get_agy_plugins_info(),
                    "docker": self.sessions.get_docker_info(),
                    "streaming": self.sessions.get_stream_info(),
                    "codex_auth_configured": self.sessions.has_codex_auth(),
                    "codex_plugins": self.policy.get_codex_plugins_info(),
                    "claude_auth": self.sessions.get_claude_auth_info(),
                    "claude_plugins": self.policy.get_claude_plugins_info(),
                    "session_persistence_enabled": bool(self.config.session_state_dir),
                    "persisted_sessions": len(self.sessions._persisted),
                    "default_workdir": self.config.default_workdir,
                    "sandbox_state_dir": self.config.sandbox_state_dir,
                    "agent_runtime_home_root": self.config.agent_runtime_home_root,
                    "plugin_state_dir": redact_diagnostic_text(
                        effective_plugin_state_dir(self.config), self.config
                    ),
                    "sandbox_lifecycle": self.sessions.get_sandbox_lifecycle_info(),
                },
                indent=2,
                ensure_ascii=False,
            )
            return _jsonrpc_result(
                req_id,
                {"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]},
            )

        if uri == "gateway://policy":
            text = json.dumps(
                {
                    "enforce_allowlist": self.config.enforce_allowlist,
                    "allowed_commands": self.config.allowed_commands,
                    "blocked_commands": self.config.blocked_commands,
                    "allowed_workdirs": self.config.allowed_workdirs,
                    "protected_paths": self.config.protected_paths,
                    "default_workdir": self.config.default_workdir,
                    "isolate_mount_namespace": self.config.isolate_mount_namespace,
                    "default_timeout_seconds": self.config.default_timeout_seconds,
                    "agent_default_timeout_seconds": self.config.agent_default_timeout_seconds,
                    "max_timeout_seconds": self.config.max_timeout_seconds,
                    "agy_queue_timeout_seconds": self.config.agy_queue_timeout_seconds,
                    "streaming": self.sessions.get_stream_info(),
                    "sandbox_state_dir": self.config.sandbox_state_dir,
                    "agent_runtime_home_root": self.config.agent_runtime_home_root,
                    "plugin_state_dir": redact_diagnostic_text(
                        effective_plugin_state_dir(self.config), self.config
                    ),
                    "sandbox_lifecycle": self.sessions.get_sandbox_lifecycle_info(),
                    "agy_default_sandbox": self.config.agy_default_sandbox,
                    "agy_sandbox_network_access": self.config.agy_sandbox_network_access,
                    "agy_sandbox_tool_permission": self.config.agy_sandbox_tool_permission,
                    "agy_include_allowed_workdirs": self.config.agy_include_allowed_workdirs,
                    "agy_readonly_roots": self.policy.get_agy_readonly_roots(),
                    "agy_writable_roots": self.policy.get_agy_writable_roots(),
                    "agy_plugins": self.policy.get_agy_plugins_info(),
                    "codex_default_sandbox": self.config.codex_default_sandbox,
                    "codex_sandbox_network_access": self.config.codex_sandbox_network_access,
                    "codex_writable_roots": self.policy.get_codex_writable_roots(),
                    "codex_plugins": self.policy.get_codex_plugins_info(),
                    "claude_default_skip_permissions": self.config.claude_default_skip_permissions,
                    "claude_default_permission_mode": self.config.claude_default_permission_mode,
                    "claude_plugins": self.policy.get_claude_plugins_info(),
                },
                indent=2,
                ensure_ascii=False,
            )
            return _jsonrpc_result(
                req_id,
                {"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]},
            )

        if uri.startswith("file://"):
            parsed = urlparse(uri)
            file_path = unquote(parsed.path)
            try:
                res = await asyncio.to_thread(self.files.read, file_path, None, "utf-8", 0, None)
            except Exception as exc:
                return _jsonrpc_error(
                    req_id,
                    -32002,
                    f"Failed to read resource {uri}: {redact_diagnostic_text(str(exc), self.config)}",
                )
            return _jsonrpc_result(
                req_id,
                {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/plain; charset=utf-8",
                            "text": res["content"],
                        }
                    ]
                },
            )

        return _jsonrpc_error(req_id, -32002, f"Resource not found: {uri}")

    def _handle_prompt_get(self, req_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        name = str(params.get("name") or "")
        p_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        cwd = p_args.get("cwd") or self.config.default_workdir

        if name == "delegate_to_agy":
            task = p_args.get("task") or "<describe feature or bugfix>"
            test_cmd = p_args.get("test_command") or "pytest -v"
            return _jsonrpc_result(
                req_id,
                {
                    "description": "Delegate implementation to local Antigravity (`agy`) and verify.",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": (
                                    f"Working in remote directory `{cwd}` via dots-gateway MCP tools:\n"
                                    f"1. Inspect the repository layout with `fs_list` and `exec_command` (`git status`).\n"
                                    f"2. Delegate the following task to `run_agy` (`skip_permissions=true`, `cwd='{cwd}'`):\n"
                                    f"   Task: {task}\n"
                                    f"3. Review changes with `exec_command` (`git diff`) and verify by running `{test_cmd}`."
                                ),
                            },
                        }
                    ],
                },
            )

        if name == "delegate_to_codex":
            task = p_args.get("task") or "<describe feature or review task>"
            test_cmd = p_args.get("test_command") or "pytest -v"
            return _jsonrpc_result(
                req_id,
                {
                    "description": "Delegate implementation or review to local OpenAI Codex (`codex`) and verify.",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": (
                                    f"Working in remote directory `{cwd}` via dots-gateway MCP tools:\n"
                                    f"1. Inspect the repository layout with `fs_list` and `exec_command` (`git status`).\n"
                                    f"2. Delegate the following task to `run_codex` (`skip_permissions=true`, `sandbox_mode='workspace-write'`, `cwd='{cwd}'`):\n"
                                    f"   Task: {task}\n"
                                    f"3. Review changes with `exec_command` (`git diff`) and verify by running `{test_cmd}`."
                                ),
                            },
                        }
                    ],
                },
            )

        if name == "delegate_to_claude":
            task = p_args.get("task") or "<describe feature or review task>"
            test_cmd = p_args.get("test_command") or "pytest -v"
            return _jsonrpc_result(
                req_id,
                {
                    "description": "Delegate implementation or review to local Anthropic Claude Code (`claude`) and verify.",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": (
                                    f"Working in remote directory `{cwd}` via dots-gateway MCP tools:\n"
                                    f"1. Inspect the repository layout with `fs_list` and `exec_command` (`git status`).\n"
                                    f"2. Delegate the following task to `run_claude` (`skip_permissions=true`, `cwd='{cwd}'`):\n"
                                    f"   Task: {task}\n"
                                    f"3. Review changes with `exec_command` (`git diff`) and verify by running `{test_cmd}`."
                                ),
                            },
                        }
                    ],
                },
            )

        if name == "remote_tdd_loop":
            goal = p_args.get("goal") or "<describe goal>"
            return _jsonrpc_result(
                req_id,
                {
                    "description": "Execute a remote TDD cycle over dots-gateway MCP.",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": (
                                    f"In remote workspace `{cwd}`, complete this TDD loop using dots-gateway MCP tools:\n"
                                    f"Goal: {goal}\n"
                                    f"1. Read relevant files using `fs_read`.\n"
                                    f"2. Add or update unit tests first using `fs_write` / `fs_patch`.\n"
                                    f"3. Run the test suite via `exec_command` to confirm the failing test.\n"
                                    f"4. Implement the fix with `fs_patch` (or `run_agy` for multi-file changes) and re-run tests until green."
                                ),
                            },
                        }
                    ],
                },
            )

        return _jsonrpc_error(req_id, -32602, f"Unknown prompt: {name}")
