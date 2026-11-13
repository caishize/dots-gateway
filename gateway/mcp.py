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
import secrets
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from . import __version__
from .config import GatewayConfig, redact_diagnostic_text
from .executor import ExecutionSession, SessionManager
from .files import FileService
from .policy import CommandPolicy, redact_for_audit_log

logger = logging.getLogger("dots_gateway")

_FORBIDDEN_TASK_PLUGIN_KEYS = (
    "plugin_dirs",
    "agy_plugin_dirs",
    "plugins",
    "plugin_root",
    "agy_plugins_enabled",
)


def _reject_task_plugin_overrides(payload: Any) -> None:
    if isinstance(payload, dict):
        for key in _FORBIDDEN_TASK_PLUGIN_KEYS:
            if key in payload:
                raise PermissionError(
                    f"Task-level '{key}' declaration is forbidden by security policy; "
                    "register trusted AGY plugins via operator configuration only"
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
    "linters, and git workflows. Use `run_agy` (local Antigravity CLI) or `run_codex` (local "
    "OpenAI Codex CLI `codex exec`) to delegate multi-file feature implementation, refactoring, "
    "cross-model code review, or autonomous debugging. "
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
                        "Optional model override for `agy` (e.g. `claude-sonnet-4-5`, "
                        "`gemini-2.5-pro`). Call `list_agy_models` for valid IDs. When "
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
                    "default": False,
                    "description": "Emit raw JSONL events on stdout (`--json`). Defaults to false (clean final message on stdout).",
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
        "name": "session_start",
        "title": "Start Background or Interactive Session",
        "description": (
            "Start a non-blocking background command (`type='exec'`), multi-turn interactive "
            "`agy` session (`type='agy'`), or background `codex` run (`type='codex'`) and "
            "immediately return its `session_id`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["exec", "agy", "codex"],
                    "default": "exec",
                    "description": "Session type: 'exec' for shell/CLI commands, 'agy' for Antigravity, or 'codex' for OpenAI Codex.",
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
                    "description": "Initial prompt when `type='agy'` or `type='codex'`.",
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
                    "description": "Optional existing Codex session ID to resume when `type='codex'`.",
                },
                "continue_last": {
                    "type": "boolean",
                    "default": False,
                    "description": "Resume the most recent `agy` or `codex` session in `cwd`.",
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
                    "description": "Additional validated workspace directories to grant access to (`agy` or `codex`).",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional validated CLI flags passed to `agy` or `codex`.",
                },
                "timeout": {
                    "type": "number",
                    "minimum": 0.1,
                    "description": "Timeout in seconds (default: 28800 [8h] for agy/codex, 21600 [6h] for exec; max: 86400 [24h]).",
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
            "Fetch current status, `process_alive` (/proc kernel identity check), stdout/stderr, "
            "and incremental events (`after_seq`) of a background or pre-restart persisted session, "
            "optionally waiting up to `wait_seconds` for new output."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Target `session_id` returned by `session_start`.",
                },
                "after_seq": {
                    "type": "integer",
                    "default": 0,
                    "description": "Only return events with sequence number > `after_seq`.",
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
            "(`prompt`) to a multi-turn `agy` session."
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
                    "description": "Follow-up user message for an interactive `agy` session.",
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
    return {
        "isError": True,
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}],
    }


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

    @staticmethod
    def should_stream_sse(payload: Any) -> bool:
        """Return True if payload contains a potentially long-running tool call suited for SSE."""
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
            if name in ("exec_command", "run_agy", "run_codex"):
                return True
            if name == "session_poll" and isinstance(args, dict) and float(args.get("wait_seconds") or 0) > 0:
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
                res, item_hdrs = await self._handle_single(item, emit_event=emit_event)
                resp_headers.update(item_hdrs)
                if res is not None:
                    responses.append(res)
            return (responses if responses else None), resp_headers

        return await self._handle_single(payload, existing_headers=resp_headers, emit_event=emit_event)

    async def _handle_single(
        self,
        msg: Any,
        existing_headers: Optional[Dict[str, str]] = None,
        emit_event: Optional[EmitCallback] = None,
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
                # Best-effort cancellation hook if a session_id was supplied in params
                cancel_sid = params.get("sessionId")
                if isinstance(cancel_sid, str):
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

    async def _watch_session_with_progress(
        self,
        session: ExecutionSession,
        progress_token: Any,
        emit_event: Optional[EmitCallback],
    ) -> Dict[str, Any]:
        """Wait for `session` to finish while emitting MCP progress notifications & NAT keepalives."""
        if emit_event is None:
            return await session.wait()

        step = 0
        async for ev in session.subscribe_with_heartbeat(
            after_seq=0, heartbeat_seconds=self.config.sse_keepalive_seconds
        ):
            if ev is None:
                await emit_event(None)
                continue
            if progress_token is not None and ev.type in ("queued", "stdout", "stderr", "agy_event", "started"):
                step += 1
                snippet = (
                    ev.data if isinstance(ev.data, str) else json.dumps(ev.data, ensure_ascii=False)
                )
                if len(snippet) > 400:
                    snippet = snippet[:400] + "..."
                await emit_event(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {
                            "progressToken": progress_token,
                            "progress": step,
                            "message": f"[{ev.type}] {snippet.strip()}",
                        },
                    }
                )
        return await session.wait()

    async def _handle_tool_call(
        self,
        req_id: Any,
        params: Dict[str, Any],
        progress_token: Any = None,
        emit_event: Optional[EmitCallback] = None,
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
            if tool_name in ("exec_command", "run_agy", "run_codex", "session_start"):
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
                    "max_concurrent_agy": self.config.max_concurrent_agy,
                    "max_concurrent_codex": self.config.max_concurrent_codex,
                    "default_timeout_seconds": self.config.default_timeout_seconds,
                    "agent_default_timeout_seconds": self.config.agent_default_timeout_seconds,
                    "max_timeout_seconds": self.config.max_timeout_seconds,
                    "agy_queue_timeout_seconds": self.config.agy_queue_timeout_seconds,
                    "default_workdir": self.config.default_workdir,
                    "allowed_workdirs": self.config.allowed_workdirs,
                    "isolate_mount_namespace": self.config.isolate_mount_namespace,
                    "sandbox_state_dir": self.config.sandbox_state_dir,
                    "sandbox_lifecycle": self.sessions.get_sandbox_lifecycle_info(),
                    "enforce_allowlist": self.config.enforce_allowlist,
                    "allowed_commands_count": len(self.config.allowed_commands),
                    "allowed_commands": list(self.config.allowed_commands),
                    "blocked_commands": list(self.config.blocked_commands),
                    "agy_binary": self.config.agy_binary,
                    "agy_default_skip_permissions": self.config.agy_default_skip_permissions,
                    "agy_default_sandbox": self.config.agy_default_sandbox,
                    "agy_sandbox_tool_permission": self.config.agy_sandbox_tool_permission,
                    "agy_include_allowed_workdirs": self.config.agy_include_allowed_workdirs,
                    "agy_readonly_roots": self.policy.get_agy_readonly_roots(),
                    "agy_writable_roots": self.policy.get_agy_writable_roots(),
                    "agy_auth": self.sessions.get_agy_auth_info(),
                    "agy_plugins": self.policy.get_agy_plugins_info(),
                    "docker": self.sessions.get_docker_info(),
                    "codex_binary": self.config.codex_binary,
                    "codex_default_skip_permissions": self.config.codex_default_skip_permissions,
                    "codex_default_sandbox": self.config.codex_default_sandbox,
                    "codex_sandbox_network_access": self.config.codex_sandbox_network_access,
                    "codex_writable_roots": self.policy.get_codex_writable_roots(),
                    "codex_auth_configured": self.sessions.has_codex_auth(),
                    "tls_enabled": bool(self.config.tls_certfile and self.config.tls_keyfile),
                    "mtls_required": self.config.tls_require_client_cert,
                }
                return _jsonrpc_result(req_id, _tool_success(data))

            if tool_name == "exec_command":
                command = args.get("command")
                if not command:
                    return _jsonrpc_result(req_id, _tool_error("Missing required argument 'command'"))
                session = await self.sessions.create_session(
                    command=command,
                    cwd=args.get("cwd"),
                    env=args.get("env"),
                    use_pty=bool(args.get("use_pty", False)),
                    timeout=args.get("timeout"),
                    initial_stdin=args.get("stdin"),
                    close_stdin=True,
                )
                summary = await self._watch_session_with_progress(session, progress_token, emit_event)
                result_data = {
                    "session_id": summary["session_id"],
                    "status": summary["status"],
                    "returncode": summary["returncode"],
                    "cwd": summary["cwd"],
                    "duration_seconds": summary["duration_seconds"],
                    "stdout": summary["stdout"],
                    "stderr": summary["stderr"],
                    "stdout_truncated": summary["stdout_truncated"],
                    "stderr_truncated": summary["stderr_truncated"],
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
                session = await self.sessions.create_agy_session(
                    prompt=prompt,
                    cwd=args.get("cwd"),
                    env=args.get("env"),
                    args=extra_args,
                    skip_permissions=args.get("skip_permissions"),
                    print_mode=True,
                    model=args.get("model"),
                    effort=args.get("effort"),
                    mode=args.get("mode"),
                    conversation_id=args.get("conversation_id"),
                    continue_last=bool(args.get("continue_last", False)),
                    add_dirs=args.get("add_dirs"),
                    timeout=args.get("timeout"),
                    close_stdin=True,
                )
                summary = await self._watch_session_with_progress(session, progress_token, emit_event)
                result_data = {
                    "session_id": summary["session_id"],
                    "status": summary["status"],
                    "returncode": summary["returncode"],
                    "cwd": summary["cwd"],
                    "duration_seconds": summary["duration_seconds"],
                    "stdout": summary["stdout"],
                    "stderr": summary["stderr"],
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
                session = await self.sessions.create_codex_session(
                    prompt=prompt,
                    cwd=args.get("cwd"),
                    env=args.get("env"),
                    args=extra_args,
                    skip_permissions=args.get("skip_permissions"),
                    sandbox_mode=args.get("sandbox_mode"),
                    json_events=bool(args.get("json_events", False)),
                    model=args.get("model"),
                    effort=args.get("effort"),
                    search=bool(args.get("search", False)),
                    session_id=args.get("session_id"),
                    continue_last=bool(args.get("continue_last", False)),
                    review=review,
                    add_dirs=args.get("add_dirs"),
                    timeout=args.get("timeout"),
                    close_stdin=True,
                )
                summary = await self._watch_session_with_progress(session, progress_token, emit_event)
                result_data = {
                    "session_id": summary["session_id"],
                    "status": summary["status"],
                    "returncode": summary["returncode"],
                    "cwd": summary["cwd"],
                    "duration_seconds": summary["duration_seconds"],
                    "stdout": summary["stdout"],
                    "stderr": summary["stderr"],
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

            if tool_name == "session_start":
                stype = str(args.get("type", "exec"))
                if stype == "agy":
                    session = await self.sessions.create_agy_session(
                        prompt=None,
                        cwd=args.get("cwd"),
                        env=args.get("env"),
                        args=args.get("args"),
                        skip_permissions=args.get("skip_permissions"),
                        print_mode=True,
                        output_format="stream-json",
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
                    )
                    if args.get("prompt"):
                        await session.send_agy_turn(str(args["prompt"]), close_after=False)
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
                    session = await self.sessions.create_codex_session(
                        prompt=str(prompt) if prompt is not None else None,
                        cwd=args.get("cwd"),
                        env=args.get("env"),
                        args=extra_args,
                        skip_permissions=args.get("skip_permissions"),
                        sandbox_mode=args.get("sandbox_mode"),
                        json_events=True,
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
                    )
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
                        close_stdin=bool(args.get("close_stdin", False)),
                    )
                return _jsonrpc_result(req_id, _tool_success(session.to_summary(include_output=False)))

            if tool_name == "session_poll":
                sid = str(args.get("session_id", ""))
                session = self.sessions.get_session(sid)
                if session is None:
                    return _jsonrpc_result(req_id, _tool_error(f"Session '{sid}' not found"))
                after_seq = int(args.get("after_seq") or 0)
                wait_seconds = min(max(0.0, float(args.get("wait_seconds") or 0.0)), 60.0)
                wait_for_exit = bool(args.get("wait_for_exit", False))

                if wait_seconds > 0 and session.status in (
                    "queued",
                    "starting",
                    "running",
                    "orphaned_running",
                ):
                    deadline = time.monotonic() + wait_seconds
                    async for ev in session.subscribe_with_heartbeat(
                        after_seq=after_seq,
                        heartbeat_seconds=min(self.config.sse_keepalive_seconds, max(1.0, wait_seconds)),
                    ):
                        if ev is None:
                            if emit_event is not None:
                                await emit_event(None)
                        elif not wait_for_exit:
                            # Allow a tiny coalescing window so immediate burst lines arrive together
                            await asyncio.sleep(0.05)
                            break
                        if time.monotonic() >= deadline:
                            break

                return _jsonrpc_result(
                    req_id, _tool_success(session.to_summary(include_output=True, after_seq=after_seq))
                )

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
                return _jsonrpc_result(
                    req_id, _tool_success({"sessions": self.sessions.list_sessions()})
                )

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
                    "max_concurrent_agy": self.config.max_concurrent_agy,
                    "max_concurrent_codex": self.config.max_concurrent_codex,
                    "default_timeout_seconds": self.config.default_timeout_seconds,
                    "agent_default_timeout_seconds": self.config.agent_default_timeout_seconds,
                    "max_timeout_seconds": self.config.max_timeout_seconds,
                    "agy_queue_timeout_seconds": self.config.agy_queue_timeout_seconds,
                    "agy_auth": self.sessions.get_agy_auth_info(),
                    "agy_plugins": self.policy.get_agy_plugins_info(),
                    "docker": self.sessions.get_docker_info(),
                    "codex_auth_configured": self.sessions.has_codex_auth(),
                    "session_persistence_enabled": bool(self.config.session_state_dir),
                    "persisted_sessions": len(self.sessions._persisted),
                    "default_workdir": self.config.default_workdir,
                    "sandbox_state_dir": self.config.sandbox_state_dir,
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
                    "sandbox_state_dir": self.config.sandbox_state_dir,
                    "sandbox_lifecycle": self.sessions.get_sandbox_lifecycle_info(),
                    "agy_default_sandbox": self.config.agy_default_sandbox,
                    "agy_sandbox_tool_permission": self.config.agy_sandbox_tool_permission,
                    "agy_include_allowed_workdirs": self.config.agy_include_allowed_workdirs,
                    "agy_readonly_roots": self.policy.get_agy_readonly_roots(),
                    "agy_writable_roots": self.policy.get_agy_writable_roots(),
                    "agy_plugins": self.policy.get_agy_plugins_info(),
                    "codex_default_sandbox": self.config.codex_default_sandbox,
                    "codex_sandbox_network_access": self.config.codex_sandbox_network_access,
                    "codex_writable_roots": self.policy.get_codex_writable_roots(),
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
