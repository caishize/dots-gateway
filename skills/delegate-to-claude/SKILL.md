---
name: delegate-to-claude
description: Delegate multi-file coding, refactoring, architectural planning, and independent code review tasks on the remote machine to Anthropic Claude Code CLI (claude -p) via dots-gateway MCP.
---

# Delegating Software Engineering & Review Tasks to Local `claude`

The remote host supports Anthropic Claude Code CLI (`claude`) running unattended inside `allowed_workdirs` (default: `~/workspaces`) via kernel mount-namespace VFS isolation (`unshare --user --mount` + `pivot_root`), isolated `CLAUDE_CONFIG_DIR` runtime home (`/mnt/dots-agent-home/claude/.claude`), strict untrusted workspace config blocking (`--setting-sources=user`, `--strict-mcp-config`, `--mcp-config={"mcpServers":{}}`), `permissions.deny` command/path guardrails, and optional operator-registered read-only `claude` plugins (`dots-gateway claude-plugins`, e.g., `oh-my-agents` whose `skills/` and native `hooks.json` handlers execute read-only via `--plugin-dir` with hooks confined inside `dots-hook-jail.py`). Task calls cannot dynamically register arbitrary plugin paths (`--plugin-dir` or `claude_plugin_dirs`) or plant repo-local `.claude/settings.local.json`, `.claude/hooks`, or `.mcp.json`.

## When to Use `run_claude` vs `run_agy` / `run_codex` vs Direct `fs_patch`
- **Use `fs_read` + `fs_patch` + `exec_command` directly** for quick inspections, targeted 1–2 file edits, git operations, or running a known test command.
- **Use `run_claude`, `run_agy`, or `run_codex`** for multi-file features, complex refactors, iterative build-fix loops, or **multi-model verification** (e.g., implement a feature with `run_agy` or `run_codex`, and run an independent architectural/security critique with `run_claude(skip_permissions=false, permission_mode="plan", cwd=...)` or `run_claude(prompt=..., cwd=...)`).

## Standard Single-Shot Delegation (`run_claude`)
1. Inspect repository status first (`exec_command` with `git status --short` in `cwd`).
2. Invoke `run_claude`:
   - `cwd`: Absolute path to the target project inside `~/workspaces`.
   - `prompt`: Self-contained task specification and test command to verify before finishing.
   - `skip_permissions`: `true` (default; passes `--dangerously-skip-permissions` inside the VFS sandbox) or `false` combined with `permission_mode: "plan"` for read-only architectural planning and code review.
   - Optional: `model` (`"sonnet"`, `"opus"`, etc.; omit to use `dots-gateway claude-model` default) and `effort` (`"low"` | `"medium"` | `"high"` | `"max"`).
   - Optional: `continue_last: true` or `session_id` (from `agent_conversation_id` / `output_format: "json"`) to resume a previous Claude Code conversation in `cwd`.
3. Verify changes afterward via `exec_command` (`git diff --stat` and the project's test suite).

## Multi-Turn Interactive `claude` Sessions
When guiding Claude Code turn-by-turn over NDJSON (`stream-json`):
1. Start an interactive session:
   `session_start(type="claude", cwd="<project_dir>", prompt="<Turn 1 instructions>", skip_permissions=true)`
2. Poll output with `session_poll(session_id=..., after_seq=..., wait_seconds=15)` until the turn's `"type": "result"` event arrives.
3. Send follow-up turns using `session_input(session_id=..., prompt="<Turn 2 instructions>", close_stdin=true)`.

## Parallel Execution & Concurrency
- `run_claude` uses its own dedicated concurrency semaphore (`max_concurrent_claude`, default: `4`), independent of `run_agy` and `run_codex`, so all three local agents can run side-by-side.
- Never run two write-enabled agents on the same working directory (`cwd`) simultaneously; create separate `git worktree` directories when running parallel tasks on one repo.
