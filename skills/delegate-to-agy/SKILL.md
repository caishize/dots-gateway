---
name: delegate-to-agy
description: Delegate multi-file coding, refactoring, and autonomous debugging tasks on the remote machine to Google Antigravity CLI (agy --dangerously-skip-permissions) via dots-gateway MCP.
---

# Delegating Software Engineering Tasks to Local `agy`

The remote host has Google Antigravity CLI (`agy`) installed and authorized by the gateway to run unattended with `--dangerously-skip-permissions`.

## When to Use `run_agy` vs Direct `fs_patch`
- **Use `fs_read` + `fs_patch` + `exec_command` directly** for quick inspections, targeted 1–2 file edits, git operations, or running a known test command.
- **Use `run_agy`** when implementing multi-file features, large refactors, unfamiliar codebase exploration, or iterative build-fix loops where executing an agent locally next to the filesystem avoids cross-network round-trips.

## Standard Single-Shot Delegation (`run_agy`)
1. Inspect the repository status first (`exec_command` with `git status --short` in `cwd`).
2. Invoke `run_agy` with a clear, self-contained engineering specification:
   - `cwd`: Absolute path to the target project on the remote machine.
   - `skip_permissions`: `true` (enables `--dangerously-skip-permissions`).
   - `prompt`: Include exact requirements, constraints, files of interest, and the test command `agy` must run before finishing.
   - Optional: Pass `continue_last: true` or `conversation_id` to iterate on `agy`'s previous run.
3. Verify independently afterward using `exec_command` (`git diff --stat` and the project's test suite).

## Multi-Turn Interactive `agy` Sessions
When you want to guide `agy` turn-by-turn without restarting its context:
1. Start an interactive session:
   `session_start(type="agy", cwd="<project_dir>", prompt="<Turn 1 instructions>", skip_permissions=true)`
2. Poll output with `session_poll(session_id=..., after_seq=..., wait_seconds=15)` until the turn's response completes.
3. Send follow-up instructions using `session_input(session_id=..., prompt="<Turn 2 instructions>", close_stdin=true)` when ready to conclude.

## Running Multiple `agy` Tasks in Parallel
- You can invoke multiple `run_agy` tool calls in parallel (or start multiple background `session_start(type="agy")` sessions concurrently). If the remote machine's `max_concurrent_agy` slot limit is reached, extra `agy` calls automatically wait in the gateway queue with SSE keepalive heartbeats until a slot opens.
- **Avoid Git/File Collisions**: Never run two parallel `agy` sessions modifying the same working directory (`cwd`) simultaneously. For parallel work on the same repository, create isolated `git worktree` directories first via `exec_command` (e.g., `git worktree add ../repo-wt-1 -b feat/part-1`) and pass each worktree's path as `cwd`.

