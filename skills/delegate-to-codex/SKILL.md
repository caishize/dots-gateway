---
name: delegate-to-codex
description: Delegate coding, refactoring, autonomous debugging, and independent code review tasks on the remote machine to OpenAI Codex CLI (codex exec) via dots-gateway MCP.
---

# Delegating Software Engineering & Review Tasks to Local `codex`

The remote host has OpenAI Codex CLI (`codex`) installed and authorized by the gateway to run unattended inside `allowed_workdirs` (default: `~/workspaces`) with `-a never -s workspace-write`, kernel mount-namespace VFS isolation, and isolated `~/.codex` persistence.

## When to Use `run_codex` vs `run_agy` vs Direct `fs_patch`
- **Use `fs_read` + `fs_patch` + `exec_command` directly** for quick inspections, targeted 1–2 file edits, git operations, or running a known test command.
- **Use `run_codex` or `run_agy`** for multi-file features, refactors, autonomous test-fix loops, or **cross-model verification** (e.g., implement a feature with `run_agy` and run an independent audit with `run_codex(review=true, args=["--uncommitted"], cwd=...)` or `sandbox_mode="read-only"`).

## Standard Single-Shot Delegation (`run_codex`)
1. Inspect repository status first (`exec_command` with `git status --short` in `cwd`).
2. Invoke `run_codex`:
   - `cwd`: Absolute path to the target project inside `~/workspaces`.
   - `sandbox_mode`: `"workspace-write"` for coding tasks, or `"read-only"` for audits/reviews.
   - `prompt`: Self-contained task specification and test command to verify before finishing.
   - Optional: `continue_last: true` or `session_id` to continue a previous Codex run in `cwd`.
   - Optional: `review: true` (with `args: ["--uncommitted"]` or `args: ["--base", "main"]`) to run Codex's built-in non-interactive code review.
3. Verify changes afterward via `exec_command` (`git diff --stat` and the project's test suite).

## Parallel Execution & Concurrency
- `run_codex` and `run_agy` share the gateway's heavy-agent concurrency semaphore (`max_concurrent_agy`) to protect host RAM. Extra calls automatically wait in the gateway queue with SSE keepalive heartbeats.
- Never run two write-enabled agents on the same working directory (`cwd`) simultaneously; create separate `git worktree` directories when running parallel tasks on one repo.
