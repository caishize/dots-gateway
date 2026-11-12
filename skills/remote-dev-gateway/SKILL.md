---
name: remote-dev-gateway
description: Inspect, edit, build, test, and manage background sessions on the user's remote development machine using the dots-gateway MCP server.
---

# Remote Development Workflow (`dots-gateway`)

Use this workflow whenever you need to inspect code, edit files, run builds/tests, or manage processes on the user's remote development machine through the `dots-gateway` MCP tools.

## 1. Discovery & Workspace Inspection
1. Call `gateway_status` first if you do not yet know `default_workdir` or `allowed_workdirs`.
2. Use `fs_list` and `fs_stat` to explore directories rather than spawning shell `ls` subprocesses.
3. Always pass an explicit `cwd` pointing to the target project root inside `allowed_workdirs`.

## 2. Atomic File Reading & Editing
- **Read files**: Use `fs_read` (`encoding="utf-8"` for source files, `encoding="base64"` for binary assets; use `offset` and `limit` for large logs).
- **Create or overwrite files**: Use `fs_write` (`mkdir_parents=true` is enabled by default; set `mode="0755"` when writing executable scripts).
- **Modify existing files**: Prefer `fs_patch` with exact `target` / `replacement` pairs instead of `sed` or heredoc shell commands to avoid quoting corruption (`replace_all=false` by default requires a unique match; pass `replace_all=true` to replace multiple occurrences intentionally).

## 3. Running Commands, Builds & Tests
- Use `exec_command` for allowlisted development tools (`git`, `pytest`, `python3`, `ruff`, `mypy`, `npm`, `pnpm`, `tsc`, `vitest`, `cargo`, `go`, `make`, `./scripts/...`, `.venv/bin/...`).
- Compound pipelines (`cd subproj && pytest -v | tee test.log`) and multi-line heredoc scripts (`python3 - <<'PY'\nimport ...\nPY`) are supported automatically inside `allowed_workdirs` (default: `~/workspaces`).
- All commands execute inside an isolated Linux mount namespace (`unshare` + `pivot_root`) confined strictly to `allowed_workdirs`; parent `$HOME` directories (`~/gateway`, `~/.ssh`, `~/.gemini`, `~/.config`), host `/tmp`, and privilege-escalation commands (`sudo`, `mkfs`, `shutdown`, etc.) are blocked by both policy and kernel VFS isolation (`docker` / `docker compose` is blocked unless policy-filtered Docker proxy access is enabled on the gateway via `dots-gateway docker on`, checkable in `gateway_status.docker.enabled`).

## 4. Long-Running & Interactive Processes
When running commands that require interactive `stdin`, long-running dev servers, or incremental log monitoring:
1. Call `session_start` (`type="exec"`, `command=...`, `cwd=...`) to obtain a `session_id` immediately.
2. Call `session_poll` (`session_id=..., after_seq=..., wait_seconds=10`) to stream new events without busy-looping.
3. Send input via `session_input` (`data="...\n"`) or stop the process cleanly via `session_signal` (`signal="SIGTERM"`).
