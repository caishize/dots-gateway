# Dots Remote Development Gateway Rules

- Always prefer `fs_read`, `fs_write`, `fs_patch`, `fs_list`, and `fs_stat` over shell `cat`/`sed`/`echo` redirections when reading or modifying remote workspace files.
- Always specify an explicit `cwd` inside the gateway's isolated workspace root (`~/workspaces`, or inspect `gateway_status` for `allowed_workdirs`) when calling `exec_command`, `run_agy`, `run_codex`, or `session_start`.
- All child processes run inside a Linux User + Mount Namespace VFS jail (`isolate_mount_namespace: true`), `run_agy` runs with `--sandbox` (`agy_default_sandbox: true`), and `run_codex` runs with `-s workspace-write`; paths outside `allowed_workdirs` (including `~/gateway`, `~/.gemini`, `~/.codex`, `~/.ssh`) are detached or isolated per agent.
- For complex multi-file coding or cross-model review tasks on the remote host, delegate execution to `run_agy` or `run_codex` and then verify the diff and test results with `exec_command`.
- Never attempt to read or modify gateway/tunnel credentials (`config.json`, `client.json`, `certs/`, `tunnel.env`, `dots-gateway.yaml`, `agy.env`, `codex.env`) or host SSH keys (`~/.ssh`); operator-registered `agy` plugins (`dots-gateway agy-plugins`, exposed read-only at `~/.gemini/config/plugins/<name>` inside `run_agy` sessions when enabled) must never be modified or overridden by task calls.
