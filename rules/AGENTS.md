# Dots Remote Development Gateway Rules

- Always prefer `fs_read`, `fs_write`, `fs_patch`, `fs_list`, and `fs_stat` over shell `cat`/`sed`/`echo` redirections when reading or modifying remote workspace files.
- Always specify an explicit `cwd` inside the gateway's isolated workspace root (`~/workspaces`, or inspect `gateway_status` for `allowed_workdirs`) when calling `exec_command`, `run_agy`, or `session_start`.
- All child processes run inside a Linux User + Mount Namespace VFS jail (`isolate_mount_namespace: true`) and `run_agy` runs with `--sandbox` enabled by default (`agy_default_sandbox: true`); paths outside `allowed_workdirs` (including `~/gateway`, `~/.gemini`, `~/.ssh`) are detached or read-only.
- For complex multi-file coding tasks on the remote host, delegate execution to `run_agy` (`skip_permissions: true`) and then verify the diff and test results with `exec_command`.
- Never attempt to read or modify gateway credentials (`config.json`, `client.json`, `certs/`), installed Antigravity plugins (`~/.gemini/config/plugins`), or host SSH keys (`~/.ssh`).
