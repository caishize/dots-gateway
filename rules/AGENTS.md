# Dots Remote Development Gateway Rules

- Always prefer `fs_read`, `fs_write`, `fs_patch`, `fs_list`, and `fs_stat` over shell `cat`/`sed`/`echo` redirections when reading or modifying remote workspace files.
- Always specify an explicit `cwd` inside the gateway's `allowed_workdirs` when calling `exec_command`, `run_agy`, or `session_start`.
- For complex multi-file coding tasks on the remote host, delegate execution to `run_agy` (`skip_permissions: true`) and then verify the diff and test results with `exec_command`.
- Never attempt to read or modify gateway credentials (`config.json`, `client.json`, `certs/`) or host SSH keys (`~/.ssh`).
