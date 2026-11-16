"""Comprehensive security & capability tests for the Hardened Dots Gateway."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import conftest  # noqa: F401
from dots_client import DotsGatewayClient
from gateway.config import (
    DEFAULT_WORKSPACE_DIR,
    GATEWAY_ROOT,
    HOME_DIR,
    GatewayConfig,
    hash_password_pbkdf2,
)
from gateway.policy import CommandPolicy
from gateway.sandbox import build_mount_ns_argv, can_use_mount_namespace
from gateway.server import GatewayServer
from gateway.tls import ensure_tls_pki


class GatewayEndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="dots_gw_test_")
        real_mns = can_use_mount_namespace()
        agy_bin = shutil.which("agy") or "agy"
        codex_bin = shutil.which("codex") or "codex"
        extra_allowed_cmds = []
        if not shutil.which("agy"):
            stub_agy = Path(self.tmpdir) / "_ci_stub_agy.py"
            stub_agy.write_text("#!/usr/bin/env python3\nimport sys\nprint('agy stub', sys.argv[1:])\n", encoding="utf-8")
            stub_agy.chmod(0o755)
            agy_bin = str(stub_agy)
            extra_allowed_cmds.append(agy_bin)
        if not shutil.which("codex"):
            stub_cdx = Path(self.tmpdir) / "_ci_stub_codex.py"
            stub_cdx.write_text("#!/usr/bin/env python3\nimport sys\nprint('codex stub', sys.argv[1:])\n", encoding="utf-8")
            stub_cdx.chmod(0o755)
            codex_bin = str(stub_cdx)
            extra_allowed_cmds.append(codex_bin)
        base_cmds = list(GatewayConfig().allowed_commands) + extra_allowed_cmds
        self.cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["test-secret-token-12345"],
            users={"dots_user": hash_password_pbkdf2("dots_pass_987")},
            hmac_secret="super-hmac-secret-key-abcdef",
            rate_limit_max_failures=5,
            rate_limit_window_seconds=60,
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            isolate_mount_namespace=real_mns,
            agy_binary=agy_bin,
            codex_binary=codex_bin,
            allowed_commands=base_cmds,
            docker_proxy_socket=os.path.join(self.tmpdir, "gw-docker-proxy.sock"),
        )
        self.server = GatewayServer(self.cfg)
        host, port = await self.server.start()
        self.port = port
        self.base_url = f"http://{host}:{port}"

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_health_anti_fingerprinting_and_auth_modes(self) -> None:
        # 1. Unauthenticated health check returns minimal {"ok": True} (no fingerprinting)
        unauth = DotsGatewayClient(base_url=self.base_url)
        health_unauth = await asyncio.to_thread(unauth.health)
        self.assertEqual(health_unauth, {"ok": True})
        self.assertNotIn("service", health_unauth)

        # 2. Authenticated health check returns full diagnostics
        token_client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )
        health_auth = await asyncio.to_thread(token_client.health)
        self.assertTrue(health_auth["ok"])
        self.assertEqual(health_auth["service"], "dots-gateway")

        # 3. Protected endpoint fails without auth
        with self.assertRaises(RuntimeError) as ctx:
            await asyncio.to_thread(unauth.policy)
        self.assertIn("401", str(ctx.exception))

        # 4. Query parameter ?token= is disabled by default (prevents proxy log leaks)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(
            b"GET /v1/policy?token=test-secret-token-12345 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        await writer.drain()
        resp_line = await reader.readline()
        writer.close()
        await writer.wait_closed()
        self.assertIn(b"401", resp_line)

        # 5. Bearer, Basic (async PBKDF2), and HMAC-SHA256 all succeed
        pol = await asyncio.to_thread(token_client.policy)
        self.assertTrue(pol["ok"])

        basic_client = DotsGatewayClient(
            base_url=self.base_url, username="dots_user", password="dots_pass_987"
        )
        self.assertTrue((await asyncio.to_thread(basic_client.policy))["ok"])

        hmac_client = DotsGatewayClient(
            base_url=self.base_url, hmac_secret="super-hmac-secret-key-abcdef"
        )
        self.assertTrue((await asyncio.to_thread(hmac_client.policy))["ok"])

    async def test_tls_pinning_and_mtls_enforcement(self) -> None:
        certs_dir = Path(self.tmpdir) / "test_certs"
        pki = ensure_tls_pki(certs_dir, extra_hosts=["127.0.0.1"])

        tls_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["tls-token-xyz"],
            hmac_secret="tls-hmac-xyz",
            allowed_workdirs=["/tmp"],
            default_workdir="/tmp",
            tls_certfile=pki["server_cert"],
            tls_keyfile=pki["server_key"],
            tls_ca_file=pki["ca_cert"],
            tls_require_client_cert=True,
        )
        tls_server = GatewayServer(tls_cfg)
        host, port = await tls_server.start()
        https_url = f"https://{host}:{port}"
        try:
            # 1. Wrong SHA-256 pin MUST fail before sending HTTP data (MITM protection)
            bad_pin_client = DotsGatewayClient(
                base_url=https_url,
                token="tls-token-xyz",
                tls_fingerprint="0" * 64,
                client_cert=pki["client_cert"],
                client_key=pki["client_key"],
            )
            with self.assertRaises(Exception) as pin_err:
                await asyncio.to_thread(bad_pin_client.policy)
            self.assertIn("SHA-256 mismatch", str(pin_err.exception))

            # 2. Missing mTLS client certificate MUST be rejected by TLS handshake
            no_client_cert = DotsGatewayClient(
                base_url=https_url,
                token="tls-token-xyz",
                tls_fingerprint=pki["server_fingerprint_sha256"],
            )
            with self.assertRaises(Exception):
                await asyncio.to_thread(no_client_cert.policy)

            # 3. Valid mTLS client cert + SHA-256 fingerprint succeeds over HTTPS and WSS
            mtls_client = DotsGatewayClient(
                base_url=https_url,
                hmac_secret="tls-hmac-xyz",
                tls_fingerprint=pki["server_fingerprint_sha256"],
                client_cert=pki["client_cert"],
                client_key=pki["client_key"],
            )
            pol = await asyncio.to_thread(mtls_client.policy)
            self.assertTrue(pol["ok"])

            async with mtls_client.connect_websocket() as ws:
                self.assertEqual(ws.welcome.get("type"), "connected")
                await ws.send_json({"id": "p1", "action": "ping"})
                pong = await ws.recv_json()
                assert pong is not None
                self.assertEqual(pong["type"], "pong")
        finally:
            await tls_server.stop()

    async def test_ip_allowlist_direct_connect(self) -> None:
        restricted_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["ip-tok"],
            allowed_client_ips=["192.0.2.0/24"],  # Excludes 127.0.0.1
        )
        srv = GatewayServer(restricted_cfg)
        h, p = await srv.start()
        try:
            c = DotsGatewayClient(base_url=f"http://{h}:{p}", token="ip-tok")
            with self.assertRaises(Exception):
                await asyncio.to_thread(c.policy)
        finally:
            await srv.stop()

    async def test_security_policy_and_protected_paths(self) -> None:
        client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )

        # Create a symlink pointing to /usr/bin/sudo (or blocked binary) to test symlink bypass
        evil_sudo = Path(self.tmpdir) / "my_helper"
        evil_sudo.symlink_to("/usr/bin/sudo")

        for dangerous_cmd in [
            "sudo ls",
            "docker run -v /:/host alpine sh",
            "shutdown -h now",
            "rm -rf /",
            "rm -rf /*",
            "mkfs.ext4 /dev/sda1",
            "bash -c 'sudo whoami'",
            "echo $(sudo id)",
            "echo `sudo id`",
            f"{evil_sudo} id",
            f"cat {GATEWAY_ROOT / 'config.json'}",
            f"ls {Path.home() / '.ssh'}",
        ]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(client.exec_command, dangerous_cmd, cwd=self.tmpdir)
            self.assertIn("403", str(ctx.exception), f"Expected 403 for {dangerous_cmd}")

        # Disallowed working directories
        for bad_cwd in ["/etc", str(Path.home() / ".ssh"), str(GATEWAY_ROOT / "certs")]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(client.exec_command, "ls", cwd=bad_cwd)
            self.assertIn("403", str(ctx.exception))

        # Gateway secrets in os.environ must NOT leak into child processes
        os.environ["GATEWAY_TOKEN"] = "SHOULD_NOT_LEAK_999"
        try:
            env_res = await asyncio.to_thread(
                client.exec_command, "env", cwd=self.tmpdir
            )
            self.assertNotIn("SHOULD_NOT_LEAK_999", env_res["stdout"])
        finally:
            os.environ.pop("GATEWAY_TOKEN", None)

    async def test_quote_aware_shell_and_workspace_scripts(self) -> None:
        client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )

        # 1. Semicolons and pipes INSIDE quotes must NOT be falsely rejected
        res_py = await asyncio.to_thread(
            client.exec_command,
            'python3 -c "import sys; x = \'a|b;c\'; print(x.upper())"',
            cwd=self.tmpdir,
        )
        self.assertEqual(res_py["returncode"], 0)
        self.assertIn("A|B;C", res_py["stdout"])

        # 2. Compound shell command with `cd`, `&&`, and `|` works automatically
        sub = Path(self.tmpdir) / "subproj"
        sub.mkdir()
        res_chain = await asyncio.to_thread(
            client.exec_command,
            f"cd {sub} && pwd | tee out.txt",
            cwd=self.tmpdir,
        )
        self.assertEqual(res_chain["returncode"], 0)
        self.assertIn("subproj", res_chain["stdout"])

        # 3. Workspace-local executable script (`./build.sh`) is allowed
        script = sub / "build.sh"
        script.write_text("#!/usr/bin/env bash\necho LOCAL_BUILD_OK\n", encoding="utf-8")
        script.chmod(0o755)
        res_script = await asyncio.to_thread(
            client.exec_command, "./build.sh", cwd=str(sub)
        )
        self.assertEqual(res_script["returncode"], 0)
        self.assertIn("LOCAL_BUILD_OK", res_script["stdout"])

    async def test_multiline_heredoc_comments_and_security_invariants(self) -> None:
        from gateway.policy import redact_for_audit_log

        client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )

        # 1. Multi-line Python heredoc (`<<'PY'`) with `import`, apostrophe comments, and MCP `exec_command`
        heredoc_py = (
            "python3 - <<'PY'\n"
            "import json\n"
            "import pathlib\n"
            "# It's a multi-line script; don't split `import` as a shell command )\n"
            "print(json.dumps({'heredoc_ok': True, 'cwd_exists': pathlib.Path('.').is_dir()}))\n"
            "PY"
        )
        mcp_resp, _ = await asyncio.to_thread(
            client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "hd-1",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {"command": heredoc_py, "cwd": self.tmpdir},
                },
            },
        )
        self.assertFalse(mcp_resp["result"]["isError"], mcp_resp)
        hd_out = json.loads(mcp_resp["result"]["structuredContent"]["stdout"].strip())
        self.assertEqual(hd_out, {"heredoc_ok": True, "cwd_exists": True})

        # 2. Chained heredoc + `$(...)` heredoc capture + `#` comments + `\\\n` continuation + `$'...'` + `if`/`for`
        complex_script = (
            "set -euo pipefail\n"
            "# Leading comment with apostrophe: don't fail\n"
            "python3 \\\n"
            "  -c \\\n"
            "  $'import sys\\nx = \\'CONT_ANSI_OK\\'\\nprint(x)'\n"
            "CAP=$(python3 - <<-'PY'\n"
            "\timport json\n"
            "\t# Unmatched paren & quote in heredoc inside $(...): don't )\n"
            "\tprint(json.dumps({'cap': 99}))\n"
            "\tPY\n"
            ")\n"
            "echo \"CAP=$CAP\"\n"
            "for tag in alpha beta; do\n"
            "  if [ \"$tag\" = \"beta\" ]; then\n"
            "    python3 - <<'PY' && echo \"LOOP_DONE\"\n"
            "import os\n"
            "print('TAG_BETA_OK')\n"
            "PY\n"
            "  fi\n"
            "done\n"
        )
        res_complex = await asyncio.to_thread(
            client.exec_command, complex_script, cwd=self.tmpdir
        )
        self.assertEqual(res_complex["returncode"], 0, res_complex["stderr"])
        self.assertIn("CONT_ANSI_OK", res_complex["stdout"])
        self.assertIn('CAP={"cap": 99}', res_complex["stdout"])
        self.assertIn("TAG_BETA_OK", res_complex["stdout"])
        self.assertIn("LOOP_DONE", res_complex["stdout"])

        # 3. Security invariants: escapes via unquoted heredoc `$(...)`, `bash <<'EOF'`, `bash -lc`,
        #    `env`, glued redirections, or `for` over protected paths MUST still be blocked (403)
        for blocked_multiline in [
            "python3 - <<PY\n'$(sudo id)'\nPY",
            "python3 - <<PY\n`sudo id`\nPY",
            "bash <<'EOF'\nsudo whoami\nEOF",
            "sh -s <<'EOF'\nrm -rf /\nEOF",
            "bash -lc 'sudo whoami'",
            "env FOO=1 sudo whoami",
            "env -C /etc ls",
            f"cat >{GATEWAY_ROOT / 'config.json'}",
            "for f in ~/.ssh/id_rsa; do cat \"$f\"; done",
        ]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(
                    client.exec_command, blocked_multiline, cwd=self.tmpdir
                )
            self.assertIn("403", str(ctx.exception), f"Expected 403 for {blocked_multiline!r}")

        # 4. Audit log redaction & MCP rejection warning verification
        redacted = redact_for_audit_log(
            "curl -H 'Authorization: Bearer sk-secret1234567890abcdef' token=my_tok_999\nnext"
        )
        self.assertNotIn("sk-secret1234567890abcdef", redacted)
        self.assertNotIn("my_tok_999", redacted)
        self.assertNotIn("\n", redacted)

        with self.assertLogs("dots_gateway", level="WARNING") as log_cm:
            rej_resp, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "rej-1",
                    "method": "tools/call",
                    "params": {
                        "name": "exec_command",
                        "arguments": {
                            "command": "not_allowed_cmd --api-key=sk-1234567890abcdef",
                            "cwd": self.tmpdir,
                        },
                    },
                },
            )
        self.assertTrue(rej_resp["result"]["isError"])
        joined_logs = "\n".join(log_cm.output)
        self.assertIn("MCP policy rejection: tool=exec_command", joined_logs)
        self.assertNotIn("sk-1234567890abcdef", joined_logs)

    async def test_large_stream_json_over_64kb_and_chunked_http(self) -> None:
        client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )

        # 1. Verify >64KB single-line NDJSON in stream_json mode does NOT trigger LimitOverrunError
        sess_info = await asyncio.to_thread(
            client.create_session,
            command=[
                "python3",
                "-c",
                "import json; print(json.dumps({'event': 'big', 'payload': 'X' * 150000}), flush=True)",
            ],
            cwd=self.tmpdir,
            stream_json=True,
            close_stdin=True,
        )
        sid = sess_info["session_id"]

        def _read_events() -> list[dict]:
            return list(client.stream_session_events(sid, after_seq=0))

        events = await asyncio.to_thread(_read_events)
        agy_events = [e for e in events if e.get("type") == "agy_event"]
        self.assertEqual(len(agy_events), 1)
        self.assertEqual(len(agy_events[0]["data"]["payload"]), 150000)

        # 2. Verify HTTP/1.1 Transfer-Encoding: chunked + Expect: 100-continue
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        body_bytes = json.dumps({"command": ["echo", "chunked_ok"]}).encode("utf-8")
        chunk_frame = f"{len(body_bytes):x}\r\n".encode("ascii") + body_bytes + b"\r\n0\r\n\r\n"
        req_hdr = (
            "POST /v1/exec HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Authorization: Bearer test-secret-token-12345\r\n"
            "Content-Type: application/json\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Expect: 100-continue\r\n"
            "\r\n"
        ).encode("ascii")
        writer.write(req_hdr)
        await writer.drain()
        cont_line = await reader.readline()
        self.assertIn(b"100 Continue", cont_line)
        await reader.readline()  # blank line after 100 Continue
        writer.write(chunk_frame)
        await writer.drain()
        raw_resp = await reader.read(65536)
        writer.close()
        await writer.wait_closed()
        self.assertIn(b"200 OK", raw_resp)
        self.assertIn(b"chunked_ok", raw_resp)

    async def test_files_api_and_symlink_escape_protection(self) -> None:
        client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )
        src_file = f"{self.tmpdir}/app/hello.py"

        # Write & read text file
        w_res = await asyncio.to_thread(
            client.write_file, src_file, "def greet():\n    return 'hi'\n"
        )
        self.assertTrue(w_res["ok"])

        # Patch file
        p_res = await asyncio.to_thread(
            client.patch_file,
            src_file,
            [{"target": "return 'hi'", "replacement": "return 'hello_world'"}],
        )
        self.assertEqual(p_res["replacements_applied"], 1)

        r_res = await asyncio.to_thread(client.read_file, src_file)
        self.assertIn("hello_world", r_res["content"])

        # Binary write & read
        bin_path = f"{self.tmpdir}/app/blob.bin"
        raw_blob = bytes(range(256)) * 4
        await asyncio.to_thread(client.write_bytes, bin_path, raw_blob)
        fetched_blob = await asyncio.to_thread(client.read_bytes, bin_path)
        self.assertEqual(fetched_blob, raw_blob)

        # List directory
        ls_res = await asyncio.to_thread(client.list_dir, f"{self.tmpdir}/app")
        names = [e["name"] for e in ls_res["entries"]]
        self.assertIn("hello.py", names)
        self.assertIn("blob.bin", names)

        # Symlink escape outside allowed_workdirs MUST fail with 403
        escape_link = Path(self.tmpdir) / "passwd_link"
        escape_link.symlink_to("/etc/passwd")
        with self.assertRaises(RuntimeError) as esc_ctx:
            await asyncio.to_thread(client.read_file, str(escape_link))
        self.assertIn("403", str(esc_ctx.exception))

        # Reading gateway config.json via /v1/files/read MUST fail with 403
        with self.assertRaises(RuntimeError) as cfg_ctx:
            await asyncio.to_thread(
                client.read_file, str(GATEWAY_ROOT / "config.json")
            )
        self.assertIn("403", str(cfg_ctx.exception))

    async def test_agy_and_websocket_bidirectional_session(self) -> None:
        client = DotsGatewayClient(
            base_url=self.base_url, hmac_secret="super-hmac-secret-key-abcdef"
        )
        agy_res = await asyncio.to_thread(
            client.run_agy, prompt=None, args=["--help"], skip_permissions=True
        )
        self.assertEqual(agy_res["returncode"], 0)
        self.assertIn("--dangerously-skip-permissions", agy_res["argv"])
        self.assertTrue(any(a.startswith("--settings=") for a in agy_res["argv"]))
        if self.cfg.isolate_mount_namespace:
            self.assertNotIn("--sandbox", agy_res["argv"])
        else:
            self.assertIn("--sandbox", agy_res["argv"])

        codex_res = await asyncio.to_thread(
            client.run_codex, prompt=None, args=["--help"], skip_permissions=True
        )
        self.assertEqual(codex_res["returncode"], 0)
        self.assertIn("-a", codex_res["argv"])
        self.assertIn("never", codex_res["argv"])
        self.assertIn("-s", codex_res["argv"])
        self.assertIn("workspace-write", codex_res["argv"])
        self.assertIn("exec", codex_res["argv"])

        async with client.connect_websocket() as ws:
            self.assertEqual(ws.welcome.get("type"), "connected")
            await ws.send_json(
                {
                    "id": "ws-file-1",
                    "action": "file.write",
                    "path": f"{self.tmpdir}/ws_note.txt",
                    "content": "ws_hello",
                }
            )
            f_ack = await ws.recv_json()
            assert f_ack is not None
            self.assertTrue(f_ack["ok"])

            await ws.send_json(
                {
                    "id": "repl-1",
                    "action": "exec",
                    "command": [
                        "python3",
                        "-u",
                        "-c",
                        (
                            "import sys\n"
                            "for line in sys.stdin:\n"
                            "    val = line.strip()\n"
                            "    print(f'ECHO:{val.upper()}', flush=True)\n"
                            "    if val == 'quit': break\n"
                        ),
                    ],
                    "interactive": True,
                }
            )
            created = await ws.recv_json()
            assert created is not None
            session_id = created["session_id"]

            await ws.send_json(
                {
                    "id": "in-1",
                    "action": "session.input",
                    "session_id": session_id,
                    "data": "quit\n",
                    "close_stdin": True,
                }
            )

            collected_stdout = ""
            exit_code = None
            while exit_code is None:
                msg = await asyncio.wait_for(ws.recv_json(), timeout=5.0)
                assert msg is not None
                if msg.get("type") == "session.event":
                    ev = msg["event"]
                    if ev["type"] == "stdout":
                        collected_stdout += ev["data"]
                    elif ev["type"] == "exit":
                        exit_code = ev["data"]["returncode"]

            self.assertIn("ECHO:QUIT", collected_stdout)
            self.assertEqual(exit_code, 0)

    async def test_workspace_jail_add_dirs_and_mount_namespace_isolation(self) -> None:
        # 1. Verify hardened defaults confine gateway strictly to ~/workspaces
        default_cfg = GatewayConfig()
        self.assertEqual(default_cfg.default_workdir, DEFAULT_WORKSPACE_DIR)
        self.assertEqual(default_cfg.allowed_workdirs, [DEFAULT_WORKSPACE_DIR])
        self.assertTrue(default_cfg.isolate_mount_namespace)
        self.assertTrue(default_cfg.agy_default_sandbox)
        self.assertTrue(default_cfg.agy_sandbox_network_access)
        self.assertTrue(default_cfg.agy_include_allowed_workdirs)
        self.assertEqual(default_cfg.agy_sandbox_tool_permission, "proceed-in-sandbox")
        self.assertIn(str(GATEWAY_ROOT), default_cfg.protected_paths)

        bad_perm_cfg = GatewayConfig(
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            agy_sandbox_tool_permission="always-proceed",
        )
        with self.assertRaises(PermissionError):
            CommandPolicy(bad_perm_cfg).build_agy_sandbox_settings(cwd=self.tmpdir)

        client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )

        # 2. Validate add_dirs and raw args bypass blocking in run_agy
        for bad_add_dir in [HOME_DIR, "/tmp", "/etc", str(GATEWAY_ROOT)]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(
                    client.run_agy,
                    prompt=None,
                    args=["--help"],
                    add_dirs=[bad_add_dir],
                )
            self.assertIn("403", str(ctx.exception))

        for bad_raw_arg in [
            f"--add-dir={HOME_DIR}",
            "--no-sandbox",
            "--sandbox=false",
            "--settings={}",
            "--remote-control",
        ]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(
                    client.run_agy,
                    prompt=None,
                    args=[bad_raw_arg, "--help"],
                )
            self.assertIn("403", str(ctx.exception))

        extra_ws = Path(self.tmpdir) / "extra_ws"
        extra_ws.mkdir()
        extra_ro_sdk = Path(self.tmpdir) / "extra_ro_sdk"
        extra_ro_sdk.mkdir()
        ro_cfg = GatewayConfig(
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            agy_extra_readonly_roots=[str(extra_ro_sdk), str(GATEWAY_ROOT)],
        )
        ro_pol = CommandPolicy(ro_cfg)
        ro_roots = ro_pol.get_agy_readonly_roots()
        self.assertIn(str(extra_ro_sdk.resolve()), ro_roots)
        self.assertNotIn(str(GATEWAY_ROOT), ro_roots)
        ro_settings = ro_pol.build_agy_sandbox_settings(cwd=self.tmpdir)
        self.assertIn(
            f"read_file({extra_ro_sdk.resolve()})",
            ro_settings["permissions"]["allow"],
        )
        self.assertNotIn(
            f"read_file({GATEWAY_ROOT})",
            ro_settings["permissions"]["allow"],
        )

        ok_agy = await asyncio.to_thread(
            client.run_agy,
            prompt=None,
            args=["--help"],
            add_dirs=[str(extra_ws)],
        )
        self.assertEqual(ok_agy["returncode"], 0)
        self.assertIn(str(extra_ws.resolve()), ok_agy["argv"])

        # 2b. Validate run_codex sandbox & workspace boundary enforcement
        for bad_add_dir in [HOME_DIR, "/tmp", "/etc", str(GATEWAY_ROOT)]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(
                    client.run_codex,
                    prompt=None,
                    args=["--help"],
                    add_dirs=[bad_add_dir],
                )
            self.assertIn("403", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            await asyncio.to_thread(
                client.run_codex,
                prompt=None,
                args=["--help"],
                sandbox_mode="danger-full-access",
            )
        self.assertIn("403", str(ctx.exception))

        for bad_codex_arg in [
            "--dangerously-bypass-approvals-and-sandbox",
            "--dangerously-bypass-hook-trust",
            "--approve-for-me",
            "-P=:danger-full-access",
            "--permission-profile=:danger-full-access",
            f"--add-dir={HOME_DIR}",
            "-s=danger-full-access",
            "--config=sandbox_mode=danger-full-access",
            "--config=default_permissions=:danger-full-access",
        ]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(
                    client.run_codex,
                    prompt=None,
                    args=[bad_codex_arg, "--help"],
                )
            self.assertIn("403", str(ctx.exception))

        # 2c. Validate Codex Git worktree metadata resolution & malicious `.git` escape rejection
        import subprocess as _sp

        wt_main = Path(self.tmpdir) / "git_main_repo"
        wt_linked = Path(self.tmpdir) / "git_linked_wt"
        wt_subdir = wt_linked / "packages" / "core"
        _sp.run(["git", "init", "-q", str(wt_main)], check=True)
        _sp.run(["git", "-C", str(wt_main), "config", "user.email", "t@example.com"], check=True)
        _sp.run(["git", "-C", str(wt_main), "config", "user.name", "Test"], check=True)
        (wt_main / "README.md").write_text("init\n", encoding="utf-8")
        _sp.run(["git", "-C", str(wt_main), "add", "README.md"], check=True)
        _sp.run(["git", "-C", str(wt_main), "commit", "-qm", "init"], check=True)
        _sp.run(
            ["git", "-C", str(wt_main), "worktree", "add", "-q", "-b", "feat/wt", str(wt_linked)],
            check=True,
        )
        wt_subdir.mkdir(parents=True, exist_ok=True)

        wt_pol = CommandPolicy(self.cfg)
        git_rw, git_ro_hooks = wt_pol.resolve_codex_git_metadata_dirs(cwd=str(wt_subdir))
        expected_common = str((wt_main / ".git").resolve())
        expected_wt_gd = str((wt_main / ".git" / "worktrees" / "git_linked_wt").resolve())
        expected_hooks = str((wt_main / ".git" / "hooks").resolve())
        self.assertIn(expected_common, git_rw)
        self.assertIn(expected_wt_gd, git_rw)
        self.assertLess(git_rw.index(expected_common), git_rw.index(expected_wt_gd))
        self.assertIn(expected_hooks, git_ro_hooks)

        codex_wr = wt_pol.get_codex_writable_roots(cwd=str(wt_subdir))
        self.assertIn(expected_common, codex_wr)
        self.assertIn(expected_wt_gd, codex_wr)

        # Verify agy --add-dir workspace approval covers allowed_workdirs (sibling evidence dirs) & git metadata
        sibling_evidence = Path(self.tmpdir) / "stripe-topup-session-evidence"
        agy_ws_dirs = wt_pol.get_agy_workspace_dirs(cwd=str(wt_subdir))
        self.assertIn(str(Path(self.tmpdir).resolve()), agy_ws_dirs)
        self.assertIn(expected_common, agy_ws_dirs)
        self.assertIn(expected_wt_gd, agy_ws_dirs)
        self.assertNotIn(str(wt_subdir.resolve()), agy_ws_dirs)
        self.assertEqual(wt_pol.get_agy_workspace_dirs(cwd=self.tmpdir), [])

        narrow_agy_cfg = GatewayConfig(
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            agy_include_allowed_workdirs=False,
            agy_extra_workspace_dirs=[str(sibling_evidence), str(GATEWAY_ROOT)],
        )
        narrow_agy_pol = CommandPolicy(narrow_agy_cfg)
        narrow_ws_dirs = narrow_agy_pol.get_agy_workspace_dirs(cwd=str(wt_subdir))
        self.assertIn(str(sibling_evidence.resolve()), narrow_ws_dirs)
        self.assertNotIn(str(Path(self.tmpdir).resolve()), narrow_ws_dirs)
        self.assertNotIn(str(GATEWAY_ROOT), narrow_ws_dirs)

        # Malicious `.git` pointer targeting outside `allowed_workdirs` MUST be ignored
        evil_wt = Path(self.tmpdir) / "evil_gitdir_escape"
        evil_wt.mkdir()
        (evil_wt / ".git").write_text(f"gitdir: {GATEWAY_ROOT}\n", encoding="utf-8")
        evil_rw, evil_ro = wt_pol.resolve_codex_git_metadata_dirs(cwd=str(evil_wt))
        self.assertEqual(evil_rw, [])
        self.assertEqual(evil_ro, [])

        ok_codex = await asyncio.to_thread(
            client.run_codex,
            prompt=None,
            args=["--help"],
            sandbox_mode="read-only",
            effort="high",
            add_dirs=[str(extra_ws)],
        )
        self.assertEqual(ok_codex["returncode"], 0)
        self.assertIn("read-only", ok_codex["argv"])
        self.assertIn(str(extra_ws.resolve()), ok_codex["argv"])

        # 3. CLI path arguments escaping allowed_workdirs or hitting gateway source are rejected (403)
        for escape_cmd in [
            f"cat {GATEWAY_ROOT / 'main.py'}",
            "ls ~",
            "ls /home",
            "ls ..",
            "cat ~/.bashrc",
        ]:
            with self.assertRaises(RuntimeError) as ctx:
                await asyncio.to_thread(client.exec_command, escape_cmd, cwd=self.tmpdir)
            self.assertIn("403", str(ctx.exception), f"Expected 403 for {escape_cmd}")

        # 4. Kernel mount-namespace VFS jail hides ~/gateway, ~/.ssh, ~/.gemini, ~/.config/dots-gateway
        #    while preserving ~/.config/gh and persistent sandbox ~/.cache across separate commands
        if self.cfg.isolate_mount_namespace:
            probe_code = (
                "import json, os\n"
                "cap_eff = ''\n"
                "for line in open('/proc/self/status'):\n"
                "    if line.startswith('CapEff:'):\n"
                "        cap_eff = line.split()[1]\n"
                f"gw_exists = os.path.exists({str(GATEWAY_ROOT)!r})\n"
                "ssh_exists = os.path.exists(os.path.expanduser('~/.ssh'))\n"
                "gem_exists = os.path.exists(os.path.expanduser('~/.gemini'))\n"
                "cdx_exists = os.path.exists(os.path.expanduser('~/.codex'))\n"
                "cfg_exists = os.path.exists(os.path.expanduser('~/.config/dots-gateway'))\n"
                "gh_exists = os.path.isdir(os.path.expanduser('~/.config/gh'))\n"
                f"ws_exists = os.path.isdir({self.tmpdir!r})\n"
                "marker = os.path.expanduser('~/.cache/_unit_persist_probe')\n"
                "open(marker, 'w').write('ok123')\n"
                "print(json.dumps({'cap_eff': cap_eff, 'gw': gw_exists, 'ssh': ssh_exists, "
                "'gem': gem_exists, 'cdx': cdx_exists, 'cfg': cfg_exists, 'gh': gh_exists, 'ws': ws_exists}))\n"
            )
            ns_res = await asyncio.to_thread(
                client.exec_command, ["python3", "-c", probe_code], cwd=self.tmpdir
            )
            self.assertEqual(ns_res["returncode"], 0, ns_res["stderr"])
            info = json.loads(ns_res["stdout"].strip())
            self.assertEqual(info["cap_eff"], "0000000000000000")
            self.assertFalse(info["gw"])
            self.assertFalse(info["ssh"])
            self.assertFalse(info["gem"])
            self.assertFalse(info["cdx"])
            self.assertFalse(info["cfg"])
            self.assertTrue(info["gh"])
            self.assertTrue(info["ws"])

            # Second separate command verifies sandbox ~/.cache persisted across VFS invocations
            ns_res2 = await asyncio.to_thread(
                client.exec_command,
                [
                    "python3",
                    "-c",
                    "import os; m=os.path.expanduser('~/.cache/_unit_persist_probe'); print(open(m).read()); os.remove(m)",
                ],
                cwd=self.tmpdir,
            )
            self.assertEqual(ns_res2["returncode"], 0, ns_res2["stderr"])
            self.assertEqual(ns_res2["stdout"].strip(), "ok123")
        else:
            from unittest.mock import patch

            with patch("gateway.sandbox.can_use_mount_namespace", return_value=True):
                vfs_argv = build_mount_ns_argv(
                    ["python3", "-c", "pass"],
                    cwd=self.tmpdir,
                    allowed_workdirs=[self.tmpdir],
                    protected_paths=self.cfg.protected_paths,
                    sandbox_state_dir=os.path.join(self.tmpdir, "sb_check"),
                )
                vfs_script = vfs_argv[vfs_argv.index("-c") + 1]
                self.assertIn("--bounding-set=-all", vfs_script)
                self.assertIn(".config/gh", vfs_script)

    async def test_fullchain_fingerprint_and_tls_hot_reload(self) -> None:
        import time
        from gateway.tls import compute_cert_sha256

        pki_dir1 = Path(self.tmpdir) / "pki_1"
        pki_dir2 = Path(self.tmpdir) / "pki_2"
        pki1 = ensure_tls_pki(pki_dir1, extra_hosts=["127.0.0.1"])
        pki2 = ensure_tls_pki(pki_dir2, extra_hosts=["127.0.0.1"])
        self.assertNotEqual(pki1["server_fingerprint_sha256"], pki2["server_fingerprint_sha256"])

        live_dir = Path(self.tmpdir) / "live_cert"
        live_dir.mkdir(parents=True, exist_ok=True)
        fullchain = live_dir / "fullchain.pem"
        privkey = live_dir / "privkey.pem"

        # Multi-PEM bundle (leaf + CA cert), matching Let's Encrypt fullchain.pem layout
        fullchain.write_text(
            Path(pki1["server_cert"]).read_text(encoding="utf-8")
            + "\n"
            + Path(pki1["ca_cert"]).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        privkey.write_text(Path(pki1["server_key"]).read_text(encoding="utf-8"), encoding="utf-8")
        self.assertEqual(compute_cert_sha256(fullchain), pki1["server_fingerprint_sha256"])

        rot_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["rot-tok"],
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            tls_certfile=str(fullchain),
            tls_keyfile=str(privkey),
        )
        rot_srv = GatewayServer(rot_cfg)
        h, p = await rot_srv.start()
        try:
            c1 = DotsGatewayClient(
                base_url=f"https://{h}:{p}",
                token="rot-tok",
                tls_fingerprint=pki1["server_fingerprint_sha256"],
            )
            r1 = await asyncio.to_thread(c1.health)
            self.assertTrue(r1["ok"])

            # Rotate cert & key on disk without restarting GatewayServer
            fullchain.write_text(
                Path(pki2["server_cert"]).read_text(encoding="utf-8")
                + "\n"
                + Path(pki2["ca_cert"]).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            privkey.write_text(
                Path(pki2["server_key"]).read_text(encoding="utf-8"), encoding="utf-8"
            )
            os.utime(fullchain, (time.time() + 5, time.time() + 5))
            os.utime(privkey, (time.time() + 5, time.time() + 5))

            c2 = DotsGatewayClient(
                base_url=f"https://{h}:{p}",
                token="rot-tok",
                tls_fingerprint=pki2["server_fingerprint_sha256"],
            )
            r2 = await asyncio.to_thread(c2.health)
            self.assertTrue(r2["ok"])
        finally:
            await rot_srv.stop()

    async def test_bwrap_descendant_containment_and_systemd_run_blocked(self) -> None:
        client = DotsGatewayClient(
            base_url=self.base_url, token="test-secret-token-12345"
        )
        # 1. Host systemd escape vector (`systemd-run`) must remain blocked
        sr_dec = self.server.policy.validate_command(["systemd-run", "--version"], cwd=self.tmpdir)
        self.assertFalse(sr_dec.allowed)

        # 2. `bwrap` wrapper flags are strictly validated and inner command is recursively checked
        self.assertTrue(
            self.server.policy.validate_command(["bwrap", "--version"], cwd=self.tmpdir).allowed
        )
        self.assertFalse(
            self.server.policy.validate_command(
                ["bwrap", "--ro-bind", "/", "/", "--", "sudo", "id"], cwd=self.tmpdir
            ).allowed
        )
        self.assertFalse(
            self.server.policy.validate_command(
                ["bwrap", "--args", "3", "--", "echo", "hi"], cwd=self.tmpdir
            ).allowed
        )
        self.assertFalse(
            self.server.policy.validate_command(
                ["bwrap", "--cap-add", "ALL", "--", "echo", "hi"], cwd=self.tmpdir
            ).allowed
        )
        self.assertFalse(
            self.server.policy.validate_command(
                ["bwrap", "--unknown-flag", "x", "--", "echo", "hi"], cwd=self.tmpdir
            ).allowed
        )
        self.assertFalse(
            self.server.policy.validate_command(
                ["bwrap", "--ro-bind", os.path.expanduser("~/.ssh"), "/mnt", "--", "ls", "/mnt"],
                cwd=self.tmpdir,
            ).allowed
        )

        # 3. `nl` utility is allowlisted
        nl_res = await asyncio.to_thread(
            client.exec_command,
            "printf 'alpha\\nbeta\\n' | nl -ba",
            self.tmpdir,
        )
        self.assertTrue(nl_res["ok"], nl_res)
        self.assertIn("alpha", nl_res["stdout"])

        # 4. If `bwrap` is installed on host, verify `--unshare-pid --die-with-parent` kills detached
        #    grandchild processes immediately upon leader exit and `/run/user/$UID/systemd` is masked
        if os.path.exists(self.cfg.bwrap_binary) or shutil.which("bwrap"):
            ver_res = await asyncio.to_thread(
                client.exec_command, ["bwrap", "--version"], self.tmpdir
            )
            self.assertTrue(ver_res["ok"], ver_res)

            escaped_marker = Path(self.tmpdir) / "detached_grandchild_escaped.txt"
            py_leader = (
                "import os, pathlib, subprocess, sys\n"
                f"marker = {str(escaped_marker)!r}\n"
                "uid_systemd = f'/run/user/{os.getuid()}/systemd'\n"
                "print('SYSTEMD_BUS_VISIBLE=' + str(os.path.exists(uid_systemd)))\n"
                "subprocess.Popen(\n"
                "    [sys.executable, '-c', f'import time, pathlib; time.sleep(0.35); pathlib.Path({marker!r}).write_text(\"escaped\")'],\n"
                "    start_new_session=True,\n"
                ")\n"
                "print('LEADER_EXITED_CLEANLY')\n"
            )
            bw_cmd = [
                "bwrap",
                "--dev-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--die-with-parent",
                "--unshare-pid",
                "--new-session",
                "--chdir",
                self.tmpdir,
                "--",
                "python3",
                "-c",
                py_leader,
            ]
            bw_res = await asyncio.to_thread(client.exec_command, bw_cmd, self.tmpdir)
            self.assertTrue(bw_res["ok"], bw_res)
            self.assertIn("LEADER_EXITED_CLEANLY", bw_res["stdout"])
            if self.cfg.isolate_mount_namespace:
                self.assertIn("SYSTEMD_BUS_VISIBLE=False", bw_res["stdout"])
            await asyncio.sleep(0.55)
            self.assertFalse(
                escaped_marker.exists(),
                "Detached grandchild inside bwrap --unshare-pid --die-with-parent must be killed when leader exits",
            )

    async def test_legacy_config_set_backfill_and_shell_set_security(self) -> None:
        legacy_cfg_path = Path(self.tmpdir) / "legacy_config.json"
        legacy_cfg_path.write_text(
            json.dumps(
                {
                    "host": "127.0.0.1",
                    "port": 0,
                    "api_tokens": ["legacy-tok"],
                    "allowed_workdirs": [self.tmpdir],
                    "default_workdir": self.tmpdir,
                    "allowed_commands": ["bash", "sh", "python3", "git", "echo"],
                    "blocked_commands": ["sudo", "docker"],
                }
            ),
            encoding="utf-8",
        )
        loaded_cfg = GatewayConfig.load(legacy_cfg_path)
        self.assertIn("set", loaded_cfg.allowed_commands)
        for sh_b in ("exit", "return", ":", "trap", "command", "type"):
            self.assertIn(sh_b, loaded_cfg.allowed_commands)
        self.assertIn("systemd-run", loaded_cfg.blocked_commands)

        # Minimal non-shell custom allowlist must NOT be bloated with shell builtins
        minimal_cfg_path = Path(self.tmpdir) / "minimal_config.json"
        minimal_cfg_path.write_text(
            json.dumps(
                {
                    "allowed_commands": ["python3"],
                    "blocked_commands": ["sudo"],
                }
            ),
            encoding="utf-8",
        )
        minimal_cfg = GatewayConfig.load(minimal_cfg_path)
        self.assertNotIn("set", minimal_cfg.allowed_commands)
        self.assertNotIn("exit", minimal_cfg.allowed_commands)
        self.assertNotIn("trap", minimal_cfg.allowed_commands)
        self.assertNotIn("command", minimal_cfg.allowed_commands)
        self.assertIn("systemd-run", minimal_cfg.blocked_commands)

        # Operator explicit block of 'set' must be respected
        blocked_set_path = Path(self.tmpdir) / "blocked_set_config.json"
        blocked_set_path.write_text(
            json.dumps(
                {
                    "allowed_commands": ["bash", "python3"],
                    "blocked_commands": ["sudo", "set"],
                }
            ),
            encoding="utf-8",
        )
        blocked_set_cfg = GatewayConfig.load(blocked_set_path)
        self.assertNotIn("set", blocked_set_cfg.allowed_commands)

        if not can_use_mount_namespace():
            loaded_cfg.isolate_mount_namespace = False
        legacy_srv = GatewayServer(loaded_cfg)
        h, p = await legacy_srv.start()
        try:
            client = DotsGatewayClient(base_url=f"http://{h}:{p}", token="legacy-tok")
            manifest_script = (
                "set -e\n"
                "python3 - <<'PY'\n"
                "import hashlib, json\n"
                "payload = b'super-ai-manifest-ok'\n"
                "print(json.dumps({'ok': True, 'sha256': hashlib.sha256(payload).hexdigest()[:12]}))\n"
                "PY\n"
            )
            res_ok = await asyncio.to_thread(
                client.exec_command, manifest_script, cwd=self.tmpdir
            )
            self.assertEqual(res_ok["returncode"], 0, res_ok["stderr"])
            self.assertTrue(json.loads(res_ok["stdout"].strip())["ok"])

            res_pos = await asyncio.to_thread(
                client.exec_command,
                'set -- alpha beta && echo "$1:$2"',
                cwd=self.tmpdir,
            )
            self.assertEqual(res_pos["returncode"], 0, res_pos["stderr"])
            self.assertEqual(res_pos["stdout"].strip(), "alpha:beta")

            for bad_set_cmd in [
                f"set -- {GATEWAY_ROOT / 'config.json'}",
                "set -- ../outside_workspace",
                'set -- sudo; "$1" id',
            ]:
                with self.assertRaises(RuntimeError) as ctx:
                    await asyncio.to_thread(
                        client.exec_command, bad_set_cmd, cwd=self.tmpdir
                    )
                self.assertIn("403", str(ctx.exception), f"Expected 403 for {bad_set_cmd!r}")
        finally:
            await legacy_srv.stop()

    async def test_custom_sandbox_store_and_lru_lifecycle_retention(self) -> None:
        from gateway.sandbox import SANDBOX_SUBDIRS, cleanup_sandbox_state

        sb_root = Path(tempfile.mkdtemp(prefix="dots_sb_store_"))
        ws_parent = "/var/tmp" if os.access("/var/tmp", os.W_OK) else str(Path.home())
        ws_dir = Path(tempfile.mkdtemp(prefix="dots_sb_ws_", dir=ws_parent))
        try:
            sb_cfg = GatewayConfig(
                host="127.0.0.1",
                port=0,
                api_tokens=["sb-tok"],
                allowed_workdirs=[str(ws_dir)],
                default_workdir=str(ws_dir),
                isolate_mount_namespace=can_use_mount_namespace(),
                sandbox_state_dir=str(sb_root),
                sandbox_cleanup_enabled=False,
                sandbox_max_retention_days=30.0,
                sandbox_min_retention_days=7.0,
                sandbox_low_space_free_gb=8.0,
                sandbox_low_space_free_percent=15.0,
            )
            sb_srv = GatewayServer(sb_cfg)
            h, p = await sb_srv.start()
            try:
                client = DotsGatewayClient(base_url=f"http://{h}:{p}", token="sb-tok")
                pol = await asyncio.to_thread(client.policy)
                self.assertEqual(pol["sandbox_state_dir"], str(sb_root))
                self.assertEqual(pol["sandbox_lifecycle"]["max_retention_days"], 30.0)
                self.assertEqual(pol["sandbox_lifecycle"]["min_retention_days"], 7.0)

                if sb_cfg.isolate_mount_namespace:
                    probe_res = await asyncio.to_thread(
                        client.exec_command,
                        [
                            "python3",
                            "-c",
                            (
                                "import json, os, pathlib\n"
                                "pathlib.Path('/tmp/sb_tmp_probe.txt').write_text('tmp_on_data_disk')\n"
                                "pathlib.Path(os.path.expanduser('~/.cache/sb_cache_probe.txt')).write_text('cache_on_data_disk')\n"
                                "print(json.dumps({'tmpdir': os.environ.get('TMPDIR')}))\n"
                            ),
                        ],
                        cwd=str(ws_dir),
                    )
                    self.assertEqual(probe_res["returncode"], 0, probe_res["stderr"])
                    self.assertEqual(
                        json.loads(probe_res["stdout"].strip())["tmpdir"], "/tmp"
                    )
                    self.assertEqual(
                        (sb_root / "tmp" / "sb_tmp_probe.txt").read_text(encoding="utf-8"),
                        "tmp_on_data_disk",
                    )
                    self.assertEqual(
                        (sb_root / "cache" / "sb_cache_probe.txt").read_text(encoding="utf-8"),
                        "cache_on_data_disk",
                    )
            finally:
                await sb_srv.stop()

            # Reset sandbox store to test deterministic 2-tier LRU lifecycle rules
            shutil.rmtree(sb_root, ignore_errors=True)
            for sub in SANDBOX_SUBDIRS:
                (sb_root / sub).mkdir(parents=True, exist_ok=True)

            now_ts = 1_800_000_000.0
            mib = 1024 * 1024
            gib = 1024 ** 3

            def _make_entry(rel_path: str, age_days: float, size_bytes: int) -> Path:
                target = sb_root / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"X" * size_bytes)
                ts = now_ts - age_days * 86400.0
                os.utime(target, (ts, ts))
                os.utime(target.parent, (ts, ts))
                return target

            p_expired_35d = _make_entry("tmp/expired_35d/blob.bin", 35.0, 4 * mib)
            p_older_22d = _make_entry("tmp/older_22d/blob.bin", 22.0, 4 * mib)
            p_older_15d = _make_entry("cache/older_15d/blob.bin", 15.0, 4 * mib)
            p_pkg_10d = _make_entry(
                "pub_cache/hosted/pub.dev/pkg_10d-1.0.0/lib.dart", 10.0, 4 * mib
            )
            p_pkg_10d_hash = _make_entry(
                "pub_cache/hosted-hashes/pub.dev/pkg_10d-1.0.0.sha256", 10.0, 64
            )
            # Directory inode looks 25d old, but a child file inside was read/modified 2d ago (<7d!)
            p_nested_active = _make_entry("tmp/nested_recent_dir/active.txt", 2.0, 2 * mib)
            old_dir_ts = now_ts - 25.0 * 86400.0
            os.utime(p_nested_active.parent, (old_dir_ts, old_dir_ts))
            p_recent_5d = _make_entry("tmp/recent_5d/blob.bin", 5.0, 4 * mib)
            p_recent_1d = _make_entry("cache/recent_1d/blob.bin", 1.0, 4 * mib)

            def _dir_bytes(root_p: Path) -> int:
                tot = 0
                for dirpath, _, filenames in os.walk(root_p, followlinks=False):
                    for fn in filenames:
                        try:
                            tot += os.lstat(os.path.join(dirpath, fn)).st_size
                        except OSError:
                            pass
                return tot

            # Phase A: Plenty of free space (30 GiB / 50 GiB) -> keep <=30d, delete >30d only
            res_plenty = cleanup_sandbox_state(
                sb_root,
                max_retention_days=30.0,
                min_retention_days=7.0,
                low_space_free_gb=8.0,
                low_space_free_percent=15.0,
                now=now_ts,
                disk_usage_fn=lambda _: (50 * gib, 30 * gib),
            )
            self.assertEqual(res_plenty["deleted_expired_count"], 1)
            self.assertEqual(res_plenty["deleted_low_space_count"], 0)
            self.assertFalse(p_expired_35d.parent.exists())
            self.assertTrue(p_older_22d.exists())
            self.assertTrue(p_older_15d.exists())
            self.assertTrue(p_pkg_10d.exists())
            self.assertTrue(p_nested_active.exists())
            self.assertTrue(p_recent_5d.exists())
            self.assertTrue(p_recent_1d.exists())

            # Phase B: Tight disk space (~5.5 MiB short of 8 GiB) -> evict oldest (22d, 15d) and keep newer 10d + <7d
            baseline_used = _dir_bytes(sb_root)
            start_avail_tight = 8 * gib - int(5.5 * mib)

            def _tight_usage(root_p: Path) -> tuple[int, int]:
                reclaimed_now = max(0, baseline_used - _dir_bytes(root_p))
                return (50 * gib, start_avail_tight + reclaimed_now)

            res_tight = cleanup_sandbox_state(
                sb_root,
                max_retention_days=30.0,
                min_retention_days=7.0,
                low_space_free_gb=8.0,
                low_space_free_percent=15.0,
                now=now_ts,
                disk_usage_fn=_tight_usage,
            )
            self.assertTrue(res_tight["low_space_before"])
            self.assertFalse(res_tight["low_space_after"])
            self.assertEqual(res_tight["deleted_low_space_count"], 2)
            self.assertFalse(p_older_22d.parent.exists())
            self.assertFalse(p_older_15d.parent.exists())
            # Newer 10d package was preserved because space recovered above 8 GiB!
            self.assertTrue(p_pkg_10d.exists())
            self.assertTrue(p_pkg_10d_hash.exists())
            self.assertTrue(p_nested_active.exists())
            self.assertTrue(p_recent_5d.exists())
            self.assertTrue(p_recent_1d.exists())

            # Phase C: Severe disk pressure (1 GiB free) -> evicts remaining >7d (10d + hash), NEVER deletes <=7d!
            res_severe = cleanup_sandbox_state(
                sb_root,
                max_retention_days=30.0,
                min_retention_days=7.0,
                low_space_free_gb=8.0,
                low_space_free_percent=15.0,
                now=now_ts,
                disk_usage_fn=lambda _: (50 * gib, 1 * gib),
            )
            self.assertEqual(res_severe["deleted_low_space_count"], 1)
            self.assertFalse(p_pkg_10d.parent.exists())
            self.assertFalse(p_pkg_10d_hash.exists())
            # All <=7d entries (including directory with 2d nested activity) MUST remain untouched
            self.assertTrue(p_nested_active.exists())
            self.assertTrue(p_recent_5d.exists())
            self.assertTrue(p_recent_1d.exists())
            for sub in SANDBOX_SUBDIRS:
                self.assertTrue((sb_root / sub).is_dir())

            # Phase D: Cooperative cancellation aborts scan/eviction immediately during shutdown
            p_cancel_40d = _make_entry("tmp/cancel_40d/blob.bin", 40.0, 2 * mib)
            import threading

            cancelled = threading.Event()
            cancelled.set()
            res_cancelled = cleanup_sandbox_state(
                sb_root,
                max_retention_days=30.0,
                min_retention_days=7.0,
                now=now_ts,
                disk_usage_fn=lambda _: (50 * gib, 1 * gib),
                cancel_event=cancelled,
            )
            self.assertTrue(res_cancelled.get("cancelled"))
            self.assertEqual(res_cancelled["deleted_expired_count"], 0)
            self.assertEqual(res_cancelled["deleted_low_space_count"], 0)
            self.assertTrue(p_cancel_40d.exists())
        finally:
            shutil.rmtree(sb_root, ignore_errors=True)
            shutil.rmtree(ws_dir, ignore_errors=True)

    async def test_hardening_regressions_timeouts_env_patch_broken_symlinks_and_http_guards(
        self,
    ) -> None:
        from gateway.executor import SessionManager, _extract_initial_agent_id

        client = DotsGatewayClient(base_url=self.base_url, token="test-secret-token-12345")

        # 1. Invalid / zero / negative / non-finite timeouts MUST fail with HTTP 400 (never infinite timeout)
        for bad_timeout in (0, -1, "NaN", "Infinity"):
            for path, payload in (
                ("/v1/exec", {"command": ["echo", "hi"], "cwd": self.tmpdir, "timeout": bad_timeout}),
                ("/v1/agy", {"prompt": "hi", "cwd": self.tmpdir, "timeout": bad_timeout}),
                ("/v1/codex", {"prompt": "hi", "cwd": self.tmpdir, "timeout": bad_timeout}),
                (
                    "/v1/sessions",
                    {
                        "type": "exec",
                        "command": ["echo", "hi"],
                        "cwd": self.tmpdir,
                        "timeout": bad_timeout,
                    },
                ),
            ):
                with self.assertRaises(RuntimeError) as err_ctx:
                    await asyncio.to_thread(client._request_json, "POST", path, payload)
                self.assertIn("400", str(err_ctx.exception))

        # 2. Failed spawn (nonexistent binary with isolate_mount_namespace=False) cleans up session slot
        missing_bin = os.path.join(self.tmpdir, "does_not_exist_bin")
        no_ns_cfg = GatewayConfig(
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            allowed_commands=[missing_bin],
            isolate_mount_namespace=False,
            max_concurrent_sessions=1,
            sandbox_cleanup_enabled=False,
        )
        mgr = SessionManager(no_ns_cfg, CommandPolicy(no_ns_cfg))
        with self.assertRaises(FileNotFoundError):
            await mgr.create_session(command=[missing_bin], cwd=self.tmpdir)
        self.assertEqual(mgr.active_count(), 0)
        self.assertEqual(mgr.list_sessions(), [])

        # 3. Caller `env` cannot override blocked security/cloud/dynamic-linker/gateway keys
        env_res = await asyncio.to_thread(
            client._request_json,
            "POST",
            "/v1/exec",
            {
                "command": [
                    "python3",
                    "-c",
                    (
                        "import json, os; print(json.dumps({"
                        "'ld': os.environ.get('LD_PRELOAD'),"
                        "'gce_host': os.environ.get('GCE_METADATA_HOST'),"
                        "'no_gce': os.environ.get('NO_GCE_CHECK'),"
                        "'adc': os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'),"
                        "'docker': os.environ.get('DOCKER_HOST'),"
                        "'gw_tok': os.environ.get('GATEWAY_TOKEN'),"
                        "'gw_sb': os.environ.get('GATEWAY_SANDBOX_STATE_DIR'),"
                        "'safe': os.environ.get('CUSTOM_CALLER_VAR')"
                        "}))"
                    ),
                ],
                "cwd": self.tmpdir,
                "env": {
                    "LD_PRELOAD": "/tmp/evil.so",
                    "GCE_METADATA_HOST": "evil.internal",
                    "NO_GCE_CHECK": "",
                    "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/fake_adc.json",
                    "DOCKER_HOST": "tcp://evil.example:2375",
                    "GATEWAY_TOKEN": "leaked",
                    "CUSTOM_CALLER_VAR": "allowed_val",
                },
            },
        )
        child_env = json.loads(env_res["stdout"].strip())
        self.assertIsNone(child_env["ld"])
        self.assertEqual(child_env["gce_host"], "127.0.0.1:1")
        self.assertEqual(child_env["no_gce"], "true")
        self.assertIsNone(child_env["adc"])
        self.assertNotEqual(child_env["docker"], "tcp://evil.example:2375")
        self.assertIsNone(child_env["gw_tok"])
        self.assertIsNone(child_env["gw_sb"])
        self.assertEqual(child_env["safe"], "allowed_val")

        # 4. `_extract_initial_agent_id` handles both agy `--conversation` and codex `resume`
        self.assertEqual(
            _extract_initial_agent_id(
                ["agy", "chat", "--conversation", "conv-123", "hi"],
                is_agy=True,
                is_codex=False,
            ),
            "conv-123",
        )
        self.assertEqual(
            _extract_initial_agent_id(
                ["agy", "chat", "--conversation=conv-456", "hi"],
                is_agy=True,
                is_codex=False,
            ),
            "conv-456",
        )
        self.assertEqual(
            _extract_initial_agent_id(
                ["codex", "exec", "resume", "thr-789", "--", "hi"],
                is_agy=False,
                is_codex=True,
            ),
            "thr-789",
        )

        # 5. `fs_patch` (`replace_all`) & `fs_stat` on broken symlinks inside workspace
        patch_file = Path(self.tmpdir) / "multi.txt"
        patch_file.write_text("alpha\nbeta\nalpha\n", encoding="utf-8")
        with self.assertRaises(RuntimeError) as patch_err:
            await asyncio.to_thread(
                client._request_json,
                "POST",
                "/v1/files/patch",
                {
                    "path": str(patch_file),
                    "edits": [{"target": "alpha", "replacement": "omega"}],
                },
            )
        self.assertIn("400", str(patch_err.exception))
        self.assertIn("matched 2 times", str(patch_err.exception))
        self.assertEqual(patch_file.read_text(encoding="utf-8"), "alpha\nbeta\nalpha\n")

        ok_patch = await asyncio.to_thread(
            client._request_json,
            "POST",
            "/v1/files/patch",
            {
                "path": str(patch_file),
                "edits": [{"target": "alpha", "replacement": "omega", "replace_all": True}],
            },
        )
        self.assertTrue(ok_patch["ok"])
        self.assertEqual(ok_patch["replacements_applied"], 2)
        self.assertEqual(patch_file.read_text(encoding="utf-8"), "omega\nbeta\nomega\n")

        broken_link = Path(self.tmpdir) / "dangling_link"
        os.symlink("missing_relative_target.txt", broken_link)
        st_broken = await asyncio.to_thread(
            client._request_json, "GET", f"/v1/files/stat?path={broken_link}"
        )
        self.assertTrue(st_broken["ok"])
        self.assertFalse(st_broken["exists"])
        self.assertTrue(st_broken["broken_symlink"])
        self.assertEqual(st_broken["type"], "symlink")

        # 6. Malformed `after_seq` returns 400 (not 500), and CL+TE smuggling attempt returns 400
        sess_created = await asyncio.to_thread(
            client._request_json,
            "POST",
            "/v1/sessions",
            {"type": "exec", "command": ["echo", "seq_check"], "cwd": self.tmpdir},
        )
        sid = sess_created["session_id"]
        with self.assertRaises(RuntimeError) as seq_err:
            await asyncio.to_thread(
                client._request_json, "GET", f"/v1/sessions/{sid}?after_seq=not_an_int"
            )
        self.assertIn("400", str(seq_err.exception))
        live_sess = self.server.sessions.get_session(sid)
        if live_sess is not None:
            await asyncio.wait_for(live_sess.wait(), timeout=5.0)

        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(
            b"POST /health HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\n"
        )
        await writer.drain()
        smuggle_status = await reader.readline()
        writer.close()
        await writer.wait_closed()
        self.assertIn(b"400", smuggle_status)

    async def test_v1522_shell_builtins_exit_trap_command_and_subshell_redirs(self) -> None:
        cfg = GatewayConfig(
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
        )
        pol = CommandPolicy(cfg)

        allowed_cmds = [
            f"(cd {self.tmpdir} && python3 --version) > {self.tmpdir}/wrap.log 2>&1; rc=$?; exit \"$rc\"",
            f"python3 --version 2>&1 | tee {self.tmpdir}/pipe.log; exit \"${{PIPESTATUS[0]}}\"",
            "command -v python3",
            "type python3",
            "return 0",
            f": > {self.tmpdir}/empty.log",
            f"trap 'rm -f {self.tmpdir}/cid.tmp' EXIT",
            "trap 'rc=$?; echo RC=$rc' EXIT TERM",
            "trap - EXIT",
            "trap -p EXIT",
            f"(echo hello) > {self.tmpdir}/sub.log 2>&1",
        ]
        for cmd in allowed_cmds:
            dec = pol.validate_command(cmd, cwd=self.tmpdir)
            self.assertTrue(dec.allowed, f"Expected allowed for {cmd!r}, got {dec.reason}")
            self.assertTrue(dec.requires_shell, f"Expected requires_shell=True for {cmd!r}")

        home_bashrc = str(Path.home() / ".bashrc")
        home_ssh_auth = str(Path.home() / ".ssh" / "authorized_keys")
        home_ssh = str(Path.home() / ".ssh")
        blocked_cmds = [
            "command -p ls",
            "command -pv ls",
            "command sudo id",
            "command -- sudo id",
            "command env rm -rf /",
            "trap -x EXIT",
            "trap 'sudo id' EXIT",
            f"trap 'rm -rf {home_ssh}' EXIT",
            f"(sudo id) > {self.tmpdir}/sub.log",
            f"(echo pwn) > {home_ssh_auth}",
            f": > {home_bashrc}",
            "(ls) sudo id",
        ]
        for bcmd in blocked_cmds:
            bdec = pol.validate_command(bcmd, cwd=self.tmpdir)
            self.assertFalse(bdec.allowed, f"Expected blocked for {bcmd!r}")

        # Live execution: wrapper preserves both raw log output and real non-zero exit code
        client = DotsGatewayClient(base_url=self.base_url, token="test-secret-token-12345")
        wrap_log = Path(self.tmpdir) / "live_wrapper_out.log"
        wrap_cmd = (
            f"(python3 -c \"import sys; print('WRAP_OUT_OK'); print('WRAP_ERR_OK', file=sys.stderr); sys.exit(7)\") "
            f"> {wrap_log} 2>&1; rc=$?; cat {wrap_log}; exit \"$rc\""
        )
        sess_res = await asyncio.to_thread(
            client._request_json,
            "POST",
            "/v1/sessions",
            {"type": "exec", "command": wrap_cmd, "cwd": self.tmpdir},
        )
        wrap_sid = sess_res["session_id"]
        wrap_sess = self.server.sessions.get_session(wrap_sid)
        assert wrap_sess is not None
        await asyncio.wait_for(wrap_sess.wait(), timeout=10.0)
        self.assertEqual(wrap_sess.returncode, 7)
        log_txt = wrap_log.read_text(encoding="utf-8")
        self.assertIn("WRAP_OUT_OK", log_txt)
        self.assertIn("WRAP_ERR_OK", log_txt)
        self.assertIn("WRAP_OUT_OK", wrap_sess.to_summary(include_output=True)["stdout"])

    async def test_v1523_agy_host_network_parity_and_fallback_safety(self) -> None:
        from unittest.mock import patch

        # 1. Default host-consistent network mode with outer mount_ns omits inner --sandbox
        # while still injecting --settings (toolPermission="always-proceed" + deny rules).
        host_net_cfg = GatewayConfig(
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            isolate_mount_namespace=True,
            agy_default_sandbox=True,
            agy_sandbox_network_access=True,
            agy_binary=self.cfg.agy_binary,
        )
        host_net_pol = CommandPolicy(host_net_cfg)
        with patch("gateway.policy.can_use_mount_namespace", return_value=True):
            argv_host_net = host_net_pol.build_agy_argv(
                prompt="git fetch", cwd=self.tmpdir, skip_permissions=False
            )
        self.assertNotIn("--dangerously-skip-permissions", argv_host_net)
        self.assertNotIn("--sandbox", argv_host_net)
        st_host = json.loads(
            next(a for a in argv_host_net if a.startswith("--settings=")).split("=", 1)[1]
        )
        self.assertEqual(st_host["toolPermission"], "always-proceed")
        self.assertIn("command(sudo)", st_host["permissions"]["deny"])
        self.assertIn(f"write_file({Path(self.tmpdir).resolve()})", st_host["permissions"]["allow"])

        # 2. Explicit agy_sandbox_network_access=False keeps inner --sandbox + proceed-in-sandbox
        offline_cfg = GatewayConfig(
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            isolate_mount_namespace=True,
            agy_default_sandbox=True,
            agy_sandbox_network_access=False,
            agy_binary=self.cfg.agy_binary,
        )
        offline_pol = CommandPolicy(offline_cfg)
        with patch("gateway.policy.can_use_mount_namespace", return_value=True):
            argv_offline = offline_pol.build_agy_argv(
                prompt="git fetch", cwd=self.tmpdir, skip_permissions=False
            )
        self.assertIn("--sandbox", argv_offline)
        st_offline = json.loads(
            next(a for a in argv_offline if a.startswith("--settings=")).split("=", 1)[1]
        )
        self.assertEqual(st_offline["toolPermission"], "proceed-in-sandbox")

        # 3. Fail-safe fallback: if outer mount_ns is disabled or unavailable, inner --sandbox stays ON
        with patch("gateway.policy.can_use_mount_namespace", return_value=False):
            argv_no_mns = host_net_pol.build_agy_argv(
                prompt="git fetch", cwd=self.tmpdir, skip_permissions=False
            )
        self.assertIn("--sandbox", argv_no_mns)
        st_no_mns = json.loads(
            next(a for a in argv_no_mns if a.startswith("--settings=")).split("=", 1)[1]
        )
        self.assertEqual(st_no_mns["toolPermission"], "proceed-in-sandbox")


if __name__ == "__main__":
    unittest.main()
