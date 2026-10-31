"""Comprehensive security & capability tests for the Hardened Dots Gateway."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import ssl
import tempfile
import unittest
from pathlib import Path

from dots_client import DotsGatewayClient
from gateway.config import (
    DEFAULT_WORKSPACE_DIR,
    GATEWAY_ROOT,
    HOME_DIR,
    GatewayConfig,
    hash_password_pbkdf2,
)
from gateway.server import GatewayServer
from gateway.tls import ensure_tls_pki


class GatewayEndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="dots_gw_test_")
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
        self.assertIn("--sandbox", agy_res["argv"])

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
        self.assertIn(str(GATEWAY_ROOT), default_cfg.protected_paths)

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
        ok_agy = await asyncio.to_thread(
            client.run_agy,
            prompt=None,
            args=["--help"],
            add_dirs=[str(extra_ws)],
        )
        self.assertEqual(ok_agy["returncode"], 0)
        self.assertIn(str(extra_ws.resolve()), ok_agy["argv"])

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

        # 4. Kernel mount-namespace VFS jail hides ~/gateway, ~/.ssh, ~/.gemini, ~/.config from inline Python
        probe_code = (
            "import json, os\n"
            "cap_eff = ''\n"
            "for line in open('/proc/self/status'):\n"
            "    if line.startswith('CapEff:'):\n"
            "        cap_eff = line.split()[1]\n"
            f"gw_exists = os.path.exists({str(GATEWAY_ROOT)!r})\n"
            "ssh_exists = os.path.exists(os.path.expanduser('~/.ssh'))\n"
            "gem_exists = os.path.exists(os.path.expanduser('~/.gemini'))\n"
            "cfg_exists = os.path.exists(os.path.expanduser('~/.config/dots-gateway'))\n"
            f"ws_exists = os.path.isdir({self.tmpdir!r})\n"
            "print(json.dumps({'cap_eff': cap_eff, 'gw': gw_exists, 'ssh': ssh_exists, "
            "'gem': gem_exists, 'cfg': cfg_exists, 'ws': ws_exists}))\n"
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
        self.assertFalse(info["cfg"])
        self.assertTrue(info["ws"])

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


if __name__ == "__main__":
    unittest.main()
