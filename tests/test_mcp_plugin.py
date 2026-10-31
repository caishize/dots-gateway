"""Unit & integration tests for the OpenAI `dots` Plugin structure, MCP `/mcp` HTTP endpoint,
and `./dots_mcp.py` stdio bridge (including TLS SHA-256 pinning, HMAC, SSE progress, and dynamic config)."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from dots_client import DotsGatewayClient
from gateway.config import GATEWAY_ROOT, HOME_DIR, GatewayConfig
from gateway.server import GatewayServer
from gateway.tls import ensure_tls_pki


class MCPAndPluginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="dots_mcp_test_")
        self.certs_dir = Path(self.tmpdir) / "certs"
        self.pki = ensure_tls_pki(self.certs_dir, extra_hosts=["127.0.0.1"])

        self.cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["mcp-bearer-token-999"],
            hmac_secret="mcp-hmac-secret-888",
            allowed_workdirs=[HOME_DIR, "/tmp"],
            default_workdir=self.tmpdir,
            tls_certfile=self.pki["server_cert"],
            tls_keyfile=self.pki["server_key"],
            tls_ca_file=self.pki["ca_cert"],
        )
        self.server = GatewayServer(self.cfg)
        host, port = await self.server.start()
        self.port = port
        self.https_url = f"https://{host}:{port}"

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_plugin_manifests_and_skills_structure(self) -> None:
        # 1. Validate root plugin.json (Agent Plugins 1.0 + OpenAI extensions)
        root_manifest = json.loads((GATEWAY_ROOT / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(root_manifest["name"], "dots-gateway")
        self.assertEqual(root_manifest["skills"], "./skills/")
        self.assertEqual(root_manifest["mcpServers"], "./mcp.json")
        self.assertIn("com.openai", root_manifest.get("extensions", {}))

        # 2. Validate .codex-plugin/plugin.json compatibility manifest
        codex_manifest = json.loads(
            (GATEWAY_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        self.assertEqual(codex_manifest["name"], "dots-gateway")
        self.assertEqual(codex_manifest["mcpServers"], "./mcp.json")

        # 3. Validate mcp.json
        mcp_cfg = json.loads((GATEWAY_ROOT / "mcp.json").read_text(encoding="utf-8"))
        srv = mcp_cfg["mcpServers"]["dots-gateway"]
        self.assertEqual(srv["type"], "stdio")
        self.assertEqual(srv["command"], "./dots_mcp.py")
        self.assertTrue(os.access(GATEWAY_ROOT / "dots_mcp.py", os.X_OK))

        # 4. Validate bundled SKILL.md files
        for skill_name in ("remote-dev-gateway", "delegate-to-agy"):
            skill_md = GATEWAY_ROOT / "skills" / skill_name / "SKILL.md"
            self.assertTrue(skill_md.is_file(), f"Missing {skill_md}")
            content = skill_md.read_text(encoding="utf-8")
            self.assertTrue(content.startswith("---\n"))
            self.assertIn(f"name: {skill_name}", content)
            self.assertIn("description:", content)

    async def test_streamable_http_mcp_lifecycle_tools_resources_prompts(self) -> None:
        # 1. Unauthenticated /mcp MUST return 401
        unauth = DotsGatewayClient(
            base_url=self.https_url,
            tls_fingerprint=self.pki["server_fingerprint_sha256"],
        )
        with self.assertRaises(RuntimeError) as auth_err:
            await asyncio.to_thread(
                unauth.mcp_request,
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
        self.assertIn("401", str(auth_err.exception))

        # 2. GET /mcp MUST return 405 Method Not Allowed per Streamable HTTP spec
        authed = DotsGatewayClient(
            base_url=self.https_url,
            token="mcp-bearer-token-999",
            tls_fingerprint=self.pki["server_fingerprint_sha256"],
        )
        with self.assertRaises(RuntimeError) as get_err:
            await asyncio.to_thread(authed._request_json, "GET", "/mcp")
        self.assertIn("405", str(get_err.exception))

        # 3. Initialize -> 200 JSON + Mcp-Session-Id header
        init_resp, sid = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "openai-dots", "version": "1.0.0"},
                },
            },
        )
        assert init_resp is not None and sid is not None
        self.assertTrue(sid.startswith("mcp_"))
        self.assertEqual(init_resp["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "dots-gateway")

        # 4. notifications/initialized -> HTTP 202 Accepted with empty body (None)
        notif_resp, sid2 = await asyncio.to_thread(
            authed.mcp_request,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            sid,
        )
        self.assertIsNone(notif_resp)
        self.assertEqual(sid2, sid)

        # 5. tools/list -> 14 curated tools
        tools_resp, _ = await asyncio.to_thread(
            authed.mcp_request,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            sid,
        )
        tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
        for expected in (
            "gateway_status",
            "exec_command",
            "run_agy",
            "session_start",
            "session_poll",
            "session_input",
            "session_signal",
            "session_list",
            "fs_stat",
            "fs_list",
            "fs_read",
            "fs_write",
            "fs_patch",
            "fs_delete",
        ):
            self.assertIn(expected, tool_names)

        # 6. File tools (`fs_write`, `fs_patch`, `fs_read`, `fs_list`) + Resource read (`file://`)
        target_py = str(Path(self.tmpdir) / "calc.py")
        w_resp, _ = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "fs_write",
                    "arguments": {
                        "path": target_py,
                        "content": "def mul(a, b):\n    return a + b\n",
                    },
                },
            },
            sid,
        )
        self.assertFalse(w_resp["result"]["isError"])

        p_resp, _ = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "fs_patch",
                    "arguments": {
                        "path": target_py,
                        "edits": [{"target": "return a + b", "replacement": "return a * b"}],
                    },
                },
            },
            sid,
        )
        self.assertFalse(p_resp["result"]["isError"])

        res_read, _ = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "resources/read",
                "params": {"uri": f"file://{target_py}"},
            },
            sid,
        )
        self.assertIn("return a * b", res_read["result"]["contents"][0]["text"])

        # 7. SSE streaming `exec_command` with `progressToken`
        progress_events: List[Dict[str, Any]] = []
        exec_resp, _ = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {
                        "command": "python3 -c 'import calc; print(\"MUL_OK=\", calc.mul(6, 7))'",
                        "cwd": self.tmpdir,
                    },
                    "_meta": {"progressToken": "prog-42"},
                },
            },
            sid,
            progress_events.append,
        )
        self.assertFalse(exec_resp["result"]["isError"])
        self.assertIn("MUL_OK= 42", exec_resp["result"]["structuredContent"]["stdout"])
        self.assertGreaterEqual(len(progress_events), 1)
        self.assertEqual(progress_events[0]["method"], "notifications/progress")

        # 8. Security policy violation returns `isError: True` (does not crash connection)
        sec_resp, _ = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {"command": "sudo whoami", "cwd": self.tmpdir},
                },
            },
            sid,
        )
        self.assertTrue(sec_resp["result"]["isError"])

        # 9. Interactive background session (`session_start` -> `session_input` -> `session_poll`)
        s_start, _ = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": "session_start",
                    "arguments": {
                        "type": "exec",
                        "command": ["python3", "-u", "-c", "import sys; line=sys.stdin.readline(); print('ECHO:' + line.strip())"],
                        "cwd": self.tmpdir,
                    },
                },
            },
            sid,
        )
        bg_sid = s_start["result"]["structuredContent"]["session_id"]

        await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "session_input",
                    "arguments": {"session_id": bg_sid, "data": "HELLO_DOTS\n", "close_stdin": True},
                },
            },
            sid,
        )

        s_poll, _ = await asyncio.to_thread(
            authed.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {"session_id": bg_sid, "wait_seconds": 5, "wait_for_exit": True},
                },
            },
            sid,
        )
        self.assertIn("ECHO:HELLO_DOTS", s_poll["result"]["structuredContent"]["stdout"])

    async def test_stdio_mcp_bridge_dynamic_config_and_tls_pinning(self) -> None:
        client_cfg_path = Path(self.tmpdir) / "dynamic_client.json"
        env = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_")}
        env["DOTS_GATEWAY_CLIENT_CONFIG"] = str(client_cfg_path)

        proc = await asyncio.create_subprocess_exec(
            str(GATEWAY_ROOT / "dots_mcp.py"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(GATEWAY_ROOT),
            env=env,
        )
        assert proc.stdin is not None and proc.stdout is not None

        async def _rpc(msg: Dict[str, Any], expect_reply: bool = True) -> Any:
            proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            await proc.stdin.drain()
            if not expect_reply:
                return None
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=10.0)
                self.assertTrue(line, "Unexpected EOF from dots_mcp.py stdout")
                parsed = json.loads(line.decode("utf-8"))
                # Skip notifications when waiting for matching request id
                if "id" in parsed and parsed["id"] == msg["id"]:
                    return parsed

        try:
            # 1. Before client.json exists, `initialize` & `tools/list` succeed immediately!
            init_res = await _rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                }
            )
            self.assertEqual(init_res["result"]["serverInfo"]["name"], "dots-gateway")
            await _rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_reply=False)

            tlist = await _rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            self.assertGreaterEqual(len(tlist["result"]["tools"]), 14)

            # 2. Calling a tool before configuring returns helpful setup guide (`isError: True`)
            unconf_call = await _rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "gateway_status", "arguments": {}},
                }
            )
            self.assertTrue(unconf_call["result"]["isError"])
            self.assertIn("not configured", unconf_call["result"]["content"][0]["text"])

            # 3. Dynamically write `client.json` while `dots_mcp.py` is running — next call bridges over HTTPS + HMAC + SHA-256 Pin!
            client_cfg_path.write_text(
                json.dumps(
                    {
                        "url": self.https_url,
                        "hmac_secret": "mcp-hmac-secret-888",
                        "tls_fingerprint": self.pki["server_fingerprint_sha256"],
                    }
                ),
                encoding="utf-8",
            )

            status_call = await _rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "gateway_status", "arguments": {}},
                }
            )
            self.assertFalse(status_call["result"]["isError"])
            self.assertTrue(status_call["result"]["structuredContent"]["tls_enabled"])

            exec_call = await _rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "exec_command",
                        "arguments": {"command": "echo BRIDGE_OVER_TLS_OK", "cwd": self.tmpdir},
                    },
                }
            )
            self.assertFalse(exec_call["result"]["isError"])
            self.assertIn(
                "BRIDGE_OVER_TLS_OK",
                exec_call["result"]["structuredContent"]["stdout"],
            )
        finally:
            proc.stdin.close()
            await asyncio.wait_for(proc.wait(), timeout=5.0)

    async def test_parallel_run_agy_and_slot_queueing(self) -> None:
        mock_agy = Path(self.tmpdir) / "mock_agy.py"
        mock_agy.write_text(
            "#!/usr/bin/env python3\n"
            "import sys, time\n"
            "time.sleep(0.25)\n"
            "print('MOCK_AGY_DONE:' + ' '.join(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        mock_agy.chmod(0o755)

        par_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["par-tok"],
            allowed_workdirs=["/tmp"],
            default_workdir=self.tmpdir,
            agy_binary=str(mock_agy),
            allowed_commands=["python3", str(mock_agy)],
            max_concurrent_agy=2,
        )
        par_srv = GatewayServer(par_cfg)
        h, p = await par_srv.start()
        try:
            client = DotsGatewayClient(base_url=f"http://{h}:{p}", token="par-tok")
            seen_notifs: List[Dict[str, Any]] = []

            async def _call_one(idx: int) -> Dict[str, Any]:
                resp, _ = await asyncio.to_thread(
                    client.mcp_request,
                    {
                        "jsonrpc": "2.0",
                        "id": f"par-{idx}",
                        "method": "tools/call",
                        "params": {
                            "name": "run_agy",
                            "arguments": {"prompt": f"TASK_{idx}", "cwd": self.tmpdir},
                            "_meta": {"progressToken": f"pt-{idx}"},
                        },
                    },
                    None,
                    seen_notifs.append,
                )
                assert resp is not None
                return resp

            t0 = asyncio.get_running_loop().time()
            results = await asyncio.gather(*(_call_one(i) for i in range(4)))
            elapsed = asyncio.get_running_loop().time() - t0

            for idx, r in enumerate(results):
                self.assertFalse(r["result"]["isError"])
                self.assertIn(
                    f"TASK_{idx}",
                    r["result"]["structuredContent"]["stdout"],
                )
            # 4 tasks x 0.25s with max_concurrent_agy=2 takes ~0.5s (2 waves), proving both parallelism & queueing
            self.assertLess(elapsed, 0.95)
            self.assertTrue(
                any("[queued]" in n.get("params", {}).get("message", "") for n in seen_notifs),
                f"Expected queued progress notification in {seen_notifs}",
            )
        finally:
            await par_srv.stop()


if __name__ == "__main__":
    unittest.main()
