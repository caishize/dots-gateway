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
from typing import Any, Dict, List, Optional

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
            allowed_workdirs=[self.tmpdir],
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
        for skill_name in ("remote-dev-gateway", "delegate-to-agy", "delegate-to-codex"):
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

        # 5. tools/list -> 15 curated tools (including run_agy & run_codex)
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
            "run_codex",
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
            sc_status = status_call["result"]["structuredContent"]
            self.assertTrue(sc_status["tls_enabled"])
            self.assertIn("allowed_commands", sc_status)
            self.assertIn("set", sc_status["allowed_commands"])
            self.assertEqual(
                sc_status["allowed_commands_count"], len(sc_status["allowed_commands"])
            )
            self.assertIn("blocked_commands", sc_status)
            self.assertIn("systemd-run", sc_status["blocked_commands"])

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
            "import json, sys, time\n"
            "t0 = time.monotonic()\n"
            "time.sleep(0.30)\n"
            "t1 = time.monotonic()\n"
            "print(json.dumps({'t0': t0, 't1': t1, 'argv': sys.argv[1:]}))\n",
            encoding="utf-8",
        )
        mock_agy.chmod(0o755)

        par_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["par-tok"],
            allowed_workdirs=[self.tmpdir],
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

            results = await asyncio.gather(*(_call_one(i) for i in range(4)))

            spans = []
            for idx, r in enumerate(results):
                self.assertFalse(r["result"]["isError"])
                out = r["result"]["structuredContent"]["stdout"].strip()
                self.assertIn(f"TASK_{idx}", out)
                info = json.loads(out.splitlines()[-1])
                spans.append((info["t0"], info["t1"]))

            # Verify true overlap within a wave (>=2 concurrent) while respecting max_concurrent_agy=2 (<=2 concurrent)
            events = []
            for s, e in spans:
                events.append((s, 1))
                events.append((e, -1))
            events.sort(key=lambda x: (x[0], x[1]))
            cur = 0
            peak = 0
            for _, delta in events:
                cur += delta
                peak = max(peak, cur)
            self.assertEqual(peak, 2, f"Expected peak concurrency of 2, spans={spans}")
            self.assertTrue(
                any("[queued]" in n.get("params", {}).get("message", "") for n in seen_notifs),
                f"Expected queued progress notification in {seen_notifs}",
            )
        finally:
            await par_srv.stop()

    async def test_oauth21_dcr_pkce_flow_and_mcp_capability_path(self) -> None:
        import base64
        import hashlib
        import re
        import ssl
        import urllib.error
        import urllib.parse
        import urllib.request

        ssl_ctx = ssl.create_default_context(cafile=self.pki["ca_cert"])

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx), _NoRedirect
        )

        def _req(method: str, path: str, data: Any = None, headers: Optional[Dict[str, str]] = None):
            hdrs = dict(headers or {})
            body_bytes = None
            if isinstance(data, dict):
                body_bytes = json.dumps(data).encode("utf-8")
                hdrs.setdefault("Content-Type", "application/json")
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            r = urllib.request.Request(f"{self.https_url}{path}", data=body_bytes, headers=hdrs, method=method)
            try:
                resp = opener.open(r, timeout=5.0)
                return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8")
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers.items()), e.read().decode("utf-8")

        # 1. Unauthenticated /mcp returns 401 with RFC 9728 resource_metadata
        st, hdrs, _ = await asyncio.to_thread(_req, "POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(st, 401)
        www_auth = hdrs.get("WWW-Authenticate", "")
        self.assertIn("resource_metadata=", www_auth)

        # 2. Protected Resource & Authorization Server Discovery
        st, _, prm_raw = await asyncio.to_thread(_req, "GET", "/.well-known/oauth-protected-resource")
        self.assertEqual(st, 200)
        prm = json.loads(prm_raw)
        self.assertEqual(prm["resource"], f"{self.https_url}/mcp")

        st, _, asm_raw = await asyncio.to_thread(_req, "GET", "/.well-known/oauth-authorization-server")
        self.assertEqual(st, 200)
        asm = json.loads(asm_raw)
        self.assertIn("S256", asm["code_challenge_methods_supported"])

        # 3. Dynamic Client Registration (RFC 7591)
        redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
        st, _, reg_raw = await asyncio.to_thread(
            _req,
            "POST",
            "/oauth/register",
            {"client_name": "dots", "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"},
        )
        self.assertEqual(st, 201)
        client_id = json.loads(reg_raw)["client_id"]

        # 4. Authorization Code + PKCE S256
        verifier = "v" * 64
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        auth_qs = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": "xyz123",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        st, _, html_doc = await asyncio.to_thread(_req, "GET", f"/oauth/authorize?{auth_qs}")
        self.assertEqual(st, 200)
        m_csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_doc)
        assert m_csrf is not None
        csrf_val = m_csrf.group(1)

        form_payload = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": "xyz123",
                "scope": "mcp",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "csrf_token": csrf_val,
                "gateway_token": self.cfg.api_tokens[0],
            }
        )
        st, redir_hdrs, _ = await asyncio.to_thread(
            _req,
            "POST",
            "/oauth/authorize",
            form_payload,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(st, 302)
        loc = redir_hdrs.get("Location", "")
        loc_qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        self.assertEqual(loc_qs["state"][0], "xyz123")
        auth_code = loc_qs["code"][0]

        # 5. Exchange code for OAuth tokens and call /mcp with Bearer access_token
        tok_form = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            }
        )
        st, _, tok_raw = await asyncio.to_thread(
            _req, "POST", "/oauth/token", tok_form, {"Content-Type": "application/x-www-form-urlencoded"}
        )
        self.assertEqual(st, 200, tok_raw)
        tok_data = json.loads(tok_raw)
        access_token = tok_data["access_token"]
        refresh_token = tok_data["refresh_token"]
        self.assertTrue(access_token.startswith("dots_at."))

        st, _, mcp_raw = await asyncio.to_thread(
            _req,
            "POST",
            "/mcp",
            {"jsonrpc": "2.0", "id": 10, "method": "tools/list"},
            {"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(st, 200)
        self.assertGreaterEqual(len(json.loads(mcp_raw)["result"]["tools"]), 14)

        # Refresh token rotation
        ref_form = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": refresh_token})
        st, _, ref_raw = await asyncio.to_thread(
            _req, "POST", "/oauth/token", ref_form, {"Content-Type": "application/x-www-form-urlencoded"}
        )
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(ref_raw)["access_token"].startswith("dots_at."))

        # 6. Secret Capability Path (/mcp/<API_TOKEN>) for UIs selecting "No Authentication"
        st_bad, _, _ = await asyncio.to_thread(
            _req, "POST", "/mcp/wrong-secret-path", {"jsonrpc": "2.0", "id": 11, "method": "tools/list"}
        )
        self.assertEqual(st_bad, 401)

        st_ok, _, cap_raw = await asyncio.to_thread(
            _req,
            "POST",
            f"/mcp/{self.cfg.api_tokens[0]}",
            {"jsonrpc": "2.0", "id": 12, "method": "tools/list"},
        )
        self.assertEqual(st_ok, 200)
        self.assertGreaterEqual(len(json.loads(cap_raw)["result"]["tools"]), 14)

    async def test_loopback_streamable_http_concurrency_and_oauth_suppression(self) -> None:
        import time
        import urllib.error
        import urllib.request

        lb_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            loopback_http_port=0,
            api_tokens=list(self.cfg.api_tokens),
            allowed_client_ips=["192.0.2.0/24"],  # Restrict external listener; loopback must still work
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            tls_certfile=self.pki["server_cert"],
            tls_keyfile=self.pki["server_key"],
            tls_ca_file=self.pki["ca_cert"],
        )
        lb_srv = GatewayServer(lb_cfg)
        await lb_srv.start()
        try:
            lb_port = lb_cfg.loopback_http_port
            assert lb_port is not None and lb_port > 0
            lb_url = f"http://127.0.0.1:{lb_port}"
            auth_hdr = f"Bearer {self.cfg.api_tokens[0]}"

            def _lb_req(
                method: str,
                path: str,
                payload: Any = None,
                headers: Dict[str, str] | None = None,
            ):
                hdrs = dict(headers or {})
                body = json.dumps(payload).encode("utf-8") if payload is not None else None
                if body is not None:
                    hdrs.setdefault("Content-Type", "application/json")
                req = urllib.request.Request(
                    f"{lb_url}{path}", data=body, headers=hdrs, method=method
                )
                try:
                    with urllib.request.urlopen(req, timeout=5.0) as resp:
                        return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8")
                except urllib.error.HTTPError as err:
                    return err.code, dict(err.headers.items()), err.read().decode("utf-8")

            # 1. Loopback listener suppresses OAuth discovery (404) & omits resource_metadata on 401
            st_wk, _, _ = await asyncio.to_thread(
                _lb_req, "GET", "/.well-known/oauth-protected-resource"
            )
            self.assertEqual(st_wk, 404)

            st_unauth, hdr_unauth, _ = await asyncio.to_thread(
                _lb_req, "POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
            self.assertEqual(st_unauth, 401)
            self.assertNotIn("resource_metadata=", hdr_unauth.get("WWW-Authenticate", ""))

            # 2. SSE stream response uses RFC-compliant `Connection: close` framing
            st_sse, hdr_sse, body_sse = await asyncio.to_thread(
                _lb_req,
                "POST",
                "/mcp",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "exec_command",
                        "arguments": {"command": ["echo", "sse_loopback_ok"], "cwd": self.tmpdir},
                    },
                },
                {
                    "Authorization": auth_hdr,
                    "Accept": "application/json, text/event-stream",
                },
            )
            self.assertEqual(st_sse, 200)
            self.assertEqual(hdr_sse.get("Connection", "").lower(), "close")
            self.assertIn("sse_loopback_ok", body_sse)

            # 3. Concurrent Streamable HTTP calls with colliding JSON-RPC `id: 1` + discovery
            #    do NOT block behind slow `tools/call` (fixes tunnel-client stdio HOL blocking)
            async def _slow_call():
                t0 = time.monotonic()
                st, _, raw = await asyncio.to_thread(
                    _lb_req,
                    "POST",
                    "/mcp",
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "exec_command",
                            "arguments": {
                                "command": ["python3", "-c", "import time; time.sleep(1.5); print('SLOW_DONE')"],
                                "cwd": self.tmpdir,
                            },
                        },
                    },
                    {"Authorization": auth_hdr},
                )
                return st, raw, time.monotonic() - t0

            async def _fast_probe():
                await asyncio.sleep(0.1)
                t0 = time.monotonic()
                st1, _, raw1 = await asyncio.to_thread(
                    _lb_req,
                    "POST",
                    "/mcp",
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    {"Authorization": auth_hdr},
                )
                st2, _, raw2 = await asyncio.to_thread(
                    _lb_req,
                    "POST",
                    "/mcp",
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "exec_command",
                            "arguments": {"command": ["echo", "FAST_PARALLEL"], "cwd": self.tmpdir},
                        },
                    },
                    {"Authorization": auth_hdr},
                )
                return st1, raw1, st2, raw2, time.monotonic() - t0

            slow_res, fast_res = await asyncio.gather(_slow_call(), _fast_probe())
            self.assertEqual(slow_res[0], 200)
            self.assertIn("SLOW_DONE", slow_res[1])
            self.assertGreaterEqual(slow_res[2], 1.45)

            self.assertEqual(fast_res[0], 200)
            self.assertGreaterEqual(len(json.loads(fast_res[1])["result"]["tools"]), 14)
            self.assertEqual(fast_res[2], 200)
            self.assertIn("FAST_PARALLEL", fast_res[3])
            self.assertLess(
                fast_res[4],
                slow_res[2] - 0.5,
                f"Fast parallel calls ({fast_res[4]:.3f}s) did not complete well before slow call ({slow_res[2]:.3f}s)",
            )
        finally:
            await lb_srv.stop()

    async def test_run_codex_vfs_isolation_and_env_injection(self) -> None:
        mock_codex = Path(self.tmpdir) / "mock_codex.py"
        mock_codex.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "info = {\n"
            "    'argv': sys.argv[1:],\n"
            "    'has_codex_dir': os.path.isdir(os.path.expanduser('~/.codex')),\n"
            "    'has_gemini_dir': os.path.exists(os.path.expanduser('~/.gemini')),\n"
            "    'has_ssh_dir': os.path.exists(os.path.expanduser('~/.ssh')),\n"
            f"    'has_gw_dir': os.path.exists({str(GATEWAY_ROOT)!r}),\n"
            "    'has_gw_cfg': os.path.exists(os.path.expanduser('~/.config/dots-gateway')),\n"
            "    'flutter_bin_writable': os.access('/opt/flutter/bin/flutter', os.W_OK) if os.path.exists('/opt/flutter/bin/flutter') else None,\n"
            "    'flutter_cache_writable': os.access('/opt/flutter/bin/cache', os.W_OK) if os.path.isdir('/opt/flutter/bin/cache') else None,\n"
            "    'injected_marker': os.environ.get('CODEX_ISOLATED_MARKER', ''),\n"
            "}\n"
            "print(json.dumps(info))\n",
            encoding="utf-8",
        )
        mock_codex.chmod(0o755)

        codex_env = Path(self.tmpdir) / "isolated_codex.env"
        codex_env.write_text("CODEX_ISOLATED_MARKER=codex_only_123\n", encoding="utf-8")
        codex_env.chmod(0o600)

        cdx_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["cdx-tok"],
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            codex_binary=str(mock_codex),
            codex_env_file=str(codex_env),
            allowed_commands=["python3", "env", str(mock_codex)],
        )
        cdx_srv = GatewayServer(cdx_cfg)
        h, p = await cdx_srv.start()
        try:
            client = DotsGatewayClient(base_url=f"http://{h}:{p}", token="cdx-tok")

            # 1. `run_codex` mounts ~/.codex & injects codex_env_file while hiding ~/.gemini, ~/.ssh, ~/gateway
            resp, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cdx-1",
                    "method": "tools/call",
                    "params": {
                        "name": "run_codex",
                        "arguments": {
                            "prompt": "- audit security edge cases",
                            "cwd": self.tmpdir,
                            "sandbox_mode": "read-only",
                            "effort": "high",
                            "continue_last": True,
                        },
                    },
                },
            )
            self.assertFalse(resp["result"]["isError"], resp)
            parsed = json.loads(resp["result"]["structuredContent"]["stdout"].strip())
            self.assertTrue(parsed["has_codex_dir"])
            self.assertFalse(parsed["has_gemini_dir"])
            self.assertFalse(parsed["has_ssh_dir"])
            self.assertFalse(parsed["has_gw_dir"])
            self.assertFalse(parsed["has_gw_cfg"])
            self.assertEqual(parsed["injected_marker"], "codex_only_123")
            self.assertIn("resume", parsed["argv"])
            self.assertIn("--last", parsed["argv"])
            self.assertIn("--", parsed["argv"])
            self.assertEqual(parsed["argv"][-1], "- audit security edge cases")
            if os.path.isdir("/opt/flutter/bin/cache"):
                self.assertFalse(parsed["flutter_bin_writable"])
                self.assertTrue(parsed["flutter_cache_writable"])

            # 2. Default workspace-write mode configures sandbox_workspace_write writable_roots & network_access
            ws_resp, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cdx-ws",
                    "method": "tools/call",
                    "params": {
                        "name": "run_codex",
                        "arguments": {
                            "prompt": "run flutter test",
                            "cwd": self.tmpdir,
                        },
                    },
                },
            )
            self.assertFalse(ws_resp["result"]["isError"], ws_resp)
            ws_parsed = json.loads(ws_resp["result"]["structuredContent"]["stdout"].strip())
            ws_argv = ws_parsed["argv"]
            self.assertIn("sandbox_workspace_write.network_access=true", ws_argv)
            wr_arg = next(
                a for a in ws_argv if a.startswith("sandbox_workspace_write.writable_roots=")
            )
            wr_list = json.loads(wr_arg.split("=", 1)[1])
            self.assertIn(str(Path(self.tmpdir).resolve()), wr_list)
            if os.path.isdir("/opt/flutter/bin/cache"):
                self.assertIn("/opt/flutter/bin/cache", wr_list)
            self.assertNotIn(str(GATEWAY_ROOT), wr_list)
            self.assertNotIn(os.path.expanduser("~/.codex"), wr_list)

            # 3. Caller-supplied '-c sandbox...' override in args is still rejected
            bad_resp, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cdx-bad",
                    "method": "tools/call",
                    "params": {
                        "name": "run_codex",
                        "arguments": {
                            "prompt": "bypass attempt",
                            "cwd": self.tmpdir,
                            "args": ["-c", "sandbox_mode=danger-full-access"],
                        },
                    },
                },
            )
            self.assertTrue(bad_resp["result"]["isError"])

            # 4. Normal `exec_command` does NOT receive codex_env_file variables
            exec_resp, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cdx-2",
                    "method": "tools/call",
                    "params": {
                        "name": "exec_command",
                        "arguments": {"command": ["env"], "cwd": self.tmpdir},
                    },
                },
            )
            self.assertFalse(exec_resp["result"]["isError"])
            self.assertNotIn(
                "codex_only_123", exec_resp["result"]["structuredContent"]["stdout"]
            )
        finally:
            await cdx_srv.stop()

    async def test_run_codex_git_worktree_metadata_writability_and_hooks_ro(self) -> None:
        import http.server
        import subprocess
        import threading

        scratch_base = Path("/var/tmp") if os.path.isdir("/var/tmp") else Path(self.tmpdir)
        nontmp_root = tempfile.mkdtemp(prefix="dots_gw_codex_wt_", dir=str(scratch_base))
        try:
            main_repo = Path(nontmp_root) / "main-repo"
            linked_wt = Path(nontmp_root) / "linked-wt"
            subprocess.run(["git", "init", "-q", str(main_repo)], check=True)
            subprocess.run(
                ["git", "-C", str(main_repo), "config", "user.email", "gw@example.com"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(main_repo), "config", "user.name", "GW Test"],
                check=True,
            )
            (main_repo / "README.md").write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(main_repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(main_repo), "commit", "-qm", "base"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(main_repo),
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "integrate/wt-check",
                    str(linked_wt),
                ],
                check=True,
            )
            hooks_dir = (main_repo / ".git" / "hooks").resolve()
            wt_gitdir = (main_repo / ".git" / "worktrees" / "linked-wt").resolve()
            common_gitdir = (main_repo / ".git").resolve()

            # A. Verify VFS mount-namespace locks `.git/hooks` read-only while exposing `commondir` & `gitdir`
            probe_codex = Path(nontmp_root) / "probe_codex.py"
            probe_codex.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                f"hooks_file = {str(hooks_dir / 'pre-commit')!r}\n"
                "hook_err = ''\n"
                "try:\n"
                "    open(hooks_file, 'w').write('#!/bin/sh\\nexit 1\\n')\n"
                "except OSError as exc:\n"
                "    hook_err = str(exc)\n"
                "print(json.dumps({\n"
                "    'argv': sys.argv[1:],\n"
                f"    'wt_index_dir_w': os.access({str(wt_gitdir)!r}, os.W_OK),\n"
                f"    'common_objs_w': os.access({str(common_gitdir / 'objects')!r}, os.W_OK),\n"
                "    'hook_err': hook_err,\n"
                "}))\n",
                encoding="utf-8",
            )
            probe_codex.chmod(0o755)

            wt_cfg = GatewayConfig(
                host="127.0.0.1",
                port=0,
                api_tokens=["wt-tok"],
                allowed_workdirs=[nontmp_root],
                default_workdir=nontmp_root,
                codex_binary=str(probe_codex),
                allowed_commands=["python3", str(probe_codex)],
            )
            wt_srv = GatewayServer(wt_cfg)
            h, p = await wt_srv.start()
            try:
                client = DotsGatewayClient(base_url=f"http://{h}:{p}", token="wt-tok")
                resp, _ = await asyncio.to_thread(
                    client.mcp_request,
                    {
                        "jsonrpc": "2.0",
                        "id": "wt-probe-1",
                        "method": "tools/call",
                        "params": {
                            "name": "run_codex",
                            "arguments": {"prompt": "commit worktree", "cwd": str(linked_wt)},
                        },
                    },
                )
                self.assertFalse(resp["result"]["isError"], resp)
                info = json.loads(resp["result"]["structuredContent"]["stdout"].strip())
                self.assertTrue(info["wt_index_dir_w"])
                self.assertTrue(info["common_objs_w"])
                self.assertTrue(info["hook_err"], "Expected .git/hooks write to fail as read-only")
                wr_arg = next(
                    a
                    for a in info["argv"]
                    if a.startswith("sandbox_workspace_write.writable_roots=")
                )
                wr_list = json.loads(wr_arg.split("=", 1)[1])
                self.assertIn(str(common_gitdir), wr_list)
                self.assertIn(str(wt_gitdir), wr_list)
            finally:
                await wt_srv.stop()

            # B. If real `codex` CLI is installed, verify real `codex exec` + `bwrap` commits in linked worktree
            real_codex = shutil.which("codex")
            if real_codex:
                tool_outputs: List[str] = []

                class _MockResponsesHandler(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *args: Any) -> None:
                        pass

                    def do_POST(self) -> None:
                        length = int(self.headers.get("Content-Length", "0"))
                        body = json.loads(self.rfile.read(length).decode("utf-8"))
                        outs = [
                            i
                            for i in body.get("input", [])
                            if i.get("type") == "function_call_output"
                        ]
                        if outs:
                            tool_outputs.append(str(outs[-1].get("output", "")))
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.end_headers()
                        if not outs:
                            sh_cmd = (
                                "echo composed >> README.md && "
                                "git add README.md && "
                                "git commit -m 'worktree composed commit' && "
                                f"(echo bad > {hooks_dir}/pre-commit 2>&1 || echo HOOK_STILL_RO) && "
                                "(echo bad > .git 2>&1 || echo DOTGIT_PTR_RO)"
                            )
                            item: Dict[str, Any] = {
                                "type": "function_call",
                                "id": "fc_wt_1",
                                "call_id": "call_wt_1",
                                "name": "exec_command",
                                "arguments": json.dumps({"cmd": sh_cmd}),
                            }
                        else:
                            item = {
                                "type": "message",
                                "id": "msg_wt_1",
                                "role": "assistant",
                                "status": "completed",
                                "content": [{"type": "output_text", "text": "COMPOSED_OK"}],
                            }
                        for ev in (
                            {
                                "type": "response.created",
                                "response": {"id": "r_wt", "status": "in_progress", "output": []},
                            },
                            {"type": "response.output_item.done", "output_index": 0, "item": item},
                            {
                                "type": "response.completed",
                                "response": {
                                    "id": "r_wt",
                                    "status": "completed",
                                    "output": [item],
                                    "usage": {
                                        "input_tokens": 5,
                                        "output_tokens": 5,
                                        "total_tokens": 10,
                                    },
                                },
                            },
                        ):
                            self.wfile.write(
                                f"event: {ev['type']}\ndata: {json.dumps(ev)}\n\n".encode("utf-8")
                            )
                        self.wfile.flush()

                mock_http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MockResponsesHandler)
                mock_port = mock_http.server_address[1]
                threading.Thread(target=mock_http.serve_forever, daemon=True).start()
                try:
                    real_cfg = GatewayConfig(
                        host="127.0.0.1",
                        port=0,
                        api_tokens=["real-cdx-tok"],
                        allowed_workdirs=[nontmp_root],
                        default_workdir=nontmp_root,
                        codex_binary=real_codex,
                    )
                    real_srv = GatewayServer(real_cfg)
                    rh, rp = await real_srv.start()
                    try:
                        rclient = DotsGatewayClient(
                            base_url=f"http://{rh}:{rp}", token="real-cdx-tok"
                        )
                        prov_override = (
                            f'model_providers.mock={{name="mock",'
                            f'base_url="http://127.0.0.1:{mock_port}",wire_api="responses"}}'
                        )
                        real_resp, _ = await asyncio.to_thread(
                            rclient.mcp_request,
                            {
                                "jsonrpc": "2.0",
                                "id": "wt-real-1",
                                "method": "tools/call",
                                "params": {
                                    "name": "run_codex",
                                    "arguments": {
                                        "prompt": "compose and commit",
                                        "cwd": str(linked_wt),
                                        "model": "codex-mini-latest",
                                        "args": [
                                            "--ephemeral",
                                            "-c",
                                            prov_override,
                                            "-c",
                                            'model_provider="mock"',
                                        ],
                                    },
                                },
                            },
                        )
                        self.assertFalse(real_resp["result"]["isError"], real_resp)
                        joined_tool_out = "\n".join(tool_outputs)
                        self.assertIn("worktree composed commit", joined_tool_out)
                        self.assertIn("HOOK_STILL_RO", joined_tool_out)
                        self.assertIn("DOTGIT_PTR_RO", joined_tool_out)
                        git_log = subprocess.check_output(
                            ["git", "-C", str(linked_wt), "log", "-1", "--oneline"],
                            text=True,
                        )
                        self.assertIn("worktree composed commit", git_log)
                    finally:
                        await real_srv.stop()
                finally:
                    mock_http.shutdown()
                    mock_http.server_close()
        finally:
            shutil.rmtree(nontmp_root, ignore_errors=True)

    async def test_run_agy_vfs_sandbox_settings_and_loopback_no_proxy(self) -> None:
        sub_ws = Path(self.tmpdir) / "nested-worktree" / "demo-app"
        sub_ws.mkdir(parents=True, exist_ok=True)

        mock_agy = Path(self.tmpdir) / "mock_agy.py"
        mock_agy.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "info = {\n"
            "    'argv': sys.argv[1:],\n"
            "    'cwd': os.getcwd(),\n"
            "    'no_proxy': os.environ.get('NO_PROXY', ''),\n"
            "    'no_proxy_lower': os.environ.get('no_proxy', ''),\n"
            "    'has_gemini_dir': os.path.isdir(os.path.expanduser('~/.gemini')),\n"
            "    'has_codex_dir': os.path.exists(os.path.expanduser('~/.codex')),\n"
            "    'has_ssh_dir': os.path.exists(os.path.expanduser('~/.ssh')),\n"
            f"    'has_gw_dir': os.path.exists({str(GATEWAY_ROOT)!r}),\n"
            "    'has_gw_cfg': os.path.exists(os.path.expanduser('~/.config/dots-gateway')),\n"
            "    'flutter_bin_writable': os.access('/opt/flutter/bin/flutter', os.W_OK) if os.path.exists('/opt/flutter/bin/flutter') else None,\n"
            "    'flutter_cache_writable': os.access('/opt/flutter/bin/cache', os.W_OK) if os.path.isdir('/opt/flutter/bin/cache') else None,\n"
            "}\n"
            "print(json.dumps(info))\n",
            encoding="utf-8",
        )
        mock_agy.chmod(0o755)

        agy_cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["agy-tok"],
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            agy_binary=str(mock_agy),
            allowed_commands=["python3", "env", str(mock_agy)],
        )
        agy_srv = GatewayServer(agy_cfg)
        h, p = await agy_srv.start()
        try:
            client = DotsGatewayClient(base_url=f"http://{h}:{p}", token="agy-tok")

            resp, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "agy-1",
                    "method": "tools/call",
                    "params": {
                        "name": "run_agy",
                        "arguments": {
                            "prompt": "run flutter test",
                            "cwd": str(sub_ws),
                        },
                    },
                },
            )
            self.assertFalse(resp["result"]["isError"], resp)
            parsed = json.loads(resp["result"]["structuredContent"]["stdout"].strip())
            self.assertEqual(parsed["cwd"], str(sub_ws.resolve()))
            self.assertTrue(parsed["has_gemini_dir"])
            self.assertFalse(parsed["has_codex_dir"])
            self.assertFalse(parsed["has_ssh_dir"])
            self.assertFalse(parsed["has_gw_dir"])
            self.assertFalse(parsed["has_gw_cfg"])
            for host in ("localhost", "127.0.0.1", "::1"):
                self.assertIn(host, parsed["no_proxy"].split(","))
                self.assertIn(host, parsed["no_proxy_lower"].split(","))
            if os.path.isdir("/opt/flutter/bin/cache"):
                self.assertFalse(parsed["flutter_bin_writable"])
                self.assertTrue(parsed["flutter_cache_writable"])

            settings_arg = next(
                a for a in parsed["argv"] if a.startswith("--settings=")
            )
            agy_add_dirs = [
                parsed["argv"][i + 1]
                for i, tok in enumerate(parsed["argv"][:-1])
                if tok == "--add-dir"
            ]
            self.assertIn(str(Path(self.tmpdir).resolve()), agy_add_dirs)
            self.assertNotIn(str(sub_ws.resolve()), agy_add_dirs)

            # Verify PreToolUse workspacePaths contract allows sibling evidence writes under allowed_workdirs
            oma_adapter = Path.home() / ".gemini/config/plugins/oh-my-agents/hooks/antigravity-adapter.py"
            if oma_adapter.is_file():
                import subprocess as _oma_sp

                ws_paths = [str(sub_ws.resolve()), *agy_add_dirs]
                sibling_meta = str(
                    Path(self.tmpdir).resolve()
                    / "stripe-topup-session-evidence"
                    / "02-red-proof-bounded.meta.txt"
                )
                allow_payload = json.dumps(
                    {
                        "conversationId": "c-topup-test",
                        "workspacePaths": ws_paths,
                        "toolCall": {
                            "name": "write_file",
                            "args": {
                                "Path": sibling_meta,
                                "Content": "passed: 4\nfailed: 14\n",
                                "Overwrite": True,
                            },
                        },
                    }
                )
                oma_ok = _oma_sp.run(
                    [
                        "python3",
                        str(oma_adapter),
                        "PreToolUse",
                        "safety-check.sh",
                        "arch-check.sh",
                        "plan-validation-check.sh",
                    ],
                    input=allow_payload,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(json.loads(oma_ok.stdout)["decision"], "allow", oma_ok.stdout)

                deny_payload = json.dumps(
                    {
                        "conversationId": "c-topup-test",
                        "workspacePaths": ws_paths,
                        "toolCall": {
                            "name": "write_file",
                            "args": {
                                "Path": "/etc/outside-approved.txt",
                                "Content": "nope\n",
                                "Overwrite": True,
                            },
                        },
                    }
                )
                oma_deny = _oma_sp.run(
                    [
                        "python3",
                        str(oma_adapter),
                        "PreToolUse",
                        "safety-check.sh",
                        "arch-check.sh",
                        "plan-validation-check.sh",
                    ],
                    input=deny_payload,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                oma_deny_obj = json.loads(oma_deny.stdout)
                self.assertEqual(oma_deny_obj["decision"], "deny")
                self.assertIn("outside approved workspacePaths", oma_deny_obj["reason"])

            settings_obj = json.loads(settings_arg.split("=", 1)[1])
            self.assertEqual(settings_obj.get("toolPermission"), "proceed-in-sandbox")
            allow_rules = settings_obj["permissions"]["allow"]
            deny_rules = settings_obj["permissions"]["deny"]
            self.assertIn(f"write_file({sub_ws.resolve()})", allow_rules)
            self.assertIn(f"write_file({Path(self.tmpdir).resolve()})", allow_rules)
            for opt_ro in (
                "/opt/uv-python",
                "/opt/uv-tools",
                "/opt/devtools",
                "/opt/flutter",
            ):
                if os.path.isdir(opt_ro):
                    self.assertIn(f"read_file({opt_ro})", allow_rules)
            if os.path.isdir("/opt/flutter") and os.path.isdir("/opt/flutter/bin/cache"):
                self.assertIn("write_file(/opt/flutter/bin/cache)", allow_rules)
                self.assertLess(
                    allow_rules.index("read_file(/opt/flutter)"),
                    allow_rules.index("write_file(/opt/flutter/bin/cache)"),
                )
            elif os.path.isdir("/opt/flutter/bin/cache"):
                self.assertIn("write_file(/opt/flutter/bin/cache)", allow_rules)
            self.assertNotIn(f"write_file({GATEWAY_ROOT})", allow_rules)
            self.assertNotIn(f"read_file({GATEWAY_ROOT})", allow_rules)
            self.assertIn("command(sudo)", deny_rules)
            self.assertIn("command(docker)", deny_rules)
            self.assertIn(f"read_file({GATEWAY_ROOT})", deny_rules)
            home_res = str(Path.home().resolve())
            self.assertIn(
                f"read_file({os.path.join(home_res, '.config', 'dots-gateway')})",
                deny_rules,
            )
            self.assertNotIn(f"read_file({os.path.join(home_res, '.gemini')})", deny_rules)
            self.assertNotIn(f"read_file({os.path.join(home_res, '.config')})", deny_rules)
            self.assertNotIn(f"read_file({os.path.join(home_res, '.local')})", deny_rules)

            # Verify skip_permissions=False omits --dangerously-skip-permissions while keeping
            # --sandbox and toolPermission="proceed-in-sandbox" for unattended headless command runs
            resp_noskip, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "agy-noskip",
                    "method": "tools/call",
                    "params": {
                        "name": "run_agy",
                        "arguments": {
                            "prompt": "git status check",
                            "cwd": str(sub_ws),
                            "skip_permissions": False,
                        },
                    },
                },
            )
            self.assertFalse(resp_noskip["result"]["isError"], resp_noskip)
            parsed_noskip = json.loads(
                resp_noskip["result"]["structuredContent"]["stdout"].strip()
            )
            self.assertNotIn("--dangerously-skip-permissions", parsed_noskip["argv"])
            self.assertIn("--sandbox", parsed_noskip["argv"])
            noskip_settings_arg = next(
                a for a in parsed_noskip["argv"] if a.startswith("--settings=")
            )
            noskip_settings = json.loads(noskip_settings_arg.split("=", 1)[1])
            self.assertEqual(noskip_settings.get("toolPermission"), "proceed-in-sandbox")

            # Verify MCP session_start(type="agy") accepts add_dirs / continue_last and rejects outside paths
            sibling_ev_dir = Path(self.tmpdir) / "stripe-topup-session-evidence"
            s_agy_ok, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "agy-sess-ok",
                    "method": "tools/call",
                    "params": {
                        "name": "session_start",
                        "arguments": {
                            "type": "agy",
                            "cwd": str(sub_ws),
                            "continue_last": True,
                            "add_dirs": [str(sibling_ev_dir)],
                        },
                    },
                },
            )
            self.assertFalse(s_agy_ok["result"]["isError"], s_agy_ok)
            s_agy_sid = s_agy_ok["result"]["structuredContent"]["session_id"]
            s_agy_argv = s_agy_ok["result"]["structuredContent"]["argv"]
            self.assertIn("--continue", s_agy_argv)
            self.assertIn(str(sibling_ev_dir.resolve()), s_agy_argv)
            self.assertIn(str(Path(self.tmpdir).resolve()), s_agy_argv)
            await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "agy-sess-poll",
                    "method": "tools/call",
                    "params": {
                        "name": "session_poll",
                        "arguments": {
                            "session_id": s_agy_sid,
                            "wait_seconds": 3,
                            "wait_for_exit": True,
                        },
                    },
                },
            )

            s_agy_bad, _ = await asyncio.to_thread(
                client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "agy-sess-bad",
                    "method": "tools/call",
                    "params": {
                        "name": "session_start",
                        "arguments": {
                            "type": "agy",
                            "cwd": str(sub_ws),
                            "add_dirs": ["/etc"],
                        },
                    },
                },
            )
            self.assertTrue(s_agy_bad["result"]["isError"])
        finally:
            await agy_srv.stop()

    async def test_session_ledger_persistence_and_restart_reconciliation(self) -> None:
        import signal
        from gateway.executor import (
            _read_boot_id,
            _read_proc_start_ticks,
            is_process_instance_alive,
        )

        # 1. Kernel `(boot_id, pid, proc_start_ticks)` PID-reuse safety unit checks
        my_pid = os.getpid()
        my_boot = _read_boot_id()
        my_ticks = _read_proc_start_ticks(my_pid)
        self.assertIsNotNone(my_ticks)
        assert my_ticks is not None
        self.assertTrue(is_process_instance_alive(my_pid, my_boot, my_ticks))
        self.assertFalse(
            is_process_instance_alive(my_pid, my_boot, my_ticks + 1),
            "Mismatched proc_start_ticks (recycled PID) must report not alive",
        )
        if my_boot:
            self.assertFalse(
                is_process_instance_alive(
                    my_pid, "00000000-0000-0000-0000-000000000000", my_ticks
                ),
                "Mismatched boot_id (host reboot) must report not alive",
            )

        # 2. End-to-end session persistence & post-restart reconciliation across GatewayServer instances
        ledger_dir = Path(self.tmpdir) / "persisted_sessions"
        cfg1 = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["persist-tok"],
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            session_state_dir=str(ledger_dir),
        )
        srv1 = GatewayServer(cfg1)
        h1, p1 = await srv1.start()
        done_sid = ""
        interrupted_sid = ""
        interrupted_pid: Optional[int] = None
        try:
            c1 = DotsGatewayClient(base_url=f"http://{h1}:{p1}", token="persist-tok")

            # A. Start and complete a fast session (including JSON thread_id extraction)
            s1_start, _ = await asyncio.to_thread(
                c1.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "p-start-1",
                    "method": "tools/call",
                    "params": {
                        "name": "session_start",
                        "arguments": {
                            "type": "exec",
                            "cwd": self.tmpdir,
                            "command": [
                                "python3",
                                "-c",
                                "print('COMPLETED_BEFORE_RESTART')",
                            ],
                        },
                    },
                },
            )
            done_sid = s1_start["result"]["structuredContent"]["session_id"]
            s1_poll, _ = await asyncio.to_thread(
                c1.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "p-poll-1",
                    "method": "tools/call",
                    "params": {
                        "name": "session_poll",
                        "arguments": {
                            "session_id": done_sid,
                            "wait_seconds": 5,
                            "wait_for_exit": True,
                        },
                    },
                },
            )
            self.assertEqual(
                s1_poll["result"]["structuredContent"]["status"], "completed"
            )
            self.assertFalse(s1_poll["result"]["structuredContent"]["process_alive"])

            # B. Start a long-running background session that is active when Gateway restarts
            s2_start, _ = await asyncio.to_thread(
                c1.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "p-start-2",
                    "method": "tools/call",
                    "params": {
                        "name": "session_start",
                        "arguments": {
                            "type": "exec",
                            "cwd": self.tmpdir,
                            "command": [
                                "python3",
                                "-c",
                                "import time; print('IN_FLIGHT_PROGRESS', flush=True); time.sleep(60)",
                            ],
                        },
                    },
                },
            )
            interrupted_sid = s2_start["result"]["structuredContent"]["session_id"]
            interrupted_pid = s2_start["result"]["structuredContent"]["pid"]

            # Wait until IN_FLIGHT_PROGRESS is captured
            for _ in range(20):
                p2_live, _ = await asyncio.to_thread(
                    c1.mcp_request,
                    {
                        "jsonrpc": "2.0",
                        "id": "p-poll-2-live",
                        "method": "tools/call",
                        "params": {
                            "name": "session_poll",
                            "arguments": {"session_id": interrupted_sid, "wait_seconds": 0.2},
                        },
                    },
                )
                sc_live = p2_live["result"]["structuredContent"]
                if "IN_FLIGHT_PROGRESS" in sc_live.get("stdout", ""):
                    self.assertTrue(sc_live["process_alive"])
                    break
                await asyncio.sleep(0.1)

            # Stop srv1 (flushes `"status": "running"` ledger file), then simulate systemd cgroup SIGKILL
            await srv1.stop()
            live_obj = srv1.sessions._sessions.get(interrupted_sid)
            if interrupted_pid:
                try:
                    os.killpg(os.getpgid(interrupted_pid), signal.SIGKILL)
                except OSError:
                    pass
            if live_obj is not None and live_obj._proc is not None:
                try:
                    await asyncio.wait_for(live_obj._proc.wait(), timeout=3.0)
                except Exception:
                    pass
            # Re-write pre-crash `"running"` snapshot so srv2 exercises full startup reconciliation
            running_snap = json.loads(
                (ledger_dir / f"{interrupted_sid}.json").read_text(encoding="utf-8")
            )
            running_snap["status"] = "running"
            running_snap["ended_at"] = None
            running_snap["returncode"] = None
            (ledger_dir / f"{interrupted_sid}.json").write_text(
                json.dumps(running_snap), encoding="utf-8"
            )
        finally:
            await srv1.stop()

        # 3. Boot a brand-new GatewayServer (`srv2`) using the same `session_state_dir`
        cfg2 = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["persist-tok"],
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            session_state_dir=str(ledger_dir),
        )
        srv2 = GatewayServer(cfg2)
        h2, p2 = await srv2.start()
        try:
            c2 = DotsGatewayClient(base_url=f"http://{h2}:{p2}", token="persist-tok")

            # Completed session from srv1 is still queryable
            r_done, _ = await asyncio.to_thread(
                c2.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "p2-done",
                    "method": "tools/call",
                    "params": {
                        "name": "session_poll",
                        "arguments": {"session_id": done_sid},
                    },
                },
            )
            self.assertFalse(r_done["result"]["isError"], r_done)
            sc_done = r_done["result"]["structuredContent"]
            self.assertEqual(sc_done["status"], "completed")
            self.assertFalse(sc_done["process_alive"])
            self.assertTrue(sc_done["reconciled_after_restart"])
            self.assertIn("COMPLETED_BEFORE_RESTART", sc_done["stdout"])

            # Interrupted running session from srv1 is reconciled deterministically as exited
            r_int, _ = await asyncio.to_thread(
                c2.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "p2-int",
                    "method": "tools/call",
                    "params": {
                        "name": "session_poll",
                        "arguments": {"session_id": interrupted_sid, "wait_seconds": 2},
                    },
                },
            )
            self.assertFalse(r_int["result"]["isError"], r_int)
            sc_int = r_int["result"]["structuredContent"]
            self.assertEqual(sc_int["status"], "interrupted_by_restart")
            self.assertFalse(sc_int["process_alive"])
            self.assertTrue(sc_int["reconciled_after_restart"])
            self.assertIn("IN_FLIGHT_PROGRESS", sc_int["stdout"])
            self.assertIn("interrupted by gateway restart", sc_int["stderr"])

            # Both appear in session_list
            r_list, _ = await asyncio.to_thread(
                c2.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "p2-list",
                    "method": "tools/call",
                    "params": {"name": "session_list", "arguments": {}},
                },
            )
            listed_ids = {
                s["session_id"]
                for s in r_list["result"]["structuredContent"]["sessions"]
            }
            self.assertIn(done_sid, listed_ids)
            self.assertIn(interrupted_sid, listed_ids)
        finally:
            await srv2.stop()


if __name__ == "__main__":
    unittest.main()
