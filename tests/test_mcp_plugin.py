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


if __name__ == "__main__":
    unittest.main()
