#!/usr/bin/env python3
"""Live end-to-end call test against the running Hardened Dots Gateway daemon (HTTPS/WSS + TLS Pinning).

Tests:
1. TLS SHA-256 Pinning & Anti-MITM check + Unauthenticated Health Anti-Fingerprinting
2. Multi-mode authentication over TLS 1.3 (Unauth 401, Bearer Token, HMAC-SHA256 signature)
3. High-risk command, `docker`, `$()` substitution, & protected-path blocking (`403 Forbidden`)
4. Quote-aware compound Shell (`cd && |`) + `/v1/files/*` write/patch/read/binary API
5. Real `agy --dangerously-skip-permissions` code generation & unit testing (`POST /v1/agy`)
6. Full-duplex WSS multi-turn bidirectional `agy` conversation (`WSS /v1/ws`)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dots_client import DotsGatewayClient  # noqa: E402
from gateway.tls import compute_cert_sha256  # noqa: E402

DEMO_WORKDIR = str(Path.home() / "workspaces" / ".live_demo")
LIVE_TEST_MODEL = (os.environ.get("GATEWAY_LIVE_TEST_MODEL") or "").strip() or None


def banner(title: str) -> None:
    print(f"\n{'=' * 74}")
    print(f"  {title}")
    print(f"{'=' * 74}", flush=True)


async def run_live_tests(base_url: str, config_path: Path) -> None:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    api_token = cfg["api_tokens"][0]
    hmac_secret = cfg["hmac_secret"]
    tls_fp = compute_cert_sha256(cfg["tls_certfile"])

    if os.path.exists(DEMO_WORKDIR):
        shutil.rmtree(DEMO_WORKDIR)
    os.makedirs(DEMO_WORKDIR, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. TLS Certificate Pinning (MITM Rejection) & Anti-Fingerprinting Health
    # ------------------------------------------------------------------
    banner("1. Testing TLS 1.3 SHA-256 Pinning & Anti-Fingerprinting Health")
    mitm_test_client = DotsGatewayClient(
        base_url=base_url, token=api_token, tls_fingerprint="f" * 64
    )
    try:
        mitm_test_client.health()
        raise AssertionError("Mismatched TLS fingerprint should have been rejected!")
    except Exception as exc:
        print(f"[PASS] Fake TLS cert pin blocked before sending HTTP headers: {exc}")
        assert "SHA-256 mismatch" in str(exc)

    unauth_client = DotsGatewayClient(base_url=base_url, tls_fingerprint=tls_fp)
    health_unauth = unauth_client.health()
    print("Unauth health response (minimal):", json.dumps(health_unauth))
    assert health_unauth == {"ok": True}, "Unauth health leaked extra metadata!"

    # ------------------------------------------------------------------
    # 2. Authentication Modes over TLS 1.3
    # ------------------------------------------------------------------
    banner("2. Testing Authentication over HTTPS (401 Rejection + Bearer + HMAC-SHA256)")
    try:
        unauth_client.policy()
        raise AssertionError("Unauthenticated request should have been rejected!")
    except RuntimeError as exc:
        print(f"[PASS] Unauthenticated call rejected: {exc}")
        assert "401" in str(exc)

    token_client = DotsGatewayClient(
        base_url=base_url, token=api_token, tls_fingerprint=tls_fp
    )
    health_auth = token_client.health()
    print("Authed health response:", json.dumps(health_auth, ensure_ascii=False))
    assert health_auth.get("tls_enabled") is True

    hmac_client = DotsGatewayClient(
        base_url=base_url, hmac_secret=hmac_secret, tls_fingerprint=tls_fp
    )
    pol_hmac = hmac_client.policy()
    print(f"[PASS] HMAC-SHA256 over TLS 1.3 authenticated; agy={pol_hmac['agy_binary']}")
    assert pol_hmac["ok"] is True

    # ------------------------------------------------------------------
    # 3. Hardened Command & Protected-Path Guardrails
    # ------------------------------------------------------------------
    banner("3. Testing Hardened Security Guardrails (403 Forbidden)")
    for bad_cmd, bad_cwd in [
        ("sudo whoami", DEMO_WORKDIR),
        ("docker run -v /:/host alpine sh", DEMO_WORKDIR),
        ("echo $(sudo id)", DEMO_WORKDIR),
        (f"cat {ROOT_DIR / 'config.json'}", DEMO_WORKDIR),
        ("ls -la", str(Path.home() / ".ssh")),
        ("ls -la", "/etc"),
    ]:
        try:
            token_client.exec_command(bad_cmd, cwd=bad_cwd)
            raise AssertionError(f"Dangerous call ({bad_cmd}, cwd={bad_cwd}) was not blocked!")
        except RuntimeError as exc:
            print(f"[PASS] Blocked ({bad_cmd!r}, cwd={bad_cwd!r}) -> {exc}")
            assert "403" in str(exc)

    # ------------------------------------------------------------------
    # 4. Quote-Aware Shell + Workspace `/v1/files/*` API
    # ------------------------------------------------------------------
    banner("4. Testing Quote-Aware Shell (`cd && |`) + `/v1/files/*` API")
    shell_res = token_client.exec_command(
        f'cd {DEMO_WORKDIR} && git init && python3 -c "print(\'QUOTE|SEMI;OK\')" | tee check.txt',
        cwd="/tmp",
    )
    assert shell_res["returncode"] == 0
    assert "QUOTE|SEMI;OK" in shell_res["stdout"]
    print("[PASS] Compound shell command with `cd`, `&&`, `|`, and quoted `;|` succeeded!")

    hmac_client.write_file(f"{DEMO_WORKDIR}/notes.md", "status: draft\n")
    hmac_client.patch_file(
        f"{DEMO_WORKDIR}/notes.md",
        [{"target": "status: draft", "replacement": "status: verified"}],
    )
    read_back = hmac_client.read_file(f"{DEMO_WORKDIR}/notes.md")
    assert "status: verified" in read_back["content"]
    print(f"[PASS] `/v1/files` write + patch + read verified: {read_back['content'].strip()!r}")

    # ------------------------------------------------------------------
    # 5. Real `agy --dangerously-skip-permissions` Coding Task over HTTPS SSE
    # ------------------------------------------------------------------
    banner("5. Testing Real `agy --dangerously-skip-permissions` Task over HTTPS SSE")
    dev_prompt = (
        f"请在当前目录 {DEMO_WORKDIR} 下创建两个文件：\n"
        "1) calc.py：实现 add(a: int, b: int) -> int 和 mul(a: int, b: int) -> int\n"
        "2) test_calc.py：使用 unittest 编写单元测试验证 add(2, 3)==5 和 mul(4, 5)==20\n"
        "创建完成后请运行 unittest 确认通过，最后回复 TASK_COMPLETE。"
    )
    t0 = time.time()
    permission_mode = None
    final_agy_status = None

    for ev in hmac_client.stream_agy(
        prompt=dev_prompt,
        cwd=DEMO_WORKDIR,
        skip_permissions=True,
        model=LIVE_TEST_MODEL,
        output_format="stream-json",
        timeout=180.0,
    ):
        if ev.get("type") == "agy_event":
            aev = ev["data"]
            etype = aev.get("event")
            if etype == "init":
                permission_mode = (aev.get("init") or {}).get("permission_mode")
                print(
                    f"  [agy init] conversation_id={aev.get('conversation_id')} "
                    f"permission_mode={permission_mode}"
                )
            elif etype == "result":
                res_obj = aev.get("result") or {}
                final_agy_status = res_obj.get("status")
                print(
                    f"  [agy result] status={final_agy_status} "
                    f"elapsed={time.time() - t0:.1f}s response={res_obj.get('response', '').strip()!r}"
                )

    assert permission_mode == "always-proceed"
    assert final_agy_status == "SUCCESS"
    verify_res = token_client.exec_command(
        "python3 -m unittest discover -s . -p 'test_*.py' -v",
        cwd=DEMO_WORKDIR,
    )
    assert verify_res["returncode"] == 0
    print("[PASS] Generated unit tests verified via `/v1/exec`!")

    # ------------------------------------------------------------------
    # 6. Full-Duplex Bidirectional Multi-Turn `agy` Session via WSS
    # ------------------------------------------------------------------
    banner("6. Testing Bidirectional Multi-Turn `agy` Session over WSS (/v1/ws)")
    async with hmac_client.connect_websocket() as ws:
        assert ws.welcome.get("type") == "connected"
        ws_agy_req = {
            "id": "agy-bi-1",
            "action": "agy",
            "interactive": True,
            "cwd": DEMO_WORKDIR,
            "prompt": "请记住项目代号：ORBIT_99。不要调用任何工具，仅回复 ACK_ORBIT。",
        }
        if LIVE_TEST_MODEL:
            ws_agy_req["model"] = LIVE_TEST_MODEL
        await ws.send_json(ws_agy_req)

        session_id = None
        turn1_resp = None
        while turn1_resp is None:
            msg = await asyncio.wait_for(ws.recv_json(), timeout=60.0)
            assert msg is not None
            if msg.get("type") == "session.created":
                session_id = msg["session_id"]
            elif msg.get("type") == "session.event":
                ev = msg["event"]
                if ev["type"] == "agy_event" and ev["data"].get("event") == "result":
                    turn1_resp = (ev["data"].get("result") or {}).get("response", "").strip()
                    print(f"  [wss <- agy Turn 1] {turn1_resp!r}")

        assert session_id is not None and "ACK_ORBIT" in turn1_resp

        await ws.send_json(
            {
                "id": "agy-bi-2",
                "action": "session.input",
                "session_id": session_id,
                "prompt": "刚才我让你记住的项目代号是什么？不要调用任何工具，直接输出代号。",
                "close_stdin": True,
            }
        )

        turn2_resp = None
        exit_rc = None
        while exit_rc is None:
            msg = await asyncio.wait_for(ws.recv_json(), timeout=60.0)
            assert msg is not None
            if msg.get("type") == "session.event":
                ev = msg["event"]
                if ev["type"] == "agy_event" and ev["data"].get("event") == "result":
                    turn2_resp = (ev["data"].get("result") or {}).get("response", "").strip()
                    print(f"  [wss <- agy Turn 2] {turn2_resp!r}")
                elif ev["type"] == "exit":
                    exit_rc = ev["data"]["returncode"]

        assert turn2_resp is not None and "ORBIT_99" in turn2_resp
        assert exit_rc == 0

    # ------------------------------------------------------------------
    # 7. MCP Plugin Verification: Streamable HTTP (`/mcp`) + `./dots_mcp.py` Stdio Bridge + `run_agy`
    # ------------------------------------------------------------------
    banner("7. Testing MCP Plugin (`/mcp` Streamable HTTP + `./dots_mcp.py` Stdio Bridge)")
    mcp_init, mcp_sid = token_client.mcp_request(
        {
            "jsonrpc": "2.0",
            "id": "m-init",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        }
    )
    assert mcp_sid and mcp_init["result"]["serverInfo"]["name"] == "dots-gateway"
    notif_out, _ = token_client.mcp_request(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session_id=mcp_sid,
    )
    assert notif_out is None
    print(f"[PASS] Remote Streamable HTTP `/mcp` initialized (Mcp-Session-Id={mcp_sid})")

    # Spawn `./dots_mcp.py` stdio bridge just as OpenAI `dots` loads the plugin via `mcp.json`
    bridge_env = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_")}
    bridge_env["GATEWAY_URL"] = base_url
    bridge_env["GATEWAY_HMAC_SECRET"] = hmac_secret
    bridge_env["GATEWAY_TLS_FINGERPRINT"] = tls_fp

    proc = await asyncio.create_subprocess_exec(
        str(ROOT_DIR / "dots_mcp.py"),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(ROOT_DIR),
        env=bridge_env,
    )
    assert proc.stdin is not None and proc.stdout is not None
    try:
        async def _stdio_rpc(req_obj: dict) -> dict:
            proc.stdin.write((json.dumps(req_obj, ensure_ascii=False) + "\n").encode("utf-8"))
            await proc.stdin.drain()
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=120.0)
                assert line, "Unexpected EOF from dots_mcp.py"
                msg_obj = json.loads(line.decode("utf-8"))
                if msg_obj.get("method") == "notifications/progress":
                    print(f"  [mcp progress] {msg_obj['params'].get('message', '')[:90]}")
                    continue
                if msg_obj.get("id") == req_obj["id"]:
                    return msg_obj

        b_init = await _stdio_rpc(
            {"jsonrpc": "2.0", "id": 101, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}
        )
        assert b_init["result"]["serverInfo"]["name"] == "dots-gateway"

        mcp_agy_args = {
            "prompt": "不要调用任何工具，直接回复 MCP_PLUGIN_AGY_OK。",
            "cwd": DEMO_WORKDIR,
            "skip_permissions": True,
        }
        if LIVE_TEST_MODEL:
            mcp_agy_args["model"] = LIVE_TEST_MODEL
        b_agy = await _stdio_rpc(
            {
                "jsonrpc": "2.0",
                "id": 102,
                "method": "tools/call",
                "params": {
                    "name": "run_agy",
                    "arguments": mcp_agy_args,
                    "_meta": {"progressToken": "live-agy-prog"},
                },
            }
        )
        assert b_agy["result"]["isError"] is False
        agy_out = b_agy["result"]["structuredContent"]["stdout"]
        print(f"  [mcp run_agy output] {agy_out.strip()!r}")
        assert "MCP_PLUGIN_AGY_OK" in agy_out
        print("[PASS] `./dots_mcp.py` plugin bridge invoked `run_agy` end-to-end over TLS 1.3 + HMAC!")
    finally:
        proc.stdin.close()
        await asyncio.wait_for(proc.wait(), timeout=5.0)

    banner("ALL 7 HARDENED HTTPS/WSS + MCP PLUGIN LIVE INTEGRATION TESTS PASSED!")


if __name__ == "__main__":
    url = os.environ.get("GATEWAY_URL", "https://127.0.0.1:8765")
    cfg_file = Path(os.environ.get("GATEWAY_CONFIG", str(ROOT_DIR / "config.json")))
    asyncio.run(run_live_tests(url, cfg_file))
