"""Unit & integration tests for streaming output toggles, semantic progress, and async tracking."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import conftest  # noqa: F401
from dots_client import DotsGatewayClient
from gateway.config import (
    GATEWAY_ROOT,
    GatewayConfig,
    normalize_stream_mode,
    resolve_effective_stream_mode,
    stream_mode_state,
)
from gateway.sandbox import can_use_mount_namespace
from gateway.server import GatewayServer


class StreamingAndProgressTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="dots_stream_test_")
        self.stream_mode_file = os.path.join(self.tmpdir, "stream.mode")
        self.cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["stream-tok-123"],
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            isolate_mount_namespace=False,
            stream_default_mode="summary",
            stream_mode_file=self.stream_mode_file,
            stream_progress_interval_seconds=0.15,
            docker_proxy_socket=os.path.join(self.tmpdir, "stream-docker.sock"),
        )
        self.server = GatewayServer(self.cfg)
        host, port = await self.server.start()
        self.base_url = f"http://{host}:{port}"
        self.client = DotsGatewayClient(base_url=self.base_url, token="stream-tok-123")

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _raw_mcp_post(self, payload: Dict[str, Any]) -> tuple[str, bytes]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url=f"{self.base_url}/mcp",
            data=body,
            headers={
                "Authorization": "Bearer stream-tok-123",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            raw = resp.read()
            return ctype, raw

    async def test_default_summary_hot_reload_and_per_call_overrides(self) -> None:
        # 1. Default global mode is 'summary' and detach_after_seconds is disabled (None)
        st = stream_mode_state(self.cfg)
        self.assertEqual(st["mode"], "summary")
        self.assertTrue(st["enabled"])
        self.assertIsNone(st["default_detach_after_seconds"])

        pol = await asyncio.to_thread(self.client.policy)
        self.assertEqual(pol["streaming"]["mode"], "summary")
        self.assertTrue(pol["streaming"]["enabled"])
        self.assertIsNone(pol["streaming"]["default_detach_after_seconds"])

        gw_st, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "st-1",
                "method": "tools/call",
                "params": {"name": "gateway_status", "arguments": {}},
            },
        )
        self.assertEqual(gw_st["result"]["structuredContent"]["streaming"]["mode"], "summary")

        # 2. Per-call override `stream=False` disables SSE completely even when global is 'summary'
        ctype_off, raw_off = await asyncio.to_thread(
            self._raw_mcp_post,
            {
                "jsonrpc": "2.0",
                "id": "off-1",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {
                        "command": "echo HI_OFF",
                        "cwd": self.tmpdir,
                        "stream": False,
                    },
                    "_meta": {"progressToken": "pt-off"},
                },
            },
        )
        self.assertIn("application/json", ctype_off)
        parsed_off = json.loads(raw_off.decode("utf-8"))
        self.assertFalse(parsed_off["result"]["isError"])
        self.assertEqual(parsed_off["result"]["structuredContent"]["stream_mode"], "off")
        self.assertIn("HI_OFF", parsed_off["result"]["structuredContent"]["stdout"])

        # 3. Hot-reload global mode to 'off' via stream.mode file (no restart)
        Path(self.stream_mode_file).write_text("# comment\noff\n", encoding="utf-8")
        pol2 = await asyncio.to_thread(self.client.policy)
        self.assertEqual(pol2["streaming"]["mode"], "off")
        self.assertFalse(pol2["streaming"]["enabled"])

        # Without per-call override -> returns application/json (no SSE)
        ctype_global_off, _ = await asyncio.to_thread(
            self._raw_mcp_post,
            {
                "jsonrpc": "2.0",
                "id": "off-2",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {"command": "echo GLOBAL_OFF", "cwd": self.tmpdir},
                    "_meta": {"progressToken": "pt-global-off"},
                },
            },
        )
        self.assertIn("application/json", ctype_global_off)

        # With per-call override `stream=True` -> overrides global 'off' back to SSE summary
        notifs: List[Dict[str, Any]] = []
        resp_on, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "on-1",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {
                        "command": "echo OVERRIDE_ON",
                        "cwd": self.tmpdir,
                        "stream": True,
                    },
                    "_meta": {"progressToken": "pt-override-on"},
                },
            },
            None,
            notifs.append,
        )
        self.assertFalse(resp_on["result"]["isError"])
        self.assertEqual(resp_on["result"]["structuredContent"]["stream_mode"], "summary")
        self.assertGreaterEqual(len(notifs), 1)
        self.assertTrue(all(n["method"] == "notifications/progress" for n in notifs))

        # 4. Precedence check: stream_mode beats stream bool
        self.assertEqual(
            resolve_effective_stream_mode(self.cfg, stream=False, stream_mode="raw")[0],
            "raw",
        )
        self.assertEqual(normalize_stream_mode(True), "summary")
        self.assertEqual(normalize_stream_mode(False), "off")
        with self.assertRaises(ValueError):
            normalize_stream_mode("bogus")

    async def test_mcp_emits_progress_only_when_progress_token_present(self) -> None:
        # Without _meta.progressToken -> ZERO notifications/progress and ZERO notifications/message
        notifs_no_tok: List[Dict[str, Any]] = []
        resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "no-pt",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {"command": "echo LINE1 && echo LINE2", "cwd": self.tmpdir},
                },
            },
            None,
            notifs_no_tok.append,
        )
        self.assertFalse(resp["result"]["isError"])
        self.assertEqual(notifs_no_tok, [])

        # With _meta.progressToken -> emits notifications/progress
        notifs_with_tok: List[Dict[str, Any]] = []
        resp2, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "with-pt",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {"command": "echo LINE1 && echo LINE2", "cwd": self.tmpdir},
                    "_meta": {"progressToken": "tok-123"},
                },
            },
            None,
            notifs_with_tok.append,
        )
        self.assertFalse(resp2["result"]["isError"])
        self.assertGreaterEqual(len(notifs_with_tok), 1)
        for n in notifs_with_tok:
            self.assertEqual(n["method"], "notifications/progress")
            self.assertEqual(n["params"]["progressToken"], "tok-123")

    async def test_agent_semantic_streaming_and_clean_final_output(self) -> None:
        # Build mock claude, codex, and agy CLIs that emit realistic NDJSON streams when streaming flags are passed
        mock_claude = Path(self.tmpdir) / "mock_claude.py"
        mock_claude.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys, time\n"
            "argv = sys.argv[1:]\n"
            "if 'stream-json' in argv or '--output-format=stream-json' in argv:\n"
            "    events = [\n"
            "        {'type': 'system', 'subtype': 'init', 'session_id': 'cl-s-1', 'model': 'claude-sonnet-4-6'},\n"
            "        {'type': 'assistant', 'message': {'content': [{'type': 'tool_use', 'name': 'Bash', 'input': {'command': 'pytest -q'}}]}},\n"
            "        {'type': 'user', 'message': {'content': [{'type': 'tool_result', 'content': '12 passed'}]}},\n"
            "        {'type': 'result', 'subtype': 'success', 'num_turns': 2, 'result': 'CLEAN_CLAUDE_ANSWER', 'session_id': 'cl-s-1'},\n"
            "    ]\n"
            "    for ev in events:\n"
            "        print(json.dumps(ev), flush=True)\n"
            "        time.sleep(0.02)\n"
            "else:\n"
            "    print(json.dumps({'raw_argv': argv, 'session_id': 'cl-plain-1'}), flush=True)\n",
            encoding="utf-8",
        )
        mock_claude.chmod(0o755)

        mock_codex = Path(self.tmpdir) / "mock_codex.py"
        mock_codex.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys, time\n"
            "argv = sys.argv[1:]\n"
            "if '--json' in argv:\n"
            "    events = [\n"
            "        {'type': 'thread.started', 'thread_id': 'cdx-thread-99'},\n"
            "        {'type': 'turn.started'},\n"
            "        {'type': 'item.started', 'item': {'type': 'command_execution', 'command': 'git status'}},\n"
            "        {'type': 'item.completed', 'item': {'type': 'command_execution', 'command': 'git status', 'exit_code': 0}},\n"
            "        {'type': 'item.completed', 'item': {'type': 'file_change', 'changes': [{'path': 'app.py'}]}},\n"
            "        {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'CLEAN_CODEX_ANSWER'}},\n"
            "        {'type': 'turn.completed', 'usage': {'output_tokens': 42}},\n"
            "    ]\n"
            "    for ev in events:\n"
            "        print(json.dumps(ev), flush=True)\n"
            "        time.sleep(0.02)\n"
            "else:\n"
            "    print('PLAIN_CODEX_TEXT', flush=True)\n",
            encoding="utf-8",
        )
        mock_codex.chmod(0o755)

        mock_agy = Path(self.tmpdir) / "mock_agy.py"
        mock_agy.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys, time\n"
            "argv = sys.argv[1:]\n"
            "if 'stream-json' in argv or '--output-format=stream-json' in argv:\n"
            "    events = [\n"
            "        {'event': 'init', 'conversation_id': 'agy-conv-7'},\n"
            "        {'event': 'tool_use', 'name': 'Read', 'input': {'file_path': 'gateway/mcp.py'}},\n"
            "        {'event': 'result', 'result': 'CLEAN_AGY_ANSWER'},\n"
            "    ]\n"
            "    for ev in events:\n"
            "        print(json.dumps(ev), flush=True)\n"
            "        time.sleep(0.02)\n"
            "else:\n"
            "    print('PLAIN_AGY_TEXT', flush=True)\n",
            encoding="utf-8",
        )
        mock_agy.chmod(0o755)

        acfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=["ag-tok"],
            allowed_workdirs=[self.tmpdir],
            default_workdir=self.tmpdir,
            isolate_mount_namespace=False,
            claude_binary=str(mock_claude),
            codex_binary=str(mock_codex),
            agy_binary=str(mock_agy),
            allowed_commands=["python3", str(mock_claude), str(mock_codex), str(mock_agy)],
            stream_default_mode="summary",
            stream_mode_file=os.path.join(self.tmpdir, "ag_stream.mode"),
            stream_progress_interval_seconds=0.05,
            docker_proxy_socket=os.path.join(self.tmpdir, "ag-docker.sock"),
        )
        srv = GatewayServer(acfg)
        h, p = await srv.start()
        try:
            cli = DotsGatewayClient(base_url=f"http://{h}:{p}", token="ag-tok")

            # 1. run_claude with progressToken in default summary mode -> auto stream-json, readable progress, clean stdout
            cl_notifs: List[Dict[str, Any]] = []
            cl_resp, _ = await asyncio.to_thread(
                cli.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cl-1",
                    "method": "tools/call",
                    "params": {
                        "name": "run_claude",
                        "arguments": {"prompt": "run tests", "cwd": self.tmpdir},
                        "_meta": {"progressToken": "pt-cl"},
                    },
                },
                None,
                cl_notifs.append,
            )
            self.assertFalse(cl_resp["result"]["isError"], cl_resp)
            cl_sc = cl_resp["result"]["structuredContent"]
            self.assertEqual(cl_sc["stdout"], "CLEAN_CLAUDE_ANSWER")
            self.assertEqual(cl_sc["final_output"], "CLEAN_CLAUDE_ANSWER")
            self.assertEqual(cl_sc["agent_conversation_id"], "cl-s-1")
            cl_msgs = [n["params"]["message"] for n in cl_notifs]
            self.assertTrue(any("Tool Bash: pytest -q" in m for m in cl_msgs), cl_msgs)
            self.assertFalse(any('{"type":' in m for m in cl_msgs), cl_msgs)

            # 2. run_claude with explicit output_format="json" is NOT overridden
            cl_plain, _ = await asyncio.to_thread(
                cli.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cl-2",
                    "method": "tools/call",
                    "params": {
                        "name": "run_claude",
                        "arguments": {
                            "prompt": "inspect",
                            "cwd": self.tmpdir,
                            "output_format": "json",
                        },
                        "_meta": {"progressToken": "pt-cl-2"},
                    },
                },
            )
            self.assertFalse(cl_plain["result"]["isError"], cl_plain)
            cl_plain_json = json.loads(cl_plain["result"]["structuredContent"]["stdout"])
            self.assertIn("json", cl_plain_json["raw_argv"])
            self.assertNotIn("stream-json", cl_plain_json["raw_argv"])

            # 3. run_codex with progressToken -> auto --json, readable tool progress, clean stdout
            cdx_notifs: List[Dict[str, Any]] = []
            cdx_resp, _ = await asyncio.to_thread(
                cli.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cdx-1",
                    "method": "tools/call",
                    "params": {
                        "name": "run_codex",
                        "arguments": {"prompt": "fix app", "cwd": self.tmpdir},
                        "_meta": {"progressToken": "pt-cdx"},
                    },
                },
                None,
                cdx_notifs.append,
            )
            self.assertFalse(cdx_resp["result"]["isError"], cdx_resp)
            cdx_sc = cdx_resp["result"]["structuredContent"]
            self.assertEqual(cdx_sc["stdout"], "CLEAN_CODEX_ANSWER")
            self.assertEqual(cdx_sc["final_output"], "CLEAN_CODEX_ANSWER")
            self.assertEqual(cdx_sc["agent_conversation_id"], "cdx-thread-99")
            cdx_msgs = [n["params"]["message"] for n in cdx_notifs]
            self.assertTrue(any("Running command: git status" in m for m in cdx_msgs), cdx_msgs)
            self.assertTrue(any("Edited files: app.py" in m for m in cdx_msgs), cdx_msgs)

            # 4. run_codex with stream=False -> runs in plain text mode (no --json, no notifications)
            cdx_off_notifs: List[Dict[str, Any]] = []
            cdx_off, _ = await asyncio.to_thread(
                cli.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "cdx-off",
                    "method": "tools/call",
                    "params": {
                        "name": "run_codex",
                        "arguments": {"prompt": "fix app", "cwd": self.tmpdir, "stream": False},
                        "_meta": {"progressToken": "pt-cdx-off"},
                    },
                },
                None,
                cdx_off_notifs.append,
            )
            self.assertEqual(cdx_off_notifs, [])
            self.assertIn("PLAIN_CODEX_TEXT", cdx_off["result"]["structuredContent"]["stdout"])

            # 5. run_agy with progressToken -> auto stream-json, readable progress, clean stdout
            agy_notifs: List[Dict[str, Any]] = []
            agy_resp, _ = await asyncio.to_thread(
                cli.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "agy-1",
                    "method": "tools/call",
                    "params": {
                        "name": "run_agy",
                        "arguments": {"prompt": "read mcp", "cwd": self.tmpdir},
                        "_meta": {"progressToken": "pt-agy"},
                    },
                },
                None,
                agy_notifs.append,
            )
            self.assertFalse(agy_resp["result"]["isError"], agy_resp)
            agy_sc = agy_resp["result"]["structuredContent"]
            self.assertEqual(agy_sc["stdout"], "CLEAN_AGY_ANSWER")
            self.assertEqual(agy_sc["final_output"], "CLEAN_AGY_ANSWER")
            agy_msgs = [n["params"]["message"] for n in agy_notifs]
            self.assertTrue(any("Tool Read: gateway/mcp.py" in m for m in agy_msgs), agy_msgs)

            # 6. stream_mode="raw" preserves raw NDJSON stdout and deduplicates JSON stdout/agy_event
            agy_raw_notifs: List[Dict[str, Any]] = []
            agy_raw, _ = await asyncio.to_thread(
                cli.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": "agy-raw",
                    "method": "tools/call",
                    "params": {
                        "name": "run_agy",
                        "arguments": {"prompt": "read mcp", "cwd": self.tmpdir, "stream_mode": "raw"},
                        "_meta": {"progressToken": "pt-agy-raw"},
                    },
                },
                None,
                agy_raw_notifs.append,
            )
            self.assertFalse(agy_raw["result"]["isError"])
            raw_sc = agy_raw["result"]["structuredContent"]
            self.assertIn('"event": "tool_use"', raw_sc["stdout"])
            self.assertEqual(raw_sc["final_output"], "CLEAN_AGY_ANSWER")
            raw_msgs = [n["params"]["message"] for n in agy_raw_notifs]
            # Should emit [agy_event] instead of duplicating [stdout] for the same JSON lines
            self.assertTrue(any(m.startswith("[agy_event]") for m in raw_msgs), raw_msgs)
            self.assertFalse(
                any(m.startswith("[stdout]") and '"event":' in m for m in raw_msgs),
                raw_msgs,
            )
        finally:
            await srv.stop()

    async def test_throttling_background_detach_progress_views_and_cancel(self) -> None:
        # 1. Rapid burst throttling in summary mode
        burst_notifs: List[Dict[str, Any]] = []
        burst_resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "burst-1",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {
                        "command": "python3 -c 'for i in range(60): print(f\"burst-line-{i}\", flush=True)'",
                        "cwd": self.tmpdir,
                    },
                    "_meta": {"progressToken": "pt-burst"},
                },
            },
            None,
            burst_notifs.append,
        )
        self.assertFalse(burst_resp["result"]["isError"])
        self.assertIn("burst-line-59", burst_resp["result"]["structuredContent"]["stdout"])
        # Throttled to a handful of notifications instead of 60+
        self.assertLess(len(burst_notifs), 15)

        # 2. background=True starts immediately and supports view='progress', view='delta', and REST /progress
        bg_resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "bg-1",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {
                        "command": "python3 -c 'import time; print(\"STEP_1\", flush=True); time.sleep(0.35); print(\"STEP_2\", flush=True)'",
                        "cwd": self.tmpdir,
                        "background": True,
                    },
                },
            },
        )
        self.assertFalse(bg_resp["result"]["isError"])
        bg_sc = bg_resp["result"]["structuredContent"]
        self.assertTrue(bg_sc["background"])
        bg_sid = bg_sc["session_id"]

        # Poll lightweight progress view (must NOT contain full 'stdout' key)
        p_resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "poll-prog",
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {
                        "session_id": bg_sid,
                        "wait_seconds": 3,
                        "wait_for_exit": True,
                        "view": "progress",
                    },
                },
            },
        )
        p_sc = p_resp["result"]["structuredContent"]
        self.assertEqual(p_sc["view"], "progress")
        self.assertNotIn("stdout", p_sc)
        self.assertIn("progress", p_sc)
        self.assertIn("STEP_2", p_sc["stdout_tail"])
        self.assertIn("STEP_2", p_sc["final_output"])

        # REST GET /v1/sessions/{id}/progress
        rest_prog = await asyncio.to_thread(self.client.get_session_progress, bg_sid)
        self.assertTrue(rest_prog["ok"])
        self.assertEqual(rest_prog["session_id"], bg_sid)
        self.assertIn("STEP_2", rest_prog["stdout_tail"])

        # Delta view
        d_resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "poll-delta",
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {"session_id": bg_sid, "after_seq": 0, "view": "delta"},
                },
            },
        )
        d_sc = d_resp["result"]["structuredContent"]
        self.assertEqual(d_sc["view"], "delta")
        self.assertIn("STEP_1", d_sc["stdout"])

        # 3. Optional detach_after_seconds detaches long-running call without killing process
        det_resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "det-1",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {
                        "command": "python3 -c 'import time; print(\"DET_START\", flush=True); time.sleep(0.8); print(\"DET_DONE\", flush=True)'",
                        "cwd": self.tmpdir,
                        "detach_after_seconds": 0.25,
                    },
                    "_meta": {"progressToken": "pt-det"},
                },
            },
        )
        self.assertFalse(det_resp["result"]["isError"])
        det_sc = det_resp["result"]["structuredContent"]
        self.assertTrue(det_sc["detached"])
        self.assertEqual(det_sc["status"], "running")
        det_sid = det_sc["session_id"]

        # Wait for detached session to finish via session_poll
        fin_resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "det-fin",
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {
                        "session_id": det_sid,
                        "wait_seconds": 5,
                        "wait_for_exit": True,
                        "view": "progress",
                    },
                },
            },
        )
        fin_sc = fin_resp["result"]["structuredContent"]
        self.assertEqual(fin_sc["status"], "completed")
        self.assertIn("DET_DONE", fin_sc["final_output"])

        # 4. REST SSE summary mode emits 'progress' and 'exit' with final_output
        sse_events = await asyncio.to_thread(
            lambda: list(
                self.client.stream_exec(
                    "echo REST_SUMMARY_OK", cwd=self.tmpdir, stream_mode="summary"
                )
            )
        )
        ev_types = [e.get("type") for e in sse_events]
        self.assertIn("progress", ev_types)
        self.assertIn("exit", ev_types)
        exit_ev = next(e for e in sse_events if e.get("type") == "exit")
        self.assertIn("REST_SUMMARY_OK", (exit_ev.get("data") or {}).get("final_output", ""))

        # 5. Standard MCP notifications/cancelled with requestId terminates the running session
        cancel_req_id = "cancel-req-77"
        long_call = asyncio.create_task(
            asyncio.to_thread(
                self.client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": cancel_req_id,
                    "method": "tools/call",
                    "params": {
                        "name": "exec_command",
                        "arguments": {
                            "command": "python3 -c 'import time; print(\"SLEEPING\", flush=True); time.sleep(30)'",
                            "cwd": self.tmpdir,
                        },
                        "_meta": {"progressToken": "pt-cancel"},
                    },
                },
            )
        )
        # Wait until requestId is registered
        for _ in range(40):
            if (None, cancel_req_id) in self.server.mcp._active_request_sessions:
                break
            await asyncio.sleep(0.05)
        self.assertIn((None, cancel_req_id), self.server.mcp._active_request_sessions)
        await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": cancel_req_id, "reason": "user cancelled"},
            },
        )
        cancelled_resp, _ = await asyncio.wait_for(long_call, timeout=8.0)
        self.assertTrue(cancelled_resp["result"]["isError"])
        self.assertNotEqual(cancelled_resp["result"]["structuredContent"]["returncode"], 0)

    async def test_review_regressions_edge_cases(self) -> None:
        # 1. Multi-block Claude assistant event keeps tool_use milestone & hides secret/blob tool inputs
        from gateway.executor import SessionEvent
        from gateway.progress import SessionProgressTracker

        tracker = SessionProgressTracker(session_kind="claude", stream_json=True)
        ev_payload = {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "thinking", "thinking": "pondering..."},
                    {
                        "type": "tool_use",
                        "name": "Write",
                        "input": {
                            "file_path": "src/app.py",
                            "content": "HUGE_SECRET_FILE_BODY",
                            "api_key": "sk-secret-123",
                        },
                    },
                    {"type": "text", "text": "Trailing narration text"},
                ]
            },
        }
        ev5 = SessionEvent(
            seq=5, type="agy_event", data=ev_payload, timestamp=1.0, session_id="s-multi"
        )
        tracker.on_event(ev5)
        formatted = tracker.get_summary_for_event(ev5)
        self.assertIsNotNone(formatted)
        summary_msg, is_milestone = formatted  # type: ignore[misc]
        self.assertTrue(is_milestone)
        self.assertIn("Tool Write: src/app.py", summary_msg)
        self.assertNotIn("HUGE_SECRET_FILE_BODY", summary_msg)
        self.assertNotIn("sk-secret-123", summary_msg)

        # Fallback key filtering when tool has only secret/blob keys
        secret_ev = {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "name": "CustomAuthTool",
                        "input": {"token": "tok-super-secret", "body": "huge payload"},
                    }
                ]
            },
        }
        ev6 = SessionEvent(
            seq=6, type="agy_event", data=secret_ev, timestamp=2.0, session_id="s-multi"
        )
        tracker.on_event(ev6)
        f_sec = tracker.get_summary_for_event(ev6)
        self.assertIsNotNone(f_sec)
        self.assertEqual(f_sec[0], "Tool CustomAuthTool")  # type: ignore[index]

        # 2. tail_chars=0 returns empty strings (never full buffer), and paginated full view omits final_output
        bg_resp, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "tail0-bg",
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {
                        "command": "python3 -c 'import sys; print(\"ABCDEFGHIJ\"); print(\"ERR123\", file=sys.stderr)'",
                        "cwd": self.tmpdir,
                        "background": True,
                    },
                },
            },
        )
        sid = bg_resp["result"]["structuredContent"]["session_id"]

        poll_zero, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "tail0-poll",
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {
                        "session_id": sid,
                        "wait_seconds": 3,
                        "wait_for_exit": True,
                        "view": "progress",
                        "tail_chars": 0,
                    },
                },
            },
        )
        pz_sc = poll_zero["result"]["structuredContent"]
        self.assertEqual(pz_sc["stdout_tail"], "")
        self.assertEqual(pz_sc["stderr_tail"], "")

        rest_zero = await asyncio.to_thread(self.client.get_session_progress, sid, 0, 0)
        self.assertEqual(rest_zero["stdout_tail"], "")
        self.assertEqual(rest_zero["stderr_tail"], "")

        paged_full, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "paged-full",
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {"session_id": sid, "view": "full", "offset": 0, "limit": 4},
                },
            },
        )
        pf_sc = paged_full["result"]["structuredContent"]
        self.assertEqual(pf_sc["stdout"], "ABCD")
        self.assertTrue(pf_sc["stdout_has_more"])
        self.assertNotIn("final_output", pf_sc)

        # 3. Malformed wait_seconds in MCP session_poll returns clean tool error (not 500)
        bad_poll, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "bad-wait",
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {"session_id": sid, "wait_seconds": "not-a-number"},
                },
            },
        )
        self.assertTrue(bad_poll["result"]["isError"])

        # Malformed detach_after_seconds (list -> TypeError) on REST returns HTTP 400
        bad_req = urllib.request.Request(
            url=f"{self.base_url}/v1/exec",
            data=json.dumps(
                {"command": "echo hi", "cwd": self.tmpdir, "detach_after_seconds": []}
            ).encode("utf-8"),
            headers={
                "Authorization": "Bearer stream-tok-123",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            await asyncio.to_thread(urllib.request.urlopen, bad_req, timeout=10.0)
        self.assertEqual(ctx.exception.code, 400)
        ctx.exception.close()

        # 4. REST SSE + detach_after_seconds emits 'detached' SSE event while leaving process alive
        sse_det_events = await asyncio.to_thread(
            lambda: list(
                self.client._stream_sse(
                    "POST",
                    "/v1/exec",
                    {
                        "command": "python3 -c 'import time; print(\"SSE_DET_1\", flush=True); time.sleep(0.7); print(\"SSE_DET_2\", flush=True)'",
                        "cwd": self.tmpdir,
                        "stream_mode": "summary",
                        "detach_after_seconds": 0.25,
                    },
                    timeout=10.0,
                )
            )
        )
        det_evs = [e for e in sse_det_events if e.get("type") == "detached" or e.get("detached")]
        self.assertEqual(len(det_evs), 1, sse_det_events)
        sse_det_sid = det_evs[0]["session_id"]
        self.assertEqual(det_evs[0]["status"], "running")
        # Detached background session still completes cleanly
        sse_fin, _ = await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "id": "sse-det-fin",
                "method": "tools/call",
                "params": {
                    "name": "session_poll",
                    "arguments": {
                        "session_id": sse_det_sid,
                        "wait_seconds": 5,
                        "wait_for_exit": True,
                        "view": "progress",
                    },
                },
            },
        )
        self.assertEqual(sse_fin["result"]["structuredContent"]["status"], "completed")
        self.assertIn("SSE_DET_2", sse_fin["result"]["structuredContent"]["final_output"])

        # 5. Cross-session requestId isolation on notifications/cancelled
        _, sid_a = await asyncio.to_thread(
            self.client.mcp_request,
            {"jsonrpc": "2.0", "id": "init-a", "method": "initialize", "params": {}},
        )
        _, sid_b = await asyncio.to_thread(
            self.client.mcp_request,
            {"jsonrpc": "2.0", "id": "init-b", "method": "initialize", "params": {}},
        )
        self.assertTrue(sid_a and sid_b and sid_a != sid_b)

        task_a = asyncio.create_task(
            asyncio.to_thread(
                self.client.mcp_request,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "exec_command",
                        "arguments": {
                            "command": "python3 -c 'import time; print(\"ISO_A\", flush=True); time.sleep(20)'",
                            "cwd": self.tmpdir,
                        },
                        "_meta": {"progressToken": "pt-iso-a"},
                    },
                },
                sid_a,
            )
        )
        for _ in range(40):
            if (sid_a, 1) in self.server.mcp._active_request_sessions:
                break
            await asyncio.sleep(0.05)
        self.assertIn((sid_a, 1), self.server.mcp._active_request_sessions)

        # Cancel requestId=1 from session B must NOT kill session A's running task
        await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 1},
            },
            sid_b,
        )
        await asyncio.sleep(0.25)
        self.assertFalse(task_a.done(), "Session B cancelled Session A's task!")

        # Now cancel requestId=1 from session A -> terminates task_a
        await asyncio.to_thread(
            self.client.mcp_request,
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 1},
            },
            sid_a,
        )
        resp_a, _ = await asyncio.wait_for(task_a, timeout=8.0)
        self.assertTrue(resp_a["result"]["isError"])

    def test_gateway_sh_stream_cli_hot_reload(self) -> None:
        gw_env = dict(os.environ)
        gw_env["GATEWAY_CONFIG_FILE"] = os.path.join(self.tmpdir, "nonexistent_config.json")
        gw_env["GATEWAY_CLIENT_CONFIG_DIR"] = self.tmpdir
        gw_env["GATEWAY_STREAM_MODE_FILE"] = self.stream_mode_file

        def _run_sh(*sh_args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", str(GATEWAY_ROOT / "gateway.sh"), "stream", *sh_args],
                env=gw_env,
                capture_output=True,
                text=True,
                timeout=15,
            )

        st0 = _run_sh("status")
        self.assertEqual(st0.returncode, 0, st0.stderr)
        self.assertIn("summary", st0.stdout)

        off_res = _run_sh("off")
        self.assertEqual(off_res.returncode, 0, off_res.stderr)
        self.assertEqual(stream_mode_state(self.cfg)["mode"], "off")
        mode_perm = stat.S_IMODE(os.stat(self.stream_mode_file).st_mode)
        self.assertEqual(mode_perm, 0o600)

        raw_res = _run_sh("raw")
        self.assertEqual(raw_res.returncode, 0, raw_res.stderr)
        self.assertEqual(stream_mode_state(self.cfg)["mode"], "raw")

        tog_res = _run_sh("toggle")
        self.assertEqual(tog_res.returncode, 0, tog_res.stderr)
        self.assertEqual(stream_mode_state(self.cfg)["mode"], "off")

        tog2_res = _run_sh("toggle")
        self.assertEqual(tog2_res.returncode, 0, tog2_res.stderr)
        self.assertEqual(stream_mode_state(self.cfg)["mode"], "summary")

        rst_res = _run_sh("reset")
        self.assertEqual(rst_res.returncode, 0, rst_res.stderr)
        self.assertFalse(os.path.exists(self.stream_mode_file))
        self.assertEqual(stream_mode_state(self.cfg)["mode"], "summary")


if __name__ == "__main__":
    unittest.main()
