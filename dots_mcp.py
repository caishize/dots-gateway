#!/usr/bin/env python3
"""Bundled Model Context Protocol (MCP) Stdio Server & Remote Bridge for `dots-gateway`.

Zero external dependencies (Python 3 standard library only).
Designed to be launched by OpenAI `dots`, Codex, ChatGPT Desktop, or any Agent Plugins 1.0
host via `mcp.json` (`stdio` transport):

1. Remote Bridge Mode (default on OpenAI `dots` cloud machines):
   - Speaks standard newline-delimited JSON-RPC 2.0 over `stdin`/`stdout`
   - Bridges tool/resource/prompt calls over HTTPS (`POST /mcp`) to your local Gateway
   - Supports Public-IP self-signed TLS SHA-256 certificate pinning (`GATEWAY_TLS_FINGERPRINT`),
     replay-proof `HMAC-SHA256` signing (`GATEWAY_HMAC_SECRET`), Bearer Token (`GATEWAY_TOKEN`),
     and mTLS (`GATEWAY_CLIENT_CERT` + `GATEWAY_CLIENT_KEY`)
   - Streams live `notifications/progress` while keeping public-network NAT connections alive
   - Reloads `~/.config/dots-gateway/client.json` dynamically so credentials can be configured
     even after the plugin process has started

2. Local In-Process Mode (`--local`):
   - Runs `MCPHandler` directly in-process when invoked on the development host itself
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Set

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dots_client import DotsGatewayClient  # noqa: E402
from gateway import __version__  # noqa: E402
from gateway.mcp import (  # noqa: E402
    DEFAULT_PROTOCOL_VERSION,
    PROMPT_DEFINITIONS,
    SERVER_INSTRUCTIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
    TOOL_DEFINITIONS,
)


class StdioMCPBridge:
    """Concurrent MCP `stdio` server bridging to remote `POST /mcp` (or local `MCPHandler`)."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self._stdout_lock = threading.Lock()
        self._remote_session_id: Optional[str] = None
        self._local_handler: Any = None

        if args.local:
            from gateway.config import GatewayConfig
            from gateway.executor import SessionManager
            from gateway.files import FileService
            from gateway.mcp import MCPHandler
            from gateway.policy import CommandPolicy

            cfg = GatewayConfig.load(args.config)
            policy = CommandPolicy(cfg)
            files = FileService(policy)
            sessions = SessionManager(cfg, policy)
            self._local_handler = MCPHandler(cfg, policy, files, sessions)

    def _build_client(self) -> DotsGatewayClient:
        return DotsGatewayClient(
            base_url=self.args.url,
            token=self.args.token,
            username=self.args.user,
            password=self.args.password,
            hmac_secret=self.args.hmac_secret,
            tls_fingerprint=self.args.tls_fingerprint,
            ca_cert=self.args.ca_cert,
            client_cert=self.args.client_cert,
            client_key=self.args.client_key,
            load_config_file=True,
            config_file_path=self.args.client_config,
        )

    def write_jsonrpc(self, message: Any) -> None:
        """Write a single newline-delimited JSON-RPC message atomically to stdout."""
        if message is None:
            return
        encoded = (
            json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with self._stdout_lock:
            sys.stdout.buffer.write(encoded)
            sys.stdout.buffer.flush()

    def _local_initialize_response(self, req_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        requested = str(params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION)
        negotiated = (
            requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        )
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                    "logging": {},
                },
                "serverInfo": {
                    "name": "dots-gateway",
                    "title": "Dots Remote Development & Antigravity Gateway",
                    "version": __version__,
                },
                "instructions": SERVER_INSTRUCTIONS,
            },
        }

    def _unconfigured_tool_error(self, req_id: Any) -> Dict[str, Any]:
        guide = {
            "error": "Dots Gateway connection credentials are not configured yet.",
            "how_to_configure": (
                "Set environment variables GATEWAY_URL, GATEWAY_HMAC_SECRET (or GATEWAY_TOKEN), "
                "and GATEWAY_TLS_FINGERPRINT, OR create ~/.config/dots-gateway/client.json with:\n"
                '{\n'
                '  "url": "https://<YOUR_PUBLIC_IP>:8765",\n'
                '  "hmac_secret": "<YOUR_HMAC_SECRET>",\n'
                '  "tls_fingerprint": "<SERVER_CERT_SHA256>"\n'
                '}\n'
                "Run `python3 main.py --print-plugin-config` on your gateway machine to generate this block."
            ),
        }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "isError": True,
                "content": [{"type": "text", "text": json.dumps(guide, indent=2, ensure_ascii=False)}],
            },
        }

    async def handle_line(self, raw_line: bytes) -> None:
        line_str = raw_line.decode("utf-8", errors="replace").strip()
        if not line_str:
            return

        try:
            payload = json.loads(line_str)
        except Exception as exc:
            self.write_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
            )
            return

        if self._local_handler is not None:
            async def _emit_local(ev: Optional[Dict[str, Any]]) -> None:
                if ev is not None:
                    self.write_jsonrpc(ev)

            resp, _ = await self._local_handler.handle_payload(payload, emit_event=_emit_local)
            if resp is not None:
                self.write_jsonrpc(resp)
            return

        # Remote Bridge Mode
        if isinstance(payload, dict):
            method = payload.get("method")
            has_id = "id" in payload
            req_id = payload.get("id")
            params = payload.get("params") if isinstance(payload.get("params"), dict) else {}

            # Fast-path local discovery & lifecycle so plugin load never fails if remote is offline
            if method == "initialize" and has_id:
                client = self._build_client()
                if client.has_credentials() and client._explicitly_configured:
                    try:
                        resp, sid = await asyncio.to_thread(
                            client.mcp_request, payload, self._remote_session_id, None, 8.0
                        )
                        if sid:
                            self._remote_session_id = sid
                        if resp is not None:
                            self.write_jsonrpc(resp)
                            return
                    except Exception as exc:
                        logging.getLogger("dots_mcp").warning(
                            "Remote initialize deferred (%s); using local schema handshake", exc
                        )
                self.write_jsonrpc(self._local_initialize_response(req_id, params))
                return

            if not has_id:
                # Notification (`notifications/initialized`, `notifications/cancelled`, etc.)
                client = self._build_client()
                if method == "notifications/cancelled" and client.has_credentials():
                    try:
                        await asyncio.to_thread(
                            client.mcp_request, payload, self._remote_session_id, None, 5.0
                        )
                    except Exception:
                        pass
                return

            if method == "ping":
                self.write_jsonrpc({"jsonrpc": "2.0", "id": req_id, "result": {}})
                return

            if method == "logging/setLevel":
                self.write_jsonrpc({"jsonrpc": "2.0", "id": req_id, "result": {}})
                return

            if method == "tools/list":
                self.write_jsonrpc(
                    {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOL_DEFINITIONS}}
                )
                return

            if method == "prompts/list":
                self.write_jsonrpc(
                    {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": PROMPT_DEFINITIONS}}
                )
                return

        # Forward active tool/resource/prompt/batch calls to remote Gateway `/mcp`
        client = self._build_client()
        if not client.has_credentials():
            if isinstance(payload, dict) and payload.get("method") == "tools/call":
                self.write_jsonrpc(self._unconfigured_tool_error(payload.get("id")))
            elif isinstance(payload, dict) and "id" in payload:
                self.write_jsonrpc(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "error": {
                            "code": -32001,
                            "message": "Dots Gateway credentials not configured (set GATEWAY_URL & GATEWAY_HMAC_SECRET/GATEWAY_TOKEN or ~/.config/dots-gateway/client.json)",
                        },
                    }
                )
            return

        try:
            resp, sid = await asyncio.to_thread(
                client.mcp_request,
                payload,
                self._remote_session_id,
                self.write_jsonrpc,
                3600.0,
            )
            if sid:
                self._remote_session_id = sid
            if resp is not None:
                self.write_jsonrpc(resp)
        except Exception as exc:
            if isinstance(payload, dict) and payload.get("method") == "tools/call":
                self.write_jsonrpc(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "result": {
                            "isError": True,
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(
                                        {
                                            "error": f"Remote gateway communication failed: {exc}",
                                            "gateway_url": client.base_url,
                                        },
                                        indent=2,
                                        ensure_ascii=False,
                                    ),
                                }
                            ],
                        },
                    }
                )
            elif isinstance(payload, dict) and "id" in payload:
                self.write_jsonrpc(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "error": {"code": -32000, "message": f"Gateway request error: {exc}"},
                    }
                )

    async def run(self) -> int:
        loop = asyncio.get_running_loop()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=32, thread_name_prefix="mcp-rpc")
        loop.set_default_executor(executor)
        line_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()

        def _stdin_reader() -> None:
            try:
                while True:
                    line = sys.stdin.buffer.readline()
                    if not line:
                        break
                    loop.call_soon_threadsafe(line_queue.put_nowait, line)
            except Exception as exc:
                logging.getLogger("dots_mcp").debug("stdin reader stopped: %s", exc)
            finally:
                loop.call_soon_threadsafe(line_queue.put_nowait, None)

        reader_thread = threading.Thread(target=_stdin_reader, name="mcp-stdin", daemon=True)
        reader_thread.start()

        in_flight: Set[asyncio.Task[None]] = set()
        while True:
            raw_line = await line_queue.get()
            if raw_line is None:
                break
            task = asyncio.create_task(self.handle_line(raw_line))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)

        if in_flight:
            await asyncio.gather(*in_flight, return_exceptions=True)
        return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dots Gateway MCP Stdio Server & Remote Bridge"
    )
    parser.add_argument("--url", default=None, help="Remote Gateway URL (e.g. https://<IP>:8765)")
    parser.add_argument("--token", default=None, help="Bearer API token")
    parser.add_argument("--user", default=None, help="Basic Auth username")
    parser.add_argument("--password", default=None, help="Basic Auth password")
    parser.add_argument("--hmac-secret", default=None, help="HMAC-SHA256 shared secret")
    parser.add_argument("--tls-fingerprint", default=None, help="Server TLS cert SHA-256 pin")
    parser.add_argument("--ca-cert", default=None, help="Custom Root CA PEM path")
    parser.add_argument("--client-cert", default=None, help="mTLS client cert PEM path")
    parser.add_argument("--client-key", default=None, help="mTLS client key PEM path")
    parser.add_argument(
        "--client-config",
        default=None,
        help="Path to client.json credentials file",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run MCP tools locally in-process instead of bridging to a remote gateway",
    )
    parser.add_argument(
        "--config",
        default=str(ROOT_DIR / "config.json"),
        help="Local gateway config.json path (used only with --local)",
    )
    return parser.parse_args()


def main() -> int:
    # MCP stdio strictly requires stdout for JSON-RPC frames only; route all logs to stderr.
    logging.basicConfig(
        stream=sys.stderr,
        level=os.environ.get("DOTS_MCP_LOG_LEVEL", "WARNING").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args()
    bridge = StdioMCPBridge(args)
    return asyncio.run(bridge.run())


if __name__ == "__main__":
    raise SystemExit(main())
