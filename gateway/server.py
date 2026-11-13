"""Hardened HTTP/SSE and WebSocket server routing for the Dots Gateway."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
import threading
import time
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from . import __version__
from .auth import Authenticator, extract_mcp_path_token
from .config import GatewayConfig, redact_diagnostic_text
from .docker_proxy import DockerProxy
from .executor import ExecutionSession, SessionManager
from .files import FileService
from .mcp import MCPHandler
from .oauth import OAuthServer
from .policy import CommandPolicy, redact_for_audit_log
from .protocol import (
    HTTPRequest,
    SSEWriter,
    WebSocketConnection,
    read_http_request,
    send_empty_response,
    send_html_response,
    send_json_response,
)
from .sandbox import SandboxStorageError
from .tls import build_server_ssl_context

logger = logging.getLogger("dots_gateway")

_SESSION_ID_RE = re.compile(
    r"^/v1/sessions/([A-Za-z0-9_-]+)(?:/(events|input|signal|resize))?$"
)
_FORBIDDEN_TASK_PLUGIN_KEYS = (
    "plugin_dirs",
    "agy_plugin_dirs",
    "plugins",
    "plugin_root",
    "agy_plugins_enabled",
)


def _reject_task_plugin_overrides(payload: Any) -> None:
    if isinstance(payload, dict):
        for key in _FORBIDDEN_TASK_PLUGIN_KEYS:
            if key in payload:
                raise PermissionError(
                    f"Task-level '{key}' declaration is forbidden by security policy; "
                    "register trusted AGY plugins via operator configuration only"
                )


class GatewayServer:
    """Asyncio server providing REST, SSE, File API, and full-duplex WebSocket access."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.oauth = OAuthServer(config)
        self.auth = Authenticator(config, oauth=self.oauth)
        self.policy = CommandPolicy(config)
        self.files = FileService(self.policy)
        self.sessions = SessionManager(config, self.policy)
        self.docker_proxy = DockerProxy(config, self.policy)
        self.sessions.attach_docker_proxy(self.docker_proxy)
        self._server: Optional[asyncio.AbstractServer] = None
        self._loopback_server: Optional[asyncio.AbstractServer] = None
        self._cleanup_task: Optional[asyncio.Task[None]] = None
        self._stop_event = threading.Event()
        self._conn_sem = asyncio.Semaphore(max(1, config.max_concurrent_connections))
        self._started_at = time.time()
        self.mcp = MCPHandler(
            config=self.config,
            policy=self.policy,
            files=self.files,
            sessions=self.sessions,
            started_at=self._started_at,
        )

    async def start(self) -> Tuple[str, int]:
        self.config.ensure_workdirs()
        ssl_ctx: Optional[ssl.SSLContext] = None
        if self.config.tls_certfile and self.config.tls_keyfile:
            ssl_ctx = build_server_ssl_context(
                certfile=self.config.tls_certfile,
                keyfile=self.config.tls_keyfile,
                cafile=self.config.tls_ca_file,
                require_client_cert=self.config.tls_require_client_cert,
            )

        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.config.host,
            port=self.config.port,
            ssl=ssl_ctx,
            limit=16 * 1024 * 1024,
        )
        sockets = self._server.sockets or []
        bound_port = sockets[0].getsockname()[1] if sockets else self.config.port
        self.config.port = bound_port

        if self.config.loopback_http_port is not None:
            self._loopback_server = await asyncio.start_server(
                self._handle_loopback_client,
                host="127.0.0.1",
                port=self.config.loopback_http_port,
                ssl=None,
                limit=16 * 1024 * 1024,
            )
            lb_sockets = self._loopback_server.sockets or []
            if lb_sockets:
                self.config.loopback_http_port = lb_sockets[0].getsockname()[1]
            logger.info(
                "Loopback tunnel HTTP listener active on http://127.0.0.1:%s/mcp",
                self.config.loopback_http_port,
            )

        self._stop_event.clear()
        if self.config.sandbox_cleanup_enabled and self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._sandbox_cleanup_loop())

        if not self.docker_proxy.is_listening:
            await self.docker_proxy.start()

        return self.config.host, bound_port

    async def _sandbox_cleanup_loop(self) -> None:
        initial_delay = min(30.0, max(0.5, float(self.config.sandbox_cleanup_interval_seconds)))
        try:
            await asyncio.sleep(initial_delay)
            while not self._stop_event.is_set():
                try:
                    res = await self.sessions.run_sandbox_cleanup(cancel_event=self._stop_event)
                    evicted = int(res.get("deleted_expired_count", 0)) + int(
                        res.get("deleted_low_space_count", 0)
                    )
                    if evicted > 0 or res.get("low_space_after"):
                        logger.info(
                            "Sandbox lifecycle sweep (%s): evicted=%s (expired=%s, low_space=%s), "
                            "reclaimed=%.2f MiB, free=%.2f GiB (%.1f%%)",
                            res.get("sandbox_state_dir"),
                            evicted,
                            res.get("deleted_expired_count"),
                            res.get("deleted_low_space_count"),
                            float(res.get("reclaimed_bytes", 0)) / (1024 * 1024),
                            float(res.get("free_gb", 0.0)),
                            float(res.get("free_percent", 0.0)),
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Sandbox lifecycle cleanup sweep failed")
                await asyncio.sleep(max(10.0, float(self.config.sandbox_cleanup_interval_seconds)))
        except asyncio.CancelledError:
            return

    async def stop(self) -> None:
        self._stop_event.set()
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        self.sessions.flush_all()
        await self.docker_proxy.stop()
        if self._loopback_server is not None:
            self._loopback_server.close()
            await self._loopback_server.wait_closed()
            self._loopback_server = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        try:
            if self._loopback_server is not None:
                async with self._server, self._loopback_server:
                    await asyncio.gather(
                        self._server.serve_forever(),
                        self._loopback_server.serve_forever(),
                    )
            else:
                async with self._server:
                    await self._server.serve_forever()
        finally:
            self.sessions.flush_all()

    async def _handle_loopback_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await self._handle_client(reader, writer, is_loopback_http=True)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_loopback_http: bool = False,
    ) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = str(peer[0]) if isinstance(peer, (tuple, list)) and peer else "unknown"

        # Fast-reject unauthorized IPs at TCP accept time in direct-connect mode
        if (
            not is_loopback_http
            and not self.config.trusted_proxies
            and not self.auth.is_ip_allowed(client_ip)
        ):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        if self._conn_sem.locked():
            try:
                await send_json_response(
                    writer, 503, {"ok": False, "error": "Server busy: too many connections"}
                )
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        async with self._conn_sem:
            try:
                try:
                    req = await read_http_request(
                        reader, client_ip=client_ip, writer=writer
                    )
                except ValueError as bad_req:
                    await send_json_response(
                        writer, 400, {"ok": False, "error": str(bad_req)}
                    )
                    return

                if req is None:
                    return

                parsed = urlparse(req.path)
                path = parsed.path
                query = parse_qs(parsed.query)
                safe_path = "/mcp/<redacted>" if extract_mcp_path_token(path) else path
                if path != "/v1/health":
                    logger.info(
                        "HTTP %s %s from %s (Host=%s, UA=%s)",
                        req.method,
                        safe_path,
                        client_ip,
                        req.headers.get("host", "-"),
                        req.headers.get("user-agent", "-")[:80],
                    )

                # CORS / preflight on MCP and OAuth discovery/token endpoints
                if req.method == "OPTIONS" and (
                    self._is_mcp_route(path)
                    or path.startswith("/.well-known/")
                    or path.startswith("/oauth/")
                ):
                    await send_empty_response(
                        writer,
                        204,
                        extra_headers={
                            "Allow": "GET, POST, DELETE, OPTIONS",
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": (
                                "Authorization, Content-Type, Accept, Mcp-Session-Id, "
                                "MCP-Protocol-Version, X-API-Token, X-Timestamp, X-Nonce, X-Signature"
                            ),
                            "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version",
                        },
                    )
                    return

                # Liveness probe on /v1/health (minimal when unauthenticated to prevent fingerprinting)
                if req.method == "GET" and path == "/v1/health":
                    has_creds = any(
                        k in req.headers
                        for k in ("authorization", "x-api-token", "x-signature")
                    )
                    is_authed = False
                    if has_creds:
                        ares = await self.auth.authenticate(
                            method=req.method,
                            raw_path=req.path,
                            headers=req.headers,
                            body=req.body,
                            client_ip=client_ip,
                            bypass_ip_allowlist=is_loopback_http,
                        )
                        is_authed = ares.authenticated

                    if self.config.minimal_unauth_health and not is_authed:
                        await send_json_response(writer, 200, {"ok": True})
                    else:
                        await send_json_response(
                            writer,
                            200,
                            {
                                "ok": True,
                                "service": "dots-gateway",
                                "version": __version__,
                                "uptime_seconds": round(time.time() - self._started_at, 2),
                                "active_sessions": self.sessions.active_count(),
                                "mcp_endpoint": "/mcp",
                                "oauth_enabled": True,
                                "tls_enabled": bool(
                                    self.config.tls_certfile and self.config.tls_keyfile
                                ),
                                "mtls_required": self.config.tls_require_client_cert,
                            },
                        )
                    return

                # OAuth 2.1 Discovery, Dynamic Client Registration, Authorize & Token endpoints
                if path.startswith("/.well-known/") or path.startswith("/oauth/"):
                    if is_loopback_http or req.headers.get("x-dots-disable-oauth") == "1":
                        await send_json_response(
                            writer,
                            404,
                            {"ok": False, "error": "OAuth discovery disabled on local tunnel listener"},
                        )
                        return
                    handled = await self._handle_oauth_routes(
                        req=req, path=path, query=query, writer=writer, client_ip=client_ip
                    )
                    if handled:
                        return

                # Authenticate all other endpoints
                auth_res = await self.auth.authenticate(
                    method=req.method,
                    raw_path=req.path,
                    headers=req.headers,
                    body=req.body,
                    client_ip=client_ip,
                    bypass_ip_allowlist=is_loopback_http,
                )
                if not auth_res.authenticated:
                    origin = self._request_origin(req)
                    if is_loopback_http or req.headers.get("x-dots-disable-oauth") == "1":
                        www_auth = 'Bearer realm="dots-gateway"'
                    else:
                        www_auth = (
                            f'Bearer realm="dots-gateway", '
                            f'resource_metadata="{origin}/.well-known/oauth-protected-resource"'
                        )
                    extra_hdrs = (
                        {
                            "WWW-Authenticate": www_auth,
                            "Access-Control-Allow-Origin": "*",
                        }
                        if auth_res.status_code == 401
                        else None
                    )
                    await send_json_response(
                        writer,
                        auth_res.status_code,
                        {"ok": False, "error": auth_res.error},
                        extra_headers=extra_hdrs,
                    )
                    return

                # Check for WebSocket upgrade on /v1/ws
                if path == "/v1/ws" and WebSocketConnection.is_websocket_upgrade(req):
                    ws = WebSocketConnection(reader, writer)
                    await ws.accept(req)
                    await self._handle_websocket(ws, auth_res.principal)
                    return

                await self._route_http(req, path, query, writer)
            except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError) as conn_exc:
                logger.debug("Client connection closed (%s): %s", client_ip, conn_exc)
            except Exception:
                logger.exception("Unhandled error handling request from %s", client_ip)
                try:
                    await send_json_response(
                        writer, 500, {"ok": False, "error": "Internal server error"}
                    )
                except Exception:
                    pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    def _parse_json_body(self, req: HTTPRequest) -> Dict[str, Any]:
        if not req.body:
            return {}
        data = json.loads(req.body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON request body must be an object")
        return data

    @staticmethod
    def _is_mcp_route(path: str) -> bool:
        cleaned = path.rstrip("/")
        return cleaned in ("/mcp", "/v1/mcp") or extract_mcp_path_token(path) is not None

    def _request_origin(self, req: HTTPRequest) -> str:
        scheme = "https" if (self.config.tls_certfile and self.config.tls_keyfile) else "http"
        host = req.headers.get("host") or f"{self.config.public_ip or '127.0.0.1'}:{self.config.port}"
        return f"{scheme}://{host}"

    async def _handle_oauth_routes(
        self,
        req: HTTPRequest,
        path: str,
        query: Dict[str, list[str]],
        writer: asyncio.StreamWriter,
        client_ip: str,
    ) -> bool:
        effective_ip = self.auth.resolve_client_ip(client_ip, req.headers)
        if not self.auth.is_ip_allowed(effective_ip):
            await send_json_response(
                writer, 403, {"error": "access_denied", "error_description": "IP not allowed"}
            )
            return True

        origin = self._request_origin(req)
        cors = {"Access-Control-Allow-Origin": "*"}
        cleaned = path.rstrip("/")

        if req.method == "GET" and cleaned in (
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource/v1/mcp",
        ):
            await send_json_response(
                writer, 200, self.oauth.protected_resource_metadata(origin), extra_headers=cors
            )
            return True

        if req.method == "GET" and cleaned in (
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/mcp",
            "/.well-known/openid-configuration",
            "/.well-known/openid-configuration/mcp",
        ):
            await send_json_response(
                writer, 200, self.oauth.authorization_server_metadata(origin), extra_headers=cors
            )
            return True

        if req.method == "POST" and cleaned == "/oauth/register":
            try:
                body = self._parse_json_body(req)
            except Exception as exc:
                await send_json_response(
                    writer,
                    400,
                    {"error": "invalid_client_metadata", "error_description": str(exc)},
                    extra_headers=cors,
                )
                return True
            status, payload = self.oauth.register_client(body)
            await send_json_response(writer, status, payload, extra_headers=cors)
            return True

        if cleaned == "/oauth/authorize":
            if req.method == "GET":
                status, html_doc = self.oauth.render_authorize_page(query)
                await send_html_response(writer, status, html_doc)
                return True
            if req.method == "POST":
                now = time.time()
                if self.auth._is_rate_limited(effective_ip, now):
                    await send_html_response(
                        writer,
                        429,
                        self.oauth._error_html("尝试次数过多，请稍后再试。"),
                    )
                    return True
                form_str = req.body.decode("utf-8", errors="replace") if req.body else ""
                status, redirect_loc, err_html = await asyncio.to_thread(
                    self.oauth.handle_authorize_submit, form_str
                )
                if status == 401:
                    self.auth._record_failure(effective_ip, now)
                if status == 302 and redirect_loc:
                    await send_empty_response(
                        writer, 302, extra_headers={"Location": redirect_loc}
                    )
                else:
                    await send_html_response(
                        writer, status, err_html or self.oauth._error_html("Authorization error")
                    )
                return True

        if req.method == "POST" and cleaned == "/oauth/token":
            now = time.time()
            if self.auth._is_rate_limited(effective_ip, now):
                await send_json_response(
                    writer,
                    429,
                    {"error": "slow_down", "error_description": "Too many failed attempts"},
                    extra_headers=cors,
                )
                return True
            status, payload = self.oauth.handle_token_request(req.body, req.headers)
            if status in (400, 401):
                self.auth._record_failure(effective_ip, now)
            await send_json_response(writer, status, payload, extra_headers=cors)
            return True

        return False

    async def _route_http(
        self,
        req: HTTPRequest,
        path: str,
        query: Dict[str, list[str]],
        writer: asyncio.StreamWriter,
    ) -> None:
        if self._is_mcp_route(path):
            await self._handle_http_mcp(req, writer)
            return

        if req.method == "GET" and path == "/v1/agy/models":
            refresh = str((query.get("refresh") or ["0"])[0]).lower() in ("1", "true", "yes")
            try:
                data = await self.sessions.list_agy_models(refresh=refresh)
            except RuntimeError as exc:
                await send_json_response(writer, 502, {"ok": False, "error": str(exc)})
                return
            await send_json_response(writer, 200, {"ok": True, **data})
            return

        if req.method == "GET" and path == "/v1/policy":
            await send_json_response(
                writer,
                200,
                {
                    "ok": True,
                    "enforce_allowlist": self.config.enforce_allowlist,
                    "allowed_commands": self.config.allowed_commands,
                    "blocked_commands": self.config.blocked_commands,
                    "allowed_workdirs": self.config.allowed_workdirs,
                    "protected_paths": self.config.protected_paths,
                    "default_workdir": self.config.default_workdir,
                    "isolate_mount_namespace": self.config.isolate_mount_namespace,
                    "max_concurrent_agy": self.config.max_concurrent_agy,
                    "max_concurrent_codex": self.config.max_concurrent_codex,
                    "default_timeout_seconds": self.config.default_timeout_seconds,
                    "agent_default_timeout_seconds": self.config.agent_default_timeout_seconds,
                    "max_timeout_seconds": self.config.max_timeout_seconds,
                    "agy_queue_timeout_seconds": self.config.agy_queue_timeout_seconds,
                    "sandbox_state_dir": self.config.sandbox_state_dir,
                    "sandbox_lifecycle": self.sessions.get_sandbox_lifecycle_info(),
                    "agy_binary": self.config.agy_binary,
                    "agy_default_skip_permissions": self.config.agy_default_skip_permissions,
                    "agy_default_sandbox": self.config.agy_default_sandbox,
                    "agy_sandbox_tool_permission": self.config.agy_sandbox_tool_permission,
                    "agy_include_allowed_workdirs": self.config.agy_include_allowed_workdirs,
                    "agy_readonly_roots": self.policy.get_agy_readonly_roots(),
                    "agy_writable_roots": self.policy.get_agy_writable_roots(),
                    "agy_auth": self.sessions.get_agy_auth_info(),
                    "agy_plugins": self.policy.get_agy_plugins_info(),
                    "docker": self.sessions.get_docker_info(),
                    "codex_binary": self.config.codex_binary,
                    "codex_default_skip_permissions": self.config.codex_default_skip_permissions,
                    "codex_default_sandbox": self.config.codex_default_sandbox,
                    "codex_sandbox_network_access": self.config.codex_sandbox_network_access,
                    "codex_writable_roots": self.policy.get_codex_writable_roots(),
                    "codex_auth_configured": self.sessions.has_codex_auth(),
                },
            )
            return

        if path.startswith("/v1/files/"):
            await self._handle_http_files(req, path, query, writer)
            return

        if req.method == "POST" and path == "/v1/exec":
            await self._handle_http_exec(req, writer)
            return

        if req.method == "POST" and path == "/v1/agy":
            await self._handle_http_agy(req, writer)
            return

        if req.method == "POST" and path == "/v1/codex":
            await self._handle_http_codex(req, writer)
            return

        if req.method == "POST" and path == "/v1/sessions":
            await self._handle_http_create_session(req, writer)
            return

        if req.method == "GET" and path == "/v1/sessions":
            await send_json_response(
                writer, 200, {"ok": True, "sessions": self.sessions.list_sessions()}
            )
            return

        m = _SESSION_ID_RE.match(path)
        if m:
            session_id, subaction = m.group(1), m.group(2)
            session = self.sessions.get_session(session_id)
            if session is None:
                await send_json_response(
                    writer, 404, {"ok": False, "error": f"Session '{session_id}' not found"}
                )
                return

            if req.method == "GET" and subaction is None:
                try:
                    after_seq = int((query.get("after_seq") or ["0"])[0])
                except ValueError:
                    await send_json_response(
                        writer, 400, {"ok": False, "error": "Invalid integer parameter 'after_seq'"}
                    )
                    return
                await send_json_response(
                    writer,
                    200,
                    {"ok": True, **session.to_summary(include_output=True, after_seq=after_seq)},
                )
                return

            if req.method == "GET" and subaction == "events":
                try:
                    after_seq = int((query.get("after_seq") or ["0"])[0])
                except ValueError:
                    await send_json_response(
                        writer, 400, {"ok": False, "error": "Invalid integer parameter 'after_seq'"}
                    )
                    return
                await self._stream_session_sse(session, writer, after_seq=after_seq)
                return

            if req.method == "POST" and subaction == "input":
                try:
                    body = self._parse_json_body(req)
                except Exception as exc:
                    await send_json_response(
                        writer,
                        400,
                        {
                            "ok": False,
                            "error": f"Invalid JSON: {redact_diagnostic_text(str(exc), self.config)}",
                        },
                    )
                    return
                close_after = bool(body.get("close_stdin", False))
                try:
                    if "prompt" in body:
                        await session.send_agy_turn(str(body["prompt"]), close_after=close_after)
                    elif "data" in body:
                        await session.write_stdin(str(body["data"]), close_after=close_after)
                    else:
                        await send_json_response(
                            writer,
                            400,
                            {"ok": False, "error": "Provide 'data' or 'prompt' in request body"},
                        )
                        return
                except Exception as exc:
                    await send_json_response(
                        writer,
                        400,
                        {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
                    )
                    return
                await send_json_response(
                    writer, 200, {"ok": True, "session_id": session_id, "status": session.status}
                )
                return

            if req.method == "POST" and subaction == "signal":
                try:
                    body = self._parse_json_body(req)
                except Exception as exc:
                    await send_json_response(
                        writer,
                        400,
                        {
                            "ok": False,
                            "error": f"Invalid JSON: {redact_diagnostic_text(str(exc), self.config)}",
                        },
                    )
                    return
                sig_name = str(body.get("signal", "SIGTERM"))
                await session.send_signal(sig_name)
                await send_json_response(
                    writer,
                    200,
                    {"ok": True, "session_id": session_id, "signal": sig_name, "status": session.status},
                )
                return

            if req.method == "POST" and subaction == "resize":
                try:
                    body = self._parse_json_body(req)
                    session.resize_pty(int(body.get("rows", 24)), int(body.get("cols", 80)))
                except Exception as exc:
                    await send_json_response(
                        writer,
                        400,
                        {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
                    )
                    return
                await send_json_response(writer, 200, {"ok": True, "session_id": session_id})
                return

        await send_json_response(
            writer, 404, {"ok": False, "error": f"Route not found: {req.method} {path}"}
        )

    async def _handle_http_mcp(
        self, req: HTTPRequest, writer: asyncio.StreamWriter
    ) -> None:
        """Serve MCP Streamable HTTP (`POST /mcp`, `DELETE /mcp`, `GET /mcp -> 405`)."""
        mcp_sid = req.headers.get("mcp-session-id")

        if req.method == "GET":
            await send_json_response(
                writer,
                405,
                {"ok": False, "error": "Method Not Allowed: use POST /mcp for Streamable HTTP"},
                extra_headers={"Allow": "POST, DELETE, OPTIONS"},
            )
            return

        if req.method == "DELETE":
            self.mcp.delete_session(mcp_sid)
            await send_empty_response(writer, 204)
            return

        if req.method != "POST":
            await send_json_response(
                writer,
                405,
                {"ok": False, "error": f"Method {req.method} not allowed on /mcp"},
                extra_headers={"Allow": "POST, DELETE, OPTIONS"},
            )
            return

        try:
            if not req.body:
                raise ValueError("Empty JSON-RPC body")
            payload = json.loads(req.body.decode("utf-8"))
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {redact_diagnostic_text(str(exc), self.config)}",
                    },
                },
            )
            return

        accept = req.headers.get("accept", "").lower()
        if "text/event-stream" in accept and self.mcp.should_stream_sse(payload):
            init_hdrs: Dict[str, str] = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version",
            }
            if mcp_sid:
                init_hdrs["Mcp-Session-Id"] = mcp_sid
            sse = SSEWriter(writer, extra_headers=init_hdrs)
            await sse.start()

            async def _emit_sse(event_obj: Optional[Dict[str, Any]]) -> None:
                if event_obj is None:
                    await sse.send_comment(f"keepalive {int(time.time())}")
                else:
                    await sse.send_event("message", event_obj)

            resp_payload, _ = await self.mcp.handle_payload(
                payload, session_id=mcp_sid, emit_event=_emit_sse
            )
            if resp_payload is not None:
                if isinstance(resp_payload, list):
                    for item in resp_payload:
                        await sse.send_event("message", item)
                else:
                    await sse.send_event("message", resp_payload)
            return

        resp_payload, resp_hdrs = await self.mcp.handle_payload(
            payload, session_id=mcp_sid, emit_event=None
        )
        merged_hdrs = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version",
        }
        if resp_hdrs:
            merged_hdrs.update(resp_hdrs)
        if resp_payload is None:
            await send_empty_response(writer, 202, extra_headers=merged_hdrs)
        else:
            await send_json_response(writer, 200, resp_payload, extra_headers=merged_hdrs)

    async def _handle_http_files(
        self,
        req: HTTPRequest,
        path: str,
        query: Dict[str, list[str]],
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            if req.method == "GET" and path == "/v1/files/stat":
                target = (query.get("path") or [""])[0]
                cwd = (query.get("cwd") or [None])[0]
                res = await asyncio.to_thread(self.files.stat, target, cwd)
                await send_json_response(writer, 200, {"ok": True, **res})
                return

            if req.method == "GET" and path == "/v1/files/list":
                target = (query.get("path") or [self.config.default_workdir])[0]
                cwd = (query.get("cwd") or [None])[0]
                recursive = (query.get("recursive") or ["false"])[0].lower() in ("1", "true", "yes")
                max_entries = int((query.get("max_entries") or ["1000"])[0])
                res = await asyncio.to_thread(
                    self.files.list_dir, target, cwd, recursive, max_entries
                )
                await send_json_response(writer, 200, {"ok": True, **res})
                return

            if req.method == "GET" and path == "/v1/files/read":
                target = (query.get("path") or [""])[0]
                cwd = (query.get("cwd") or [None])[0]
                encoding = (query.get("encoding") or ["utf-8"])[0]
                offset = int((query.get("offset") or ["0"])[0])
                limit_raw = (query.get("limit") or [None])[0]
                limit = int(limit_raw) if limit_raw is not None else None
                res = await asyncio.to_thread(
                    self.files.read, target, cwd, encoding, offset, limit
                )
                await send_json_response(writer, 200, {"ok": True, **res})
                return

            if req.method == "POST" and path == "/v1/files/write":
                body = self._parse_json_body(req)
                res = await asyncio.to_thread(
                    self.files.write,
                    str(body.get("path", "")),
                    str(body.get("content", "")),
                    body.get("cwd"),
                    str(body.get("encoding", "utf-8")),
                    bool(body.get("append", False)),
                    bool(body.get("mkdir_parents", True)),
                    body.get("mode"),
                )
                await send_json_response(writer, 200, {"ok": True, **res})
                return

            if req.method == "POST" and path == "/v1/files/patch":
                body = self._parse_json_body(req)
                res = await asyncio.to_thread(
                    self.files.patch,
                    str(body.get("path", "")),
                    body.get("edits") or [],
                    body.get("cwd"),
                )
                await send_json_response(writer, 200, {"ok": True, **res})
                return

            if req.method == "POST" and path == "/v1/files/delete":
                body = self._parse_json_body(req)
                res = await asyncio.to_thread(
                    self.files.delete,
                    str(body.get("path", "")),
                    body.get("cwd"),
                )
                await send_json_response(writer, 200, {"ok": True, **res})
                return

            await send_json_response(
                writer, 404, {"ok": False, "error": f"Unknown file endpoint: {req.method} {path}"}
            )
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning(
                "HTTP file policy rejection: path=%s reason=%s",
                path,
                safe_err,
            )
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
        except FileNotFoundError as exc:
            await send_json_response(
                writer,
                404,
                {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
            )
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
            )

    async def _stream_session_sse(
        self, session: ExecutionSession, writer: asyncio.StreamWriter, after_seq: int = 0
    ) -> None:
        sse = SSEWriter(writer, extra_headers={"X-Session-Id": session.session_id})
        await sse.start()
        async for ev in session.subscribe_with_heartbeat(
            after_seq=after_seq, heartbeat_seconds=self.config.sse_keepalive_seconds
        ):
            if ev is None:
                await sse.send_comment(f"keepalive {int(time.time())}")
            else:
                await sse.send_event(ev.type, ev.to_dict(), event_id=ev.seq)

    async def _handle_http_exec(
        self, req: HTTPRequest, writer: asyncio.StreamWriter
    ) -> None:
        try:
            body = self._parse_json_body(req)
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {
                    "ok": False,
                    "error": f"Invalid JSON: {redact_diagnostic_text(str(exc), self.config)}",
                },
            )
            return

        try:
            _reject_task_plugin_overrides(body)
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning("HTTP exec plugin override rejection: route=%s reason=%s", req.path, safe_err)
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
            return

        command = body.get("command")
        if not command:
            await send_json_response(
                writer, 400, {"ok": False, "error": "Missing required field 'command'"}
            )
            return

        stream = bool(body.get("stream", False)) or (
            "text/event-stream" in req.headers.get("accept", "")
        )
        close_stdin = bool(body.get("close_stdin", not bool(body.get("interactive", False))))
        raw_shell = body.get("shell")
        shell_opt = None if raw_shell is None else bool(raw_shell)

        try:
            session = await self.sessions.create_session(
                command=command,
                cwd=body.get("cwd"),
                env=body.get("env"),
                shell=shell_opt,
                use_pty=bool(body.get("use_pty", False)),
                stream_json=bool(body.get("stream_json", False)),
                timeout=body.get("timeout"),
                initial_stdin=body.get("stdin"),
                close_stdin=close_stdin,
            )
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning(
                "HTTP exec policy rejection: route=%s cwd=%r reason=%s preview=%s",
                req.path,
                body.get("cwd"),
                safe_err,
                redact_for_audit_log(command),
            )
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
            return
        except SandboxStorageError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.error("HTTP exec sandbox storage failure: route=%s reason=%s", req.path, safe_err)
            await send_json_response(writer, 503, {"ok": False, "error": safe_err})
            return
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
            )
            return

        if stream:
            await self._stream_session_sse(session, writer, after_seq=0)
        else:
            summary = await session.wait()
            await send_json_response(
                writer,
                200,
                {"ok": summary["returncode"] == 0, **summary},
                extra_headers={"X-Session-Id": session.session_id},
            )

    async def _handle_http_agy(
        self, req: HTTPRequest, writer: asyncio.StreamWriter
    ) -> None:
        try:
            body = self._parse_json_body(req)
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {
                    "ok": False,
                    "error": f"Invalid JSON: {redact_diagnostic_text(str(exc), self.config)}",
                },
            )
            return

        try:
            _reject_task_plugin_overrides(body)
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning("HTTP agy plugin override rejection: route=%s reason=%s", req.path, safe_err)
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
            return

        prompt = body.get("prompt")
        args = body.get("args") or []
        interactive = bool(body.get("interactive", False))
        if prompt is None and not args and not interactive:
            await send_json_response(
                writer,
                400,
                {"ok": False, "error": "Provide 'prompt', 'args', or set 'interactive': true"},
            )
            return

        stream = bool(body.get("stream", False)) or (
            "text/event-stream" in req.headers.get("accept", "")
        )
        input_format = body.get("input_format")
        output_format = body.get("output_format")
        if interactive and not input_format:
            input_format = "stream-json"
            output_format = "stream-json"

        close_stdin = bool(body.get("close_stdin", not interactive))

        try:
            session = await self.sessions.create_agy_session(
                prompt=prompt if not interactive else None,
                cwd=body.get("cwd"),
                env=body.get("env"),
                args=args,
                skip_permissions=body.get("skip_permissions"),
                print_mode=bool(body.get("print_mode", True)),
                output_format=output_format,
                input_format=input_format,
                model=body.get("model"),
                effort=body.get("effort"),
                mode=body.get("mode"),
                conversation_id=body.get("conversation_id"),
                continue_last=bool(body.get("continue_last", False)),
                add_dirs=body.get("add_dirs"),
                use_pty=bool(body.get("use_pty", False)),
                timeout=body.get("timeout"),
                initial_stdin=body.get("stdin"),
                close_stdin=close_stdin,
            )
            if interactive and prompt is not None:
                await session.send_agy_turn(str(prompt), close_after=False)
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning(
                "HTTP agy policy rejection: route=%s cwd=%r reason=%s preview=%s",
                req.path,
                body.get("cwd"),
                safe_err,
                redact_for_audit_log(args or body.get("add_dirs")),
            )
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
            return
        except SandboxStorageError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.error("HTTP agy sandbox storage failure: route=%s reason=%s", req.path, safe_err)
            await send_json_response(writer, 503, {"ok": False, "error": safe_err})
            return
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
            )
            return

        if stream:
            await self._stream_session_sse(session, writer, after_seq=0)
        elif interactive and not bool(body.get("wait", False)):
            await send_json_response(
                writer,
                200,
                {"ok": True, **session.to_summary(include_output=False)},
                extra_headers={"X-Session-Id": session.session_id},
            )
        else:
            summary = await session.wait()
            await send_json_response(
                writer,
                200,
                {"ok": summary["returncode"] == 0, **summary},
                extra_headers={"X-Session-Id": session.session_id},
            )

    async def _handle_http_codex(
        self, req: HTTPRequest, writer: asyncio.StreamWriter
    ) -> None:
        try:
            body = self._parse_json_body(req)
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {
                    "ok": False,
                    "error": f"Invalid JSON: {redact_diagnostic_text(str(exc), self.config)}",
                },
            )
            return

        try:
            _reject_task_plugin_overrides(body)
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning("HTTP codex plugin override rejection: route=%s reason=%s", req.path, safe_err)
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
            return

        prompt = body.get("prompt")
        args = body.get("args") or []
        review = bool(body.get("review", False))
        if prompt is None and not args and not review:
            await send_json_response(
                writer,
                400,
                {"ok": False, "error": "Provide 'prompt', 'review': true, or 'args'"},
            )
            return

        stream = bool(body.get("stream", False)) or (
            "text/event-stream" in req.headers.get("accept", "")
        )
        try:
            session = await self.sessions.create_codex_session(
                prompt=prompt,
                cwd=body.get("cwd"),
                env=body.get("env"),
                args=args,
                skip_permissions=body.get("skip_permissions"),
                sandbox_mode=body.get("sandbox_mode"),
                json_events=bool(body.get("json_events", False)),
                model=body.get("model"),
                effort=body.get("effort"),
                search=bool(body.get("search", False)),
                session_id=body.get("session_id"),
                continue_last=bool(body.get("continue_last", False)),
                review=review,
                add_dirs=body.get("add_dirs"),
                use_pty=bool(body.get("use_pty", False)),
                timeout=body.get("timeout"),
                initial_stdin=body.get("stdin"),
                close_stdin=bool(body.get("close_stdin", True)),
            )
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning(
                "HTTP codex policy rejection: route=%s cwd=%r reason=%s preview=%s",
                req.path,
                body.get("cwd"),
                safe_err,
                redact_for_audit_log(args or body.get("add_dirs") or body.get("sandbox_mode")),
            )
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
            return
        except SandboxStorageError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.error("HTTP codex sandbox storage failure: route=%s reason=%s", req.path, safe_err)
            await send_json_response(writer, 503, {"ok": False, "error": safe_err})
            return
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
            )
            return

        if stream:
            await self._stream_session_sse(session, writer, after_seq=0)
        else:
            summary = await session.wait()
            await send_json_response(
                writer,
                200,
                {"ok": summary["returncode"] == 0, **summary},
                extra_headers={"X-Session-Id": session.session_id},
            )

    async def _handle_http_create_session(
        self, req: HTTPRequest, writer: asyncio.StreamWriter
    ) -> None:
        """Start a background interactive session and return its session_id immediately."""
        try:
            body = self._parse_json_body(req)
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {
                    "ok": False,
                    "error": f"Invalid JSON: {redact_diagnostic_text(str(exc), self.config)}",
                },
            )
            return

        session_type = body.get("type", "exec")
        try:
            _reject_task_plugin_overrides(body)
            if session_type == "agy":
                input_format = body.get("input_format", "stream-json")
                output_format = body.get("output_format", "stream-json")
                session = await self.sessions.create_agy_session(
                    prompt=None,
                    cwd=body.get("cwd"),
                    env=body.get("env"),
                    args=body.get("args"),
                    skip_permissions=body.get("skip_permissions"),
                    print_mode=bool(body.get("print_mode", True)),
                    output_format=output_format,
                    input_format=input_format,
                    model=body.get("model"),
                    effort=body.get("effort"),
                    mode=body.get("mode"),
                    conversation_id=body.get("conversation_id"),
                    continue_last=bool(body.get("continue_last", False)),
                    add_dirs=body.get("add_dirs"),
                    use_pty=bool(body.get("use_pty", False)),
                    timeout=body.get("timeout"),
                    close_stdin=False,
                )
                if body.get("prompt"):
                    await session.send_agy_turn(str(body["prompt"]), close_after=False)
            elif session_type == "codex":
                prompt = body.get("prompt")
                args = body.get("args") or []
                review = bool(body.get("review", False))
                if prompt is None and not args and not review:
                    await send_json_response(
                        writer,
                        400,
                        {"ok": False, "error": "Missing 'prompt' for session type 'codex'"},
                    )
                    return
                session = await self.sessions.create_codex_session(
                    prompt=prompt,
                    cwd=body.get("cwd"),
                    env=body.get("env"),
                    args=args,
                    skip_permissions=body.get("skip_permissions"),
                    sandbox_mode=body.get("sandbox_mode"),
                    json_events=bool(body.get("json_events", True)),
                    model=body.get("model"),
                    effort=body.get("effort"),
                    search=bool(body.get("search", False)),
                    session_id=body.get("session_id"),
                    continue_last=bool(body.get("continue_last", False)),
                    review=review,
                    add_dirs=body.get("add_dirs"),
                    use_pty=bool(body.get("use_pty", False)),
                    timeout=body.get("timeout"),
                    close_stdin=True,
                )
            else:
                command = body.get("command")
                if not command:
                    await send_json_response(
                        writer, 400, {"ok": False, "error": "Missing required field 'command'"}
                    )
                    return
                raw_shell = body.get("shell")
                shell_opt = None if raw_shell is None else bool(raw_shell)
                session = await self.sessions.create_session(
                    command=command,
                    cwd=body.get("cwd"),
                    env=body.get("env"),
                    shell=shell_opt,
                    use_pty=bool(body.get("use_pty", False)),
                    stream_json=bool(body.get("stream_json", False)),
                    timeout=body.get("timeout"),
                    initial_stdin=body.get("stdin"),
                    close_stdin=bool(body.get("close_stdin", False)),
                )
        except PermissionError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.warning(
                "HTTP session policy rejection: route=%s type=%s cwd=%r reason=%s preview=%s",
                req.path,
                session_type,
                body.get("cwd"),
                safe_err,
                redact_for_audit_log(body.get("command") or body.get("args") or body.get("add_dirs")),
            )
            await send_json_response(writer, 403, {"ok": False, "error": safe_err})
            return
        except SandboxStorageError as exc:
            safe_err = redact_diagnostic_text(str(exc), self.config)
            logger.error(
                "HTTP session sandbox storage failure: route=%s type=%s reason=%s",
                req.path,
                session_type,
                safe_err,
            )
            await send_json_response(writer, 503, {"ok": False, "error": safe_err})
            return
        except Exception as exc:
            await send_json_response(
                writer,
                400,
                {"ok": False, "error": redact_diagnostic_text(str(exc), self.config)},
            )
            return

        await send_json_response(
            writer,
            200,
            {"ok": True, **session.to_summary(include_output=False)},
            extra_headers={"X-Session-Id": session.session_id},
        )

    async def _handle_websocket(self, ws: WebSocketConnection, principal: str) -> None:
        """Full-duplex WebSocket session loop for bidirectional RPC with `dots`."""
        stream_tasks: Set[asyncio.Task[Any]] = set()

        async def _ws_keepalive_loop() -> None:
            while not ws.closed:
                await asyncio.sleep(20.0)
                if ws.closed:
                    break
                try:
                    await ws.send_ping(b"dots-gw-ping")
                except Exception:
                    break

        async def _forward_session_events(
            session: ExecutionSession, req_id: Optional[str], after_seq: int = 0
        ) -> None:
            try:
                async for ev in session.subscribe(after_seq=after_seq):
                    if ws.closed:
                        break
                    await ws.send_json(
                        {
                            "type": "session.event",
                            "request_id": req_id,
                            "session_id": session.session_id,
                            "event": ev.to_dict(),
                        }
                    )
            except Exception:
                pass

        ping_task = asyncio.create_task(_ws_keepalive_loop())
        await ws.send_json(
            {
                "type": "connected",
                "service": "dots-gateway",
                "version": __version__,
                "principal": principal,
            }
        )

        try:
            while not ws.closed:
                msg = await ws.recv_json()
                if msg is None:
                    break
                req_id = msg.get("id")
                action = str(msg.get("action", "")).strip()

                if action == "ping":
                    await ws.send_json(
                        {"type": "pong", "id": req_id, "timestamp": time.time()}
                    )
                    continue

                if action == "exec":
                    try:
                        _reject_task_plugin_overrides(msg)
                    except Exception as exc:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": redact_diagnostic_text(str(exc), self.config),
                            }
                        )
                        continue
                    command = msg.get("command")
                    if not command:
                        await ws.send_json(
                            {"type": "error", "id": req_id, "error": "Missing 'command'"}
                        )
                        continue
                    close_stdin = bool(
                        msg.get("close_stdin", not bool(msg.get("interactive", False)))
                    )
                    raw_shell = msg.get("shell")
                    shell_opt = None if raw_shell is None else bool(raw_shell)
                    try:
                        session = await self.sessions.create_session(
                            command=command,
                            cwd=msg.get("cwd"),
                            env=msg.get("env"),
                            shell=shell_opt,
                            use_pty=bool(msg.get("use_pty", False)),
                            stream_json=bool(msg.get("stream_json", False)),
                            timeout=msg.get("timeout"),
                            initial_stdin=msg.get("stdin"),
                            close_stdin=close_stdin,
                        )
                    except Exception as exc:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": redact_diagnostic_text(str(exc), self.config),
                            }
                        )
                        continue

                    await ws.send_json(
                        {
                            "type": "session.created",
                            "id": req_id,
                            "session_id": session.session_id,
                            "pid": session.pid,
                            "argv": session.argv,
                            "cwd": session.cwd,
                        }
                    )
                    t = asyncio.create_task(_forward_session_events(session, req_id))
                    stream_tasks.add(t)
                    t.add_done_callback(stream_tasks.discard)
                    continue

                if action == "agy":
                    interactive = bool(msg.get("interactive", False))
                    prompt = msg.get("prompt")
                    input_format = msg.get("input_format")
                    output_format = msg.get("output_format")
                    if interactive and not input_format:
                        input_format = "stream-json"
                        output_format = "stream-json"
                    close_stdin = bool(msg.get("close_stdin", not interactive))
                    try:
                        _reject_task_plugin_overrides(msg)
                        session = await self.sessions.create_agy_session(
                            prompt=prompt if not interactive else None,
                            cwd=msg.get("cwd"),
                            env=msg.get("env"),
                            args=msg.get("args"),
                            skip_permissions=msg.get("skip_permissions"),
                            print_mode=bool(msg.get("print_mode", True)),
                            output_format=output_format,
                            input_format=input_format,
                            model=msg.get("model"),
                            effort=msg.get("effort"),
                            mode=msg.get("mode"),
                            conversation_id=msg.get("conversation_id"),
                            continue_last=bool(msg.get("continue_last", False)),
                            add_dirs=msg.get("add_dirs"),
                            use_pty=bool(msg.get("use_pty", False)),
                            timeout=msg.get("timeout"),
                            initial_stdin=msg.get("stdin"),
                            close_stdin=close_stdin,
                        )
                        if interactive and prompt is not None:
                            await session.send_agy_turn(str(prompt), close_after=False)
                    except Exception as exc:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": redact_diagnostic_text(str(exc), self.config),
                            }
                        )
                        continue

                    await ws.send_json(
                        {
                            "type": "session.created",
                            "id": req_id,
                            "session_id": session.session_id,
                            "pid": session.pid,
                            "argv": session.argv,
                            "cwd": session.cwd,
                        }
                    )
                    t = asyncio.create_task(_forward_session_events(session, req_id))
                    stream_tasks.add(t)
                    t.add_done_callback(stream_tasks.discard)
                    continue

                if action == "codex":
                    try:
                        _reject_task_plugin_overrides(msg)
                        session = await self.sessions.create_codex_session(
                            prompt=msg.get("prompt"),
                            cwd=msg.get("cwd"),
                            env=msg.get("env"),
                            args=msg.get("args"),
                            skip_permissions=msg.get("skip_permissions"),
                            sandbox_mode=msg.get("sandbox_mode"),
                            json_events=bool(msg.get("json_events", True)),
                            model=msg.get("model"),
                            effort=msg.get("effort"),
                            search=bool(msg.get("search", False)),
                            session_id=msg.get("session_id"),
                            continue_last=bool(msg.get("continue_last", False)),
                            review=bool(msg.get("review", False)),
                            add_dirs=msg.get("add_dirs"),
                            use_pty=bool(msg.get("use_pty", False)),
                            timeout=msg.get("timeout"),
                            initial_stdin=msg.get("stdin"),
                            close_stdin=bool(msg.get("close_stdin", True)),
                        )
                    except Exception as exc:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": redact_diagnostic_text(str(exc), self.config),
                            }
                        )
                        continue

                    await ws.send_json(
                        {
                            "type": "session.created",
                            "id": req_id,
                            "session_id": session.session_id,
                            "pid": session.pid,
                            "argv": session.argv,
                            "cwd": session.cwd,
                        }
                    )
                    t = asyncio.create_task(_forward_session_events(session, req_id))
                    stream_tasks.add(t)
                    t.add_done_callback(stream_tasks.discard)
                    continue

                if action == "session.input":
                    session_id = str(msg.get("session_id", ""))
                    session = self.sessions.get_session(session_id)
                    if not session:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": f"Session '{session_id}' not found",
                            }
                        )
                        continue
                    close_after = bool(msg.get("close_stdin", False))
                    try:
                        if "prompt" in msg:
                            await session.send_agy_turn(
                                str(msg["prompt"]), close_after=close_after
                            )
                        else:
                            await session.write_stdin(
                                str(msg.get("data", "")), close_after=close_after
                            )
                        await ws.send_json(
                            {
                                "type": "session.input.ack",
                                "id": req_id,
                                "session_id": session_id,
                            }
                        )
                    except Exception as exc:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": redact_diagnostic_text(str(exc), self.config),
                            }
                        )
                    continue

                if action == "session.signal":
                    session_id = str(msg.get("session_id", ""))
                    session = self.sessions.get_session(session_id)
                    if not session:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": f"Session '{session_id}' not found",
                            }
                        )
                        continue
                    sig_name = str(msg.get("signal", "SIGTERM"))
                    await session.send_signal(sig_name)
                    await ws.send_json(
                        {
                            "type": "session.signal.ack",
                            "id": req_id,
                            "session_id": session_id,
                            "signal": sig_name,
                        }
                    )
                    continue

                if action == "session.resize":
                    session_id = str(msg.get("session_id", ""))
                    session = self.sessions.get_session(session_id)
                    if not session:
                        await ws.send_json(
                            {"type": "error", "id": req_id, "error": f"Session '{session_id}' not found"}
                        )
                        continue
                    try:
                        session.resize_pty(int(msg.get("rows", 24)), int(msg.get("cols", 80)))
                        await ws.send_json(
                            {"type": "session.resize.ack", "id": req_id, "session_id": session_id}
                        )
                    except Exception as exc:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": redact_diagnostic_text(str(exc), self.config),
                            }
                        )
                    continue

                if action == "session.subscribe":
                    session_id = str(msg.get("session_id", ""))
                    session = self.sessions.get_session(session_id)
                    if not session:
                        await ws.send_json(
                            {
                                "type": "error",
                                "id": req_id,
                                "error": f"Session '{session_id}' not found",
                            }
                        )
                        continue
                    after_seq = int(msg.get("after_seq", 0))
                    t = asyncio.create_task(
                        _forward_session_events(session, req_id, after_seq=after_seq)
                    )
                    stream_tasks.add(t)
                    t.add_done_callback(stream_tasks.discard)
                    continue

                if action == "session.list":
                    await ws.send_json(
                        {
                            "type": "session.list.result",
                            "id": req_id,
                            "sessions": self.sessions.list_sessions(),
                        }
                    )
                    continue

                if action.startswith("file."):
                    try:
                        if action == "file.read":
                            fres = await asyncio.to_thread(
                                self.files.read,
                                str(msg.get("path", "")),
                                msg.get("cwd"),
                                str(msg.get("encoding", "utf-8")),
                                int(msg.get("offset", 0)),
                                msg.get("limit"),
                            )
                        elif action == "file.write":
                            fres = await asyncio.to_thread(
                                self.files.write,
                                str(msg.get("path", "")),
                                str(msg.get("content", "")),
                                msg.get("cwd"),
                                str(msg.get("encoding", "utf-8")),
                                bool(msg.get("append", False)),
                                bool(msg.get("mkdir_parents", True)),
                                msg.get("mode"),
                            )
                        elif action == "file.patch":
                            fres = await asyncio.to_thread(
                                self.files.patch,
                                str(msg.get("path", "")),
                                msg.get("edits") or [],
                                msg.get("cwd"),
                            )
                        elif action == "file.list":
                            fres = await asyncio.to_thread(
                                self.files.list_dir,
                                str(msg.get("path", self.config.default_workdir)),
                                msg.get("cwd"),
                                bool(msg.get("recursive", False)),
                                int(msg.get("max_entries", 1000)),
                            )
                        elif action == "file.stat":
                            fres = await asyncio.to_thread(
                                self.files.stat, str(msg.get("path", "")), msg.get("cwd")
                            )
                        elif action == "file.delete":
                            fres = await asyncio.to_thread(
                                self.files.delete, str(msg.get("path", "")), msg.get("cwd")
                            )
                        else:
                            raise ValueError(f"Unknown file action '{action}'")
                        await ws.send_json({"type": f"{action}.result", "id": req_id, "ok": True, **fres})
                    except Exception as exc:
                        await ws.send_json({"type": "error", "id": req_id, "error": str(exc)})
                    continue

                await ws.send_json(
                    {
                        "type": "error",
                        "id": req_id,
                        "error": f"Unknown WebSocket action '{action}'",
                    }
                )
        finally:
            ping_task.cancel()
            for t in list(stream_tasks):
                t.cancel()
            await ws.close()
