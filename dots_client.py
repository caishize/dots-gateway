#!/usr/bin/env python3
"""Remote client SDK and CLI for `dots` (on OpenAI machines) to call the local Dots Gateway.

Zero external dependencies (uses Python 3 standard library only).
Supports:
- TLS 1.2+/1.3 with SHA-256 Certificate Fingerprint Pinning (`GATEWAY_TLS_FINGERPRINT`),
  Custom Private CA (`GATEWAY_CA_CERT`), and Mutual TLS (`GATEWAY_CLIENT_CERT` + `GATEWAY_CLIENT_KEY`)
- Bearer Token, Basic Auth (username/password), and HMAC-SHA256 request signing
- Synchronous & SSE-streaming HTTP calls (`/v1/exec`, `/v1/agy`, `/v1/sessions`, `/v1/files/*`)
- Full-duplex RFC 6455 WebSocket sessions (`/v1/ws`) with fragmented frame support & keepalive
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union


def load_client_config_file(explicit_path: Optional[str] = None) -> Dict[str, Any]:
    """Load optional client credentials JSON from DOTS_GATEWAY_CLIENT_CONFIG, PLUGIN_DATA, or ~/.config."""
    override = explicit_path or os.environ.get("DOTS_GATEWAY_CLIENT_CONFIG")
    if override:
        candidates: List[Path] = [Path(override).expanduser()]
    else:
        candidates = []
        if os.environ.get("PLUGIN_DATA"):
            candidates.append(Path(os.environ["PLUGIN_DATA"]).expanduser() / "client.json")
        candidates.append(Path.home() / ".config" / "dots-gateway" / "client.json")
        candidates.append(Path(__file__).resolve().parent / "client.json")

    for p in candidates:
        try:
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return {}


def _normalize_fingerprint(fp: Optional[str]) -> Optional[str]:
    if not fp:
        return None
    cleaned = fp.strip().lower().replace(":", "").replace(" ", "")
    if cleaned.startswith("sha256="):
        cleaned = cleaned[7:]
    return cleaned or None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that verifies peer X.509 DER SHA-256 digest before sending HTTP data."""

    def __init__(self, host: str, *, expected_sha256: str, **kwargs: Any) -> None:
        super().__init__(host, **kwargs)
        self._expected_sha256 = expected_sha256

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True) if self.sock else None
        if not der:
            self.close()
            raise ssl.SSLCertVerificationError("Peer did not present a TLS certificate")
        actual = hashlib.sha256(der).hexdigest()
        if not secrets.compare_digest(actual, self._expected_sha256):
            self.close()
            raise ssl.SSLCertVerificationError(
                f"TLS certificate SHA-256 mismatch: expected {self._expected_sha256}, got {actual}"
            )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, expected_sha256: str) -> None:
        super().__init__(context=context)
        self._ctx = context
        self._expected_sha256 = expected_sha256

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        def _conn_factory(host: str, **kwargs: Any) -> _PinnedHTTPSConnection:
            kwargs["context"] = self._ctx
            return _PinnedHTTPSConnection(
                host, expected_sha256=self._expected_sha256, **kwargs
            )

        return self.do_open(_conn_factory, req)


class DotsGatewayClient:
    """Client for interacting with the Dots Gateway over HTTPS/HTTP, SSE, and WSS/WS."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hmac_secret: Optional[str] = None,
        tls_fingerprint: Optional[str] = None,
        ca_cert: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        verify_tls: bool = True,
        load_config_file: bool = False,
        config_file_path: Optional[str] = None,
    ) -> None:
        file_cfg = load_client_config_file(config_file_path) if load_config_file else {}
        explicit_url = (
            base_url
            or os.environ.get("GATEWAY_URL")
            or file_cfg.get("url")
            or file_cfg.get("base_url")
        )
        self._explicitly_configured = bool(explicit_url)
        raw_url = str(explicit_url or "https://127.0.0.1:8765")
        self.base_url = raw_url.rstrip("/")
        self.token = token or os.environ.get("GATEWAY_TOKEN") or file_cfg.get("token")
        self.username = username or os.environ.get("GATEWAY_USER") or file_cfg.get("username")
        self.password = password or os.environ.get("GATEWAY_PASSWORD") or file_cfg.get("password")
        self.hmac_secret = (
            hmac_secret or os.environ.get("GATEWAY_HMAC_SECRET") or file_cfg.get("hmac_secret")
        )
        self.tls_fingerprint = _normalize_fingerprint(
            tls_fingerprint
            or os.environ.get("GATEWAY_TLS_FINGERPRINT")
            or file_cfg.get("tls_fingerprint")
        )
        self.ca_cert = ca_cert or os.environ.get("GATEWAY_CA_CERT") or file_cfg.get("ca_cert")
        self.client_cert = (
            client_cert or os.environ.get("GATEWAY_CLIENT_CERT") or file_cfg.get("client_cert")
        )
        self.client_key = (
            client_key or os.environ.get("GATEWAY_CLIENT_KEY") or file_cfg.get("client_key")
        )
        self.verify_tls = (
            bool(file_cfg["verify_tls"])
            if ("verify_tls" in file_cfg and verify_tls is True)
            else verify_tls
        )

    def has_credentials(self) -> bool:
        return bool(self.hmac_secret or self.token or (self.username and self.password is not None))

    def is_configured(self) -> bool:
        return self._explicitly_configured and self.has_credentials()

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.base_url.lower().startswith(("https://", "wss://")):
            return None

        if self.tls_fingerprint and not self.ca_cert:
            # Certificate identity is verified cryptographically via DER SHA-256 pinning
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif not self.verify_tls:
            ctx = ssl._create_unverified_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        elif self.ca_cert:
            ctx = ssl.create_default_context(cafile=self.ca_cert)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if self.tls_fingerprint:
                # Allow connecting via raw public IP even if SAN changed, since both CA + SHA256 pin match
                ctx.check_hostname = False
        else:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.client_cert:
            ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        return ctx

    def _open_url(self, req: urllib.request.Request, timeout: float) -> Any:
        ctx = self._ssl_context()
        if ctx is not None and self.tls_fingerprint:
            opener = urllib.request.build_opener(
                _PinnedHTTPSHandler(context=ctx, expected_sha256=self.tls_fingerprint)
            )
            return opener.open(req, timeout=timeout)
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)

    def _build_auth_headers(
        self, method: str, path: str, body: bytes = b""
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.hmac_secret:
            ts = f"{time.time():.3f}"
            nonce = secrets.token_hex(16)
            body_hash = hashlib.sha256(body).hexdigest()
            canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{body_hash}".encode(
                "utf-8"
            )
            sig = hmac.new(
                self.hmac_secret.encode("utf-8"), canonical, hashlib.sha256
            ).hexdigest()
            headers["X-Timestamp"] = ts
            headers["X-Nonce"] = nonce
            headers["X-Signature"] = f"sha256={sig}"
        elif self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password is not None:
            raw = f"{self.username}:{self.password}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(raw).decode('ascii')}"
        return headers

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: float = 600.0,
    ) -> Dict[str, Any]:
        body = (
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if payload is not None
            else b""
        )
        parsed_path = urllib.parse.urlparse(path).path
        headers = self._build_auth_headers(method, parsed_path, body)
        if payload is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"

        req = urllib.request.Request(
            url=f"{self.base_url}{path}",
            data=body if method.upper() != "GET" else None,
            headers=headers,
            method=method.upper(),
        )
        try:
            with self._open_url(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            try:
                err_json = json.loads(err_body)
            except Exception:
                err_json = {"ok": False, "error": err_body, "status_code": exc.code}
            err_json.setdefault("status_code", exc.code)
            raise RuntimeError(
                f"Gateway HTTP {exc.code}: {err_json.get('error', err_body)}"
            ) from exc

    def _stream_sse(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: float = 3600.0,
    ) -> Iterator[Dict[str, Any]]:
        body = (
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if payload is not None
            else b""
        )
        parsed_path = urllib.parse.urlparse(path).path
        headers = self._build_auth_headers(method, parsed_path, body)
        headers["Accept"] = "text/event-stream"
        if payload is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"

        req = urllib.request.Request(
            url=f"{self.base_url}{path}",
            data=body if method.upper() != "GET" else None,
            headers=headers,
            method=method.upper(),
        )
        with self._open_url(req, timeout=timeout) as resp:
            event_type = "message"
            data_lines: List[str] = []
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.startswith(":"):
                    # SSE keepalive comment (`: keepalive ...`), ignore
                    continue
                if not line:
                    if data_lines:
                        raw_data = "\n".join(data_lines)
                        data_lines.clear()
                        try:
                            yield json.loads(raw_data)
                        except json.JSONDecodeError:
                            yield {"type": event_type, "data": raw_data}
                    event_type = "message"
                elif line.startswith("event:"):
                    event_type = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip(" "))

    def health(self) -> Dict[str, Any]:
        return self._request_json("GET", "/v1/health", timeout=10.0)

    def policy(self) -> Dict[str, Any]:
        return self._request_json("GET", "/v1/policy", timeout=10.0)

    def mcp_request(
        self,
        payload: Any,
        session_id: Optional[str] = None,
        on_notification: Optional[Callable[[Dict[str, Any]], None]] = None,
        timeout: float = 3600.0,
    ) -> Tuple[Optional[Any], Optional[str]]:
        """Send a JSON-RPC 2.0 request/notification to `POST /mcp` over Streamable HTTP.

        Automatically handles:
        - TLS SHA-256 certificate pinning + HMAC-SHA256 / Bearer / Basic / mTLS auth
        - HTTP `202 Accepted` empty responses for notifications
        - Both `application/json` and SSE `text/event-stream` responses (forwarding live
          `notifications/progress` to `on_notification` while ignoring `: keepalive` comments)
        """
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        path = "/mcp"
        headers = self._build_auth_headers("POST", path, body)
        headers["Content-Type"] = "application/json; charset=utf-8"
        headers["Accept"] = "application/json, text/event-stream"
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        req = urllib.request.Request(
            url=f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with self._open_url(req, timeout=timeout) as resp:
                resp_sid = resp.headers.get("Mcp-Session-Id") or session_id
                status = getattr(resp, "status", 200)
                if status in (202, 204):
                    return None, resp_sid

                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "text/event-stream" in ctype:
                    responses: List[Any] = []
                    data_lines: List[str] = []
                    for raw_line in resp:
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        if line.startswith(":"):
                            continue
                        if not line:
                            if data_lines:
                                raw_data = "\n".join(data_lines)
                                data_lines.clear()
                                msg = json.loads(raw_data)
                                if isinstance(msg, dict) and "method" in msg and "id" not in msg:
                                    if on_notification is not None:
                                        on_notification(msg)
                                else:
                                    responses.append(msg)
                        elif line.startswith("data:"):
                            data_lines.append(line[5:].lstrip(" "))

                    if data_lines:
                        msg = json.loads("\n".join(data_lines))
                        if isinstance(msg, dict) and "method" in msg and "id" not in msg:
                            if on_notification is not None:
                                on_notification(msg)
                        else:
                            responses.append(msg)

                    if not responses:
                        return None, resp_sid
                    if isinstance(payload, list):
                        return responses, resp_sid
                    return responses[-1], resp_sid

                raw_bytes = resp.read()
                if not raw_bytes:
                    return None, resp_sid
                return json.loads(raw_bytes.decode("utf-8")), resp_sid
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            raise RuntimeError(f"Gateway MCP HTTP {exc.code}: {err_body}") from exc

    # ------------------------------------------------------------------
    # Command & Antigravity (`agy`) Execution
    # ------------------------------------------------------------------

    def exec_command(
        self,
        command: Union[str, Sequence[str]],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        shell: Optional[bool] = None,
        use_pty: bool = False,
        stdin: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Execute a command and return the full output when complete."""
        payload: Dict[str, Any] = {
            "command": list(command) if isinstance(command, (list, tuple)) else command,
            "use_pty": use_pty,
            "stream": False,
        }
        if shell is not None:
            payload["shell"] = shell
        if cwd:
            payload["cwd"] = cwd
        if env:
            payload["env"] = env
        if stdin is not None:
            payload["stdin"] = stdin
        if timeout is not None:
            payload["timeout"] = timeout
        return self._request_json("POST", "/v1/exec", payload, timeout=(timeout or 21600.0) + 30.0)

    def stream_exec(
        self,
        command: Union[str, Sequence[str]],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        shell: Optional[bool] = None,
        use_pty: bool = False,
        stdin: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Execute a command and yield real-time SSE events (`started`, `stdout`, `stderr`, `exit`)."""
        payload: Dict[str, Any] = {
            "command": list(command) if isinstance(command, (list, tuple)) else command,
            "use_pty": use_pty,
            "stream": True,
        }
        if shell is not None:
            payload["shell"] = shell
        if cwd:
            payload["cwd"] = cwd
        if env:
            payload["env"] = env
        if stdin is not None:
            payload["stdin"] = stdin
        if timeout is not None:
            payload["timeout"] = timeout
        yield from self._stream_sse("POST", "/v1/exec", payload, timeout=(timeout or 21600.0) + 30.0)

    def run_agy(
        self,
        prompt: Optional[str] = None,
        cwd: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: bool = True,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        mode: Optional[str] = None,
        conversation_id: Optional[str] = None,
        continue_last: bool = False,
        output_format: Optional[str] = None,
        add_dirs: Optional[Sequence[str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Invoke `agy --dangerously-skip-permissions` on the gateway machine and return result."""
        payload: Dict[str, Any] = {
            "prompt": prompt,
            "args": list(args or []),
            "skip_permissions": skip_permissions,
            "continue_last": continue_last,
            "stream": False,
        }
        if cwd:
            payload["cwd"] = cwd
        if model:
            payload["model"] = model
        if effort:
            payload["effort"] = effort
        if mode:
            payload["mode"] = mode
        if conversation_id:
            payload["conversation_id"] = conversation_id
        if output_format:
            payload["output_format"] = output_format
        if add_dirs:
            payload["add_dirs"] = list(add_dirs)
        if timeout is not None:
            payload["timeout"] = timeout
        return self._request_json("POST", "/v1/agy", payload, timeout=(timeout or 28800.0) + 30.0)

    def list_agy_models(self, refresh: bool = False) -> Dict[str, Any]:
        """List available Antigravity (`agy`) models and current gateway default model (`GET /v1/agy/models`)."""
        suffix = "?refresh=1" if refresh else ""
        return self._request_json("GET", f"/v1/agy/models{suffix}", timeout=75.0)

    def stream_agy(
        self,
        prompt: Optional[str] = None,
        cwd: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: bool = True,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        mode: Optional[str] = None,
        conversation_id: Optional[str] = None,
        continue_last: bool = False,
        output_format: Optional[str] = "stream-json",
        add_dirs: Optional[Sequence[str]] = None,
        timeout: Optional[float] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Invoke `agy --dangerously-skip-permissions` and stream real-time SSE events."""
        payload: Dict[str, Any] = {
            "prompt": prompt,
            "args": list(args or []),
            "skip_permissions": skip_permissions,
            "continue_last": continue_last,
            "stream": True,
        }
        if cwd:
            payload["cwd"] = cwd
        if model:
            payload["model"] = model
        if effort:
            payload["effort"] = effort
        if mode:
            payload["mode"] = mode
        if conversation_id:
            payload["conversation_id"] = conversation_id
        if output_format:
            payload["output_format"] = output_format
        if add_dirs:
            payload["add_dirs"] = list(add_dirs)
        if timeout is not None:
            payload["timeout"] = timeout
        yield from self._stream_sse("POST", "/v1/agy", payload, timeout=(timeout or 28800.0) + 30.0)

    def run_codex(
        self,
        prompt: Optional[str] = None,
        cwd: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: bool = True,
        sandbox_mode: str = "workspace-write",
        json_events: bool = False,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        search: bool = False,
        session_id: Optional[str] = None,
        continue_last: bool = False,
        review: bool = False,
        add_dirs: Optional[Sequence[str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Invoke `codex -a never -s <sandbox_mode> exec` on the gateway machine and return result."""
        payload: Dict[str, Any] = {
            "prompt": prompt,
            "args": list(args or []),
            "skip_permissions": skip_permissions,
            "sandbox_mode": sandbox_mode,
            "json_events": json_events,
            "search": search,
            "continue_last": continue_last,
            "review": review,
            "stream": False,
        }
        if cwd:
            payload["cwd"] = cwd
        if model:
            payload["model"] = model
        if effort:
            payload["effort"] = effort
        if session_id:
            payload["session_id"] = session_id
        if add_dirs:
            payload["add_dirs"] = list(add_dirs)
        if timeout is not None:
            payload["timeout"] = timeout
        return self._request_json("POST", "/v1/codex", payload, timeout=(timeout or 28800.0) + 30.0)

    def stream_codex(
        self,
        prompt: Optional[str] = None,
        cwd: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: bool = True,
        sandbox_mode: str = "workspace-write",
        json_events: bool = True,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        search: bool = False,
        session_id: Optional[str] = None,
        continue_last: bool = False,
        review: bool = False,
        add_dirs: Optional[Sequence[str]] = None,
        timeout: Optional[float] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Invoke `codex exec` and stream real-time SSE events."""
        payload: Dict[str, Any] = {
            "prompt": prompt,
            "args": list(args or []),
            "skip_permissions": skip_permissions,
            "sandbox_mode": sandbox_mode,
            "json_events": json_events,
            "search": search,
            "continue_last": continue_last,
            "review": review,
            "stream": True,
        }
        if cwd:
            payload["cwd"] = cwd
        if model:
            payload["model"] = model
        if effort:
            payload["effort"] = effort
        if session_id:
            payload["session_id"] = session_id
        if add_dirs:
            payload["add_dirs"] = list(add_dirs)
        if timeout is not None:
            payload["timeout"] = timeout
        yield from self._stream_sse("POST", "/v1/codex", payload, timeout=(timeout or 28800.0) + 30.0)

    def create_session(self, **kwargs: Any) -> Dict[str, Any]:
        """Start an interactive session via REST (`POST /v1/sessions`)."""
        return self._request_json("POST", "/v1/sessions", kwargs)

    def stream_session_events(
        self, session_id: str, after_seq: int = 0, timeout: float = 28800.0
    ) -> Iterator[Dict[str, Any]]:
        """Resume/subscribe to SSE events of a running or completed session from `after_seq`."""
        yield from self._stream_sse(
            "GET", f"/v1/sessions/{session_id}/events?after_seq={after_seq}", timeout=timeout
        )

    def send_session_input(
        self,
        session_id: str,
        data: Optional[str] = None,
        prompt: Optional[str] = None,
        close_stdin: bool = False,
    ) -> Dict[str, Any]:
        """Send stdin or a new `agy` turn to a running session via REST."""
        body: Dict[str, Any] = {"close_stdin": close_stdin}
        if prompt is not None:
            body["prompt"] = prompt
        if data is not None:
            body["data"] = data
        return self._request_json("POST", f"/v1/sessions/{session_id}/input", body)

    def send_session_signal(self, session_id: str, sig_name: str = "SIGTERM") -> Dict[str, Any]:
        return self._request_json(
            "POST", f"/v1/sessions/{session_id}/signal", {"signal": sig_name}
        )

    def get_session(self, session_id: str, after_seq: int = 0) -> Dict[str, Any]:
        return self._request_json("GET", f"/v1/sessions/{session_id}?after_seq={after_seq}")

    # ------------------------------------------------------------------
    # Workspace File Operations (`/v1/files/*`)
    # ------------------------------------------------------------------

    def stat_file(self, path: str, cwd: Optional[str] = None) -> Dict[str, Any]:
        q: Dict[str, str] = {"path": path}
        if cwd:
            q["cwd"] = cwd
        return self._request_json("GET", f"/v1/files/stat?{urllib.parse.urlencode(q)}")

    def list_dir(
        self,
        path: str,
        cwd: Optional[str] = None,
        recursive: bool = False,
        max_entries: int = 1000,
    ) -> Dict[str, Any]:
        q: Dict[str, str] = {
            "path": path,
            "recursive": "true" if recursive else "false",
            "max_entries": str(max_entries),
        }
        if cwd:
            q["cwd"] = cwd
        return self._request_json("GET", f"/v1/files/list?{urllib.parse.urlencode(q)}")

    def read_file(
        self,
        path: str,
        cwd: Optional[str] = None,
        encoding: str = "utf-8",
        offset: int = 0,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        q: Dict[str, str] = {"path": path, "encoding": encoding, "offset": str(offset)}
        if cwd:
            q["cwd"] = cwd
        if limit is not None:
            q["limit"] = str(limit)
        return self._request_json("GET", f"/v1/files/read?{urllib.parse.urlencode(q)}")

    def read_bytes(self, path: str, cwd: Optional[str] = None) -> bytes:
        res = self.read_file(path, cwd=cwd, encoding="base64")
        return base64.b64decode(res["content"])

    def write_file(
        self,
        path: str,
        content: str,
        cwd: Optional[str] = None,
        encoding: str = "utf-8",
        append: bool = False,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "path": path,
            "content": content,
            "encoding": encoding,
            "append": append,
        }
        if cwd:
            body["cwd"] = cwd
        if mode is not None:
            body["mode"] = mode
        return self._request_json("POST", "/v1/files/write", body)

    def write_bytes(
        self,
        path: str,
        data: bytes,
        cwd: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        b64 = base64.b64encode(data).decode("ascii")
        return self.write_file(path, b64, cwd=cwd, encoding="base64", mode=mode)

    def patch_file(
        self,
        path: str,
        edits: List[Dict[str, str]],
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"path": path, "edits": edits}
        if cwd:
            body["cwd"] = cwd
        return self._request_json("POST", "/v1/files/patch", body)

    def delete_file(self, path: str, cwd: Optional[str] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"path": path}
        if cwd:
            body["cwd"] = cwd
        return self._request_json("POST", "/v1/files/delete", body)

    def connect_websocket(self) -> "DotsWebSocketSession":
        """Create an async full-duplex WebSocket session context manager."""
        return DotsWebSocketSession(self)


class DotsWebSocketSession:
    """Async full-duplex RFC 6455 WebSocket client with TLS pinning & frame reassembly."""

    def __init__(self, client: DotsGatewayClient) -> None:
        self.client = client
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._write_lock = asyncio.Lock()
        self.closed = False
        self.welcome: Dict[str, Any] = {}

    async def __aenter__(self) -> "DotsWebSocketSession":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    async def connect(self) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(self.client.base_url)
        use_tls = parsed.scheme.lower() in ("https", "wss")
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if use_tls else 80)

        ssl_ctx = self.client._ssl_context() if use_tls else None
        server_hostname = (
            host
            if (use_tls and ssl_ctx is not None and ssl_ctx.check_hostname)
            else None
        )
        self.reader, self.writer = await asyncio.open_connection(
            host=host,
            port=port,
            ssl=ssl_ctx,
            server_hostname=server_hostname,
            limit=16 * 1024 * 1024,
        )

        # Verify SHA-256 certificate pin BEFORE sending HTTP upgrade headers/tokens
        if use_tls and self.client.tls_fingerprint:
            ssl_obj = self.writer.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            actual = hashlib.sha256(der).hexdigest() if der else ""
            if not der or not secrets.compare_digest(actual, self.client.tls_fingerprint):
                self.writer.close()
                await self.writer.wait_closed()
                raise ssl.SSLCertVerificationError(
                    f"WebSocket TLS certificate SHA-256 mismatch: expected {self.client.tls_fingerprint}, got {actual}"
                )

        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        ws_path = "/v1/ws"
        auth_headers = self.client._build_auth_headers("GET", ws_path, b"")

        lines = [
            f"GET {ws_path} HTTP/1.1\r\n",
            f"Host: {host}:{port}\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            f"Sec-WebSocket-Key: {ws_key}\r\n",
            "Sec-WebSocket-Version: 13\r\n",
        ]
        for k, v in auth_headers.items():
            lines.append(f"{k}: {v}\r\n")
        lines.append("\r\n")

        self.writer.write("".join(lines).encode("latin-1"))
        await self.writer.drain()

        status_line = await self.reader.readline()
        if not status_line.startswith(b"HTTP/1.1 101"):
            rest = await self.reader.read(4096)
            raise RuntimeError(
                f"WebSocket handshake failed: {status_line.decode('latin-1', 'replace').strip()} {rest.decode('utf-8', 'replace')}"
            )
        while True:
            hline = await self.reader.readline()
            if not hline or hline in (b"\r\n", b"\n"):
                break

        first_msg = await self.recv_json()
        if first_msg:
            self.welcome = first_msg
        return self.welcome

    async def _send_masked_frame(self, opcode: int, payload: bytes) -> None:
        if self.closed or self.writer is None:
            return
        async with self._write_lock:
            header = bytearray()
            header.append(0x80 | (opcode & 0x0F))
            length = len(payload)
            if length < 126:
                header.append(0x80 | length)
            elif length < 65536:
                header.append(0x80 | 126)
                header.extend(struct.pack("!H", length))
            else:
                header.append(0x80 | 127)
                header.extend(struct.pack("!Q", length))

            mask_key = os.urandom(4)
            header.extend(mask_key)
            masked = bytearray(length)
            for i in range(length):
                masked[i] = payload[i] ^ mask_key[i & 3]

            self.writer.write(bytes(header) + bytes(masked))
            await self.writer.drain()

    async def send_json(self, message: Dict[str, Any]) -> None:
        raw = json.dumps(message, ensure_ascii=False).encode("utf-8")
        await self._send_masked_frame(0x1, raw)

    async def recv_json(self) -> Optional[Dict[str, Any]]:
        if self.reader is None:
            return None
        fragments: list[bytes] = []
        while not self.closed:
            try:
                b1, b2 = await self.reader.readexactly(2)
            except (asyncio.IncompleteReadError, ConnectionError):
                self.closed = True
                return None
            fin = bool(b1 & 0x80)
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", await self.reader.readexactly(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", await self.reader.readexactly(8))
            mask_key = await self.reader.readexactly(4) if masked else b""
            payload = await self.reader.readexactly(length) if length > 0 else b""
            if masked and payload:
                payload = bytes(payload[i] ^ mask_key[i & 3] for i in range(length))

            if opcode == 0x8:  # CLOSE
                self.closed = True
                return None
            if opcode == 0x9:  # PING
                await self._send_masked_frame(0xA, payload[:125])
                continue
            if opcode == 0xA:  # PONG
                continue
            if opcode in (0x0, 0x1, 0x2):  # CONTINUATION / TEXT / BINARY
                fragments.append(payload)
                if fin:
                    raw = b"".join(fragments)
                    fragments.clear()
                    return json.loads(raw.decode("utf-8", errors="replace"))
        return None

    async def close(self) -> None:
        if self.closed:
            return
        try:
            await self._send_masked_frame(0x8, struct.pack("!H", 1000))
        except Exception:
            pass
        self.closed = True
        if self.writer is not None:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Dots Remote Client for Local Gateway")
    parser.add_argument(
        "--url",
        default=None,
        help="Gateway base URL (default: GATEWAY_URL or client.json or https://127.0.0.1:8765)",
    )
    parser.add_argument("--token", default=os.environ.get("GATEWAY_TOKEN"), help="Bearer Token")
    parser.add_argument("--user", default=os.environ.get("GATEWAY_USER"), help="Basic Auth username")
    parser.add_argument(
        "--password", default=os.environ.get("GATEWAY_PASSWORD"), help="Basic Auth password"
    )
    parser.add_argument(
        "--hmac-secret", default=os.environ.get("GATEWAY_HMAC_SECRET"), help="HMAC-SHA256 secret"
    )
    parser.add_argument(
        "--tls-fingerprint",
        default=os.environ.get("GATEWAY_TLS_FINGERPRINT"),
        help="Expected server certificate SHA-256 fingerprint (MITM-proof pinning)",
    )
    parser.add_argument(
        "--ca-cert", default=os.environ.get("GATEWAY_CA_CERT"), help="Root CA PEM file path"
    )
    parser.add_argument(
        "--client-cert",
        default=os.environ.get("GATEWAY_CLIENT_CERT"),
        help="mTLS client certificate PEM path",
    )
    parser.add_argument(
        "--client-key",
        default=os.environ.get("GATEWAY_CLIENT_KEY"),
        help="mTLS client key PEM path",
    )
    parser.add_argument("--cwd", default=None, help="Working directory on gateway host")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="Check gateway health")
    sub.add_parser("policy", help="Inspect gateway command policy")

    p_exec = sub.add_parser("exec", help="Execute a command on the gateway")
    p_exec.add_argument("command", help="Command string to run")
    p_exec.add_argument("--shell", action="store_true", default=None, help="Force shell execution")
    p_exec.add_argument("--no-stream", action="store_true", help="Wait instead of streaming")

    p_agy = sub.add_parser("agy", help="Run `agy --dangerously-skip-permissions` on the gateway")
    p_agy.add_argument("prompt", help="Prompt to send to agy")
    p_agy.add_argument("--model", default=None, help="Model override")
    p_agy.add_argument("--effort", default=None, help="Reasoning effort (low|medium|high|xhigh|max)")
    p_agy.add_argument("--conversation", default=None, help="Resume conversation ID")
    p_agy.add_argument("-c", "--continue-last", action="store_true", help="Continue last conversation")
    p_agy.add_argument("--output-format", default="text", help="Output format (text|json|stream-json)")
    p_agy.add_argument("--no-stream", action="store_true", help="Wait instead of streaming")

    p_agy_models = sub.add_parser("agy-models", help="List available agy models and default selection")
    p_agy_models.add_argument("--refresh", action="store_true", help="Bypass server cache")

    p_codex = sub.add_parser("codex", help="Run OpenAI Codex (`codex exec`) on the gateway")
    p_codex.add_argument("prompt", nargs="?", default=None, help="Task prompt for codex")
    p_codex.add_argument("-m", "--model", default=None, help="Model override")
    p_codex.add_argument("-e", "--effort", default=None, help="Effort level (low|medium|high|xhigh)")
    p_codex.add_argument(
        "-s", "--sandbox-mode", default="workspace-write", help="Sandbox mode (read-only|workspace-write)"
    )
    p_codex.add_argument("--session", default=None, help="Resume Codex session ID")
    p_codex.add_argument("-c", "--continue-last", action="store_true", help="Resume last Codex session")
    p_codex.add_argument("--review", action="store_true", help="Run `codex exec review`")
    p_codex.add_argument("--json", action="store_true", help="Emit JSONL events")
    p_codex.add_argument("--no-stream", action="store_true", help="Wait instead of streaming")

    p_ls = sub.add_parser("ls", help="List remote workspace directory")
    p_ls.add_argument("path", nargs="?", default=".", help="Remote directory path")
    p_ls.add_argument("-r", "--recursive", action="store_true", help="Recursive listing")

    p_up = sub.add_parser("upload", help="Upload a local file to the remote workspace")
    p_up.add_argument("local_path", help="Local file path")
    p_up.add_argument("remote_path", help="Destination path on gateway")

    p_dl = sub.add_parser("download", help="Download a remote file to local disk")
    p_dl.add_argument("remote_path", help="Source path on gateway")
    p_dl.add_argument("local_path", help="Destination local path")

    args = parser.parse_args()
    client = DotsGatewayClient(
        base_url=args.url,
        token=args.token,
        username=args.user,
        password=args.password,
        hmac_secret=args.hmac_secret,
        tls_fingerprint=args.tls_fingerprint,
        ca_cert=args.ca_cert,
        client_cert=args.client_cert,
        client_key=args.client_key,
        load_config_file=True,
    )

    if args.cmd == "health":
        print(json.dumps(client.health(), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "policy":
        print(json.dumps(client.policy(), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "ls":
        print(
            json.dumps(
                client.list_dir(args.path, cwd=args.cwd, recursive=args.recursive),
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if args.cmd == "upload":
        raw = Path(args.local_path).read_bytes()
        res = client.write_bytes(args.remote_path, raw, cwd=args.cwd)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "download":
        raw = client.read_bytes(args.remote_path, cwd=args.cwd)
        dest = Path(args.local_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        print(json.dumps({"ok": True, "local_path": str(dest), "bytes": len(raw)}, indent=2))
        return 0

    if args.cmd == "exec":
        if args.no_stream:
            res = client.exec_command(args.command, cwd=args.cwd, shell=args.shell)
            sys.stdout.write(res.get("stdout", ""))
            sys.stderr.write(res.get("stderr", ""))
            return int(res.get("returncode") or 0)
        rc = 0
        for ev in client.stream_exec(args.command, cwd=args.cwd, shell=args.shell):
            etype = ev.get("type")
            if etype == "stdout":
                sys.stdout.write(str(ev.get("data", "")))
                sys.stdout.flush()
            elif etype == "stderr":
                sys.stderr.write(str(ev.get("data", "")))
                sys.stderr.flush()
            elif etype == "exit":
                rc = int((ev.get("data") or {}).get("returncode") or 0)
        return rc

    if args.cmd == "agy":
        if args.no_stream:
            res = client.run_agy(
                prompt=args.prompt,
                cwd=args.cwd,
                model=args.model,
                effort=args.effort,
                conversation_id=args.conversation,
                continue_last=args.continue_last,
                output_format=args.output_format,
            )
            sys.stdout.write(res.get("stdout", ""))
            sys.stderr.write(res.get("stderr", ""))
            return int(res.get("returncode") or 0)
        rc = 0
        for ev in client.stream_agy(
            prompt=args.prompt,
            cwd=args.cwd,
            model=args.model,
            effort=args.effort,
            conversation_id=args.conversation,
            continue_last=args.continue_last,
            output_format=args.output_format,
        ):
            etype = ev.get("type")
            if etype == "stdout":
                sys.stdout.write(str(ev.get("data", "")))
                sys.stdout.flush()
            elif etype == "stderr":
                sys.stderr.write(str(ev.get("data", "")))
                sys.stderr.flush()
            elif etype == "exit":
                rc = int((ev.get("data") or {}).get("returncode") or 0)
        return rc

    if args.cmd == "agy-models":
        print(json.dumps(client.list_agy_models(refresh=args.refresh), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "codex":
        if args.no_stream:
            res = client.run_codex(
                prompt=args.prompt,
                cwd=args.cwd,
                sandbox_mode=args.sandbox_mode,
                json_events=args.json,
                model=args.model,
                effort=args.effort,
                session_id=args.session,
                continue_last=args.continue_last,
                review=args.review,
            )
            sys.stdout.write(res.get("stdout", ""))
            sys.stderr.write(res.get("stderr", ""))
            return int(res.get("returncode") or 0)
        rc = 0
        for ev in client.stream_codex(
            prompt=args.prompt,
            cwd=args.cwd,
            sandbox_mode=args.sandbox_mode,
            json_events=args.json,
            model=args.model,
            effort=args.effort,
            session_id=args.session,
            continue_last=args.continue_last,
            review=args.review,
        ):
            etype = ev.get("type")
            if etype == "stdout":
                sys.stdout.write(str(ev.get("data", "")))
                sys.stdout.flush()
            elif etype == "stderr":
                sys.stderr.write(str(ev.get("data", "")))
                sys.stderr.flush()
            elif etype == "exit":
                rc = int((ev.get("data") or {}).get("returncode") or 0)
        return rc

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
