"""Hardened pure-stdlib asyncio HTTP/1.1, SSE, and RFC 6455 WebSocket protocol helpers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Dict, Optional, Tuple

WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

MAX_REQUEST_LINE_BYTES = 8192
MAX_HEADER_LINE_BYTES = 8192
MAX_HEADER_COUNT = 64


@dataclass
class HTTPRequest:
    method: str
    path: str
    version: str
    headers: Dict[str, str]
    body: bytes
    client_ip: str


async def _read_bounded_line(
    reader: asyncio.StreamReader, max_bytes: int, timeout: float
) -> bytes:
    """Read a CRLF/LF-terminated line while strictly enforcing `max_bytes`."""
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return b""
        if len(exc.partial) > max_bytes:
            raise ValueError(f"HTTP line exceeds maximum length ({max_bytes} bytes)") from exc
        return exc.partial
    except asyncio.LimitOverrunError as exc:
        raise ValueError(f"HTTP line exceeds buffer limit ({max_bytes} bytes)") from exc

    if len(line) > max_bytes:
        raise ValueError(f"HTTP line exceeds maximum length ({max_bytes} bytes)")
    return line


async def _read_chunked_body(
    reader: asyncio.StreamReader, max_body_bytes: int, timeout: float = 60.0
) -> bytes:
    """Decode an HTTP/1.1 `Transfer-Encoding: chunked` request body safely."""
    chunks: list[bytes] = []
    total = 0
    while True:
        size_line = await _read_bounded_line(reader, 256, timeout=timeout)
        if not size_line:
            raise ValueError("Unexpected EOF in chunked request body")
        size_str = size_line.decode("latin-1").split(";", 1)[0].strip()
        try:
            chunk_len = int(size_str, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid chunk size {size_str!r}") from exc

        if chunk_len < 0:
            raise ValueError("Negative chunk size")
        if chunk_len == 0:
            # Consume trailing headers + final CRLF
            while True:
                trailer = await _read_bounded_line(reader, MAX_HEADER_LINE_BYTES, timeout=10.0)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            break

        total += chunk_len
        if total > max_body_bytes:
            raise ValueError(f"Chunked request body exceeds limit ({max_body_bytes} bytes)")

        data = await asyncio.wait_for(reader.readexactly(chunk_len), timeout=timeout)
        chunks.append(data)
        crlf = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if crlf != b"\r\n":
            raise ValueError("Missing CRLF after HTTP chunk")

    return b"".join(chunks)


async def read_http_request(
    reader: asyncio.StreamReader,
    client_ip: str,
    writer: Optional[asyncio.StreamWriter] = None,
    max_body_bytes: int = 32 * 1024 * 1024,
) -> Optional[HTTPRequest]:
    """Parse an incoming HTTP/1.1 request with anti-Slowloris bounds and chunked/100-continue support."""
    try:
        request_line = await _read_bounded_line(
            reader, MAX_REQUEST_LINE_BYTES, timeout=20.0
        )
    except asyncio.TimeoutError:
        return None
    if not request_line:
        return None

    line_str = request_line.decode("latin-1", errors="replace").strip()
    if not line_str:
        return None
    parts = line_str.split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"Malformed HTTP request line")
    method, path, version = parts

    headers: Dict[str, str] = {}
    header_count = 0
    while True:
        hline = await _read_bounded_line(reader, MAX_HEADER_LINE_BYTES, timeout=10.0)
        if not hline or hline in (b"\r\n", b"\n"):
            break
        header_count += 1
        if header_count > MAX_HEADER_COUNT:
            raise ValueError(f"Too many HTTP headers (>{MAX_HEADER_COUNT})")
        hstr = hline.decode("latin-1", errors="replace").strip()
        if ":" in hstr:
            k, v = hstr.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    # Handle Expect: 100-continue for standard HTTP clients (curl, httpx, etc.)
    if headers.get("expect", "").lower() == "100-continue" and writer is not None:
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        body = await _read_chunked_body(reader, max_body_bytes=max_body_bytes, timeout=60.0)
    else:
        content_length = int(headers.get("content-length", "0") or "0")
        if content_length < 0 or content_length > max_body_bytes:
            raise ValueError(f"Request body size invalid or too large ({content_length} bytes)")
        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(reader.readexactly(content_length), timeout=60.0)

    return HTTPRequest(
        method=method.upper(),
        path=path,
        version=version,
        headers=headers,
        body=body,
        client_ip=client_ip,
    )


async def send_json_response(
    writer: asyncio.StreamWriter,
    status_code: int,
    payload: Any,
    extra_headers: Optional[Dict[str, str]] = None,
) -> None:
    """Write a complete HTTP/1.1 JSON response."""
    body = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        phrase = HTTPStatus(status_code).phrase
    except ValueError:
        phrase = "OK"

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(body)),
        "Connection": "close",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if extra_headers:
        headers.update(extra_headers)

    header_lines = [f"HTTP/1.1 {status_code} {phrase}\r\n"]
    for k, v in headers.items():
        header_lines.append(f"{k}: {v}\r\n")
    header_lines.append("\r\n")

    writer.write("".join(header_lines).encode("latin-1") + body)
    await writer.drain()


async def send_empty_response(
    writer: asyncio.StreamWriter,
    status_code: int,
    extra_headers: Optional[Dict[str, str]] = None,
) -> None:
    """Write an HTTP/1.1 response with an empty body (e.g., 202 Accepted or 204 No Content)."""
    try:
        phrase = HTTPStatus(status_code).phrase
    except ValueError:
        phrase = "OK"

    headers = {
        "Content-Length": "0",
        "Connection": "close",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if extra_headers:
        headers.update(extra_headers)

    header_lines = [f"HTTP/1.1 {status_code} {phrase}\r\n"]
    for k, v in headers.items():
        header_lines.append(f"{k}: {v}\r\n")
    header_lines.append("\r\n")

    writer.write("".join(header_lines).encode("latin-1"))
    await writer.drain()


async def send_html_response(
    writer: asyncio.StreamWriter,
    status_code: int,
    html_text: str,
    extra_headers: Optional[Dict[str, str]] = None,
) -> None:
    """Write a complete HTTP/1.1 HTML response with strict security headers."""
    body = html_text.encode("utf-8")
    try:
        phrase = HTTPStatus(status_code).phrase
    except ValueError:
        phrase = "OK"

    headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": str(len(body)),
        "Connection": "close",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    }
    if extra_headers:
        headers.update(extra_headers)

    header_lines = [f"HTTP/1.1 {status_code} {phrase}\r\n"]
    for k, v in headers.items():
        header_lines.append(f"{k}: {v}\r\n")
    header_lines.append("\r\n")

    writer.write("".join(header_lines).encode("latin-1") + body)
    await writer.drain()


class SSEWriter:
    """Server-Sent Events (SSE) stream writer over HTTP/1.1 with NAT keep-alive support."""

    def __init__(
        self, writer: asyncio.StreamWriter, extra_headers: Optional[Dict[str, str]] = None
    ) -> None:
        self.writer = writer
        self.extra_headers = extra_headers or {}
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        lines = [
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream; charset=utf-8\r\n",
            "Cache-Control: no-cache, no-store\r\n",
            "Connection: keep-alive\r\n",
            "X-Accel-Buffering: no\r\n",
        ]
        for k, v in self.extra_headers.items():
            lines.append(f"{k}: {v}\r\n")
        lines.append("\r\n")
        self.writer.write("".join(lines).encode("latin-1"))
        await self.writer.drain()

    async def send_comment(self, comment: str = "keepalive") -> None:
        """Send an SSE comment frame (`: keepalive\\n\\n`) to prevent NAT idle disconnects."""
        async with self._lock:
            self.writer.write(f": {comment}\n\n".encode("utf-8"))
            await self.writer.drain()

    async def send_event(
        self, event: str, data: Any, event_id: Optional[str | int] = None
    ) -> None:
        async with self._lock:
            lines = []
            if event_id is not None:
                lines.append(f"id: {event_id}\n")
            if event:
                lines.append(f"event: {event}\n")
            serialized = (
                data
                if isinstance(data, str)
                else json.dumps(data, ensure_ascii=False)
            )
            for line in serialized.splitlines() or [""]:
                lines.append(f"data: {line}\n")
            lines.append("\n")
            self.writer.write("".join(lines).encode("utf-8"))
            await self.writer.drain()


class WebSocketConnection:
    """RFC 6455 WebSocket full-duplex connection over asyncio streams."""

    OPCODE_CONTINUATION = 0x0
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xA

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.reader = reader
        self.writer = writer
        self._write_lock = asyncio.Lock()
        self.closed = False

    @staticmethod
    def is_websocket_upgrade(req: HTTPRequest) -> bool:
        return (
            "upgrade" in req.headers.get("connection", "").lower()
            and req.headers.get("upgrade", "").lower() == "websocket"
            and bool(req.headers.get("sec-websocket-key"))
        )

    async def accept(self, req: HTTPRequest) -> None:
        ws_key = req.headers["sec-websocket-key"].strip()
        accept_raw = (ws_key + WS_MAGIC_GUID).encode("ascii")
        accept_token = base64.b64encode(hashlib.sha1(accept_raw).digest()).decode(
            "ascii"
        )
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_token}\r\n"
            "\r\n"
        )
        self.writer.write(response.encode("latin-1"))
        await self.writer.drain()

    async def _read_frame(self) -> Tuple[int, bool, bytes]:
        b1, b2 = await self.reader.readexactly(2)
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F

        if length == 126:
            ext = await self.reader.readexactly(2)
            (length,) = struct.unpack("!H", ext)
        elif length == 127:
            ext = await self.reader.readexactly(8)
            (length,) = struct.unpack("!Q", ext)

        if length > 32 * 1024 * 1024:
            raise ValueError(f"WebSocket frame too large: {length} bytes")

        mask_key = await self.reader.readexactly(4) if masked else b""
        payload = await self.reader.readexactly(length) if length > 0 else b""

        if masked and payload:
            unmasked = bytearray(length)
            for i in range(length):
                unmasked[i] = payload[i] ^ mask_key[i & 3]
            payload = bytes(unmasked)

        return opcode, fin, payload

    async def recv_json(self) -> Optional[Dict[str, Any]]:
        """Receive the next JSON message from the WebSocket client, handling Ping/Close/Continuation."""
        fragments: list[bytes] = []
        while not self.closed:
            try:
                opcode, fin, payload = await self._read_frame()
            except (asyncio.IncompleteReadError, ConnectionError):
                self.closed = True
                return None

            if opcode == self.OPCODE_CLOSE:
                await self.close()
                return None
            if opcode == self.OPCODE_PING:
                await self._send_frame(self.OPCODE_PONG, payload[:125])
                continue
            if opcode == self.OPCODE_PONG:
                continue

            if opcode in (self.OPCODE_TEXT, self.OPCODE_BINARY, self.OPCODE_CONTINUATION):
                fragments.append(payload)
                if sum(len(f) for f in fragments) > 32 * 1024 * 1024:
                    raise ValueError("Fragmented WebSocket message exceeds 32 MiB")
                if fin:
                    raw = b"".join(fragments)
                    fragments.clear()
                    text = raw.decode("utf-8", errors="replace")
                    return json.loads(text)
        return None

    async def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self.closed:
            return
        async with self._write_lock:
            if self.closed:
                return
            header = bytearray()
            header.append(0x80 | (opcode & 0x0F))
            length = len(payload)
            if length < 126:
                header.append(length)
            elif length < 65536:
                header.append(126)
                header.extend(struct.pack("!H", length))
            else:
                header.append(127)
                header.extend(struct.pack("!Q", length))

            self.writer.write(bytes(header) + payload)
            await self.writer.drain()

    async def send_ping(self, payload: bytes = b"keepalive") -> None:
        await self._send_frame(self.OPCODE_PING, payload[:125])

    async def send_json(self, data: Any) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        await self._send_frame(self.OPCODE_TEXT, payload)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        payload = struct.pack("!H", code) + reason.encode("utf-8")[:120]
        try:
            await self._send_frame(self.OPCODE_CLOSE, payload)
        except Exception:
            pass
        self.closed = True
        try:
            self.writer.close()
        except Exception:
            pass
