"""Authentication, IP allowlisting, and anti-brute-force protection for the Dots Gateway."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

from .config import GatewayConfig, verify_password_pbkdf2
from .oauth import OAuthServer

IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def extract_mcp_path_token(path: str) -> Optional[str]:
    """Extract secret capability token from `/mcp/<token>` or `/v1/mcp/<token>`."""
    cleaned = path.rstrip("/")
    for prefix in ("/mcp/", "/v1/mcp/"):
        if cleaned.startswith(prefix):
            rest = cleaned[len(prefix) :]
            if rest and "/" not in rest:
                return rest
    return None


@dataclass
class AuthResult:
    authenticated: bool
    principal: str = ""
    method: str = ""
    error: str = ""
    status_code: int = 200


def _parse_networks(entries: List[str]) -> List[IPNet]:
    nets: List[IPNet] = []
    for raw in entries:
        val = raw.strip()
        if not val:
            continue
        try:
            nets.append(ipaddress.ip_network(val, strict=False))
        except ValueError:
            pass
    return nets


def _ip_in_networks(ip_str: str, nets: List[IPNet]) -> bool:
    if not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.split("%")[0])
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
    except ValueError:
        return False

    for net in nets:
        if addr.version == net.version and addr in net:
            return True
    return False


class Authenticator:
    """Validates IP allowlists, Bearer Token, Basic Auth (async PBKDF2), or HMAC-SHA256 signatures."""

    MAX_TRACKED_IPS = 4096
    MAX_SEEN_NONCES = 8192

    def __init__(self, config: GatewayConfig, oauth: Optional[OAuthServer] = None) -> None:
        self.config = config
        self.oauth = oauth
        self._allowed_nets = _parse_networks(config.allowed_client_ips)
        self._trusted_proxy_nets = _parse_networks(config.trusted_proxies)
        # ip -> list of failure timestamps (bounded OrderedDict)
        self._failures: OrderedDict[str, List[float]] = OrderedDict()
        # nonce -> expiry timestamp (bounded OrderedDict)
        self._seen_nonces: OrderedDict[str, float] = OrderedDict()

    def resolve_client_ip(self, peer_ip: str, headers: Dict[str, str]) -> str:
        """Return effective client IP; only honors X-Forwarded-For when peer is a trusted proxy."""
        if not self._trusted_proxy_nets or not _ip_in_networks(peer_ip, self._trusted_proxy_nets):
            return peer_ip

        xff = headers.get("x-forwarded-for", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            for candidate in reversed(parts):
                if not _ip_in_networks(candidate, self._trusted_proxy_nets):
                    return candidate
        xri = headers.get("x-real-ip", "").strip()
        return xri or peer_ip

    def is_ip_allowed(self, client_ip: str) -> bool:
        """Check whether client_ip passes the optional `allowed_client_ips` CIDR allowlist."""
        if not self.config.allowed_client_ips:
            return True
        return _ip_in_networks(client_ip, self._allowed_nets)

    def _is_rate_limited(self, client_ip: str, now: float) -> bool:
        window = self.config.rate_limit_window_seconds
        history = self._failures.get(client_ip)
        if not history:
            return False
        fresh = [ts for ts in history if now - ts < window]
        if fresh:
            self._failures[client_ip] = fresh
            self._failures.move_to_end(client_ip)
        else:
            self._failures.pop(client_ip, None)
        return len(fresh) >= self.config.rate_limit_max_failures

    def _record_failure(self, client_ip: str, now: float) -> None:
        window = self.config.rate_limit_window_seconds
        history = [ts for ts in self._failures.get(client_ip, []) if now - ts < window]
        history.append(now)
        self._failures[client_ip] = history
        self._failures.move_to_end(client_ip)
        while len(self._failures) > self.MAX_TRACKED_IPS:
            self._failures.popitem(last=False)

    def _cleanup_nonces(self, now: float) -> None:
        if len(self._seen_nonces) >= self.MAX_SEEN_NONCES:
            expired = [k for k, exp in self._seen_nonces.items() if exp <= now]
            for k in expired:
                self._seen_nonces.pop(k, None)
            while len(self._seen_nonces) >= self.MAX_SEEN_NONCES:
                self._seen_nonces.popitem(last=False)

    def verify_token(self, candidate: str) -> bool:
        if not candidate:
            return False
        matched = False
        for valid_token in self.config.api_tokens:
            if secrets.compare_digest(candidate, valid_token):
                matched = True
        if matched:
            return True
        if self.oauth is not None and candidate.startswith("dots_at."):
            return self.oauth.verify_signed_token(candidate, expected_type="at") is not None
        return False

    def verify_user_password(self, username: str, password: str) -> bool:
        stored = self.config.users.get(username)
        if not stored:
            # Constant-work dummy hash check to prevent username timing enumeration
            verify_password_pbkdf2(password, "pbkdf2_sha256$0000000000000000$00")
            return False
        return verify_password_pbkdf2(password, stored)

    def verify_hmac(
        self,
        method: str,
        path: str,
        body: bytes,
        timestamp_str: str,
        nonce: str,
        signature: str,
        now: float,
    ) -> Tuple[bool, str]:
        if not self.config.hmac_secret:
            return False, "HMAC authentication is not configured"
        try:
            ts = float(timestamp_str)
        except ValueError:
            return False, "Invalid X-Timestamp header"

        if abs(now - ts) > self.config.hmac_max_skew_seconds:
            return False, "Timestamp outside allowed clock skew window"

        self._cleanup_nonces(now)
        if not nonce or len(nonce) < 8 or len(nonce) > 128:
            return False, "Missing or invalid X-Nonce header"
        if nonce in self._seen_nonces and self._seen_nonces[nonce] > now:
            return False, "Replay detected: nonce already used"

        body_hash = hashlib.sha256(body).hexdigest()
        canonical = f"{method.upper()}\n{path}\n{timestamp_str}\n{nonce}\n{body_hash}".encode(
            "utf-8"
        )
        expected_sig = hmac.new(
            self.config.hmac_secret.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest()

        provided = signature
        if provided.startswith("sha256="):
            provided = provided[len("sha256=") :]

        if not secrets.compare_digest(provided, expected_sig):
            return False, "HMAC signature mismatch"

        self._seen_nonces[nonce] = now + self.config.hmac_max_skew_seconds * 2
        self._seen_nonces.move_to_end(nonce)
        return True, ""

    async def authenticate(
        self,
        method: str,
        raw_path: str,
        headers: Dict[str, str],
        body: bytes = b"",
        client_ip: str = "unknown",
        bypass_ip_allowlist: bool = False,
    ) -> AuthResult:
        """Authenticate an incoming HTTP or WebSocket handshake request without blocking event loop."""
        hdrs = {k.lower(): v for k, v in headers.items()}
        effective_ip = self.resolve_client_ip(client_ip, hdrs)

        if not bypass_ip_allowlist and not self.is_ip_allowed(effective_ip):
            return AuthResult(
                authenticated=False,
                error=f"Client IP {effective_ip} is not in allowed_client_ips",
                status_code=403,
            )

        now = time.time()
        if self._is_rate_limited(effective_ip, now):
            return AuthResult(
                authenticated=False,
                error="Too many failed authentication attempts; try again later",
                status_code=429,
            )

        # 1. Check X-API-Token header
        api_token = hdrs.get("x-api-token", "").strip()
        if api_token:
            if self.verify_token(api_token):
                return AuthResult(True, principal="token-client", method="x-api-token")
            self._record_failure(effective_ip, now)
            return AuthResult(False, error="Invalid X-API-Token", status_code=401)

        # 2. Check Authorization header (Bearer, Basic, or raw token for SDKs such as xAI Grok)
        auth_header = hdrs.get("authorization", "").strip()
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
                if token.lower().startswith("bearer "):
                    token = token[7:].strip()
                if self.verify_token(token):
                    return AuthResult(True, principal="bearer-client", method="bearer")
                self._record_failure(effective_ip, now)
                return AuthResult(False, error="Invalid Bearer token", status_code=401)

            if auth_header.lower().startswith("basic "):
                b64_part = auth_header[6:].strip()
                try:
                    decoded = base64.b64decode(b64_part).decode("utf-8")
                    username, password = decoded.split(":", 1)
                except Exception:
                    self._record_failure(effective_ip, now)
                    return AuthResult(False, error="Malformed Basic auth header", status_code=401)
                # Offload 200k-round PBKDF2 to worker thread so event loop never stalls
                ok_pw = await asyncio.to_thread(self.verify_user_password, username, password)
                if ok_pw:
                    return AuthResult(True, principal=f"user:{username}", method="basic")
                self._record_failure(effective_ip, now)
                return AuthResult(False, error="Invalid username or password", status_code=401)

            if " " not in auth_header:
                if self.verify_token(auth_header):
                    return AuthResult(True, principal="bearer-client", method="authorization-token")
                self._record_failure(effective_ip, now)
                return AuthResult(False, error="Invalid Authorization token", status_code=401)

        # 3. Check HMAC-SHA256 headers
        sig = hdrs.get("x-signature", "").strip()
        if sig:
            ts_str = hdrs.get("x-timestamp", "").strip()
            nonce = hdrs.get("x-nonce", "").strip()
            parsed_path = urlparse(raw_path).path
            ok, err = self.verify_hmac(method, parsed_path, body, ts_str, nonce, sig, now)
            if ok:
                return AuthResult(True, principal="hmac-client", method="hmac-sha256")
            self._record_failure(effective_ip, now)
            return AuthResult(False, error=err, status_code=401)

        # 4. Secret capability path token (/mcp/<API_TOKEN>) for UIs without custom header fields
        path_tok = extract_mcp_path_token(urlparse(raw_path).path)
        if path_tok:
            if self.verify_token(path_tok):
                return AuthResult(True, principal="mcp-path-client", method="mcp-path-token")
            self._record_failure(effective_ip, now)
            return AuthResult(False, error="Invalid MCP path token", status_code=401)

        # 5. Optional query parameter ?token=... (disabled by default for security)
        if self.config.allow_query_token:
            parsed = urlparse(raw_path)
            if parsed.query:
                qs = parse_qs(parsed.query)
                q_token = (qs.get("token") or [""])[0]
                if q_token:
                    if self.verify_token(q_token):
                        return AuthResult(True, principal="query-token-client", method="query-token")
                    self._record_failure(effective_ip, now)
                    return AuthResult(False, error="Invalid query token", status_code=401)

        self._record_failure(effective_ip, now)
        return AuthResult(
            authenticated=False,
            error="Authentication required (Bearer Token, Basic Auth, X-API-Token, or HMAC Signature)",
            status_code=401,
        )
