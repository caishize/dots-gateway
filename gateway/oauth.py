"""Built-in MCP OAuth 2.1 Authorization Server (RFC 9728, RFC 8414, RFC 7591, PKCE S256).

Enables zero-install Remote MCP clients (such as OpenAI `dots` / ChatGPT / Codex) to
authenticate via standard OAuth 2.1 Authorization Code + PKCE (`S256`) and Dynamic Client
Registration, backed by the gateway's existing access tokens / PBKDF2 user credentials and
stateless HMAC-SHA256 signed access & refresh tokens that survive service restarts.
"""

from __future__ import annotations

import base64
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import hmac
import html
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .config import GatewayConfig, verify_password_pbkdf2

ACCESS_TOKEN_TTL_SECONDS = 86400          # 24 hours
REFRESH_TOKEN_TTL_SECONDS = 90 * 86400    # 90 days
AUTH_CODE_TTL_SECONDS = 300               # 5 minutes
CSRF_TTL_SECONDS = 900                    # 15 minutes
MAX_PENDING_AUTH_CODES = 1024


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(val: str) -> bytes:
    padded = val + "=" * (-len(val) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _is_valid_redirect_uri(uri: str) -> bool:
    """Allow HTTPS redirect URIs or loopback HTTP URIs per OAuth 2.1 Section 4.1.1."""
    if not uri or len(uri) > 2048:
        return False
    parsed = urlparse(uri)
    if parsed.fragment:
        return False
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme == "https" and host:
        return True
    if scheme == "http" and host in ("localhost", "127.0.0.1", "::1"):
        return True
    return False


def _append_query_params(uri: str, extra: Dict[str, str]) -> str:
    parsed = urlparse(uri)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    flat: List[Tuple[str, str]] = []
    for k, vals in existing.items():
        for v in vals:
            flat.append((k, v))
    for k, v in extra.items():
        if v != "":
            flat.append((k, v))
    return urlunparse(parsed._replace(query=urlencode(flat)))


@dataclass
class PendingAuthCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str
    resource: str
    principal: str
    expires_at: float


class OAuthServer:
    """Stateless-token MCP OAuth 2.1 provider with PKCE S256 & Dynamic Client Registration."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self._fallback_secret = secrets.token_hex(32)
        self._codes: OrderedDict[str, PendingAuthCode] = OrderedDict()

    def _signing_key(self) -> bytes:
        base = self.config.hmac_secret or (
            self.config.api_tokens[0] if self.config.api_tokens else self._fallback_secret
        )
        return hashlib.sha256(f"dots-gateway-oauth-v1:{base}".encode("utf-8")).digest()

    def _derive_client_secret(self, client_id: str) -> str:
        digest = hmac.new(
            self._signing_key(), f"client_secret:{client_id}".encode("utf-8"), hashlib.sha256
        ).digest()
        return "dcs_" + _b64url_encode(digest)

    def _mint_signed_token(self, token_type: str, subject: str, scope: str, ttl: int) -> str:
        now = int(time.time())
        payload = {
            "typ": token_type,
            "sub": subject,
            "scp": scope or "mcp",
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_urlsafe(12),
        }
        body_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = hmac.new(self._signing_key(), body_b64.encode("ascii"), hashlib.sha256).digest()
        prefix = "dots_at" if token_type == "at" else "dots_rt"
        return f"{prefix}.{body_b64}.{_b64url_encode(sig)}"

    def verify_signed_token(
        self, token: str, expected_type: str = "at"
    ) -> Optional[Dict[str, Any]]:
        prefix = "dots_at." if expected_type == "at" else "dots_rt."
        if not token or not token.startswith(prefix):
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        _, body_b64, sig_b64 = parts
        try:
            expected_sig = hmac.new(
                self._signing_key(), body_b64.encode("ascii"), hashlib.sha256
            ).digest()
            provided_sig = _b64url_decode(sig_b64)
            if not secrets.compare_digest(provided_sig, expected_sig):
                return None
            payload = json.loads(_b64url_decode(body_b64).decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("typ") != expected_type:
                return None
            if int(payload.get("exp", 0)) <= int(time.time()):
                return None
            return payload
        except Exception:
            return None

    def _mint_csrf(self, client_id: str, redirect_uri: str) -> str:
        ts = str(int(time.time()))
        msg = f"csrf:{ts}:{client_id}:{redirect_uri}".encode("utf-8")
        sig = _b64url_encode(hmac.new(self._signing_key(), msg, hashlib.sha256).digest())
        return f"{ts}.{sig}"

    def _verify_csrf(self, token: str, client_id: str, redirect_uri: str) -> bool:
        if not token or "." not in token:
            return False
        ts_str, sig = token.split(".", 1)
        try:
            ts = int(ts_str)
        except ValueError:
            return False
        if abs(int(time.time()) - ts) > CSRF_TTL_SECONDS:
            return False
        msg = f"csrf:{ts_str}:{client_id}:{redirect_uri}".encode("utf-8")
        expected = _b64url_encode(hmac.new(self._signing_key(), msg, hashlib.sha256).digest())
        return secrets.compare_digest(sig, expected)

    def _verify_gateway_credential(self, credential: str) -> Optional[str]:
        val = credential.strip()
        if not val:
            return None
        for valid_tok in self.config.api_tokens:
            if secrets.compare_digest(val, valid_tok):
                return "oauth-token-admin"
        if ":" in val and self.config.users:
            username, password = val.split(":", 1)
            stored = self.config.users.get(username)
            if stored and verify_password_pbkdf2(password, stored):
                return f"oauth-user:{username}"
        return None

    # ------------------------------------------------------------------
    # Discovery Metadata (RFC 9728 & RFC 8414)
    # ------------------------------------------------------------------

    def protected_resource_metadata(self, origin: str) -> Dict[str, Any]:
        return {
            "resource": f"{origin}/mcp",
            "authorization_servers": [origin],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
        }

    def authorization_server_metadata(self, origin: str) -> Dict[str, Any]:
        return {
            "issuer": origin,
            "authorization_endpoint": f"{origin}/oauth/authorize",
            "token_endpoint": f"{origin}/oauth/token",
            "registration_endpoint": f"{origin}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["mcp"],
        }

    # ------------------------------------------------------------------
    # Dynamic Client Registration (RFC 7591)
    # ------------------------------------------------------------------

    def register_client(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        redirect_uris = payload.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return 400, {
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris must be a non-empty list",
            }
        cleaned_uris: List[str] = []
        for u in redirect_uris:
            if not isinstance(u, str) or not _is_valid_redirect_uri(u):
                return 400, {
                    "error": "invalid_redirect_uri",
                    "error_description": f"Invalid or insecure redirect_uri: {u!r}",
                }
            cleaned_uris.append(u)

        auth_method = str(payload.get("token_endpoint_auth_method") or "none").strip().lower()
        if auth_method not in ("none", "client_secret_post", "client_secret_basic"):
            auth_method = "none"

        prefix = "pub_" if auth_method == "none" else "sec_"
        client_id = prefix + secrets.token_urlsafe(16)
        now = int(time.time())
        resp: Dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": now,
            "client_name": str(payload.get("client_name") or "MCP Client")[:128],
            "redirect_uris": cleaned_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": auth_method,
            "scope": str(payload.get("scope") or "mcp"),
        }
        if auth_method != "none":
            resp["client_secret"] = self._derive_client_secret(client_id)
            resp["client_secret_expires_at"] = 0
        return 201, resp

    # ------------------------------------------------------------------
    # Authorization Endpoint (OAuth 2.1 + PKCE S256)
    # ------------------------------------------------------------------

    def render_authorize_page(
        self, query: Dict[str, List[str]], error_msg: str = ""
    ) -> Tuple[int, str]:
        resp_type = (query.get("response_type") or [""])[0].strip()
        client_id = (query.get("client_id") or [""])[0].strip()
        redirect_uri = (query.get("redirect_uri") or [""])[0].strip()
        state = (query.get("state") or [""])[0]
        scope = (query.get("scope") or ["mcp"])[0].strip() or "mcp"
        resource = (query.get("resource") or [""])[0].strip()
        code_challenge = (query.get("code_challenge") or [""])[0].strip()
        code_challenge_method = (
            (query.get("code_challenge_method") or ["S256"])[0].strip() or "S256"
        )

        if resp_type != "code":
            return 400, self._error_html("Unsupported response_type (expected 'code').")
        if not client_id:
            return 400, self._error_html("Missing required parameter: client_id.")
        if not _is_valid_redirect_uri(redirect_uri):
            return 400, self._error_html("Invalid or insecure redirect_uri.")
        if not code_challenge or code_challenge_method.upper() != "S256":
            return 400, self._error_html("OAuth 2.1 requires PKCE with code_challenge_method=S256.")

        csrf = self._mint_csrf(client_id, redirect_uri)
        redirect_host = urlparse(redirect_uri).netloc
        err_block = (
            f'<div class="err">{html.escape(error_msg)}</div>' if error_msg else ""
        )

        page = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dots Gateway — OAuth 授权确认</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0f172a; color: #f8fafc; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; margin: 0; padding: 16px; box-sizing: border-box; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
          max-width: 440px; width: 100%; padding: 28px; box-shadow: 0 20px 40px rgba(0,0,0,.4); }}
  h1 {{ font-size: 20px; margin: 0 0 8px; }}
  p {{ color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 18px; }}
  .meta {{ background: #0f172a; border-radius: 8px; padding: 12px; font-size: 13px;
          color: #cbd5e1; margin-bottom: 18px; word-break: break-all; }}
  label {{ display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #e2e8f0; }}
  input[type=password] {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px;
                          border: 1px solid #475569; background: #0f172a; color: #f8fafc;
                          font-size: 14px; margin-bottom: 18px; }}
  button {{ width: 100%; padding: 11px; border: 0; border-radius: 8px; background: #3b82f6;
           color: #fff; font-weight: 600; font-size: 15px; cursor: pointer; }}
  button:hover {{ background: #2563eb; }}
  .err {{ background: #7f1d1d; border: 1px solid #ef4444; color: #fecaca; padding: 10px 12px;
         border-radius: 8px; font-size: 13px; margin-bottom: 16px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>授权连接 Dots Remote MCP</h1>
    <p>远程客户端正在请求访问本机受隔离的工作区 (<code>~/workspaces</code>)。请输入本机网关的 Bearer API Token 完成授权：</p>
    <div class="meta">
      <div><strong>回调域名:</strong> {html.escape(redirect_host)}</div>
      <div><strong>Client ID:</strong> {html.escape(client_id[:64])}</div>
      <div><strong>权限范围:</strong> {html.escape(scope)}</div>
    </div>
    {err_block}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="response_type" value="code">
      <input type="hidden" name="client_id" value="{html.escape(client_id)}">
      <input type="hidden" name="redirect_uri" value="{html.escape(redirect_uri)}">
      <input type="hidden" name="state" value="{html.escape(state)}">
      <input type="hidden" name="scope" value="{html.escape(scope)}">
      <input type="hidden" name="resource" value="{html.escape(resource)}">
      <input type="hidden" name="code_challenge" value="{html.escape(code_challenge)}">
      <input type="hidden" name="code_challenge_method" value="S256">
      <input type="hidden" name="csrf_token" value="{html.escape(csrf)}">
      <label for="gateway_token">Gateway Bearer API Token（或 用户名:密码）</label>
      <input id="gateway_token" name="gateway_token" type="password" required autofocus autocomplete="off" placeholder="粘贴 dots-gateway config 中的 Bearer API Token">
      <button type="submit">确认授权连接</button>
    </form>
  </div>
</body>
</html>
"""
        return (401 if error_msg else 200), page

    def handle_authorize_submit(
        self, form_body: str
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """Process POST /oauth/authorize. Returns (status, redirect_location, html_if_error)."""
        form = parse_qs(form_body, keep_blank_values=True)
        client_id = (form.get("client_id") or [""])[0].strip()
        redirect_uri = (form.get("redirect_uri") or [""])[0].strip()
        state = (form.get("state") or [""])[0]
        scope = (form.get("scope") or ["mcp"])[0].strip() or "mcp"
        resource = (form.get("resource") or [""])[0].strip()
        code_challenge = (form.get("code_challenge") or [""])[0].strip()
        code_challenge_method = (form.get("code_challenge_method") or ["S256"])[0].strip()
        csrf_token = (form.get("csrf_token") or [""])[0].strip()
        credential = (form.get("gateway_token") or [""])[0]

        if not client_id or not _is_valid_redirect_uri(redirect_uri):
            return 400, None, self._error_html("Invalid client_id or redirect_uri.")
        if not code_challenge or code_challenge_method.upper() != "S256":
            return 400, None, self._error_html("Missing PKCE S256 challenge.")
        if not self._verify_csrf(csrf_token, client_id, redirect_uri):
            _, page = self.render_authorize_page(form, "授权页面已过期，请刷新重试。")
            return 400, None, page

        principal = self._verify_gateway_credential(credential)
        if not principal:
            _, page = self.render_authorize_page(form, "密钥验证失败，请检查后重新输入。")
            return 401, None, page

        now = time.time()
        self._cleanup_codes(now)
        code = secrets.token_urlsafe(32)
        self._codes[code] = PendingAuthCode(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            scope=scope,
            resource=resource,
            principal=principal,
            expires_at=now + AUTH_CODE_TTL_SECONDS,
        )
        self._codes.move_to_end(code)

        params: Dict[str, str] = {"code": code}
        if state:
            params["state"] = state
        return 302, _append_query_params(redirect_uri, params), None

    def _cleanup_codes(self, now: float) -> None:
        expired = [k for k, v in self._codes.items() if v.expires_at <= now]
        for k in expired:
            self._codes.pop(k, None)
        while len(self._codes) >= MAX_PENDING_AUTH_CODES:
            self._codes.popitem(last=False)

    # ------------------------------------------------------------------
    # Token Endpoint (authorization_code + PKCE S256 & refresh_token)
    # ------------------------------------------------------------------

    def handle_token_request(
        self, raw_body: bytes, headers: Dict[str, str]
    ) -> Tuple[int, Dict[str, Any]]:
        ctype = headers.get("content-type", "").lower()
        params: Dict[str, str] = {}
        try:
            text = raw_body.decode("utf-8") if raw_body else ""
            if "application/json" in ctype:
                loaded = json.loads(text) if text else {}
                if isinstance(loaded, dict):
                    params = {k: str(v) for k, v in loaded.items() if v is not None}
            else:
                parsed = parse_qs(text, keep_blank_values=True)
                params = {k: vals[0] for k, vals in parsed.items() if vals}
        except Exception:
            return 400, {"error": "invalid_request", "error_description": "Malformed request body"}

        # Extract optional Basic client credentials
        basic_cid = ""
        basic_csec = ""
        auth_hdr = headers.get("authorization", "").strip()
        if auth_hdr.lower().startswith("basic "):
            try:
                dec = base64.b64decode(auth_hdr[6:].strip()).decode("utf-8")
                basic_cid, basic_csec = dec.split(":", 1)
            except Exception:
                return 401, {"error": "invalid_client", "error_description": "Invalid Basic header"}

        client_id = params.get("client_id") or basic_cid
        client_secret = params.get("client_secret") or basic_csec
        if client_id.startswith("sec_"):
            expected_sec = self._derive_client_secret(client_id)
            if not client_secret or not secrets.compare_digest(client_secret, expected_sec):
                return 401, {"error": "invalid_client", "error_description": "Invalid client_secret"}

        grant_type = params.get("grant_type", "").strip()

        if grant_type == "authorization_code":
            code = params.get("code", "").strip()
            verifier = params.get("code_verifier", "").strip()
            redirect_uri = params.get("redirect_uri", "").strip()

            pending = self._codes.pop(code, None)
            if pending is None or pending.expires_at <= time.time():
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "Authorization code is invalid or expired",
                }
            if client_id and client_id != pending.client_id:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "client_id mismatch",
                }
            if redirect_uri and redirect_uri != pending.redirect_uri:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "redirect_uri mismatch",
                }
            if not verifier or len(verifier) < 43 or len(verifier) > 128:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "Missing or invalid PKCE code_verifier",
                }
            computed_challenge = _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
            if not secrets.compare_digest(computed_challenge, pending.code_challenge):
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "PKCE code_verifier verification failed",
                }

            at = self._mint_signed_token(
                "at", pending.principal, pending.scope, ACCESS_TOKEN_TTL_SECONDS
            )
            rt = self._mint_signed_token(
                "rt", pending.principal, pending.scope, REFRESH_TOKEN_TTL_SECONDS
            )
            return 200, {
                "access_token": at,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                "refresh_token": rt,
                "scope": pending.scope,
            }

        if grant_type == "refresh_token":
            rt_in = params.get("refresh_token", "").strip()
            claims = self.verify_signed_token(rt_in, expected_type="rt")
            if claims is None:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "Refresh token is invalid or expired",
                }
            sub = str(claims.get("sub") or "oauth-client")
            scp = str(claims.get("scp") or "mcp")
            at = self._mint_signed_token("at", sub, scp, ACCESS_TOKEN_TTL_SECONDS)
            rt = self._mint_signed_token("rt", sub, scp, REFRESH_TOKEN_TTL_SECONDS)
            return 200, {
                "access_token": at,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                "refresh_token": rt,
                "scope": scp,
            }

        return 400, {
            "error": "unsupported_grant_type",
            "error_description": f"Unsupported grant_type: {grant_type!r}",
        }

    @staticmethod
    def _error_html(msg: str) -> str:
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>OAuth Error</title></head>"
            f"<body style='font-family:sans-serif;padding:32px;background:#0f172a;color:#fecaca'>"
            f"<h2>OAuth Request Error</h2><p>{html.escape(msg)}</p></body></html>"
        )
