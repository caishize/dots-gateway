# Dots <-> Local Dev & Antigravity (`agy`) Hardened Bidirectional Gateway

A zero-dependency Python 3.11+ remote development gateway designed for **Public-IP Direct Connection** from **dots** (running on OpenAI machines across the internet) to securely execute local software development workflows, transfer/patch files, and run **`agy --dangerously-skip-permissions`** in real time.

## Architecture Overview

```
OpenAI Machine (dots)                              Local Dev Machine (~/gateway)
+-------------------------------+   TLS 1.3 (mTLS  +--------------------------------------------+
| Dots Agent / dots_client.py   |   / SHA256 Pin)  | GatewayServer (gateway/server.py)          |
|  - TLS SHA-256 Cert Pinning   | <==============> |  1. TLS / mTLS + IP CIDR Allowlist         |
|  - Bearer / Basic / HMAC Auth |  - HTTPS / SSE   |  2. Authenticator (gateway/auth.py)        |
|  - File Read/Write/Patch SDK  |  - WSS /v1/ws    |     - Bearer / Async PBKDF2 / HMAC-SHA256  |
|  - Full-Duplex WSS Client     |  - /v1/files/*   |     - Bounded Rate-Limit & Replay Cache    |
|  - SSE Keepalive Stream       |  - /v1/agy, exec |  3. CommandPolicy & FileService            |
+-------------------------------+                  |     - Quote-Aware Shell Lexer + `$()` Check|
                                                   |     - Protected Credential Path Isolation  |
                                                   |  4. SessionManager (gateway/executor.py)   |
                                                   |     - 16MB+ Line Safe `stream-json` Reader |
                                                   |     - Rolling 32MB Memory Cap + Heartbeats |
                                                   +--------------------------------------------+
```

## Directory Structure

- `main.py` — Gateway CLI entrypoint, credential generator, and automatic TLS/mTLS PKI initializer
- `config.example.json` — Example configuration template (`config.json` with live secrets is auto-generated on first run with `0600` permissions and git-ignored)
- `dots_client.py` — Standalone zero-dependency SDK & CLI ready to copy to the OpenAI `dots` machine
- `deploy/dots-gateway.service` — `systemd --user` service unit for persistent background operation
- `gateway/`
  - `tls.py` — OpenSSL PKI generator, DER SHA-256 fingerprint calculator, and TLS 1.2+/1.3 / mTLS `SSLContext` builder
  - `config.py` — Configuration schema, environment overrides, and 200,000-round `PBKDF2-HMAC-SHA256` hashing
  - `auth.py` — CIDR IP allowlist, async non-blocking PBKDF2 Basic Auth, Bearer Token, HMAC-SHA256 replay protection, and bounded per-IP rate limiting
  - `policy.py` — Quote-aware shell lexer, recursive `$(...)` / `bash -c` inspection, symlink-safe workspace script support, and credential path protection
  - `files.py` — Symlink-checked `/v1/files/*` (`stat`, `list`, `read`, `write`, `patch`, `delete`, binary Base64)
  - `executor.py` — Async subprocess & PTY session manager with >64KB `stream-json` safe line reader, 32MB output memory cap, and SSE/WSS keepalive heartbeats
  - `protocol.py` — Hardened HTTP/1.1 (`chunked` + `100-continue` + header bounds), SSE, and RFC 6455 WebSocket framing
  - `server.py` — HTTPS/SSE & WSS router
- `tests/`
  - `test_gateway.py` — Automated unit, security, TLS/mTLS, and protocol test suite
  - `live_call_test.py` — End-to-end live integration test over HTTPS/WSS against a running daemon

---

## 1. Quick Start & Service Deployment (Local Machine)

```bash
git clone https://github.com/caishize/dots-gateway.git ~/gateway
cd ~/gateway

# Initialize credentials (`config.json`) & TLS/mTLS PKI (`certs/`) and start server
python3 main.py

# Or install as a persistent systemd user service:
mkdir -p ~/.config/systemd/user
cp deploy/dots-gateway.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now dots-gateway.service

# Optional: Lock down to OpenAI egress IP CIDRs or enable strict mTLS
python3 main.py --public-ip <YOUR_PUBLIC_IP> --allow-ip <OPENAI_CIDR> --init-only
systemctl --user restart dots-gateway.service
```

---

## 2. Connecting from `dots` (OpenAI Machine via Public IP)

Copy `dots_client.py` to the OpenAI machine (uses Python 3 standard library only — zero `pip` packages needed) and set three environment variables (no certificate files needed when using SHA-256 pinning):

```bash
export GATEWAY_URL="https://<YOUR_PUBLIC_IP>:8765"
export GATEWAY_HMAC_SECRET="<YOUR_HMAC_SECRET>"       # Or export GATEWAY_TOKEN="<YOUR_API_TOKEN>"
export GATEWAY_TLS_FINGERPRINT="<SERVER_CERT_SHA256>" # Cryptographic MITM-proof pinning!

# 1. Run `agy --dangerously-skip-permissions` with real-time streaming
python3 dots_client.py agy "在当前项目下实现功能并运行单元测试" --cwd ~/my_project

# 2. Run compound shell commands (`cd`, `&&`, `|`, virtualenvs, `./scripts/...`)
python3 dots_client.py exec "cd ~/my_project && pytest -v | tee test.log"

# 3. Upload / download / list files directly
python3 dots_client.py upload ./patch.diff ~/my_project/patch.diff
python3 dots_client.py download ~/my_project/test.log ./test.log
```

### Python SDK Usage in `dots`

```python
import asyncio
from dots_client import DotsGatewayClient

client = DotsGatewayClient(
    base_url="https://<YOUR_PUBLIC_IP>:8765",
    hmac_secret="<YOUR_HMAC_SECRET>",            # Or token="<YOUR_API_TOKEN>"
    tls_fingerprint="<SERVER_CERT_SHA256>",      # Prevents any public-network MITM
)

# 1. Read, write, and patch workspace files atomically
client.write_file("/tmp/demo/app.py", "def add(a, b):\n    return a - b\n")
client.patch_file(
    "/tmp/demo/app.py",
    edits=[{"target": "return a - b", "replacement": "return a + b"}],
)

# 2. Stream `agy --dangerously-skip-permissions`
for ev in client.stream_agy(
    prompt="为 app.py 编写单元测试并运行验证",
    cwd="/tmp/demo",
    skip_permissions=True,
):
    if ev.get("type") == "agy_event":
        print(ev["data"])

# 3. Full-Duplex Bidirectional WSS Multi-Turn Session
async def multi_turn_session():
    async with client.connect_websocket() as ws:
        await ws.send_json({
            "id": "turn-1",
            "action": "agy",
            "interactive": True,
            "cwd": "/tmp/demo",
            "prompt": "检查代码结构并汇报",
        })
        while True:
            msg = await ws.recv_json()
            if not msg:
                break
            print(msg)

asyncio.run(multi_turn_session())
```

---

## 3. Running Tests

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```
