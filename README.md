# Dots <-> Local Dev & Antigravity (`agy`) MCP Plugin & Hardened Gateway

A zero-dependency Python 3.11+ **OpenAI `dots` / Codex / Agent Plugins 1.0** package and remote development gateway designed for **Public-IP Direct Connection**. It enables **dots** (running on OpenAI cloud machines) to securely inspect/edit workspace files, execute allowlisted development commands, and run **`agy --dangerously-skip-permissions`** via the **Model Context Protocol (MCP)**.

## Architecture Overview

```
OpenAI Cloud Machine (`dots`)                            Local Dev Machine (`~/gateway`)
+-------------------------------------------+            +----------------------------------------------+
| Option A: Installed Plugin (`plugin.json`)|  TLS 1.3   | GatewayServer (`gateway/server.py`)          |
|  - `skills/` (`remote-dev-gateway`,       |  + SHA256  |  1. TLS 1.2/1.3 / mTLS + IP CIDR Allowlist   |
|    `delegate-to-agy`)                     |  Cert Pin  |  2. Authenticator (`gateway/auth.py`)        |
|  - `mcp.json` -> `./dots_mcp.py` (stdio)  | <========> |     - Bearer / Async PBKDF2 / HMAC-SHA256    |
|    Bridges JSON-RPC + SSE Progress        |  POST /mcp |  3. MCP Server Engine (`gateway/mcp.py`)     |
+-------------------------------------------+            |     - Streamable HTTP (`/mcp`) + SSE Progress|
| Option B: Direct Remote MCP Connector     | <========> |     - 14 Tools, Resources & Guided Prompts   |
|  - URL: `https://<PUBLIC_IP>:8765/mcp`    |  Bearer    |  4. CommandPolicy, FileService & Sessions    |
+-------------------------------------------+            |     - `agy --dangerously-skip-permissions`   |
                                                         +----------------------------------------------+
```

## Plugin & Repository Layout

- `plugin.json` & `.codex-plugin/plugin.json` — Portable **Agent Plugins 1.0** + OpenAI `extensions.com.openai` & Codex plugin manifests
- `mcp.json` — Bundled `stdio` MCP server definition (`./dots_mcp.py`) supporting self-signed TLS SHA-256 pinning & HMAC-SHA256
- `mcp.remote.example.json` — Example `streamable-http` MCP configuration for direct `/mcp` connectors
- `skills/`
  - `remote-dev-gateway/SKILL.md` — Workflow guide for remote file operations, builds/tests, and background sessions
  - `delegate-to-agy/SKILL.md` — Workflow guide for delegating multi-file engineering tasks to local `agy --dangerously-skip-permissions`
- `rules/AGENTS.md` — Active workspace & security rules bundled with the plugin
- `dots_mcp.py` — Standalone zero-dependency MCP `stdio` bridge & local MCP runner
- `dots_client.py` — Standalone zero-dependency Python SDK & CLI
- `main.py` — Gateway daemon entrypoint, PKI initializer, and `--print-plugin-config` generator
- `gateway/`
  - `mcp.py` — Full MCP JSON-RPC 2.0 dispatcher (`2024-11-05` / `2025-03-26` / `2025-06-18` / `2026-07-28`)
  - `server.py` — Streamable HTTP `/mcp`, REST/SSE `/v1/*`, and full-duplex WebSocket `/v1/ws` router
  - `tls.py`, `auth.py`, `policy.py`, `files.py`, `executor.py`, `protocol.py`, `config.py`

---

## Exposed MCP Tools, Resources & Prompts

| MCP Tool | Description |
| :--- | :--- |
| `gateway_status` | Live health, uptime, active sessions, allowed workspaces, and policy summary |
| `run_agy` | Run `agy --dangerously-skip-permissions` on the local host (supports `cwd`, `model`, `effort`, `conversation_id`, `continue_last`) |
| `exec_command` | Execute allowlisted commands or shell pipelines (`git`, `pytest`, `npm`, `cargo`, `./scripts/...`) with live SSE progress |
| `fs_stat` / `fs_list` | Inspect file metadata or list directory entries inside allowed workspaces |
| `fs_read` | Read UTF-8 text or Base64 binary files with optional byte `offset`/`limit` |
| `fs_write` / `fs_patch` / `fs_delete` | Atomically write, exact search-and-replace patch, or delete workspace files |
| `session_start` | Launch non-blocking background `exec` or multi-turn interactive `agy` sessions |
| `session_poll` | Poll incremental events (`after_seq`) with optional long-poll `wait_seconds` |
| `session_input` / `session_signal` / `session_list` | Send `stdin` / follow-up `agy` turns, signal (`SIGINT`/`SIGTERM`/`SIGKILL`), or list sessions |

- **MCP Resources**: `gateway://status`, `gateway://policy`, and template `file://{path}`
- **MCP Prompts**: `delegate_to_agy`, `remote_tdd_loop`

---

## 1. Start the Local Gateway & Export Plugin Config

```bash
git clone https://github.com/caishize/dots-gateway.git ~/gateway
cd ~/gateway

# Install & start persistent background service
mkdir -p ~/.config/systemd/user
cp deploy/dots-gateway.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now dots-gateway.service

# Generate ready-to-paste OpenAI `dots` Plugin & MCP configuration snippets
python3 main.py --public-ip <YOUR_PUBLIC_IP> --print-plugin-config
```

---

## 2. Connect from OpenAI `dots`

### Option A (Recommended for Public-IP Direct Connect): Install Plugin Repo (`stdio` Bridge)

Install this repository (`https://github.com/caishize/dots-gateway.git`) as a plugin in `dots` / Codex. Because `mcp.json` runs `./dots_mcp.py`, it supports **self-signed TLS SHA-256 certificate pinning** (`GATEWAY_TLS_FINGERPRINT`) and **replay-proof HMAC-SHA256 signing** over raw public IPs without needing third-party CA certificates.

Configure credentials on the `dots` machine via environment variables:

```bash
export GATEWAY_URL="https://<YOUR_PUBLIC_IP>:8765"
export GATEWAY_HMAC_SECRET="<YOUR_HMAC_SECRET>"       # Or GATEWAY_TOKEN="<YOUR_API_TOKEN>"
export GATEWAY_TLS_FINGERPRINT="<SERVER_CERT_SHA256>"
```

Or save `~/.config/dots-gateway/client.json` (reloaded dynamically without restarting the plugin):

```json
{
  "url": "https://<YOUR_PUBLIC_IP>:8765",
  "hmac_secret": "<YOUR_HMAC_SECRET>",
  "tls_fingerprint": "<SERVER_CERT_SHA256>"
}
```

### Option B: Direct Remote Streamable HTTP MCP Connector (`/mcp`)

Point `dots` / ChatGPT Custom MCP Connector directly at the gateway's native Streamable HTTP endpoint:

- **MCP Endpoint URL**: `https://<YOUR_PUBLIC_IP_OR_DOMAIN>:8765/mcp`
- **HTTP Header**: `Authorization: Bearer <YOUR_API_TOKEN>`

*(Note: Direct cloud-hosted HTTP connectors typically require a publicly trusted TLS certificate if connecting without `dots_mcp.py`'s SHA-256 cert pinning bridge).*

---

## 3. Running Automated & Live Tests

```bash
# Unit, security, MCP protocol, and stdio plugin bridge test suite
python3 -m unittest discover -s tests -p "test_*.py" -v

# Full live end-to-end verification against running dots-gateway.service (HTTPS + WSS + MCP + agy)
python3 tests/live_call_test.py
```
