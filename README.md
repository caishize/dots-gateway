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
  - `sandbox.py` — Unprivileged Linux User + Mount Namespace (`unshare` + `pivot_root` + `setpriv`) VFS workspace jail confining child processes strictly to `~/workspaces`
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

## 1. Start, Manage & Configure Secure MCP Tunnel

```bash
git clone https://github.com/caishize/dots-gateway.git ~/gateway
cd ~/gateway

# Unified CLI (also symlinked as ~/.local/bin/dots-gateway)
dots-gateway --help
dots-gateway start
dots-gateway status
dots-gateway restart
dots-gateway stop
dots-gateway logs -f

# Recommended: Configure & start OpenAI official Secure MCP Tunnel (outbound-only, port-free)
dots-gateway tunnel-setup

# Issue auto-renewing Let's Encrypt bare-IP + sslip.io TLS certificate (optional, for direct HTTPS)
dots-gateway sync-ip

# Print direct Remote MCP URLs, OAuth 2.1 endpoints & capability path
dots-gateway config
```

---

## 2. Connect from OpenAI `dots`

### Option A (Recommended — Zero Inbound Ports, Zero Install in `dots`): OpenAI Secure MCP Tunnel (`tunnel-client`)

Because OpenAI's cloud connector firewall blocks non-`443` ports (`:8765`), raw IPv4 URLs, and wildcard DNS (`sslip.io`), the most reliable zero-install method is OpenAI's official **`tunnel-client`** daemon managed by `dots-gateway`:

1. Create or copy a **Tunnel ID** (`tunnel_...`) at <https://platform.openai.com/settings/organization/tunnels> (under the same OpenAI Org/Workspace as `dots`).
2. Create a **Runtime Credential** with **`Tunnels Read + Use`** permissions at <https://platform.openai.com/settings/organization/api-keys>.
3. Run on this host:
   ```bash
   dots-gateway tunnel-setup
   ```
   This writes `~/.config/dots-gateway/tunnel.env` (`0600`), configures `~/.config/tunnel-client/dots-gateway.yaml` (`sample_mcp_stdio_local` -> `dots_mcp.py` -> loopback `https://127.0.0.1:8765`), runs `tunnel-client doctor`, enables `dots-gateway-tunnel.service`, and verifies `http://127.0.0.1:18766/readyz`.
4. In `dots` / ChatGPT Connectors, select your Secure MCP Tunnel (`No authentication` / `无需身份认证`). All commands and `agy` runs remain strictly confined to `~/workspaces` via Linux User + Mount Namespace VFS jailing.

### Option B: Direct Remote Streamable HTTP MCP (`/mcp`, Built-in OAuth 2.1 or Capability Path)

When exposed on standard HTTPS `:443` with a custom domain, `dots-gateway` natively supports:
- **Built-in MCP OAuth 2.1 (`gateway/oauth.py`)**: RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`), RFC 8414 Authorization Server Metadata (`/.well-known/oauth-authorization-server`), RFC 7591 Dynamic Client Registration (`/oauth/register`), PKCE `S256` `/oauth/authorize`, and stateless HMAC `/oauth/token`.
- **Zero-Header Capability Path**: `https://<YOUR_DOMAIN>/mcp/<YOUR_GATEWAY_CREDENTIAL>` (for `No authentication` mode) or `Authorization: Bearer` header on `/mcp`.

### Option C: Install Plugin Repo (`stdio` Bridge)

Install this repository (`https://github.com/caishize/dots-gateway.git`) as a plugin in Codex / local MCP hosts (`mcp.json` runs `./dots_mcp.py` with TLS SHA-256 certificate pinning and replay-proof HMAC-SHA256 signing via `~/.config/dots-gateway/client.json`).

---

## 3. Running Automated & Live Tests

```bash
# Unit, security, MCP protocol, and stdio plugin bridge test suite
python3 -m unittest discover -s tests -p "test_*.py" -v

# Full live end-to-end verification against running dots-gateway.service (HTTPS + WSS + MCP + agy)
python3 tests/live_call_test.py
```
