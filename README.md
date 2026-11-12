# Dots <-> Local Dev, Antigravity (`agy`) & Codex MCP Plugin & Hardened Gateway

A zero-dependency Python 3.11+ **OpenAI `dots` / Codex / Agent Plugins 1.0** package and remote development gateway. It enables **dots** (running on OpenAI cloud machines) to securely inspect/edit workspace files, execute allowlisted development commands inside a Linux User + Mount Namespace VFS jail, and delegate tasks to **`agy` (`--sandbox`)** and **`codex` (`codex exec`)** via the **Model Context Protocol (MCP)**.

## Architecture Overview

```
OpenAI Cloud Machine (`dots`)                            Local Dev Machine (`~/gateway`)
+-------------------------------------------+            +----------------------------------------------+
| Option A: OpenAI Secure MCP Tunnel        |  Outbound  | GatewayServer (`gateway/server.py`)          |
|  - `tunnel-client` -> Loopback HTTP       |  HTTP/2    |  1. Loopback `/mcp` + TLS 1.3 / mTLS + CIDR  |
|    `http://127.0.0.1:18765/mcp`           | <========> |  2. Authenticator (`auth.py` / `oauth.py`)   |
+-------------------------------------------+            |     - Bearer / Async PBKDF2 / HMAC / OAuth2.1 |
| Option B: Direct Remote MCP / Plugin      |  TLS 1.3   |  3. MCP Server Engine (`gateway/mcp.py`)     |
|  - `https://<DOMAIN>/mcp` or `dots_mcp.py`| <========> |     - Streamable HTTP (`/mcp`) + SSE Progress|
|  - `skills/` (`remote-dev-gateway`,       |  POST /mcp |     - 16 Tools, Resources & Guided Prompts   |
|    `delegate-to-agy`, `delegate-to-codex`)|            |  4. Policy, VFS Jail & Optional Docker Proxy |
+-------------------------------------------+            |     - `agy --sandbox` & `codex exec`         |
                                                         +----------------------------------------------+
```

## Plugin & Repository Layout

- `plugin.json` & `.codex-plugin/plugin.json` — Portable **Agent Plugins 1.0** + OpenAI `extensions.com.openai` & Codex plugin manifests (`v1.5.15`)
- `mcp.json` — Bundled `stdio` MCP server definition (`./dots_mcp.py`) supporting self-signed TLS SHA-256 pinning & HMAC-SHA256
- `mcp.remote.example.json` — Example `streamable-http` MCP configuration for direct `/mcp` connectors
- `skills/`
  - `remote-dev-gateway/SKILL.md` — Workflow guide for remote file operations, builds/tests, and background sessions
  - `delegate-to-agy/SKILL.md` — Workflow guide for delegating multi-file engineering tasks to local `agy` (`--sandbox`)
  - `delegate-to-codex/SKILL.md` — Workflow guide for delegating coding & independent reviews to local `codex exec`
- `rules/AGENTS.md` — Active workspace & security rules bundled with the plugin
- `gateway.sh` — Unified operator CLI (`~/.local/bin/dots-gateway`) for service lifecycle, tunnels, auth, models, and Docker toggle
- `dots_mcp.py` — Standalone zero-dependency MCP `stdio` bridge & local MCP runner
- `dots_client.py` — Standalone zero-dependency Python SDK & CLI (`health`, `policy`, `exec`, `agy`, `agy-models`, `codex`, `ls`, `upload`, `download`)
- `main.py` — Gateway daemon entrypoint, PKI initializer, and `--print-plugin-config` generator
- `deploy/` — User `systemd` unit templates (`dots-gateway.service`, `dots-gateway-tunnel.service`) and Let's Encrypt certificate helper
- `gateway/`
  - `mcp.py` — Full MCP JSON-RPC 2.0 dispatcher (`2024-11-05` / `2025-03-26` / `2025-06-18` / `2026-07-28`)
  - `server.py` — Streamable HTTP `/mcp`, REST/SSE `/v1/*`, OAuth 2.1 routes, and full-duplex WebSocket `/v1/ws` router
  - `sandbox.py` — Unprivileged Linux User + Mount Namespace (`unshare` + `pivot_root` + `setpriv`) VFS workspace jail & 2-tier LRU cache lifecycle manager
  - `docker_proxy.py` — Policy-filtering Unix-socket Docker API proxy for sandboxed sessions
  - `oauth.py` — Stateless HMAC-signed MCP OAuth 2.1 Authorization Server (RFC 9728 / RFC 8414 / RFC 7591 / PKCE `S256`)
  - `tls.py`, `auth.py`, `policy.py`, `files.py`, `executor.py`, `protocol.py`, `config.py`

---

## Exposed MCP Tools (16), Resources & Prompts

| MCP Tool | Description |
| :--- | :--- |
| `gateway_status` | Live health, uptime, active/queued agent slots, allowed workspaces, Docker proxy state, and policy summary |
| `list_agy_models` | List model IDs available under the gateway's active `agy` auth mode (`adc` or `oauth`) plus default model info |
| `run_agy` | Run `agy --sandbox` (`--dangerously-skip-permissions` optional) on the local host (`cwd`, `model`, `effort`, `conversation_id`, `continue_last`, `add_dirs`) |
| `run_codex` | Run OpenAI Codex CLI (`codex -a never -s workspace-write exec`) on the local host (`cwd`, `sandbox_mode`, `model`, `effort`, `session_id`, `continue_last`, `review`) |
| `exec_command` | Execute allowlisted commands or shell pipelines (`git`, `pytest`, `npm`, `cargo`, `./scripts/...`) with live SSE progress |
| `fs_stat` / `fs_list` | Inspect file/symlink metadata or list directory entries inside allowed workspaces |
| `fs_read` | Read UTF-8 text or Base64 binary files with optional byte `offset`/`limit` |
| `fs_write` / `fs_patch` / `fs_delete` | Atomically write, exact search-and-replace patch (`replace_all` guarded), or delete workspace files |
| `session_start` | Launch non-blocking background `exec`, `codex`, or multi-turn interactive `agy` sessions |
| `session_poll` | Poll incremental events (`after_seq`) with optional long-poll `wait_seconds` and `wait_for_exit` |
| `session_input` / `session_signal` / `session_list` | Send `stdin` / follow-up `agy` turns, signal (`SIGINT`/`SIGTERM`/`SIGKILL`), or list live & persisted sessions |

- **MCP Resources**: `gateway://status`, `gateway://policy`, and template `file://{path}`
- **MCP Prompts**: `delegate_to_agy`, `delegate_to_codex`, `remote_tdd_loop`

---

## 1. Start, Manage & Configure Gateway CLI

```bash
git clone https://github.com/caishize/dots-gateway.git ~/gateway
cd ~/gateway

# Unified CLI (also symlinked as ~/.local/bin/dots-gateway)
dots-gateway --help
dots-gateway start
dots-gateway status
dots-gateway restart          # Safely drains active sessions unless --force is passed
dots-gateway stop
dots-gateway logs -f

# Recommended: Configure & start OpenAI official Secure MCP Tunnel (outbound-only, port-free)
dots-gateway tunnel-setup

# Switch Antigravity auth profile (ADC vs OAuth) & default model (hot-reloaded, zero restart)
dots-gateway agy-auth status|adc|oauth
dots-gateway agy-model list|status|set <model_id>|clear

# Configure OpenAI API Key for local Codex CLI (`run_codex`, stored 0600, effective immediately)
dots-gateway codex-setup

# Hot-toggle policy-filtered Docker access for sandboxed exec_command / run_agy / run_codex
dots-gateway docker on|off|status|test
```

### Sandbox Docker Access (`dots-gateway docker`)

The host `docker.sock` (root-equivalent) is **always masked** inside the mount-namespace jail.
When `dots-gateway docker on` is set (hot-reloaded per session, no restart), sessions instead get a
gateway-owned filtering proxy socket at `/var/run/docker.sock`, so `docker` / `docker compose` /
`docker build` work from `exec_command`, scripts, `run_agy`, and `run_codex` with these rules:

- bind mounts (and bind-backed volumes) only inside `allowed_workdirs` (+ `docker_extra_bind_roots`), never in `protected_paths`, symlinks resolved and re-checked at `start`, `restart`, and `unpause`;
- no `--privileged`, `--device`, `--cap-add` (unless in `docker_allowed_capabilities`), `--pid/--ipc/--uts/--userns=host`, custom runtimes, unconfined security options;
- only containers/volumes/networks created through the proxy (label `io.dots-gateway.managed=true`) can be inspected, exec'd, attached, or removed — host containers stay invisible;
- published ports are rewritten to `127.0.0.1` (`docker_force_loopback_ports`); swarm, plugins, and unknown API routes are denied.

> Note: files written by root inside containers to bind-mounted workspaces become root-owned; run containers with `--user "$(id -u):$(id -g)"` when needed.

```bash
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
   This writes `~/.config/dots-gateway/tunnel.env` (`0600`), configures `~/.config/tunnel-client/dots-gateway.yaml` to forward concurrent Streamable HTTP requests to `http://127.0.0.1:18765/mcp` (avoiding single-pipe stdio head-of-line blocking), runs `tunnel-client doctor`, enables `dots-gateway-tunnel.service`, and verifies `http://127.0.0.1:18766/readyz`.
4. In `dots` / ChatGPT Connectors, select your Secure MCP Tunnel (`No authentication` / `无需身份认证`). All commands, `agy`, and `codex` runs remain strictly confined to `~/workspaces` via Linux User + Mount Namespace VFS jailing.

### Option B: Direct Remote Streamable HTTP MCP (`/mcp`, Built-in OAuth 2.1 or Capability Path)

When exposed on standard HTTPS `:443` with a custom domain, `dots-gateway` natively supports:
- **Built-in MCP OAuth 2.1 (`gateway/oauth.py`)**: RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`), RFC 8414 Authorization Server Metadata (`/.well-known/oauth-authorization-server`), RFC 7591 Dynamic Client Registration (`/oauth/register`), PKCE `S256` `/oauth/authorize`, and stateless HMAC `/oauth/token`.
- **Zero-Header Capability Path**: `https://<YOUR_DOMAIN>/mcp/<YOUR_GATEWAY_CREDENTIAL>` (for `No authentication` mode) or `Authorization: Bearer` header on `/mcp`.

### Option C: Install Plugin Repo (`stdio` Bridge)

Install this repository (`https://github.com/caishize/dots-gateway.git`) as a plugin in Codex / local MCP hosts (`mcp.json` runs `./dots_mcp.py` with TLS SHA-256 certificate pinning and replay-proof HMAC-SHA256 signing via `~/.config/dots-gateway/client.json`).

---

## 3. Running Automated & Live Tests

```bash
# Unit, security, Docker proxy, MCP protocol, and stdio plugin bridge test suite
pytest -v
# or via stdlib unittest:
python3 -m unittest discover -s tests -p "test_*.py" -v

# Lint check
ruff check .

# Full live end-to-end verification against running dots-gateway.service (HTTPS + WSS + MCP + agy)
python3 tests/live_call_test.py
```
