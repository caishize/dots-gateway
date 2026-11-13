# Dots <-> Local Dev, Antigravity (`agy`) & Codex MCP Plugin & Hardened Gateway (`v1.5.16`)

A zero-dependency Python 3.11+ **OpenAI `dots` / Codex / Agent Plugins 1.0** package and remote development gateway. It enables **dots** (running on OpenAI cloud machines) to securely inspect/edit workspace files, execute allowlisted development commands inside a Linux User + Mount Namespace VFS jail, and delegate tasks to **`agy` (`--sandbox`, with optional isolated read-only plugins)** and **`codex` (`codex exec`)** via the **Model Context Protocol (MCP)**.

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
|    `delegate-to-agy`, `delegate-to-codex`)|            |  4. Policy, VFS Jail, AGY Plugins & Docker   |
+-------------------------------------------+            |     - `agy --sandbox` & `codex exec`         |
                                                         +----------------------------------------------+
```

## Plugin & Repository Layout

- `plugin.json` & `.codex-plugin/plugin.json` — Portable **Agent Plugins 1.0** + OpenAI `extensions.com.openai` & Codex plugin manifests (`v1.5.16`)
- `pyproject.toml` — Zero-dependency Python 3.11+ package metadata (`v1.5.16`), `pytest`, and `ruff` configuration
- `mcp.json` — Bundled `stdio` MCP server definition (`./dots_mcp.py`) supporting self-signed TLS SHA-256 pinning & HMAC-SHA256
- `mcp.remote.example.json` — Example `streamable-http` MCP configuration for direct `/mcp` connectors
- `config.example.json` — Reference host gateway configuration including 3-tier isolation, `agy` plugins, and Docker proxy settings
- `skills/`
  - `remote-dev-gateway/SKILL.md` — Workflow guide for remote file operations, builds/tests, and background sessions
  - `delegate-to-agy/SKILL.md` — Workflow guide for delegating multi-file engineering tasks to local `agy` (`--sandbox`)
  - `delegate-to-codex/SKILL.md` — Workflow guide for delegating coding & independent reviews to local `codex exec`
- `rules/AGENTS.md` — Active workspace & security rules bundled with the plugin
- `gateway.sh` — Unified operator CLI (`~/.local/bin/dots-gateway`) for service lifecycle, tunnels, auth, models, trusted `agy` plugins, and Docker toggle
- `dots_mcp.py` — Standalone zero-dependency MCP `stdio` bridge & local MCP runner
- `dots_client.py` — Standalone zero-dependency Python SDK & CLI (`health`, `policy`, `exec`, `agy`, `agy-models`, `codex`, `ls`, `upload`, `download`)
- `main.py` — Gateway daemon entrypoint, PKI initializer, and `--print-plugin-config` generator
- `deploy/` — User `systemd` unit templates (`dots-gateway.service`, `dots-gateway-tunnel.service`) and Let's Encrypt certificate helper
- `gateway/`
  - `mcp.py` — Full MCP JSON-RPC 2.0 dispatcher (`2024-11-05` / `2025-03-26` / `2025-06-18` / `2026-07-28`)
  - `server.py` — Streamable HTTP `/mcp`, REST/SSE `/v1/*`, OAuth 2.1 routes, and full-duplex WebSocket `/v1/ws` router
  - `policy.py` — Command/shell validation, 3-tier `agy` plugin boundary verification, and per-session `--settings` synthesis
  - `sandbox.py` — Unprivileged Linux User + Mount Namespace (`unshare` + `pivot_root` + `setpriv`) VFS workspace jail, read-only plugin mounts, storage fault lock probes, & 2-tier LRU cache lifecycle manager
  - `executor.py` — Async process/PTY session manager, environment sanitization, and queued session TOCTOU re-validation
  - `docker_proxy.py` — Policy-filtering Unix-socket Docker API proxy for sandboxed sessions
  - `oauth.py` — Stateless HMAC-signed MCP OAuth 2.1 Authorization Server (RFC 9728 / RFC 8414 / RFC 7591 / PKCE `S256`)
  - `tls.py`, `auth.py`, `files.py`, `protocol.py`, `config.py`
- `tests/` — End-to-end security, MCP, Docker proxy, and dedicated `agy` plugin isolation test suites (`test_gateway.py`, `test_mcp_plugin.py`, `test_docker_proxy.py`, `test_agy_plugins.py`)

---

## Exposed MCP Tools (16), Resources & Prompts

| MCP Tool | Description |
| :--- | :--- |
| `gateway_status` | Live health, uptime, active/queued agent slots, allowed workspaces, trusted `agy` plugin state, Docker proxy state, and policy summary |
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

# Register & hot-toggle operator-verified read-only AGY plugins (default OFF, zero restart)
dots-gateway agy-plugins status|add <plugin_dir>|on|off|remove <plugin_dir>|clear|doctor

# Configure OpenAI API Key for local Codex CLI (`run_codex`, stored 0600, effective immediately)
dots-gateway codex-setup

# Hot-toggle policy-filtered Docker access for sandboxed exec_command / run_agy / run_codex
dots-gateway docker on|off|status|test
```

### Trusted Read-Only `agy` Plugins & 3-Tier Directory Isolation (`dots-gateway agy-plugins`)

By default, `agy` plugin mounting is **disabled (`agy_plugins_enabled: false`)** and preserves 100% original behavior. Because `agy` evaluates `permissions.deny` ahead of `permissions.allow`, placing plugins inside a protected gateway/credential parent directory causes `Matches user-configured deny rule` when reading `SKILL.md`—while deleting parent `deny` rules would expose tunnel and gateway secrets. Instead, `dots-gateway` enforces strict **3-tier directory separation**:

| Directory Category | Recommended Host Layout | Access Contract |
| :--- | :--- | :--- |
| **1. Plugin Resources (`插件资源`)** | `/opt/agy-plugins/oh-my-agents` or `~/agy-plugins/oh-my-agents` | **Read-only (`ro,nosuid,nodev`) + executable scripts** (`skills/`, `hooks/`, `rules/`, `templates/`). Tasks cannot modify installed plugin files; installation/upgrades are operator-only. |
| **2. Project Workspaces (`项目工作区`)** | `~/workspaces/<project>` (`allowed_workdirs`) | **Per-task read-write (`rw`)**. Supports code edits, build/test caches, and `oh-my-agents` `/verify` outputs (`.claude/signals/verify-latest.json`, `.claude/metrics/verify.jsonl`, `docs/exec-plans/active/*.json`). |
| **3. Runtime State & Credentials (`运行状态与凭据`)** | Secrets: `~/gateway`, `~/.config/dots-gateway`, `~/.config/tunnel-client`<br>Login state: `~/.gemini`, `~/.codex`<br>Sandbox runtime: `~/.cache/dots-sandbox` or `/var/tmp/dots-gateway-sandbox` | **Independently protected**. Gateway/tunnel keys remain masked and blocked by parent `permissions.deny`; sandbox locks/queues/tmp (`sandbox_lock_timeout_seconds: 5.0`) fail explicitly (`HTTP 503`) on lock timeout or disk faults (`ENOSPC`/`EROFS`/`EIO`) without falling back to `HOME` or plugin directories. |

**`config.json` Fields (Optional Static Defaults; Hot-Reload Managed via `agy-plugins.json`):**

```json
{
  "allowed_workdirs": ["/home/<your-user>/workspaces"],
  "default_workdir": "/home/<your-user>/workspaces",
  "isolate_mount_namespace": true,
  "agy_default_sandbox": true,
  "agy_plugins_enabled": false,
  "agy_plugin_dirs": [],
  "agy_plugins_file": "/home/<your-user>/.config/dots-gateway/agy-plugins.json",
  "sandbox_state_dir": "/home/<your-user>/.cache/dots-sandbox",
  "sandbox_lock_timeout_seconds": 5.0
}
```

**Operator Setup, Diagnostics & Two-Level Rollback:**

```bash
# 1. Clone plugin into a dedicated directory disjoint from protected_paths, workspaces, ~/.gemini, & /tmp
mkdir -p ~/agy-plugins
git clone -b gemini https://github.com/caishize/oh-my-agents.git ~/agy-plugins/oh-my-agents
chmod -R go-w ~/agy-plugins/oh-my-agents

# 2. Validate boundaries & enable hot-reload (~/.config/dots-gateway/agy-plugins.json, 0600)
dots-gateway agy-plugins add ~/agy-plugins/oh-my-agents
dots-gateway agy-plugins on
dots-gateway agy-plugins doctor   # 4-step check: config, sandbox lock/tmp probe, 3-tier disjointness & --settings

# 3. Inspect secret-redacted diagnostics via CLI, GET /v1/policy, or MCP gateway_status
dots-gateway agy-plugins status

# 4a. Level-1 Rollback (Instant, Zero-Restart): masks plugin paths & strips allow rules immediately
dots-gateway agy-plugins off
# Or clear the hot-reload registry and scrub any stale plugin entries from settings.json:
dots-gateway agy-plugins clear

# 4b. Level-2 Rollback (Version Rollback to an earlier release tag or commit):
dots-gateway agy-plugins clear && git checkout <previous-release-tag-or-commit> && dots-gateway restart
```

- **Synchronized Kernel VFS + `--settings` Rules**: Validated plugins are bind-mounted `ro,nosuid,nodev` at both `<source_dir>` and `~/.gemini/config/plugins/<plugin_name>` (over an isolated read-only `tmpfs`) exclusively inside `run_agy` / `session_start(type="agy")` namespaces, paired with `read_file(...)` (never `write_file(...)`) in `--settings`, `PYTHONDONTWRITEBYTECODE=1`, and `AGY_PLUGIN_ROOT`.
- **Fail-Closed Overlap & Symlink Checks**: Rejects any plugin directory that overlaps protected/credential paths or writable workspace/sandbox/temp paths, or contains symlinked parent components, escaping/dangling symlinks, world-writable (`o+w`) files, `setuid`/`setgid` files, or device/FIFO nodes.
- **Zero Privilege Creep & Queue Re-Validation**: Tasks cannot pass `plugin_dirs` / `--plugin-dir`, inject `--settings`, invoke `agy`/`codex` via `exec_command`, or override `PATH`/`PYTHONPATH`/`AGY_PLUGIN_ROOT`/`TMPDIR`. `/v1/files/*` (`fs_*`), `exec_command`, `run_codex`, and `DockerProxy` gain zero access to plugin directories, and queued `run_agy` sessions re-validate plugin state immediately before process spawn.

### Sandbox Docker Access (`dots-gateway docker`)

The host `docker.sock` (root-equivalent) is **always masked** inside the mount-namespace jail.
When `dots-gateway docker on` is set (hot-reloaded per session, no restart), sessions instead get a
gateway-owned filtering proxy socket at `/var/run/docker.sock`, so `docker` / `docker compose` /
`docker build` work from `exec_command`, scripts, `run_agy`, and `run_codex` with these rules:

- bind mounts (and bind-backed volumes) only inside `allowed_workdirs` (+ `docker_extra_bind_roots`), never in `protected_paths` or registered `agy` plugin directories, symlinks resolved and re-checked at `start`, `restart`, and `unpause`;
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
# Dedicated AGY plugin isolation, adversarial security, fault-injection & rollback suite
PYTHONPATH=.:tests python3 -m unittest tests/test_agy_plugins.py -v

# Full unit, security, Docker proxy, MCP protocol, and stdio plugin bridge test suite
pytest -v
# or via stdlib unittest:
python3 -m unittest discover -s tests -p "test_*.py" -v

# Lint check
ruff check .

# Full live end-to-end verification against running dots-gateway.service (HTTPS + WSS + MCP + agy)
python3 tests/live_call_test.py
```
