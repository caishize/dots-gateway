# Dots <-> Local Dev, Antigravity (`agy`) & Codex MCP Plugin & Hardened Gateway (`v1.5.24`)

A zero-dependency Python 3.11+ **OpenAI `dots` / Codex / Agent Plugins 1.0** package and remote development gateway (`Apache-2.0`). It enables **dots** (or any MCP-compatible client) to securely inspect/edit workspace files, execute allowlisted development commands inside a Linux User + Mount Namespace VFS jail, and delegate tasks to **`agy` (`--sandbox`, with optional isolated read-only plugins & native hook sandboxing)** and **`codex` (`codex exec`, with optional isolated read-only plugins & native hook sandboxing)** via the **Model Context Protocol (MCP)**.

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
|    `delegate-to-agy`, `delegate-to-codex`)|            |  4. Policy, VFS Jail, Plugins, Hook Jail     |
+-------------------------------------------+            |     - `agy --sandbox` & `codex exec`         |
                                                         +----------------------------------------------+
```

---

## Prerequisites

- **Operating System**: Linux with user `systemd` (`systemctl --user`) for background daemon management (or run `python3 main.py` directly in the foreground on containers/WSL).
- **Required System Packages** (zero third-party `pip` packages required):
  - `python3` (`>= 3.11`)
  - `openssl` (auto-generates self-signed TLS 1.3 PKI on first start)
  - `curl` & `git`
  - `util-linux` (`unshare`, `setpriv`, `mount`) with unprivileged user + mount namespaces enabled:
    ```bash
    # Preflight check (should exit 0):
    unshare --user --map-current-user --mount true
    ```
    > **Ubuntu 24.04+ Note**: If AppArmor blocks unprivileged user namespaces (`Operation not permitted`), enable userns or configure an AppArmor profile (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`).
- **Optional Local Agent & Tunnel CLIs** (install only what you need):
  - **OpenAI Codex CLI (`codex`) + `bubblewrap` (`bwrap`)**: Required only if calling `run_codex`.
  - **Google Antigravity CLI (`agy`)**: Required only if calling `run_agy` / `list_agy_models`.
  - **OpenAI `tunnel-client`**: Required only if using Option A (OpenAI Secure MCP Tunnel).
  - **Docker Engine**: Required only if enabling policy-filtered container access (`dots-gateway docker on`).

---

## 1. Quick Start (Deploy in 3 Minutes)

### Step 1: Clone & Start the Gateway

```bash
git clone https://github.com/caishize/dots-gateway.git ~/gateway
cd ~/gateway

# Ensure ~/.local/bin is on PATH, then start the service:
export PATH="$HOME/.local/bin:$PATH"
./gateway.sh start
```

What `./gateway.sh start` does automatically on first run:
1. Generates `config.json` (`0600`) with random 256-bit Bearer API token, HMAC-SHA256 secret, and PBKDF2 credentials.
2. Generates a local Root CA + TLS 1.3 server/client certificate pair under `certs/` (`0600` private keys) and writes local CLI credentials to `~/.config/dots-gateway/client.json` (`0600`).
3. Creates the isolated default workspace directory `~/workspaces`.
4. Installs & starts `~/.config/systemd/user/dots-gateway.service` (with `loginctl enable-linger` so it survives SSH logout) and symlinks `~/.local/bin/dots-gateway`.

> **Foreground / Container Mode (without `systemd`)**:
> ```bash
> python3 main.py --init-only
> python3 main.py
> ```

### Step 2: Verify Local Health & View Connection Credentials

```bash
dots-gateway status
python3 dots_client.py health
python3 dots_client.py exec "git --version && python3 --version"

# Print ready-to-use MCP URLs, Bearer/HMAC tokens, and client.json snippets:
dots-gateway config
```

### Step 3 (Optional): Configure Local Coding Agents (`codex` / `agy`)

```bash
# Configure OpenAI API Key for local Codex CLI (`run_codex`, stored 0600, effective immediately)
dots-gateway codex-setup

# Switch Antigravity auth profile (OAuth vs Google Cloud ADC) & default model (zero restart)
dots-gateway agy-auth status
dots-gateway agy-model list
```

---

## 2. Connect Your MCP Client (`dots` / ChatGPT / Codex / Claude)

### Option A (Recommended — Zero Inbound Ports): OpenAI Secure MCP Tunnel (`tunnel-client`)

Because cloud connector firewalls often block non-`443` ports (`:8765`), raw IPv4 URLs, and wildcard DNS (`sslip.io`), the easiest zero-inbound-port method for OpenAI `dots` is `tunnel-client`:

1. Create or copy a **Tunnel ID** (`tunnel_...`) at <https://platform.openai.com/settings/organization/tunnels> (under the same OpenAI Org/Workspace as `dots`).
2. Create a **Runtime Credential** with **`Tunnels Read + Use`** permissions at <https://platform.openai.com/settings/organization/api-keys>.
3. Run on your gateway host:
   ```bash
   dots-gateway tunnel-setup
   ```
   This writes `~/.config/dots-gateway/tunnel.env` (`0600`), configures `~/.config/tunnel-client/dots-gateway.yaml` to forward concurrent Streamable HTTP requests to `http://127.0.0.1:18765/mcp` (avoiding single-pipe stdio head-of-line blocking), runs `tunnel-client doctor`, enables `dots-gateway-tunnel.service`, and verifies `http://127.0.0.1:18766/readyz`.
4. In `dots` / ChatGPT Connectors, select your Secure MCP Tunnel (`No authentication` / `无需身份认证`). All commands, `agy`, and `codex` runs remain strictly confined to `~/workspaces` via Linux User + Mount Namespace VFS jailing.

### Option B: Direct Remote Streamable HTTP MCP (`/mcp`, Built-in OAuth 2.1 or Bearer/Capability Path)

When exposed over HTTPS (either via a reverse proxy like Caddy/Nginx on `:443` with a custom domain, or directly via `dots-gateway sync-ip` Let's Encrypt certificate):
- **Built-in MCP OAuth 2.1 (`gateway/oauth.py`)**: RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`), RFC 8414 Authorization Server Metadata (`/.well-known/oauth-authorization-server`), RFC 7591 Dynamic Client Registration (`/oauth/register`), PKCE `S256` `/oauth/authorize` (restricted by `oauth_allowed_redirect_hosts` in `config.json`), and stateless HMAC `/oauth/token`.
- **Standard Bearer Header**: Point any Streamable HTTP MCP client at `https://<YOUR_DOMAIN>/mcp` with `Authorization: Bearer <YOUR_API_TOKEN>` (see `mcp.remote.example.json`).
- **Zero-Header Capability Path**: `https://<YOUR_DOMAIN>/mcp/<YOUR_API_TOKEN>` for UIs without custom header fields.

### Option C: Install as Local / Remote `stdio` Plugin (`dots_mcp.py`)

Install this repository (`https://github.com/caishize/dots-gateway.git`) as a plugin in Codex or any MCP `stdio` host:
1. Run `dots-gateway config` on the gateway host and copy the generated `client.json` block to `~/.config/dots-gateway/client.json` (`0600`) on the client machine (or set `GATEWAY_URL`, `GATEWAY_HMAC_SECRET`, and `GATEWAY_TLS_FINGERPRINT`).
2. `mcp.json` launches `./dots_mcp.py`, bridging JSON-RPC over TLS 1.3 with SHA-256 certificate pinning and replay-proof HMAC-SHA256 request signing (or pass `./dots_mcp.py --local` when running on the same machine).

---

## 3. Day-2 Operations CLI Reference (`dots-gateway`)

```bash
dots-gateway --help
dots-gateway status           # Service health, sandbox storage, active agents, plugins & tunnel status
dots-gateway start            # Start gateway (and configured tunnel) + run health checks
dots-gateway restart          # Safely drains active sessions before restarting (pass --force to skip drain)
dots-gateway stop             # Stop gateway & tunnel services
dots-gateway logs -f          # Tail systemd journal for gateway & tunnel (`dots-gateway logs tunnel -f` for tunnel only)
dots-gateway config           # Print remote MCP URLs, OAuth endpoints & client.json snippets
dots-gateway sync-ip [IP]     # Issue/renew Let's Encrypt short-lived IP + sslip.io certificate (requires TCP :80)

# Hot-reloadable Agent & Sandbox Controls (effective immediately for new sessions, zero restart):
dots-gateway agy-auth status|adc [PROJECT_ID]|oauth|toggle
dots-gateway agy-model list|status|set <MODEL_ID>|reset
dots-gateway agy-plugins status|add <PLUGIN_DIR>|on|off|remove <PLUGIN_DIR>|clear|doctor
dots-gateway codex-setup
dots-gateway codex-plugins status|add <PLUGIN_DIR>|on|off|remove <PLUGIN_DIR>|clear|doctor
dots-gateway docker on|off|toggle|status|test
```

---

## 4. Exposed MCP Tools (16), Resources & Prompts

| MCP Tool | Description |
| :--- | :--- |
| `gateway_status` | Live health, uptime, active/queued agent slots, allowed workspaces, trusted `agy` & `codex` plugin state, Docker proxy state, and policy summary |
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

## 5. Advanced Isolation & Security Architecture

### Isolated Plugin Discovery & Unified Native Hook Sandboxing (`agy-plugins` & `codex-plugins`)

By default, both `agy` and `codex` plugin mounting are **disabled (`agy_plugins_enabled: false`, `codex_plugins_enabled: false`)**.

#### Why Isolated Discovery + Unified Hook Sandboxing Are Required
1. **Protected `HOME` vs Plugin Discovery (`deny > allow`)**: When a deployment protects `HOME`, Gateway keeps `read_file(<real_HOME>)` in `permissions.deny`. Discovering plugins under `<real_HOME>/.gemini/config/plugins/<name>` would hit user deny rules, whereas deleting parent `deny` rules would expose tunnel and gateway secrets.
2. **Native Auto-Triggered Hooks Run Outside Inner Tool Sandboxes**: Both `agy` and `codex` execute `hooks.json` command handlers directly in the outer agent process (outside `agy --sandbox` and outside `codex-linux-sandbox`), where an unsandboxed hook could read agent OAuth/ADC/`auth.json` credentials or execute untrusted code planted inside a writable workspace.

Gateway solves both problems simultaneously **without opening real `HOME` or weakening parent `deny` rules**:
- **Isolated Runtime & Plugin Discovery (`agent_runtime_home_root`, default `/mnt/dots-agent-home`)**: Inside the session's mount namespace, `agy` runs with `HOME=<agent_runtime_home_root>/agy` (discovering read-only plugins at `<agent_runtime_home_root>/agy/.gemini/config/plugins/<name>`) and `codex` runs with `HOME=<agent_runtime_home_root>/codex` + `CODEX_HOME=<agent_runtime_home_root>/codex/.codex` backed by disk storage at `<sandbox_state_dir>/codex_home` (permanently masking `$CODEX_HOME/hooks.json` with `/dev/null` and discovering read-only plugins over an isolated `tmpfs` at `<CODEX_HOME>/plugins/cache/<marketplace>/<name>/<version>` with synthesized `config.toml` `trusted_hash` & `trusted_content_hash`), while `<real_HOME>` stays masked and denied.
- **Strict 3-Category Directory Separation (`plugin_state_dir`)**: Project progress (`docs/exec-plans/active/*.json`), `/verify` signals (`.claude/signals/verify-latest.json` for `agy`, `.codex/signals/verify-latest.json` for `codex`), and metrics (`.claude/metrics/*`, `.codex/metrics/*`) write strictly to authorized `allowed_workdirs`, while hook temporary queues (`TMPDIR`) and `PLUGIN_DATA` / `CLAUDE_PLUGIN_DATA` write strictly to isolated per-session directories under `plugin_state_dir` (default `<sandbox_state_dir>/plugin_state`).
- **Unified Native Hook Jail (`gateway/hook_jail.py` -> `dots-hook-jail.py`)**: Every native `hooks.json` command handler in staged `agy` and `codex` plugins is validated fail-closed and rewritten to execute inside `dots-hook-jail.py`. Each hook invocation enters a dedicated inner `unshare --user --map-current-user --mount --propagation private` + `pivot_root` jail that:
  - masks agent credentials (`oauth_creds.json`, `application_default_credentials.json`, `$CODEX_HOME/auth.json`, `~/.config/gh`, `~/.ssh`, `protected_paths`) and scrubs secret environment variables (`OPENAI_API_KEY`, `CODEX_API_KEY`, `GOOGLE_*`, `ANTHROPIC_*`, `GH_TOKEN`, etc.);
  - mounts `allowed_workdirs` with **`rw,nosuid,nodev,noexec`** (W^X: hooks can inspect files and append project metrics ledgers while kernel `noexec` + path validation block executing untrusted workspace binaries/scripts);
  - forces `python3 -I` + `PYTHONSAFEPATH=1` + `PYTHONDONTWRITEBYTECODE=1` and injects `GIT_CONFIG_COUNT` overrides neutralizing repo `.git/config` `core.fsmonitor` / `core.sshCommand` / `core.hooksPath` / `diff.external` execution;
  - masks active workspace hook/config injection paths (`.gemini/settings.json`, `.gemini/antigravity-cli`, `.gemini/config/plugins`, `.codex/hooks.json`, `.codex/config.toml`, `.agents/plugins`, `.git/hooks`) and locks passive Git-tracked Claude config/hook paths (`.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks`) read-only + `noexec`;
  - **fails closed** if Linux user + mount namespaces (`unshare`) are disabled or blocked by host kernel/seccomp policy.

| Directory Category | Recommended Host Layout | Access Contract |
| :--- | :--- | :--- |
| **1. Plugin Resources (`插件资源`)** | `~/agy-plugins/oh-my-agents` (`gemini` branch)<br>`~/codex-plugins/oh-my-agents` (`codex` branch) | **Read-only (`ro,nosuid,nodev`) + executable scripts**, exposed under `agent_runtime_home_root`. Tasks and hooks cannot modify installed plugin files. |
| **2. Project Workspaces (`项目工作区`)** | `~/workspaces/<project>` (`allowed_workdirs`) | **Per-task read-write (`rw`)** for the agent (`rw,nosuid,nodev,noexec` W^X inside native hooks; repo-local hook/config injection paths masked). |
| **3. Runtime State & Credentials (`运行状态与凭据`)** | Secrets: `~/gateway`, `~/.config/dots-gateway`, `~/.config/tunnel-client`<br>Login state: `~/.gemini`, `~/.codex`<br>Sandbox & hook state: `~/.cache/dots-sandbox` (`plugin_state_dir`) | **Independently protected**. Gateway/tunnel keys stay masked in both agents and hooks; agent login tokens are visible only to the outer agent binary and masked inside native hooks. |

**Operator Setup & Instant Rollback Example (`oh-my-agents`):**

```bash
# 1a. Clone & enable oh-my-agents (gemini branch) for AGY (zero gateway restart)
mkdir -p ~/agy-plugins
git clone -b gemini https://github.com/caishize/oh-my-agents.git ~/agy-plugins/oh-my-agents
chmod -R go-w ~/agy-plugins/oh-my-agents
dots-gateway agy-plugins add ~/agy-plugins/oh-my-agents --enable
dots-gateway agy-plugins doctor

# 1b. Clone & enable oh-my-agents (codex branch) for Codex (zero gateway restart)
mkdir -p ~/codex-plugins
git clone -b codex https://github.com/caishize/oh-my-agents.git ~/codex-plugins/oh-my-agents
chmod -R go-w ~/codex-plugins/oh-my-agents
dots-gateway codex-plugins add ~/codex-plugins/oh-my-agents --enable
dots-gateway codex-plugins doctor

# 2. Instant Rollback (zero restart):
dots-gateway agy-plugins off && dots-gateway codex-plugins off
```

### Sandbox Docker Access (`dots-gateway docker`)

The host `docker.sock` (root-equivalent) is **always masked** inside the mount-namespace jail. When `dots-gateway docker on` is set, sessions get a gateway-owned filtering proxy socket at `/var/run/docker.sock`:
- bind mounts (and bind-backed volumes) only inside `allowed_workdirs` (+ `docker_extra_bind_roots`), never in `protected_paths`, `plugin_state_dir`, or registered plugin directories, with symlinks re-checked at `start`, `restart`, and `unpause`;
- no `--privileged`, `--device`, `--cap-add` (unless in `docker_allowed_capabilities`), `--pid/--ipc/--uts/--userns=host`, custom runtimes, or unconfined security options;
- only containers/volumes/networks created through the proxy (label `io.dots-gateway.managed=true`) can be inspected, exec'd, attached, or removed — host containers stay invisible;
- published ports are rewritten to `127.0.0.1` (`docker_force_loopback_ports`); swarm, plugins, and unknown API routes are denied.

> Note: files written by root inside containers to bind-mounted workspaces become root-owned; run containers with `--user "$(id -u):$(id -g)"` when needed.

---

## 6. Plugin & Repository Layout

- `plugin.json` & `.codex-plugin/plugin.json` — Portable **Agent Plugins 1.0** + OpenAI `extensions.com.openai` & Codex plugin manifests (`v1.5.24`, `Apache-2.0`)
- `pyproject.toml` — Zero-dependency Python 3.11+ package metadata (`v1.5.24`), `pytest`, and `ruff` configuration
- `LICENSE` & `SECURITY.md` — Apache License 2.0 and private vulnerability disclosure / deployment baseline
- `mcp.json` & `mcp.remote.example.json` — Bundled `stdio` MCP definition (`./dots_mcp.py`) and example `streamable-http` MCP configuration
- `config.example.json` & `client.example.json` — Reference host gateway & client configuration templates
- `skills/` (`remote-dev-gateway`, `delegate-to-agy`, `delegate-to-codex`) & `rules/AGENTS.md` — Bundled agent workflow skills and workspace safety rules
- `gateway.sh` — Unified operator CLI (`~/.local/bin/dots-gateway`)
- `dots_mcp.py` & `dots_client.py` — Standalone zero-dependency MCP `stdio` bridge and Python SDK/CLI
- `main.py` & `deploy/` — Gateway entrypoint, `systemd` user unit templates, and Let's Encrypt IP certificate helper
- `gateway/` — Core server (`server.py`, `mcp.py`, `auth.py`, `oauth.py`, `policy.py`, `sandbox.py`, `hook_jail.py`, `executor.py`, `docker_proxy.py`, `files.py`, `tls.py`, `protocol.py`, `config.py`)

---

## 7. Running Automated & Live Tests

```bash
# Full unit, security, Docker proxy, MCP protocol, and plugin/hook isolation test suite
pytest -v
# or via stdlib unittest (zero external test dependencies):
python3 -m unittest discover -s tests -p "test_*.py" -v

# Lint & shell syntax checks
ruff check .
bash -n gateway.sh

# Full live end-to-end verification against running dots-gateway.service (HTTPS + WSS + MCP + agy)
python3 tests/live_call_test.py
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
