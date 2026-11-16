# Dots <-> Local Dev, Antigravity (`agy`) & Codex MCP Plugin & Hardened Gateway (`v1.5.23`)

A zero-dependency Python 3.11+ **OpenAI `dots` / Codex / Agent Plugins 1.0** package and remote development gateway. It enables **dots** (running on OpenAI cloud machines) to securely inspect/edit workspace files, execute allowlisted development commands inside a Linux User + Mount Namespace VFS jail, and delegate tasks to **`agy` (`--sandbox`, with optional isolated read-only plugins & native hook sandboxing)** and **`codex` (`codex exec`, with optional isolated read-only plugins & native hook sandboxing)** via the **Model Context Protocol (MCP)**.

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

## Plugin & Repository Layout

- `plugin.json` & `.codex-plugin/plugin.json` — Portable **Agent Plugins 1.0** + OpenAI `extensions.com.openai` & Codex plugin manifests (`v1.5.23`)
- `pyproject.toml` — Zero-dependency Python 3.11+ package metadata (`v1.5.23`), `pytest`, and `ruff` configuration
- `mcp.json` — Bundled `stdio` MCP server definition (`./dots_mcp.py`) supporting self-signed TLS SHA-256 pinning & HMAC-SHA256
- `mcp.remote.example.json` — Example `streamable-http` MCP configuration for direct `/mcp` connectors
- `config.example.json` — Reference host gateway configuration including isolated plugin runtime (`agent_runtime_home_root`, `plugin_state_dir`), `agy` & `codex` plugins, and Docker proxy settings
- `skills/`
  - `remote-dev-gateway/SKILL.md` — Workflow guide for remote file operations, builds/tests, and background sessions
  - `delegate-to-agy/SKILL.md` — Workflow guide for delegating multi-file engineering tasks to local `agy` (`--sandbox`)
  - `delegate-to-codex/SKILL.md` — Workflow guide for delegating coding & independent reviews to local `codex exec`
- `rules/AGENTS.md` — Active workspace & security rules bundled with the plugin
- `gateway.sh` — Unified operator CLI (`~/.local/bin/dots-gateway`) for service lifecycle, tunnels, auth, models, trusted `agy` & `codex` plugins, and Docker toggle
- `dots_mcp.py` — Standalone zero-dependency MCP `stdio` bridge & local MCP runner
- `dots_client.py` — Standalone zero-dependency Python SDK & CLI (`health`, `policy`, `exec`, `agy`, `agy-models`, `codex`, `ls`, `upload`, `download`)
- `main.py` — Gateway daemon entrypoint, PKI initializer, and `--print-plugin-config` generator
- `deploy/` — User `systemd` unit templates (`dots-gateway.service`, `dots-gateway-tunnel.service`) and Let's Encrypt certificate helper
- `gateway/`
  - `mcp.py` — Full MCP JSON-RPC 2.0 dispatcher (`2024-11-05` / `2025-03-26` / `2025-06-18` / `2026-07-28`)
  - `server.py` — Streamable HTTP `/mcp`, REST/SSE `/v1/*`, OAuth 2.1 routes, and full-duplex WebSocket `/v1/ws` router
  - `policy.py` — Command/shell validation, 3-tier `agy` & `codex` plugin boundary verification, and per-session `--settings` / `codex` argv synthesis
  - `hook_jail.py` — Isolated plugin runtime synthesizer (`agent_runtime_home_root`), hook manifest validator, Codex trust-hash synthesizer, and standalone `dots-hook-jail.py` runner for native `agy` & `codex` hooks
  - `sandbox.py` — Unprivileged Linux User + Mount Namespace (`unshare` + `pivot_root` + `setpriv`) VFS workspace jail, isolated runtime homes, read-only plugin mounts, workspace hook-injection masking, storage fault lock probes, & 2-tier LRU cache lifecycle manager
  - `executor.py` — Async process/PTY session manager, environment sanitization, isolated plugin/hook staging, and queued session TOCTOU re-validation
  - `docker_proxy.py` — Policy-filtering Unix-socket Docker API proxy for sandboxed sessions
  - `oauth.py` — Stateless HMAC-signed MCP OAuth 2.1 Authorization Server (RFC 9728 / RFC 8414 / RFC 7591 / PKCE `S256`)
  - `tls.py`, `auth.py`, `files.py`, `protocol.py`, `config.py`
- `tests/` — End-to-end security, MCP, Docker proxy, and dedicated `agy` & `codex` plugin/hook isolation test suites (`test_gateway.py`, `test_mcp_plugin.py`, `test_docker_proxy.py`, `test_agy_plugins.py`, `test_plugin_isolation_and_hooks_v1517.py`)

---

## Exposed MCP Tools (16), Resources & Prompts

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

# Register & hot-toggle operator-verified read-only Codex plugins (default OFF, zero restart)
dots-gateway codex-plugins status|add <plugin_dir>|on|off|remove <plugin_dir>|clear|doctor

# Configure OpenAI API Key for local Codex CLI (`run_codex`, stored 0600, effective immediately)
dots-gateway codex-setup

# Hot-toggle policy-filtered Docker access for sandboxed exec_command / run_agy / run_codex
dots-gateway docker on|off|status|test
```

### Isolated Plugin Discovery & Unified Native Hook Sandboxing (`agy-plugins` & `codex-plugins`, `v1.5.17`)

By default, both `agy` and `codex` plugin mounting are **disabled (`agy_plugins_enabled: false`, `codex_plugins_enabled: false`)** and preserve 100% backward-compatible behavior.

#### Why Isolated Discovery + Unified Hook Sandboxing Are Required
1. **Protected `HOME` vs Plugin Discovery (`deny > allow`)**: When a deployment protects `HOME` (or an umbrella parent directory holding gateway config, tunnel credentials, and agent binaries), Gateway keeps `read_file(<real_HOME>)` in `permissions.deny`. In `v1.5.16`, discovering plugins under `<real_HOME>/.gemini/config/plugins/<name>` triggered `Matches user-configured deny rule` when reading `SKILL.md`. Deleting parent `deny` rules would expose tunnel and gateway secrets.
2. **Native Auto-Triggered Hooks Run Outside Inner Tool Sandboxes**: Both `agy` and `codex` execute `hooks.json` command handlers directly in the outer agent process (outside `agy --sandbox` and outside `codex-linux-sandbox`), where an unsandboxed hook could read agent OAuth/ADC/`auth.json` credentials or execute untrusted code planted inside a writable workspace.

`v1.5.17` solves both problems simultaneously **without opening real `HOME` or weakening parent `deny` rules**:
- **Isolated Runtime & Plugin Discovery (`agent_runtime_home_root`, default `/mnt/dots-agent-home`)**: Inside the session's mount namespace, `agy` runs with `HOME=<agent_runtime_home_root>/agy` (discovering read-only plugins at `<agent_runtime_home_root>/agy/.gemini/config/plugins/<name>`) and `codex` runs with `HOME=<agent_runtime_home_root>/codex` + `CODEX_HOME=<agent_runtime_home_root>/codex/.codex` backed by disk storage at `<sandbox_state_dir>/codex_home` (preventing root `tmpfs` `ENOSPC` / `SQLITE_FULL` during rollout indexing and plugin catalog staging while permanently masking `$CODEX_HOME/hooks.json` with `/dev/null` and discovering read-only plugins over an isolated `tmpfs` at `<CODEX_HOME>/plugins/cache/<marketplace>/<name>/<version>` with synthesized `config.toml` `trusted_hash` & `trusted_content_hash`), while `<real_HOME>` and host `<sandbox_state_dir>/codex_home` stay masked and denied (`~` in host `settings.json` deny rules is expanded to `<real_HOME>` before mounting). If `agy_binary` or `codex_binary` resides under a protected parent directory, only that exact binary (plus resolved shared-library target inside the same tree) is re-exposed read+exec (`0555`) over a masked `tmpfs` while sibling config/credentials stay invisible.
- **Strict 3-Category Directory Separation (`plugin_state_dir`)**: Project progress (`docs/exec-plans/active/*.json`), `/verify` signals (`.claude/signals/verify-latest.json` for `agy`, `.codex/signals/verify-latest.json` for `codex`), and metrics (`.claude/metrics/*`, `.codex/metrics/*`) write strictly to authorized `allowed_workdirs`, while hook temporary queues (`antigravity-adapter.py` `TMPDIR`) and Codex persistent hook data (`PLUGIN_DATA` / `CLAUDE_PLUGIN_DATA`) write strictly to isolated per-session directories under `plugin_state_dir` (default `<sandbox_state_dir>/plugin_state`)—never to read-only plugin code directories or real `HOME`.
- **Unified Native Hook Jail (`gateway/hook_jail.py` -> `dots-hook-jail.py`)**: Every native `hooks.json` command handler in staged `agy` and `codex` plugins is validated fail-closed (must resolve strictly inside the plugin tree; rejects workspace executables, `..`, shell expansions, and non-command handlers) and rewritten to execute inside `dots-hook-jail.py`. Each hook invocation enters a dedicated inner `unshare --user --map-current-user --mount --propagation private` + `pivot_root` jail that:
  - masks agent credentials (`oauth_creds.json`, `application_default_credentials.json`, `$CODEX_HOME/auth.json`, `~/.config/gh`, `~/.ssh`, `protected_paths`) and scrubs secret environment variables (`OPENAI_API_KEY`, `CODEX_API_KEY`, `GOOGLE_*`, `ANTHROPIC_*`, `GH_TOKEN`, etc.);
  - mounts `allowed_workdirs` with **`rw,nosuid,nodev,noexec`** (W^X: hooks can inspect files and append project metrics ledgers such as `.claude/metrics/*` / `.codex/metrics/*`, while kernel `noexec` + command path validation block executing untrusted binaries/scripts in the project tree);
  - forces `python3 -I` + `PYTHONSAFEPATH=1` + `PYTHONDONTWRITEBYTECODE=1` (defeating `<cwd>/json.py` import hijacking) and injects `GIT_CONFIG_COUNT` overrides neutralizing repo `.git/config` `core.fsmonitor` / `core.sshCommand` / `core.hooksPath` / `diff.external` execution;
  - masks active workspace hook/config injection paths (`.gemini/settings.json`, `.gemini/antigravity-cli`, `.gemini/config/plugins`, `.codex/hooks.json`, `.codex/config.toml`, `.agents/plugins`, `.git/hooks`) and locks passive Git-tracked Claude config/hook paths (`.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks`) read-only + `noexec` in both outer and inner VFS (preserving clean `git status` / `git merge` while blocking writes and enforcing symlink-escape checks in `PreToolUse`);
  - **fails closed** (never silently degrades) if Linux user + mount namespaces (`unshare`) are disabled or blocked by host kernel/seccomp policy.

| Directory Category | Recommended Host Layout | Access Contract |
| :--- | :--- | :--- |
| **1. Plugin Resources (`插件资源`)** | `~/agy-plugins/oh-my-agents` (`gemini` branch)<br>`~/codex-plugins/oh-my-agents` (`codex` branch) | **Read-only (`ro,nosuid,nodev`) + executable scripts** (`skills/`, `hooks/`, `scripts/`, `rules/`, `templates/`), exposed under `agent_runtime_home_root`. Tasks and hooks cannot modify installed plugin files. |
| **2. Project Workspaces (`项目工作区`)** | `~/workspaces/<project>` (`allowed_workdirs`) | **Per-task read-write (`rw`)** for the agent (`rw,nosuid,nodev,noexec` W^X inside native hooks; repo-local hook/config injection paths masked). Supports code edits, build/test caches, and `oh-my-agents` `/verify` outputs (`.claude/signals/*`, `.codex/signals/*`, `.claude/metrics/*`, `.codex/metrics/*`, `docs/exec-plans/*`). |
| **3. Runtime State & Credentials (`运行状态与凭据`)** | Secrets: `~/gateway`, `~/.config/dots-gateway`, `~/.config/tunnel-client`<br>Login state: `~/.gemini`, `~/.codex`<br>Sandbox & hook state: `~/.cache/dots-sandbox` (`plugin_state_dir`) | **Independently protected**. Gateway/tunnel keys stay masked in both agents and hooks; agent login tokens are visible only to the outer agent binary and masked inside native hooks; lock/disk faults fail closed (`HTTP 503`) without falling back to `HOME` or plugin directories. |

**`config.json` Fields (Optional Static Defaults; Hot-Reload Managed via `agy-plugins.json` & `codex-plugins.json`):**

```json
{
  "allowed_workdirs": ["/home/<your-user>/workspaces"],
  "default_workdir": "/home/<your-user>/workspaces",
  "isolate_mount_namespace": true,
  "agent_runtime_home_root": "/mnt/dots-agent-home",
  "sandbox_state_dir": "/home/<your-user>/.cache/dots-sandbox",
  "plugin_state_dir": "/home/<your-user>/.cache/dots-sandbox/plugin_state",
  "sandbox_lock_timeout_seconds": 5.0,
  "agy_default_sandbox": true,
  "agy_plugins_enabled": false,
  "agy_plugin_dirs": [],
  "agy_plugins_file": "/home/<your-user>/.config/dots-gateway/agy-plugins.json",
  "codex_plugins_enabled": false,
  "codex_plugin_dirs": [],
  "codex_plugins_file": "/home/<your-user>/.config/dots-gateway/codex-plugins.json"
}
```

**Operator Setup, Diagnostics & Two-Level Rollback (`oh-my-agents` for `agy` & `codex`):**

```bash
# 1a. Clone & enable oh-my-agents (gemini branch) for AGY (zero gateway restart)
mkdir -p ~/agy-plugins
git clone -b gemini https://github.com/caishize/oh-my-agents.git ~/agy-plugins/oh-my-agents
chmod -R go-w ~/agy-plugins/oh-my-agents
dots-gateway agy-plugins add ~/agy-plugins/oh-my-agents
dots-gateway agy-plugins on
dots-gateway agy-plugins doctor   # Verifies config, state lock/tmp, isolated runtime staging + hook jail & --settings
dots-gateway agy-plugins status

# 1b. Clone & enable oh-my-agents (codex branch) for Codex (zero gateway restart)
mkdir -p ~/codex-plugins
git clone -b codex https://github.com/caishize/oh-my-agents.git ~/codex-plugins/oh-my-agents
chmod -R go-w ~/codex-plugins/oh-my-agents
dots-gateway codex-plugins add ~/codex-plugins/oh-my-agents
dots-gateway codex-plugins on
dots-gateway codex-plugins doctor # Verifies config, state lock/tmp, isolated CODEX_HOME staging, trust hashes & hook jail
dots-gateway codex-plugins status

# 2a. Level-1 Rollback (Instant, Zero-Restart): disables plugins & removes isolated mounts immediately
dots-gateway agy-plugins off
dots-gateway codex-plugins off
# Or clear registries completely:
dots-gateway agy-plugins clear
dots-gateway codex-plugins clear

# 2b. Level-2 Rollback (Version Rollback to an earlier release tag or commit):
dots-gateway agy-plugins clear && dots-gateway codex-plugins clear
git checkout <previous-release-tag-or-commit> && dots-gateway restart
```

### Sandbox Docker Access (`dots-gateway docker`)

The host `docker.sock` (root-equivalent) is **always masked** inside the mount-namespace jail.
When `dots-gateway docker on` is set (hot-reloaded per session, no restart), sessions instead get a
gateway-owned filtering proxy socket at `/var/run/docker.sock`, so `docker` / `docker compose` /
`docker build` work from `exec_command`, scripts, `run_agy`, and `run_codex` with these rules:

- bind mounts (and bind-backed volumes) only inside `allowed_workdirs` (+ `docker_extra_bind_roots`), never in `protected_paths`, `plugin_state_dir`, or registered `agy` / `codex` plugin directories, symlinks resolved and re-checked at `start`, `restart`, and `unpause`;
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
# Dedicated AGY & Codex isolated plugin discovery, native hook jail, symlink & rollback suites
python3 -m unittest discover -s tests -p "test_plugin_isolation_and_hooks_v1517.py" -v
python3 -m unittest discover -s tests -p "test_agy_plugins.py" -v

# Full unit, security, Docker proxy, MCP protocol, and stdio plugin bridge test suite
pytest -v
# or via stdlib unittest:
python3 -m unittest discover -s tests -p "test_*.py" -v

# Lint & shell syntax checks
ruff check .
bash -n gateway.sh

# Full live end-to-end verification against running dots-gateway.service (HTTPS + WSS + MCP + agy)
python3 tests/live_call_test.py
```
