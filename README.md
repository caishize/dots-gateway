# Dots Gateway — Hardened Remote Dev & Multi-Agent (`agy` / `codex` / `claude`) MCP Server (`v1.5.25`)

A **zero-dependency** Python 3.11+ remote development gateway and multi-platform plugin (`Apache-2.0`). `dots-gateway` connects cloud, desktop, and custom AI agents (**OpenAI `dots` / ChatGPT / Codex**, **Anthropic Claude Code / Claude.ai / Messages API**, **xAI Grok**, **OpenClaw**, **Google Antigravity `agy`**, **Cursor / Windsurf / VS Code**, and custom Python/TS agents) to your Linux development machine over the **Model Context Protocol (MCP)**, REST/SSE, and full-duplex WebSockets.

All commands and local coding agents execute inside a **Linux User + Mount Namespace VFS jail (`unshare` + `pivot_root`)** confined strictly to authorized workspaces (`~/workspaces`), with optional **isolated read-only plugins** and **unified W^X native hook sandboxing (`dots-hook-jail.py`)** across **`agy`**, **`codex`**, and **`claude`**.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [1. Quick Start (Deploy in 3 Minutes)](#1-quick-start-deploy-in-3-minutes)
- [2. Client Configuration Guide (OpenAI / Anthropic / Grok / OpenClaw / Custom Agents)](#2-client-configuration-guide-openai--anthropic--grok--openclaw--custom-agents)
  - [2.1 Choose Your Transport & Exposure Mode](#21-choose-your-transport--exposure-mode)
  - [2.2 OpenAI (`dots` / ChatGPT / Codex CLI / Responses API / Agents SDK)](#22-openai-dots--chatgpt--codex-cli--responses-api--agents-sdk)
  - [2.3 Anthropic (Claude Code CLI / Claude.ai / Claude Desktop / Messages API)](#23-anthropic-claude-code-cli--claudeai--claude-desktop--messages-api)
  - [2.4 xAI Grok (Responses API & `xai-sdk`)](#24-xai-grok-responses-api--xai-sdk)
  - [2.5 OpenClaw (`openclaw.json` & CLI)](#25-openclaw-openclawjson--cli)
  - [2.6 Other IDEs & Custom Agent Frameworks (`agy` / Cursor / MCP SDK / LangGraph / Python SDK)](#26-other-ides--custom-agent-frameworks-agy--cursor--mcp-sdk--langgraph--python-sdk)
- [3. Day-2 Operations CLI Reference (`dots-gateway`)](#3-day-2-operations-cli-reference-dots-gateway)
- [4. Exposed MCP Tools (17), Resources & Prompts](#4-exposed-mcp-tools-17-resources--prompts)
- [5. Isolation & Security Architecture](#5-isolation--security-architecture)
- [6. Repository Layout](#6-repository-layout)
- [7. Running Automated & Live Tests](#7-running-automated--live-tests)
- [License](#license)

---

## Architecture Overview

```text
Cloud / Desktop / Custom AI Clients                      Linux Dev Host (`~/gateway`)
+---------------------------------------------+          +--------------------------------------------------+
| • OpenAI: dots / ChatGPT / Codex / API      |          | GatewayServer (`gateway/server.py`)              |
| • Anthropic: Claude Code / Claude / API     |  TLS 1.3 |  1. Transports                                   |
| • xAI Grok: Responses API / xai-sdk         |   or     |     - Streamable HTTP `/mcp` + SSE Progress      |
| • OpenClaw: `mcp.servers.dots-gateway`      |  Tunnel  |     - Loopback `127.0.0.1:18765/mcp` (Tunnel)    |
| • IDEs & Custom Agents: agy / Cursor / SDK  | <======> |     - REST `/v1/*` + Duplex WebSocket `/v1/ws`   |
|                                             |          |  2. Auth (`auth.py` / `oauth.py`)                |
| Connection Modes:                           |          |     - Bearer / Bare Token / Capability Path      |
|  A) OpenAI `tunnel-client` (0 inbound port) |          |     - OAuth 2.1 + PKCE / HMAC-SHA256 / mTLS      |
|  B) Remote Streamable HTTP (`POST /mcp`)    |          |  3. Policy + VFS Namespace Jail (`sandbox.py`)   |
|  C) Local/Pinned `stdio` (`dots_mcp.py`)    |          |     - Atomic `fs_*` + Allowlisted `exec_command` |
+---------------------------------------------+          |     - Local Agents: `agy` | `codex` | `claude`   |
                                                         |     - Hook Jail (`dots-hook-jail.py`) + Docker   |
                                                         +--------------------------------------------------+
```

---

## Prerequisites

- **Operating System**: Linux (`x86_64` / `arm64`) with user `systemd` (`systemctl --user`) for background daemon management (or run `python3 main.py` directly in containers/WSL).
- **Required System Packages** (zero third-party `pip` dependencies):
  - `python3` (`>= 3.11`), `openssl`, `curl`, `git`
  - `util-linux` (`unshare`, `setpriv`, `mount`) with unprivileged user + mount namespaces enabled:
    ```bash
    # Preflight check (must exit 0):
    unshare --user --map-current-user --mount true
    ```
    > **Ubuntu 24.04+ Note**: If AppArmor restricts unprivileged user namespaces (`Operation not permitted`), allow userns (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`) or install an AppArmor profile.
- **Optional Local Coding Agents & Companions** (install any subset on the gateway host):
  - **Google Antigravity CLI (`agy`)**: Enables `run_agy`, `list_agy_models`, and interactive `session_start(type="agy")`.
  - **OpenAI Codex CLI (`codex`) + `bubblewrap` (`bwrap`)**: Enables `run_codex` and `codex exec review`.
  - **Anthropic Claude Code CLI (`claude`)**: Enables `run_claude` and interactive `session_start(type="claude")`.
  - **OpenAI `tunnel-client`**: Enables zero-inbound-port Secure MCP Tunnel (`dots-gateway tunnel-setup`).
  - **Docker Engine**: Enables policy-filtered sandbox container access (`dots-gateway docker on`).

---

## 1. Quick Start (Deploy in 3 Minutes)

### Step 1: Clone & Start the Gateway

```bash
git clone https://github.com/caishize/dots-gateway.git ~/gateway
cd ~/gateway

# Ensure ~/.local/bin is on PATH, then initialize & start the service:
export PATH="$HOME/.local/bin:$PATH"
./gateway.sh start
```

On first run, `./gateway.sh start` automatically:
1. Generates `config.json` (`0600`) with a 256-bit Bearer API token, 256-bit HMAC-SHA256 secret, and PBKDF2 Basic Auth credentials.
2. Generates a local Root CA + TLS 1.3 server/client certificate pair in `certs/` (`0600`) and writes local CLI credentials to `~/.config/dots-gateway/client.json` (`0600`).
3. Creates the jailed default workspace directory `~/workspaces`.
4. Installs & starts `~/.config/systemd/user/dots-gateway.service` (enabling `loginctl enable-linger` so it survives SSH logout) and symlinks `~/.local/bin/dots-gateway`.

> **Foreground / Container Mode (without `systemd`)**:
> ```bash
> python3 main.py --init-only
> python3 main.py
> ```

### Step 2: Verify Health & Print Ready-to-Use Client Snippets

```bash
dots-gateway status
python3 dots_client.py health
python3 dots_client.py exec "git --version && python3 --version"

# Print your generated URLs, tokens, and copy-paste snippets for all clients:
dots-gateway config
```

### Step 3 (Optional): Configure Local Coding Agents (`agy` / `codex` / `claude`)

All agent credentials are stored with `0600` permissions under `~/.config/dots-gateway/` and **hot-reloaded per session without restarting the gateway**:

```bash
# 1. Google Antigravity CLI (`run_agy`) — switch OAuth vs Google Cloud ADC & default model:
dots-gateway agy-auth status
dots-gateway agy-model list

# 2. OpenAI Codex CLI (`run_codex`) — store isolated API credential:
dots-gateway codex-setup

# 3. Anthropic Claude Code CLI (`run_claude`) — store isolated credential
#    (or run `claude auth login` on the host to use ~/.claude/.credentials.json):
dots-gateway claude-setup
dots-gateway claude-model status
```

---

## 2. Client Configuration Guide (OpenAI / Anthropic / Grok / OpenClaw / Custom Agents)

Run `dots-gateway config` on your gateway host at any time to print pre-filled URLs, `client.json`, and CLI commands for your deployment.

### 2.1 Choose Your Transport & Exposure Mode

| Mode | Best For | Inbound Ports Needed? | TLS Requirement |
| :--- | :--- | :--- | :--- |
| **A. OpenAI Secure MCP Tunnel** (`dots-gateway tunnel-setup`) | OpenAI `dots` / ChatGPT Enterprise Connectors | **None (0 inbound ports)** | Outbound HTTP/2 tunnel to OpenAI -> local `http://127.0.0.1:18765/mcp` |
| **B. Remote Streamable HTTP** (`https://<DOMAIN>/mcp`) | Cloud APIs (**OpenAI Responses API**, **Anthropic Messages API**, **xAI Grok API**, **Claude.ai**, **ChatGPT**) & remote IDEs (**Claude Code**, **Codex**, **OpenClaw**, **Cursor**) | `:443` via Caddy/Nginx/Cloudflare Tunnel/Tailscale Funnel, or `:8765` via `dots-gateway sync-ip` | Public CA certificate (Let's Encrypt / Cloudflare / Tailscale) required by cloud APIs |
| **C. `dots_mcp.py` `stdio` Bridge** (`client.json` + SHA-256 Pin) | Local/desktop agents (**Claude Code**, **Codex**, **OpenClaw**, **Claude Desktop**, **Cursor**, **`agy`**) connecting over raw IP or self-signed TLS | Direct TCP to `:8765` (or SSH port-forward / WireGuard / Tailscale) | Works out-of-the-box with **self-signed TLS + SHA-256 fingerprint pinning + HMAC-SHA256 signing** |

> **Tip for Cloud-Hosted MCP Connectors (OpenAI / Anthropic / xAI Grok)**: Cloud APIs invoke your MCP server from their own data centers and require a **publicly trusted HTTPS certificate** (not self-signed). Either place Caddy / Nginx / Cloudflare Tunnel / Tailscale Funnel in front of `http://127.0.0.1:18765/mcp`, or run `dots-gateway sync-ip` (which issues a Let's Encrypt certificate for `<IP>.sslip.io`).
>
> **Tip for Mode C (`dots_mcp.py` `stdio` Bridge)**: Copy the `client.json` snippet printed by `dots-gateway config` into `~/.config/dots-gateway/client.json` (`chmod 600`) on your client machine once — `dots_mcp.py` will automatically load it without needing plaintext secrets inside IDE/agent config files.

---

### 2.2 OpenAI (`dots` / ChatGPT / Codex CLI / Responses API / Agents SDK)

#### 1) OpenAI `dots` & ChatGPT Connectors
- **Recommended (Zero Inbound Ports — Secure MCP Tunnel)**:
  1. Create a **Tunnel ID** (`tunnel_...`) at <https://platform.openai.com/settings/organization/tunnels> and a Runtime Credential with **`Tunnels Read + Use`** permissions.
  2. On the gateway host, run:
     ```bash
     dots-gateway tunnel-setup
     ```
  3. In `dots` / ChatGPT Connectors, select your Secure MCP Tunnel (`No authentication`).
- **Direct HTTPS (Built-in OAuth 2.1 or Capability URL)**:
  - **OAuth 2.1 Mode**: Set MCP Server URL to `https://<YOUR_DOMAIN>/mcp` and choose **OAuth** (`dots-gateway` serves `/.well-known/oauth-protected-resource`, `/oauth/register`, PKCE `/oauth/authorize`, and `/oauth/token` out of the box).
  - **Zero-Popup Capability URL**: Choose **No authentication** and set URL to `https://<YOUR_DOMAIN>/mcp/<BEARER_TOKEN_FROM_CONFIG>`.

#### 2) OpenAI Codex CLI (`codex`)
- **Remote Streamable HTTP (One-Liner, reads `DOTS_GATEWAY_TOKEN` from environment)**:
  ```bash
  read -rsp "Dots Gateway Token: " DOTS_GATEWAY_TOKEN && echo && export DOTS_GATEWAY_TOKEN
  codex mcp add dots-gateway \
    --url "https://<YOUR_DOMAIN>/mcp" \
    --bearer-token-env-var DOTS_GATEWAY_TOKEN
  ```
  Or in `~/.codex/config.toml`:
  ```toml
  [mcp_servers.dots-gateway]
  url = "https://<YOUR_DOMAIN>/mcp"
  bearer_token_env_var = "DOTS_GATEWAY_TOKEN"
  startup_timeout_sec = 20
  tool_timeout_sec = 28800
  ```
- **Pinned `stdio` Bridge / Native Codex Plugin** (supports self-signed TLS + HMAC over raw IP via `~/.config/dots-gateway/client.json`):
  ```bash
  codex mcp add dots-gateway -- python3 /path/to/dots-gateway/dots_mcp.py
  ```
  *(This repo also ships `.codex-plugin/plugin.json` and `plugin.json` for direct plugin installation alongside bundled `skills/`.)*

#### 3) OpenAI Responses API (Remote MCP Tool)
```python
import os
from openai import OpenAI

client = OpenAI()
resp = client.responses.create(
    model="gpt-5",
    tools=[
        {
            "type": "mcp",
            "server_label": "dots_gateway",
            "server_url": os.environ["DOTS_GATEWAY_MCP_URL"],  # e.g. "https://<YOUR_DOMAIN>/mcp"
            "authorization": os.environ["DOTS_GATEWAY_TOKEN"],
            "require_approval": "never",
        }
    ],
    input="Check gateway_status and run pytest -q in ~/workspaces/my-project.",
)
print(resp.output_text)
```

#### 4) OpenAI Agents SDK (`openai-agents`)
```python
import os
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp

async with MCPServerStreamableHttp(
    name="dots-gateway",
    params={
        "url": os.environ["DOTS_GATEWAY_MCP_URL"],
        "headers": {"Authorization": f"Bearer {os.environ['DOTS_GATEWAY_TOKEN']}"},
        "timeout": 60,
    },
) as mcp_server:
    agent = Agent(
        name="RemoteDevEngineer",
        instructions="Use dots-gateway MCP tools to inspect, edit, and test code in ~/workspaces.",
        mcp_servers=[mcp_server],
    )
    result = await Runner.run(agent, "Inspect git status in ~/workspaces/app")
    print(result.final_output)
```

---

### 2.3 Anthropic (Claude Code CLI / Claude.ai / Claude Desktop / Messages API)

#### 1) Claude Code CLI (`claude`)
- **Method A — Remote Streamable HTTP (One-Liner)**:
  ```bash
  claude mcp add --transport http --scope user dots-gateway \
    "https://<YOUR_DOMAIN>/mcp" \
    --header "Authorization: Bearer ${DOTS_GATEWAY_TOKEN}"
  ```
- **Method B — Project-Shared `.mcp.json`** (supports `${ENV_VAR}` expansion natively):
  ```json
  {
    "mcpServers": {
      "dots-gateway": {
        "type": "http",
        "url": "https://<YOUR_DOMAIN>/mcp",
        "headers": {
          "Authorization": "Bearer ${DOTS_GATEWAY_TOKEN}"
        }
      }
    }
  }
  ```
- **Method C — Native Claude Code Plugin (`.claude-plugin/plugin.json`) or Pinned `stdio` Bridge**:
  With `~/.config/dots-gateway/client.json` (`0600`) in place, load the full plugin (MCP server + `remote-dev-gateway`, `delegate-to-agy`, `delegate-to-codex`, and `delegate-to-claude` skills):
  ```bash
  claude --plugin-dir /path/to/dots-gateway
  ```
  or register the zero-dependency `stdio` bridge permanently:
  ```bash
  claude mcp add --transport stdio --scope user dots-gateway -- \
    python3 /path/to/dots-gateway/dots_mcp.py
  ```

#### 2) Claude.ai Web & Claude Desktop
- **Claude.ai / Claude Desktop Custom Connector (Remote HTTPS)**:
  Open **Settings -> Integrations / Connectors -> Add Custom Connector** and enter:
  - **URL**: `https://<YOUR_DOMAIN>/mcp` (uses built-in OAuth 2.1 + PKCE; `claude.ai` and `claude.com` callbacks are pre-allowlisted in `oauth_allowed_redirect_hosts`), **or**
  - **Capability URL**: `https://<YOUR_DOMAIN>/mcp/<BEARER_TOKEN_FROM_CONFIG>`
- **Claude Desktop Local Config (`claude_desktop_config.json` via `dots_mcp.py` + `~/.config/dots-gateway/client.json`)**:
  ```json
  {
    "mcpServers": {
      "dots-gateway": {
        "command": "python3",
        "args": ["/absolute/path/to/dots-gateway/dots_mcp.py"]
      }
    }
  }
  ```

#### 3) Anthropic Messages API (MCP Connector)
```python
import os
import anthropic

client = anthropic.Anthropic()
response = client.beta.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=4096,
    mcp_servers=[
        {
            "type": "url",
            "name": "dots-gateway",
            "url": os.environ["DOTS_GATEWAY_MCP_URL"],  # e.g. "https://<YOUR_DOMAIN>/mcp"
            "authorization_token": os.environ["DOTS_GATEWAY_TOKEN"],
        }
    ],
    messages=[
        {
            "role": "user",
            "content": "Call gateway_status and list projects in the default workspace.",
        }
    ],
    betas=["mcp-client-2025-04-04"],
)
print(response.content)
```

---

### 2.4 xAI Grok (Responses API & `xai-sdk`)

`dots-gateway` accepts both `Authorization: Bearer <TOKEN>` and bare `Authorization: <TOKEN>`, so Grok's remote MCP tool works seamlessly via either the OpenAI-compatible SDK or native `xai-sdk`.

#### 1) Grok Responses API (`https://api.x.ai/v1` via OpenAI SDK)
```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["XAI_API_KEY"],
    base_url="https://api.x.ai/v1",
)

resp = client.responses.create(
    model="grok-4",
    tools=[
        {
            "type": "mcp",
            "server_label": "dots_gateway",
            "server_url": os.environ["DOTS_GATEWAY_MCP_URL"],
            "authorization": os.environ["DOTS_GATEWAY_TOKEN"],
        }
    ],
    input="Check gateway_status on my dev box and run git status in ~/workspaces/app.",
)
print(resp.output_text)
```

#### 2) Native xAI Python SDK (`xai-sdk`)
```python
import os
from xai_sdk import Client
from xai_sdk.chat import user
from xai_sdk.tools import mcp

client = Client(api_key=os.environ["XAI_API_KEY"])
chat = client.chat.create(
    model="grok-4",
    tools=[
        mcp(
            server_url=os.environ["DOTS_GATEWAY_MCP_URL"],
            server_label="dots_gateway",
            authorization=os.environ["DOTS_GATEWAY_TOKEN"],
        )
    ],
)
chat.append(user("Inspect ~/workspaces using fs_list and run the unit tests."))
response = chat.sample()
print(response.content)
```

---

### 2.5 OpenClaw (`openclaw.json` & CLI)

OpenClaw configures MCP servers under `mcp.servers` in `~/.openclaw/openclaw.json` (or via `openclaw mcp add`):

#### Option 1 — Remote Streamable HTTP (`~/.openclaw/openclaw.json`)
```json
{
  "mcp": {
    "servers": {
      "dots-gateway": {
        "transport": "streamable-http",
        "url": "https://<YOUR_DOMAIN>/mcp",
        "headers": {
          "Authorization": "Bearer ${DOTS_GATEWAY_TOKEN}"
        }
      }
    }
  }
}
```
Or via the OpenClaw CLI:
```bash
openclaw mcp add dots-gateway \
  --transport streamable-http \
  --url "https://<YOUR_DOMAIN>/mcp" \
  --header "Authorization: Bearer ${DOTS_GATEWAY_TOKEN}"
```

#### Option 2 — Local / Self-Signed TLS Pinning via `dots_mcp.py` (`stdio`)
Place `client.json` in `~/.config/dots-gateway/client.json` (`0600`), then add to `~/.openclaw/openclaw.json`:
```json
{
  "mcp": {
    "servers": {
      "dots-gateway": {
        "command": "python3",
        "args": ["/absolute/path/to/dots-gateway/dots_mcp.py"]
      }
    }
  }
}
```

---

### 2.6 Other IDEs & Custom Agent Frameworks (`agy` / Cursor / MCP SDK / LangGraph / Python SDK)

#### 1) Google Antigravity (`agy` / IDE), Gemini CLI, Cursor, Windsurf & VS Code
Add `dots-gateway` to your IDE's MCP config (`~/.gemini/settings.json`, `~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, or VS Code `.vscode/mcp.json`):
- **Via `dots_mcp.py` (`stdio` + `~/.config/dots-gateway/client.json`, works over self-signed IP)**:
  ```json
  {
    "mcpServers": {
      "dots-gateway": {
        "command": "python3",
        "args": ["/absolute/path/to/dots-gateway/dots_mcp.py"]
      }
    }
  }
  ```
- **Via Streamable HTTP** (see [`mcp.remote.example.json`](mcp.remote.example.json); for VS Code `.vscode/mcp.json`, use top-level `"servers"` and `"type": "http"`).

#### 2) Official Python MCP SDK (`mcp`) & LangGraph (`langchain-mcp-adapters`)
```python
import os
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def run_custom_mcp_agent() -> None:
    headers = {"Authorization": f"Bearer {os.environ['DOTS_GATEWAY_TOKEN']}"}
    async with streamablehttp_client(os.environ["DOTS_GATEWAY_MCP_URL"], headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            status = await session.call_tool("gateway_status", {})
            print(f"Loaded {len(tools.tools)} tools; status:", status.structuredContent)
```
With **LangGraph** (`pip install langgraph langchain-mcp-adapters`):
```python
import os
from langchain_mcp_adapters.client import MultiServerMCPClient

mcp_client = MultiServerMCPClient(
    {
        "dots-gateway": {
            "transport": "streamable_http",
            "url": os.environ["DOTS_GATEWAY_MCP_URL"],
            "headers": {"Authorization": f"Bearer {os.environ['DOTS_GATEWAY_TOKEN']}"},
        }
    }
)
tools = await mcp_client.get_tools()  # Pass directly into create_react_agent(model, tools)
```

#### 3) Zero-Dependency Python SDK (`DotsGatewayClient` — Direct REST / SSE / WebSocket)
For custom Python orchestrators, CI pipelines, or agents that prefer direct typed Python methods without an MCP library, import [`dots_client.py`](dots_client.py) directly (stdlib only; auto-loads `~/.config/dots-gateway/client.json` or `GATEWAY_*` env vars with SHA-256 TLS pinning + replay-proof HMAC-SHA256 signing):
```python
from dots_client import DotsGatewayClient

gw = DotsGatewayClient(load_config_file=True)

print(gw.health())
gw.write_file("hello.py", "print('hello from custom agent')\n", cwd="~/workspaces/demo")
print(gw.exec_command("python3 hello.py", cwd="~/workspaces/demo")["stdout"])

# Orchestrate all three local coding agents side-by-side:
agy_res = gw.run_agy("Implement feature X and unit tests", cwd="~/workspaces/demo")
codex_res = gw.run_codex(review=True, args=["--uncommitted"], sandbox_mode="read-only", cwd="~/workspaces/demo")
claude_res = gw.run_claude(
    "Review architecture and edge cases of uncommitted changes",
    cwd="~/workspaces/demo",
    skip_permissions=False,
    permission_mode="plan",
)
```

---

## 3. Day-2 Operations CLI Reference (`dots-gateway`)

```bash
dots-gateway --help
dots-gateway status           # Live health, sandbox storage, agy/codex/claude status, plugins & tunnel
dots-gateway start            # Start gateway (and configured tunnel) + run health checks
dots-gateway restart          # Drain active sessions safely before restarting (--wait or --force)
dots-gateway stop             # Stop gateway & tunnel services
dots-gateway logs -f          # Tail systemd journal (`dots-gateway logs tunnel -f` for tunnel only)
dots-gateway config           # Print ready-to-use MCP snippets for OpenAI, Claude, Grok, OpenClaw & IDEs
dots-gateway tunnel-setup     # Configure & start OpenAI Secure MCP Tunnel (`tunnel-client`)
dots-gateway sync-ip [IP]     # Issue/renew Let's Encrypt short-lived IP + sslip.io certificate (TCP :80)

# Hot-Reloadable Local Agent & Sandbox Controls (instant effect on new sessions, zero restart):
dots-gateway agy-auth status|adc [PROJECT_ID]|oauth|toggle
dots-gateway agy-model list|status|set <MODEL_ID>|reset
dots-gateway agy-plugins status|add <PLUGIN_DIR> [--enable]|on|off|remove <PLUGIN_DIR>|clear|doctor

dots-gateway codex-setup
dots-gateway codex-plugins status|add <PLUGIN_DIR> [--enable]|on|off|remove <PLUGIN_DIR>|clear|doctor

dots-gateway claude-setup [status|clear]
dots-gateway claude-model status|set <MODEL_ID>|reset
dots-gateway claude-plugins status|add <PLUGIN_DIR> [--enable]|on|off|remove <PLUGIN_DIR>|clear|doctor

dots-gateway docker on|off|toggle|status|test
```

---

## 4. Exposed MCP Tools (17), Resources & Prompts

| MCP Tool | Description |
| :--- | :--- |
| `gateway_status` | Live health, uptime, active/queued `agy`/`codex`/`claude` slots, allowed workspaces, plugin & hook jail state, Docker proxy state, and command policy |
| `list_agy_models` | List model IDs available under the gateway's active `agy` auth mode (`adc` or `oauth`) plus default model |
| `run_agy` | Run Google Antigravity CLI (`agy --sandbox`) inside the jailed workspace (`cwd`, `model`, `effort`, `conversation_id`, `continue_last`, `add_dirs`) |
| `run_codex` | Run OpenAI Codex CLI (`codex -a never -s workspace-write exec` or `review`) inside the jailed workspace (`cwd`, `sandbox_mode`, `model`, `effort`, `session_id`, `continue_last`, `review`) |
| `run_claude` | Run Anthropic Claude Code CLI (`claude -p`) inside the jailed workspace (`cwd`, `skip_permissions`, `permission_mode`, `model`, `effort`, `session_id`, `continue_last`, `output_format`, `add_dirs`) |
| `exec_command` | Execute allowlisted commands, compound pipelines, or heredoc scripts (`git`, `pytest`, `npm`, `cargo`, `go`, `./scripts/...`) with live SSE progress |
| `fs_stat` / `fs_list` | Inspect file/symlink metadata or list directory entries inside allowed workspaces |
| `fs_read` | Read UTF-8 text or Base64 binary files with optional byte `offset`/`limit` |
| `fs_write` / `fs_patch` / `fs_delete` | Atomically create/overwrite, exact search-and-replace patch (`replace_all` guarded), or delete workspace files |
| `session_start` | Start background `exec`, `codex`, or interactive multi-turn `agy` / `claude` (`stream-json`) sessions |
| `session_poll` | Poll incremental events (`after_seq`) with optional long-poll `wait_seconds`, `wait_for_exit`, and output paging |
| `session_input` / `session_signal` / `session_list` | Send `stdin` or follow-up `agy`/`claude` turns, signal process groups (`SIGINT`/`SIGTERM`/`SIGKILL`), or list live & persisted sessions |

- **MCP Resources**: `gateway://status`, `gateway://policy`, and template `file://{path}`
- **MCP Prompts**: `delegate_to_agy`, `delegate_to_codex`, `delegate_to_claude`, `remote_tdd_loop`
- **REST & WebSocket Parity**: Every capability is also exposed via `/v1/exec`, `/v1/agy`, `/v1/codex`, `/v1/claude`, `/v1/sessions`, `/v1/files/*`, and full-duplex `/v1/ws` (`action: "exec" | "agy" | "codex" | "claude"`).

---

## 5. Isolation & Security Architecture

### Three-Agent Isolated Plugin Discovery & Unified Hook Sandboxing (`agy-plugins` / `codex-plugins` / `claude-plugins`)

By default, plugin mounting is **disabled** for all three local agents (`agy_plugins_enabled: false`, `codex_plugins_enabled: false`, `claude_plugins_enabled: false`).

#### Security Guarantees
1. **Isolated Runtime Homes (`agent_runtime_home_root`, default `/mnt/dots-agent-home`)**:
   - Real host `$HOME` (`~/gateway`, `~/.config/dots-gateway`, `~/.config/tunnel-client`, `~/.ssh`, `~/.gemini`, `~/.codex`, `~/.claude`) stays masked and denied.
   - Inside each session's private mount namespace:
     - `agy` runs with `HOME=/mnt/dots-agent-home/agy` and discovers read-only plugins under `/mnt/dots-agent-home/agy/.gemini/config/plugins/<name>`.
     - `codex` runs with `CODEX_HOME=/mnt/dots-agent-home/codex/.codex` (disk-backed at `<sandbox_state_dir>/codex_home`, `$CODEX_HOME/hooks.json` masked to `/dev/null`, and plugins mounted read-only with synthesized `trusted_hash` & `trusted_content_hash`).
     - `claude` runs with `CLAUDE_CONFIG_DIR=/mnt/dots-agent-home/claude/.claude` (disk-backed at `<sandbox_state_dir>/claude_home`, `--setting-sources=user`, `--strict-mcp-config`, `--mcp-config={"mcpServers":{}}`, and operator-registered plugins passed via `--plugin-dir=/mnt/dots-agent-home/claude/plugins/<name>`).
2. **Untrusted Workspace Config & Hook Blocking**:
   - Active workspace config/hook injection paths (`.gemini/settings.json`, `.gemini/antigravity-cli`, `.gemini/config/plugins`, `.codex/hooks.json`, `.codex/config.toml`, `.agents/plugins`, `.claude/settings.local.json`, `.mcp.json`, `.git/hooks`) are masked or neutralized, while Git-tracked `.claude/settings.json` and `.claude/hooks` are locked `ro,noexec` so `git status`/`git diff` stay clean without trusting repo-planted hooks.
   - Task-level overrides (`plugin_dirs`, `--plugin-dir`, `--mcp-config`, `--setting-sources`, etc.) are rejected fail-closed by `CommandPolicy` and `MCPHandler`.
3. **Unified W^X Native Hook Jail (`gateway/hook_jail.py` -> `dots-hook-jail.py`)**:
   - Every `hooks.json` command handler in registered `agy`, `codex`, and `claude` plugins is validated at registration/startup and rewritten to run inside `dots-hook-jail.py`.
   - Each hook invocation enters an inner `unshare --user --map-current-user --mount --propagation private` + `pivot_root` jail that masks agent OAuth/ADC/API credentials, scrubs secret env vars, mounts workspaces **`rw,nosuid,nodev,noexec`** (W^X), enforces `python3 -I`, neutralizes `.git/config` command hooks (`GIT_CONFIG_COUNT`), and fails closed if namespace isolation is unavailable.

**Operator Setup & Zero-Restart Rollback Example (`oh-my-agents` across all 3 agents):**

```bash
# 1a. Antigravity (`agy`) — `gemini` branch
mkdir -p ~/agy-plugins
git clone -b gemini https://github.com/caishize/oh-my-agents.git ~/agy-plugins/oh-my-agents
chmod -R go-w ~/agy-plugins/oh-my-agents
dots-gateway agy-plugins add ~/agy-plugins/oh-my-agents --enable && dots-gateway agy-plugins doctor

# 1b. OpenAI Codex (`codex`) — `codex` branch
mkdir -p ~/codex-plugins
git clone -b codex https://github.com/caishize/oh-my-agents.git ~/codex-plugins/oh-my-agents
chmod -R go-w ~/codex-plugins/oh-my-agents
dots-gateway codex-plugins add ~/codex-plugins/oh-my-agents --enable && dots-gateway codex-plugins doctor

# 1c. Anthropic Claude Code (`claude`) — `main` branch
mkdir -p ~/claude-plugins
git clone -b main https://github.com/caishize/oh-my-agents.git ~/claude-plugins/oh-my-agents
chmod -R go-w ~/claude-plugins/oh-my-agents
dots-gateway claude-plugins add ~/claude-plugins/oh-my-agents --enable && dots-gateway claude-plugins doctor

# Instant Rollback (effective immediately for new sessions, zero restart):
dots-gateway agy-plugins off
dots-gateway codex-plugins off
dots-gateway claude-plugins off
```

### Policy-Filtered Sandbox Docker Access (`dots-gateway docker`)

Host `/var/run/docker.sock` is **always masked** inside the mount-namespace jail. When `dots-gateway docker on` is enabled, sessions talk to an in-gateway HTTP filtering proxy (`gateway/docker_proxy.py`):
- Bind mounts (and bind-backed volumes) are restricted to `allowed_workdirs` (+ `docker_extra_bind_roots`), never `protected_paths`, `plugin_state_dir`, or registered plugin directories, with symlink re-verification on `start`/`restart`/`unpause`.
- Blocks `--privileged`, `--device`, `--cap-add`, `--pid/--ipc/--uts/--userns=host`, custom runtimes, and unconfined security profiles.
- Isolates visibility strictly to proxy-created resources (`io.dots-gateway.managed=true`) and rewrites published container ports to `127.0.0.1` (`docker_force_loopback_ports`).

---

## 6. Repository Layout

- `plugin.json`, `.codex-plugin/plugin.json`, `.claude-plugin/plugin.json` — Native plugin manifests for Agent Plugins 1.0 / OpenAI `dots`, OpenAI Codex, and Anthropic Claude Code (`v1.5.25`, `Apache-2.0`)
- `pyproject.toml` — Zero-dependency Python 3.11+ package metadata (`v1.5.25`), `pytest`, and `ruff` config
- `LICENSE` & `SECURITY.md` — Apache License 2.0 and private vulnerability disclosure / deployment security baseline
- `mcp.json` & `mcp.remote.example.json` — Bundled `stdio` MCP bridge definition and `streamable-http` template
- `config.example.json` & `client.example.json` — Reference gateway & client configuration templates
- `skills/` (`remote-dev-gateway`, `delegate-to-agy`, `delegate-to-codex`, `delegate-to-claude`) & `rules/AGENTS.md` — Agent workflow skills and workspace safety rules
- `gateway.sh` — Unified operator CLI (`~/.local/bin/dots-gateway`)
- `dots_mcp.py` & `dots_client.py` — Zero-dependency MCP `stdio` bridge and standalone Python SDK/CLI
- `main.py` & `deploy/` — Gateway entrypoint, `systemd` user service units, and Let's Encrypt IP certificate helper
- `gateway/` — Core server (`server.py`, `mcp.py`, `auth.py`, `oauth.py`, `policy.py`, `sandbox.py`, `hook_jail.py`, `executor.py`, `docker_proxy.py`, `files.py`, `tls.py`, `protocol.py`, `config.py`)

---

## 7. Running Automated & Live Tests

```bash
# Full unit, security, Docker proxy, MCP protocol, and agy/codex/claude sandbox test suite
pytest -v
# or via stdlib unittest (zero external test dependencies):
python3 -m unittest discover -s tests -p "test_*.py" -v

# Lint & shell syntax checks
ruff check .
bash -n gateway.sh

# Live end-to-end verification against running dots-gateway.service (HTTPS + WSS + MCP)
python3 tests/live_call_test.py
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
