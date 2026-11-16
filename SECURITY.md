# Security Policy

## Supported Versions

Security updates are provided for the latest `1.5.x` release line on `main`.

| Version | Supported |
| :--- | :--- |
| `1.5.x` | Yes |
| `< 1.5.0` | No |

## Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities** (such as authentication bypasses, sandbox escapes, command policy bypasses, Docker proxy policy bypasses, or OAuth redirect/token flaws).

Instead, report vulnerabilities privately through **GitHub Private Vulnerability Reporting**:

1. Navigate to <https://github.com/caishize/dots-gateway/security/advisories/new>.
2. Include a clear description of the affected component (`gateway/auth.py`, `gateway/oauth.py`, `gateway/policy.py`, `gateway/sandbox.py`, `gateway/hook_jail.py`, `gateway/docker_proxy.py`, etc.), minimal reproduction steps, and impact assessment.

## Deployment Security Baseline

Because `dots-gateway` mediates remote command execution and autonomous coding agents (`agy` and `codex`), operators deploying it MUST adhere to the following baseline:

1. **Outbound Tunnel Preferred**: Prefer OpenAI Secure MCP Tunnel (`dots-gateway tunnel-setup` -> loopback `127.0.0.1:18765/mcp`) so no inbound TCP ports need to be exposed to the public internet.
2. **Never Disable TLS on Non-Loopback Interfaces**: Only pass `--no-tls` when binding strictly to `127.0.0.1` or an encrypted private overlay tunnel. Direct public listeners must use TLS 1.2/1.3 (with SHA-256 certificate pinning, Let's Encrypt, or `tls_require_client_cert: true` mTLS) and optional `allowed_client_ips` CIDR restrictions.
3. **Keep Linux Namespace Isolation Enabled**: Keep `isolate_mount_namespace: true` and `agy_default_sandbox: true` on a Linux host where unprivileged user + mount namespaces (`unshare --user --map-current-user --mount`) are available. Native plugin hooks (`dots-hook-jail.py`) intentionally fail closed if namespace isolation is unavailable.
4. **Restrict OAuth Redirect Hosts**: When exposing built-in OAuth 2.1 on a public HTTPS endpoint, keep `oauth_allowed_redirect_hosts` restricted to trusted client callback domains (e.g., `chatgpt.com`, `openai.com`, `claude.ai`, `localhost`, `127.0.0.1`).
5. **Protect Runtime Credential Files**: Never commit `config.json`, `client.json`, `certs/`, `certs_letsencrypt/`, or `~/.config/dots-gateway/*` (`0600` permissions).
