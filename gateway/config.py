"""Configuration management for the Dots Gateway."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

GATEWAY_ROOT: Path = Path(__file__).resolve().parent.parent
HOME_DIR: str = str(Path.home())
DEFAULT_WORKSPACE_DIR: str = str(Path.home() / "workspaces")
DEFAULT_AGY_BIN: str = shutil.which("agy") or str(Path.home() / ".local" / "bin" / "agy")
DEFAULT_CODEX_BIN: str = shutil.which("codex") or "/usr/local/bin/codex"
DEFAULT_CLAUDE_BIN: str = shutil.which("claude") or (
    str(Path.home() / ".local" / "bin" / "claude")
    if os.path.exists(str(Path.home() / ".local" / "bin" / "claude"))
    else "/usr/local/bin/claude"
)
DEFAULT_BWRAP_BIN: str = shutil.which("bwrap") or (
    "/usr/local/bin/bwrap"
    if os.path.exists("/usr/local/bin/bwrap")
    else (
        "/usr/bin/bwrap"
        if os.path.exists("/usr/bin/bwrap")
        else str(Path.home() / ".local" / "bin" / "bwrap")
    )
)


DEFAULT_ALLOWED_COMMANDS: List[str] = [
    # Local autonomous coding agents (Antigravity CLI, OpenAI Codex CLI & Anthropic Claude Code CLI) & nested sandbox runner
    "agy",
    DEFAULT_AGY_BIN,
    "codex",
    DEFAULT_CODEX_BIN,
    "claude",
    DEFAULT_CLAUDE_BIN,
    "bwrap",
    DEFAULT_BWRAP_BIN,
    # Shell & builtins
    "bash",
    "sh",
    "cd",
    "set",
    "export",
    "unset",
    "true",
    "false",
    "test",
    "[",
    "source",
    ".",
    "exit",
    "return",
    ":",
    "trap",
    "command",
    "type",
    "sleep",
    "time",
    "timeout",
    "nohup",
    # Version control & GitHub CLI
    "git",
    "gh",
    # Python ecosystem
    "python",
    "python3",
    "pytest",
    "pip",
    "pip3",
    "uv",
    "uvx",
    "poetry",
    "pre-commit",
    "ruff",
    "black",
    "mypy",
    "flake8",
    "isort",
    "pylint",
    "coverage",
    "tox",
    "uvicorn",
    "gunicorn",
    "flask",
    "django-admin",
    "alembic",
    # Node / JS / TS ecosystem
    "node",
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "corepack",
    "yarn",
    "bun",
    "tsc",
    "tsx",
    "ts-node",
    "eslint",
    "prettier",
    "vitest",
    "jest",
    "playwright",
    # Flutter / Dart / Mobile & Infra tools
    "flutter",
    "dart",
    "terraform",
    "trivy",
    # Rust / Go / C / C++ / Build tools
    "cargo",
    "rustc",
    "rustfmt",
    "cargo-clippy",
    "go",
    "gofmt",
    "golangci-lint",
    "make",
    "cmake",
    "ninja",
    "pkg-config",
    "gcc",
    "g++",
    "clang",
    "clang++",
    "clang-format",
    "gdb",
    "valgrind",
    "strace",
    "ldd",
    "nm",
    "objdump",
    "strings",
    # Databases & local dev clients
    "sqlite3",
    "psql",
    "mysql",
    "redis-cli",
    # Standard UNIX file, text & inspection utilities
    "ls",
    "tree",
    "cat",
    "nl",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "find",
    "fd",
    "sed",
    "awk",
    "jq",
    "wc",
    "sort",
    "uniq",
    "tr",
    "cut",
    "paste",
    "tee",
    "xargs",
    "diff",
    "patch",
    "mkdir",
    "cp",
    "mv",
    "rm",
    "ln",
    "touch",
    "chmod",
    "stat",
    "file",
    "readlink",
    "realpath",
    "dirname",
    "basename",
    "du",
    "df",
    "free",
    "uname",
    "whoami",
    "id",
    "hostname",
    "which",
    "env",
    "printenv",
    "pwd",
    "echo",
    "printf",
    "date",
    "sha256sum",
    "md5sum",
    "base64",
    "xxd",
    # Archiving & HTTP/sync
    "tar",
    "gzip",
    "gunzip",
    "zip",
    "unzip",
    "curl",
    "wget",
    "rsync",
    # Process & port inspection
    "ps",
    "pgrep",
    "pkill",
    "kill",
    "lsof",
    "ss",
    "ip",
]

DEFAULT_BLOCKED_COMMANDS: List[str] = [
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "init",
    "mkfs",
    "mkfs.ext4",
    "mkfs.xfs",
    "fdisk",
    "parted",
    "dd",
    "mount",
    "umount",
    "iptables",
    "ip6tables",
    "nft",
    "ufw",
    "useradd",
    "userdel",
    "usermod",
    "passwd",
    "chpasswd",
    "visudo",
    "su",
    "sudo",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "docker",
    "docker-compose",
    "podman",
    "nsenter",
    "chroot",
    "systemd-run",
]

DEFAULT_BLOCKED_PATTERNS: List[str] = [
    r"(?:^|[;&|]\s*)rm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)+/(?:\s|$|\*)",
    r"(?:^|[;&|]\s*)rm\s+.*--no-preserve-root",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r">\s*/dev/sd[a-z]",
    r">\s*/etc/(?:passwd|shadow|sudoers|hosts)",
    r"(?:^|[;&|]\s*)(?:chmod|chown)\s+-R\s+.*\s+/(?:\s|$)",
    r"(?:^|[;&|]\s*)mkfs",
    r"(?:^|[;&|]\s*)dd\s+if=",
]

DEFAULT_PROTECTED_PATHS: List[str] = [
    str(GATEWAY_ROOT),
    str(GATEWAY_ROOT / "config.json"),
    str(GATEWAY_ROOT / "client.json"),
    str(GATEWAY_ROOT / "certs"),
    str(Path.home() / "oh-my-agents"),
    str(Path.home() / ".config"),
    str(Path.home() / ".gemini"),
    str(Path.home() / ".codex"),
    str(Path.home() / ".claude"),
    str(Path.home() / ".claude.json"),
    str(Path.home() / ".ssh"),
    str(Path.home() / ".gnupg"),
    str(Path.home() / ".local"),
    str(Path.home() / ".bashrc"),
    str(Path.home() / ".profile"),
    str(Path.home() / ".bash_profile"),
]

DEFAULT_AGY_READONLY_ROOTS: List[str] = [
    "/opt/codex",
    "/opt/uv-python",
    "/opt/uv-tools",
    "/opt/devtools",
    "/opt/flutter",
]

DEFAULT_OAUTH_ALLOWED_REDIRECT_HOSTS: List[str] = [
    "chatgpt.com",
    "*.chatgpt.com",
    "openai.com",
    "*.openai.com",
    "claude.ai",
    "*.claude.ai",
    "claude.com",
    "*.claude.com",
    "anthropic.com",
    "*.anthropic.com",
    "x.ai",
    "*.x.ai",
    "grok.com",
    "*.grok.com",
    "localhost",
    "127.0.0.1",
    "::1",
]


def detect_default_sandbox_state_dir() -> str:
    """Prefer env override, then persistent large data disk `/mnt/data/dots-sandbox` when writable; else `~/.cache/dots-sandbox`."""
    env_override = (
        os.environ.get("GATEWAY_SANDBOX_STATE_DIR") or os.environ.get("GATEWAY_SANDBOX_DIR") or ""
    ).strip()
    if env_override:
        return env_override
    data_sb = Path("/mnt/data/dots-sandbox")
    try:
        if data_sb.is_dir() and os.access(data_sb, os.W_OK | os.X_OK):
            return str(data_sb)
        data_root = Path("/mnt/data")
        if data_root.is_dir() and os.access(data_root, os.W_OK | os.X_OK):
            return str(data_sb)
    except OSError:
        pass
    return str(Path.home() / ".cache" / "dots-sandbox")


DEFAULT_SANDBOX_STATE_DIR: str = detect_default_sandbox_state_dir()


def detect_recommended_max_agy() -> int:
    """Auto-tune default concurrent `agy` limit (~270 MiB RSS each) based on host MemTotal + SwapTotal."""
    try:
        mem_kib = 0
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith(("MemTotal:", "SwapTotal:")):
                parts = line.split()
                if len(parts) >= 2:
                    mem_kib += int(parts[1])
        total_mib = mem_kib // 1024
        if total_mib < 2048:
            return 1
        if total_mib < 4096:
            return 2
        if total_mib < 8192:
            return 4
        return 8
    except Exception:
        return 2


def hash_password_pbkdf2(password: str, salt: Optional[str] = None) -> str:
    """Create a PBKDF2-HMAC-SHA256 hash string in format 'pbkdf2_sha256$<salt>$<hex>'."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password_pbkdf2(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2 hash (or constant-time plain fallback)."""
    if stored_hash.startswith("pbkdf2_sha256$"):
        parts = stored_hash.split("$")
        if len(parts) != 3:
            return False
        _, salt, _ = parts
        expected = hash_password_pbkdf2(password, salt=salt)
        return secrets.compare_digest(expected, stored_hash)
    return secrets.compare_digest(password, stored_hash)


@dataclass
class GatewayConfig:
    """Runtime configuration for the Dots Gateway."""

    host: str = "0.0.0.0"
    port: int = 8765
    loopback_http_port: Optional[int] = None
    public_ip: Optional[str] = None
    # Authentication & network access control
    api_tokens: List[str] = field(default_factory=list)
    users: Dict[str, str] = field(default_factory=dict)  # username -> pbkdf2 hash or password
    hmac_secret: str = ""
    hmac_max_skew_seconds: int = 300
    allow_query_token: bool = False
    minimal_unauth_health: bool = True
    allowed_client_ips: List[str] = field(default_factory=list)  # IP or CIDR allowlist (empty = all)
    trusted_proxies: List[str] = field(default_factory=list)  # empty for public IP direct-connect
    rate_limit_max_failures: int = 10
    rate_limit_window_seconds: int = 60
    oauth_allowed_redirect_hosts: List[str] = field(
        default_factory=lambda: list(DEFAULT_OAUTH_ALLOWED_REDIRECT_HOSTS)
    )
    # Command & workspace policy settings
    enforce_allowlist: bool = True
    allowed_commands: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_COMMANDS))
    blocked_commands: List[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_COMMANDS))
    blocked_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_PATTERNS))
    allowed_workdirs: List[str] = field(default_factory=lambda: [DEFAULT_WORKSPACE_DIR])
    protected_paths: List[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED_PATHS))
    default_workdir: str = DEFAULT_WORKSPACE_DIR
    isolate_mount_namespace: bool = True
    # Antigravity (agy) & OpenAI Codex (codex) agent settings
    agy_binary: str = DEFAULT_AGY_BIN
    agy_default_skip_permissions: bool = True
    agy_default_sandbox: bool = True
    agy_sandbox_network_access: bool = True
    agy_sandbox_tool_permission: str = "proceed-in-sandbox"
    agy_include_allowed_workdirs: bool = True
    agy_extra_workspace_dirs: List[str] = field(default_factory=list)
    agy_extra_readonly_roots: List[str] = field(default_factory=list)
    agy_env_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_AGY_ENV_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "agy.env")
        ).strip()
    )
    # Default `agy --model` for gateway sessions when callers omit `model`.
    # Precedence: per-call `model` > hot-reload `agy_model_file` > `agy_default_model` >
    # agy's own `~/.gemini/antigravity-cli/settings.json` selection.
    agy_default_model: Optional[str] = field(
        default_factory=lambda: (os.environ.get("GATEWAY_AGY_DEFAULT_MODEL") or "").strip() or None
    )
    agy_model_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_AGY_MODEL_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "agy.model")
        ).strip()
    )
    agy_models_cache_seconds: float = 300.0
    # Operator-confirmed read-only Antigravity (`agy`) plugin resource registration (default OFF).
    # Precedence: hot-reload `agy_plugins_file` (written by `dots-gateway agy-plugins`, 0600) >
    # `agy_plugins_enabled` + `agy_plugin_dirs` in `config.json`.
    agy_plugins_enabled: bool = False
    agy_plugin_dirs: List[str] = field(default_factory=list)
    agy_plugins_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_AGY_PLUGINS_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "agy-plugins.json")
        ).strip()
    )
    # Configurable isolated VFS runtime HOME / plugin discovery root inside mount namespaces.
    # Allows `agy` (`<root>/agy/.gemini/config/plugins/<name>`) and `codex`
    # (`CODEX_HOME=<root>/codex/.codex`) to discover read-only plugins without opening real HOME
    # or deleting parent `permissions.deny` rules.
    agent_runtime_home_root: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_AGENT_RUNTIME_HOME_ROOT") or "/mnt/dots-agent-home"
        ).strip()
    )
    # Optional dedicated writable state directory for plugin hook temp queues (`TMPDIR`) and
    # `PLUGIN_DATA` (defaults to `<sandbox_state_dir>/plugin_state` when unset).
    plugin_state_dir: Optional[str] = field(
        default_factory=lambda: (os.environ.get("GATEWAY_PLUGIN_STATE_DIR") or "").strip() or None
    )
    codex_binary: str = DEFAULT_CODEX_BIN
    bwrap_binary: str = DEFAULT_BWRAP_BIN
    codex_default_skip_permissions: bool = True
    codex_default_sandbox: str = "workspace-write"
    codex_sandbox_network_access: bool = True
    codex_extra_writable_roots: List[str] = field(default_factory=list)
    codex_env_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_CODEX_ENV_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "codex.env")
        ).strip()
    )
    # Operator-confirmed read-only OpenAI Codex (`codex`) plugin resource registration (default OFF).
    # Precedence: hot-reload `codex_plugins_file` (written by `dots-gateway codex-plugins`, 0600) >
    # `codex_plugins_enabled` + `codex_plugin_dirs` in `config.json`.
    codex_plugins_enabled: bool = False
    codex_plugin_dirs: List[str] = field(default_factory=list)
    codex_plugins_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_CODEX_PLUGINS_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "codex-plugins.json")
        ).strip()
    )
    # Anthropic Claude Code (`claude`) agent settings & hot-reloadable plugin registry (default OFF)
    claude_binary: str = DEFAULT_CLAUDE_BIN
    claude_default_skip_permissions: bool = True
    claude_default_permission_mode: str = "bypassPermissions"
    claude_env_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_CLAUDE_ENV_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "claude.env")
        ).strip()
    )
    claude_default_model: Optional[str] = field(
        default_factory=lambda: (os.environ.get("GATEWAY_CLAUDE_DEFAULT_MODEL") or "").strip() or None
    )
    claude_model_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_CLAUDE_MODEL_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "claude.model")
        ).strip()
    )
    claude_plugins_enabled: bool = False
    claude_plugin_dirs: List[str] = field(default_factory=list)
    claude_plugins_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_CLAUDE_PLUGINS_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "claude-plugins.json")
        ).strip()
    )
    # Policy-filtered Docker access for sandboxed sessions (exec_command / run_agy / run_codex / run_claude).
    # The real daemon socket is ALWAYS masked inside the mount-namespace jail; when enabled, a
    # gateway-owned filtering proxy socket is bind-mounted at `/run/docker.sock` instead.
    # Precedence: hot-reload `docker_mode_file` ("on"/"off") > `docker_enabled`.
    docker_enabled: bool = False
    docker_mode_file: str = field(
        default_factory=lambda: os.environ.get("GATEWAY_DOCKER_MODE_FILE")
        or str(Path.home() / ".config" / "dots-gateway" / "docker.mode")
    )
    docker_upstream_socket: str = "/var/run/docker.sock"
    docker_proxy_socket: str = field(
        default_factory=lambda: os.environ.get("GATEWAY_DOCKER_PROXY_SOCKET")
        or str(Path.home() / ".config" / "dots-gateway" / "docker-proxy.sock")
    )
    docker_mask_paths: List[str] = field(
        default_factory=lambda: ["/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock"]
    )
    docker_force_loopback_ports: bool = True
    docker_allow_host_network: bool = True
    docker_allowed_capabilities: List[str] = field(default_factory=list)
    docker_extra_bind_roots: List[str] = field(default_factory=list)
    max_concurrent_agy: int = field(default_factory=detect_recommended_max_agy)
    max_concurrent_codex: int = 6
    max_concurrent_claude: int = 4
    agy_queue_timeout_seconds: float = 28800.0
    # Isolated sandbox storage location & LRU lifecycle retention policy
    sandbox_state_dir: str = field(default_factory=detect_default_sandbox_state_dir)
    sandbox_cleanup_enabled: bool = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_SANDBOX_CLEANUP_ENABLED")
            or os.environ.get("GATEWAY_SANDBOX_CLEANUP")
            or "true"
        )
        .strip()
        .lower()
        in ("1", "true", "yes")
    )
    sandbox_cleanup_interval_seconds: float = 3600.0
    sandbox_max_retention_days: float = 30.0
    sandbox_min_retention_days: float = 7.0
    sandbox_low_space_free_gb: float = 8.0
    sandbox_low_space_free_percent: float = 15.0
    sandbox_lock_timeout_seconds: float = 5.0
    # Execution, connection, session persistence & memory limits
    session_state_dir: Optional[str] = None
    max_persisted_sessions: int = 200
    default_timeout_seconds: float = 21600.0
    agent_default_timeout_seconds: float = 28800.0
    max_timeout_seconds: float = 86400.0
    max_concurrent_sessions: int = 32
    max_concurrent_connections: int = 128
    max_output_buffer_events: int = 5000
    max_output_bytes: int = 32 * 1024 * 1024  # 32 MiB per stream
    sse_keepalive_seconds: float = 15.0
    # Real-time streaming & progress feedback controls
    # Valid modes: "off" | "summary" | "raw" (default: "summary")
    # Precedence: per-call override > hot-reload stream_mode_file > stream_default_mode
    stream_default_mode: str = "summary"
    stream_mode_file: str = field(
        default_factory=lambda: (
            os.environ.get("GATEWAY_STREAM_MODE_FILE")
            or str(Path.home() / ".config" / "dots-gateway" / "stream.mode")
        ).strip()
    )
    stream_progress_interval_seconds: float = 1.0
    default_detach_after_seconds: Optional[float] = None
    # TLS / mTLS settings
    tls_certfile: Optional[str] = None
    tls_keyfile: Optional[str] = None
    tls_ca_file: Optional[str] = None
    tls_require_client_cert: bool = False

    @classmethod
    def load(cls, config_path: Optional[str | Path] = None) -> "GatewayConfig":
        """Load configuration from JSON file and environment variables."""
        cfg = cls()
        if config_path:
            path = Path(config_path)
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                for key, value in data.items():
                    if hasattr(cfg, key):
                        setattr(cfg, key, value)

        # Environment variable overrides
        if os.environ.get("GATEWAY_HOST"):
            cfg.host = os.environ["GATEWAY_HOST"]
        if os.environ.get("GATEWAY_PORT"):
            cfg.port = int(os.environ["GATEWAY_PORT"])
        if os.environ.get("GATEWAY_LOOPBACK_HTTP_PORT"):
            raw_lb = os.environ["GATEWAY_LOOPBACK_HTTP_PORT"].strip()
            cfg.loopback_http_port = int(raw_lb) if raw_lb and raw_lb != "0" else None
        if os.environ.get("GATEWAY_PUBLIC_IP"):
            cfg.public_ip = os.environ["GATEWAY_PUBLIC_IP"].strip()
        if os.environ.get("GATEWAY_TOKEN"):
            for tok in os.environ["GATEWAY_TOKEN"].split(","):
                tok = tok.strip()
                if tok and tok not in cfg.api_tokens:
                    cfg.api_tokens.append(tok)
        if os.environ.get("GATEWAY_USER") and os.environ.get("GATEWAY_PASSWORD"):
            cfg.users[os.environ["GATEWAY_USER"]] = hash_password_pbkdf2(
                os.environ["GATEWAY_PASSWORD"]
            )
        if os.environ.get("GATEWAY_HMAC_SECRET"):
            cfg.hmac_secret = os.environ["GATEWAY_HMAC_SECRET"]
        if os.environ.get("GATEWAY_ALLOWED_IPS"):
            cfg.allowed_client_ips = [
                x.strip() for x in os.environ["GATEWAY_ALLOWED_IPS"].split(",") if x.strip()
            ]
        if os.environ.get("GATEWAY_OAUTH_REDIRECT_HOSTS"):
            cfg.oauth_allowed_redirect_hosts = [
                x.strip()
                for x in os.environ["GATEWAY_OAUTH_REDIRECT_HOSTS"].split(",")
                if x.strip()
            ]
        if os.environ.get("GATEWAY_WORKDIR"):
            cfg.default_workdir = os.environ["GATEWAY_WORKDIR"]
        if os.environ.get("GATEWAY_ALLOW_DIRS"):
            cfg.allowed_workdirs = [
                x.strip() for x in os.environ["GATEWAY_ALLOW_DIRS"].split(",") if x.strip()
            ]
        if os.environ.get("GATEWAY_MOUNT_NS"):
            cfg.isolate_mount_namespace = os.environ["GATEWAY_MOUNT_NS"].strip().lower() in (
                "1",
                "true",
                "yes",
            )
        if os.environ.get("GATEWAY_AGY_BIN"):
            cfg.agy_binary = os.environ["GATEWAY_AGY_BIN"]
        if os.environ.get("GATEWAY_AGY_SANDBOX"):
            cfg.agy_default_sandbox = os.environ["GATEWAY_AGY_SANDBOX"].strip().lower() in (
                "1",
                "true",
                "yes",
            )
        if os.environ.get("GATEWAY_AGY_SANDBOX_NETWORK_ACCESS"):
            cfg.agy_sandbox_network_access = (
                os.environ["GATEWAY_AGY_SANDBOX_NETWORK_ACCESS"].strip().lower()
                in ("1", "true", "yes")
            )
        if os.environ.get("GATEWAY_AGY_SANDBOX_TOOL_PERMISSION"):
            cfg.agy_sandbox_tool_permission = os.environ[
                "GATEWAY_AGY_SANDBOX_TOOL_PERMISSION"
            ].strip()
        if os.environ.get("GATEWAY_AGY_INCLUDE_ALLOWED_WORKDIRS"):
            cfg.agy_include_allowed_workdirs = (
                os.environ["GATEWAY_AGY_INCLUDE_ALLOWED_WORKDIRS"].strip().lower()
                in ("1", "true", "yes")
            )
        if os.environ.get("GATEWAY_AGY_WORKSPACE_DIRS"):
            cfg.agy_extra_workspace_dirs = [
                x.strip()
                for x in os.environ["GATEWAY_AGY_WORKSPACE_DIRS"].split(",")
                if x.strip()
            ]
        if os.environ.get("GATEWAY_AGY_READONLY_ROOTS"):
            cfg.agy_extra_readonly_roots = [
                x.strip()
                for x in os.environ["GATEWAY_AGY_READONLY_ROOTS"].split(",")
                if x.strip()
            ]
        if os.environ.get("GATEWAY_AGY_ENV_FILE"):
            cfg.agy_env_file = os.environ["GATEWAY_AGY_ENV_FILE"].strip()
        if os.environ.get("GATEWAY_AGY_DEFAULT_MODEL"):
            cfg.agy_default_model = os.environ["GATEWAY_AGY_DEFAULT_MODEL"].strip() or None
        if os.environ.get("GATEWAY_AGY_MODEL_FILE"):
            cfg.agy_model_file = os.environ["GATEWAY_AGY_MODEL_FILE"].strip()
        if os.environ.get("GATEWAY_AGY_PLUGINS_ENABLED"):
            cfg.agy_plugins_enabled = os.environ["GATEWAY_AGY_PLUGINS_ENABLED"].strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
        if os.environ.get("GATEWAY_AGY_PLUGIN_DIRS"):
            cfg.agy_plugin_dirs = [
                x.strip()
                for x in os.environ["GATEWAY_AGY_PLUGIN_DIRS"].split(",")
                if x.strip()
            ]
        if os.environ.get("GATEWAY_AGY_PLUGINS_FILE"):
            cfg.agy_plugins_file = os.environ["GATEWAY_AGY_PLUGINS_FILE"].strip()
        if os.environ.get("GATEWAY_AGENT_RUNTIME_HOME_ROOT"):
            cfg.agent_runtime_home_root = (
                os.environ["GATEWAY_AGENT_RUNTIME_HOME_ROOT"].strip() or "/mnt/dots-agent-home"
            )
        if os.environ.get("GATEWAY_PLUGIN_STATE_DIR"):
            cfg.plugin_state_dir = os.environ["GATEWAY_PLUGIN_STATE_DIR"].strip() or None
        if os.environ.get("GATEWAY_DOCKER_ENABLED"):
            cfg.docker_enabled = os.environ["GATEWAY_DOCKER_ENABLED"].strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
        if os.environ.get("GATEWAY_DOCKER_MODE_FILE"):
            cfg.docker_mode_file = os.environ["GATEWAY_DOCKER_MODE_FILE"].strip()
        if os.environ.get("GATEWAY_DOCKER_SOCKET"):
            cfg.docker_upstream_socket = os.environ["GATEWAY_DOCKER_SOCKET"].strip()
        if os.environ.get("GATEWAY_DOCKER_PROXY_SOCKET"):
            cfg.docker_proxy_socket = os.environ["GATEWAY_DOCKER_PROXY_SOCKET"].strip()
        if os.environ.get("GATEWAY_CODEX_BIN"):
            cfg.codex_binary = os.environ["GATEWAY_CODEX_BIN"]
        if os.environ.get("GATEWAY_BWRAP_BIN"):
            cfg.bwrap_binary = os.environ["GATEWAY_BWRAP_BIN"]
        if os.environ.get("GATEWAY_SESSION_STATE_DIR"):
            raw_ssd = os.environ["GATEWAY_SESSION_STATE_DIR"].strip()
            cfg.session_state_dir = raw_ssd if raw_ssd else None
        elif config_path and cfg.session_state_dir is None:
            cfg.session_state_dir = str(Path.home() / ".config" / "dots-gateway" / "sessions")
        if os.environ.get("GATEWAY_CODEX_SANDBOX"):
            cfg.codex_default_sandbox = os.environ["GATEWAY_CODEX_SANDBOX"].strip()
        if os.environ.get("GATEWAY_CODEX_NETWORK_ACCESS"):
            cfg.codex_sandbox_network_access = (
                os.environ["GATEWAY_CODEX_NETWORK_ACCESS"].strip().lower()
                in ("1", "true", "yes")
            )
        if os.environ.get("GATEWAY_CODEX_WRITABLE_ROOTS"):
            cfg.codex_extra_writable_roots = [
                x.strip()
                for x in os.environ["GATEWAY_CODEX_WRITABLE_ROOTS"].split(",")
                if x.strip()
            ]
        if os.environ.get("GATEWAY_CODEX_ENV_FILE"):
            cfg.codex_env_file = os.environ["GATEWAY_CODEX_ENV_FILE"].strip()
        if os.environ.get("GATEWAY_CODEX_PLUGINS_ENABLED"):
            cfg.codex_plugins_enabled = (
                os.environ["GATEWAY_CODEX_PLUGINS_ENABLED"].strip().lower()
                in ("1", "true", "yes", "on")
            )
        if os.environ.get("GATEWAY_CODEX_PLUGIN_DIRS"):
            cfg.codex_plugin_dirs = [
                x.strip()
                for x in os.environ["GATEWAY_CODEX_PLUGIN_DIRS"].split(",")
                if x.strip()
            ]
        if os.environ.get("GATEWAY_CODEX_PLUGINS_FILE"):
            cfg.codex_plugins_file = os.environ["GATEWAY_CODEX_PLUGINS_FILE"].strip()
        if os.environ.get("GATEWAY_CLAUDE_BIN"):
            cfg.claude_binary = os.environ["GATEWAY_CLAUDE_BIN"]
        if os.environ.get("GATEWAY_CLAUDE_PERMISSION_MODE"):
            cfg.claude_default_permission_mode = os.environ["GATEWAY_CLAUDE_PERMISSION_MODE"].strip()
        if os.environ.get("GATEWAY_CLAUDE_ENV_FILE"):
            cfg.claude_env_file = os.environ["GATEWAY_CLAUDE_ENV_FILE"].strip()
        if os.environ.get("GATEWAY_CLAUDE_DEFAULT_MODEL"):
            cfg.claude_default_model = os.environ["GATEWAY_CLAUDE_DEFAULT_MODEL"].strip() or None
        if os.environ.get("GATEWAY_CLAUDE_MODEL_FILE"):
            cfg.claude_model_file = os.environ["GATEWAY_CLAUDE_MODEL_FILE"].strip()
        if os.environ.get("GATEWAY_CLAUDE_PLUGINS_ENABLED"):
            cfg.claude_plugins_enabled = (
                os.environ["GATEWAY_CLAUDE_PLUGINS_ENABLED"].strip().lower()
                in ("1", "true", "yes", "on")
            )
        if os.environ.get("GATEWAY_CLAUDE_PLUGIN_DIRS"):
            cfg.claude_plugin_dirs = [
                x.strip()
                for x in os.environ["GATEWAY_CLAUDE_PLUGIN_DIRS"].split(",")
                if x.strip()
            ]
        if os.environ.get("GATEWAY_CLAUDE_PLUGINS_FILE"):
            cfg.claude_plugins_file = os.environ["GATEWAY_CLAUDE_PLUGINS_FILE"].strip()
        if os.environ.get("GATEWAY_MAX_AGY"):
            cfg.max_concurrent_agy = max(1, int(os.environ["GATEWAY_MAX_AGY"]))
        if os.environ.get("GATEWAY_MAX_CODEX"):
            cfg.max_concurrent_codex = max(1, int(os.environ["GATEWAY_MAX_CODEX"]))
        if os.environ.get("GATEWAY_MAX_CLAUDE"):
            cfg.max_concurrent_claude = max(1, int(os.environ["GATEWAY_MAX_CLAUDE"]))
        if os.environ.get("GATEWAY_SANDBOX_DIR") or os.environ.get("GATEWAY_SANDBOX_STATE_DIR"):
            cfg.sandbox_state_dir = (
                os.environ.get("GATEWAY_SANDBOX_STATE_DIR") or os.environ["GATEWAY_SANDBOX_DIR"]
            ).strip()
        if os.environ.get("GATEWAY_SANDBOX_CLEANUP") or os.environ.get("GATEWAY_SANDBOX_CLEANUP_ENABLED"):
            raw_sb_en = (
                os.environ.get("GATEWAY_SANDBOX_CLEANUP_ENABLED")
                or os.environ["GATEWAY_SANDBOX_CLEANUP"]
            )
            cfg.sandbox_cleanup_enabled = raw_sb_en.strip().lower() in ("1", "true", "yes")
        if os.environ.get("GATEWAY_SANDBOX_CLEANUP_INTERVAL"):
            cfg.sandbox_cleanup_interval_seconds = max(
                10.0, float(os.environ["GATEWAY_SANDBOX_CLEANUP_INTERVAL"])
            )
        if os.environ.get("GATEWAY_SANDBOX_MAX_RETENTION_DAYS"):
            cfg.sandbox_max_retention_days = float(
                os.environ["GATEWAY_SANDBOX_MAX_RETENTION_DAYS"]
            )
        if os.environ.get("GATEWAY_SANDBOX_MIN_RETENTION_DAYS"):
            cfg.sandbox_min_retention_days = float(
                os.environ["GATEWAY_SANDBOX_MIN_RETENTION_DAYS"]
            )
        if os.environ.get("GATEWAY_SANDBOX_LOW_SPACE_GB") or os.environ.get("GATEWAY_SANDBOX_LOW_SPACE_FREE_GB"):
            cfg.sandbox_low_space_free_gb = max(
                0.0,
                float(
                    os.environ.get("GATEWAY_SANDBOX_LOW_SPACE_FREE_GB")
                    or os.environ["GATEWAY_SANDBOX_LOW_SPACE_GB"]
                ),
            )
        if os.environ.get("GATEWAY_SANDBOX_LOW_SPACE_PCT") or os.environ.get("GATEWAY_SANDBOX_LOW_SPACE_FREE_PERCENT"):
            cfg.sandbox_low_space_free_percent = max(
                0.0,
                min(
                    95.0,
                    float(
                        os.environ.get("GATEWAY_SANDBOX_LOW_SPACE_FREE_PERCENT")
                        or os.environ["GATEWAY_SANDBOX_LOW_SPACE_PCT"]
                    ),
                ),
            )
        if os.environ.get("GATEWAY_SANDBOX_LOCK_TIMEOUT"):
            cfg.sandbox_lock_timeout_seconds = max(
                0.1, float(os.environ["GATEWAY_SANDBOX_LOCK_TIMEOUT"])
            )
        if os.environ.get("GATEWAY_MAX_TIMEOUT"):
            cfg.max_timeout_seconds = max(60.0, float(os.environ["GATEWAY_MAX_TIMEOUT"]))
        if os.environ.get("GATEWAY_DEFAULT_TIMEOUT"):
            cfg.default_timeout_seconds = max(1.0, float(os.environ["GATEWAY_DEFAULT_TIMEOUT"]))
        if os.environ.get("GATEWAY_AGENT_DEFAULT_TIMEOUT"):
            cfg.agent_default_timeout_seconds = max(
                1.0, float(os.environ["GATEWAY_AGENT_DEFAULT_TIMEOUT"])
            )
        if os.environ.get("GATEWAY_AGY_QUEUE_TIMEOUT"):
            cfg.agy_queue_timeout_seconds = max(
                1.0, float(os.environ["GATEWAY_AGY_QUEUE_TIMEOUT"])
            )
        if os.environ.get("GATEWAY_STREAM_MODE") or os.environ.get("GATEWAY_STREAM_DEFAULT_MODE"):
            raw_sm = (
                os.environ.get("GATEWAY_STREAM_MODE")
                or os.environ.get("GATEWAY_STREAM_DEFAULT_MODE")
                or ""
            ).strip()
            if raw_sm:
                cfg.stream_default_mode = normalize_stream_mode(raw_sm, default="summary") or "summary"
        if os.environ.get("GATEWAY_STREAM_MODE_FILE"):
            cfg.stream_mode_file = os.environ["GATEWAY_STREAM_MODE_FILE"].strip()
        if os.environ.get("GATEWAY_STREAM_PROGRESS_INTERVAL"):
            cfg.stream_progress_interval_seconds = max(
                0.05, float(os.environ["GATEWAY_STREAM_PROGRESS_INTERVAL"])
            )
        if os.environ.get("GATEWAY_DEFAULT_DETACH_AFTER_SECONDS"):
            raw_det = os.environ["GATEWAY_DEFAULT_DETACH_AFTER_SECONDS"].strip().lower()
            if raw_det in ("", "0", "none", "off", "false"):
                cfg.default_detach_after_seconds = None
            else:
                det_val = float(raw_det)
                cfg.default_detach_after_seconds = det_val if det_val > 0 else None

        cfg.stream_default_mode = (
            normalize_stream_mode(getattr(cfg, "stream_default_mode", "summary"), default="summary")
            or "summary"
        )
        cfg.stream_progress_interval_seconds = max(
            0.05,
            float(
                1.0
                if getattr(cfg, "stream_progress_interval_seconds", None) is None
                else cfg.stream_progress_interval_seconds
            ),
        )
        if cfg.default_detach_after_seconds is not None:
            det_f = float(cfg.default_detach_after_seconds)
            cfg.default_detach_after_seconds = det_f if det_f > 0 else None

        cfg.max_timeout_seconds = max(60.0, float(cfg.max_timeout_seconds or 86400.0))
        cfg.default_timeout_seconds = min(
            cfg.max_timeout_seconds, max(1.0, float(cfg.default_timeout_seconds or 21600.0))
        )
        cfg.agent_default_timeout_seconds = min(
            cfg.max_timeout_seconds,
            max(1.0, float(cfg.agent_default_timeout_seconds or 28800.0)),
        )
        cfg.agy_queue_timeout_seconds = max(1.0, float(cfg.agy_queue_timeout_seconds or 28800.0))
        cfg.sandbox_lock_timeout_seconds = max(
            0.1,
            float(
                5.0
                if cfg.sandbox_lock_timeout_seconds is None
                else cfg.sandbox_lock_timeout_seconds
            ),
        )
        cfg.max_concurrent_codex = max(1, int(cfg.max_concurrent_codex or 6))
        cfg.max_concurrent_claude = max(1, int(cfg.max_concurrent_claude or 4))
        if not cfg.sandbox_state_dir:
            cfg.sandbox_state_dir = detect_default_sandbox_state_dir()
        cfg.sandbox_min_retention_days = max(
            0.0, float(7.0 if cfg.sandbox_min_retention_days is None else cfg.sandbox_min_retention_days)
        )
        cfg.sandbox_max_retention_days = max(
            cfg.sandbox_min_retention_days,
            float(30.0 if cfg.sandbox_max_retention_days is None else cfg.sandbox_max_retention_days),
        )
        cfg.sandbox_low_space_free_gb = max(
            0.0, float(8.0 if cfg.sandbox_low_space_free_gb is None else cfg.sandbox_low_space_free_gb)
        )
        cfg.sandbox_low_space_free_percent = max(
            0.0,
            min(
                95.0,
                float(
                    15.0
                    if cfg.sandbox_low_space_free_percent is None
                    else cfg.sandbox_low_space_free_percent
                ),
            ),
        )
        cfg.sandbox_cleanup_interval_seconds = max(
            10.0,
            float(
                3600.0
                if cfg.sandbox_cleanup_interval_seconds is None
                else cfg.sandbox_cleanup_interval_seconds
            ),
        )

        codex_home_str = str(Path.home() / ".codex")
        if cfg.protected_paths and codex_home_str not in cfg.protected_paths:
            cfg.protected_paths.append(codex_home_str)
        for claude_prot in (str(Path.home() / ".claude"), str(Path.home() / ".claude.json")):
            if cfg.protected_paths and claude_prot not in cfg.protected_paths:
                cfg.protected_paths.append(claude_prot)
        for b_cmd in DEFAULT_BLOCKED_COMMANDS:
            if b_cmd not in cfg.blocked_commands and b_cmd not in cfg.allowed_commands:
                cfg.blocked_commands.append(b_cmd)
        if "bash" in cfg.allowed_commands or "sh" in cfg.allowed_commands:
            for sh_builtin in (
                "cd",
                "set",
                "export",
                "unset",
                "true",
                "false",
                "test",
                "[",
                "source",
                ".",
                "exit",
                "return",
                ":",
                "trap",
                "command",
                "type",
            ):
                if (
                    sh_builtin not in cfg.allowed_commands
                    and sh_builtin not in cfg.blocked_commands
                ):
                    cfg.allowed_commands.append(sh_builtin)
        if "agy" in cfg.allowed_commands:
            for c_cmd in ("codex", cfg.codex_binary, "claude", cfg.claude_binary):
                if c_cmd and c_cmd not in cfg.allowed_commands and c_cmd not in cfg.blocked_commands:
                    cfg.allowed_commands.append(c_cmd)
        if "agy" in cfg.allowed_commands or "git" in cfg.allowed_commands:
            for extra_cmd in ("bwrap", cfg.bwrap_binary, "nl"):
                if (
                    extra_cmd
                    and extra_cmd not in cfg.allowed_commands
                    and extra_cmd not in cfg.blocked_commands
                ):
                    cfg.allowed_commands.append(extra_cmd)
        if os.environ.get("GATEWAY_TLS_CERT"):
            cfg.tls_certfile = os.environ["GATEWAY_TLS_CERT"]
        if os.environ.get("GATEWAY_TLS_KEY"):
            cfg.tls_keyfile = os.environ["GATEWAY_TLS_KEY"]
        if os.environ.get("GATEWAY_TLS_CA"):
            cfg.tls_ca_file = os.environ["GATEWAY_TLS_CA"]
        if os.environ.get("GATEWAY_TLS_MTLS", "").lower() in ("1", "true", "yes"):
            cfg.tls_require_client_cert = True

        return cfg

    def ensure_workdirs(self) -> None:
        """Ensure configured workspace root directories exist on disk."""
        for raw_dir in self.allowed_workdirs:
            p = Path(raw_dir).expanduser()
            p.mkdir(parents=True, exist_ok=True)
        def_p = Path(self.default_workdir).expanduser()
        def_p.mkdir(parents=True, exist_ok=True)

    def save(self, save_path: Path) -> None:
        """Persist configuration JSON atomically with 0600 permissions."""
        save_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = save_path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, save_path)

    def ensure_credentials(self, save_path: Optional[Path] = None) -> Dict[str, str]:
        """Ensure at least one token, user/password, and HMAC secret exist; return summary."""
        generated: Dict[str, str] = {}
        if not self.api_tokens:
            token = f"dots_gw_{secrets.token_urlsafe(32)}"
            self.api_tokens.append(token)
            generated["api_token"] = token
        if not self.hmac_secret:
            self.hmac_secret = secrets.token_hex(32)
            generated["hmac_secret"] = self.hmac_secret
        if not self.users:
            raw_password = secrets.token_urlsafe(18)
            self.users["dots"] = hash_password_pbkdf2(raw_password)
            generated["username"] = "dots"
            generated["password"] = raw_password

        if save_path and generated:
            self.save(save_path)
        return generated


DOCKER_CLI_BASENAMES = frozenset({"docker", "docker-compose"})
_DOCKER_ON_VALUES = ("1", "true", "yes", "on", "enable", "enabled")
_DOCKER_OFF_VALUES = ("0", "false", "no", "off", "disable", "disabled")


def docker_access_state(cfg: "GatewayConfig") -> Dict[str, object]:
    """Return hot-reloaded Docker access state `{"enabled": bool, "source": str}`.

    Precedence: `docker_mode_file` (first non-comment line `on`/`off`, written by
    `dots-gateway docker on|off`) > `cfg.docker_enabled`. Read on every call so toggling
    takes effect for new sessions without restarting the gateway.
    """
    mode_file = str(getattr(cfg, "docker_mode_file", "") or "").strip()
    if mode_file:
        try:
            raw = Path(mode_file).expanduser().read_text(encoding="utf-8")
        except OSError:
            raw = ""
        for line in raw.splitlines():
            val = line.split("#", 1)[0].strip().lower()
            if not val:
                continue
            if val in _DOCKER_ON_VALUES:
                return {"enabled": True, "source": mode_file}
            if val in _DOCKER_OFF_VALUES:
                return {"enabled": False, "source": mode_file}
            break
    return {"enabled": bool(getattr(cfg, "docker_enabled", False)), "source": "config.docker_enabled"}


def docker_access_enabled(cfg: "GatewayConfig") -> bool:
    """Shorthand for `docker_access_state(cfg)["enabled"]`."""
    return bool(docker_access_state(cfg)["enabled"])


VALID_STREAM_MODES: Tuple[str, ...] = ("off", "summary", "raw")
_STREAM_OFF_VALUES = ("0", "false", "no", "off", "none", "disable", "disabled")
_STREAM_SUMMARY_VALUES = ("1", "true", "yes", "on", "enable", "enabled", "summary", "progress")
_STREAM_RAW_VALUES = ("raw", "full", "verbose", "all")


def normalize_stream_mode(value: Any, *, default: Optional[str] = None) -> Optional[str]:
    """Normalize bool/string streaming toggle into `'off'`, `'summary'`, or `'raw'`."""
    if value is None:
        return default
    if isinstance(value, bool):
        return "summary" if value else "off"
    raw = str(value).strip().lower()
    if not raw:
        return default
    if raw in _STREAM_OFF_VALUES:
        return "off"
    if raw in _STREAM_SUMMARY_VALUES:
        return "summary"
    if raw in _STREAM_RAW_VALUES:
        return "raw"
    raise ValueError(f"Invalid stream_mode {value!r}; expected 'off', 'summary', or 'raw'")


def stream_mode_state(cfg: "GatewayConfig") -> Dict[str, Any]:
    """Return hot-reloaded streaming state without requiring a gateway restart.

    Precedence: `stream_mode_file` (first non-comment line `off`/`summary`/`raw`, written by
    `dots-gateway stream ...`) > `cfg.stream_default_mode` (default: `'summary'`).
    """
    interval = max(
        0.05,
        float(
            1.0
            if getattr(cfg, "stream_progress_interval_seconds", None) is None
            else cfg.stream_progress_interval_seconds
        ),
    )
    raw_detach = getattr(cfg, "default_detach_after_seconds", None)
    default_detach = float(raw_detach) if (raw_detach is not None and float(raw_detach) > 0) else None

    mode_file = str(getattr(cfg, "stream_mode_file", "") or "").strip()
    if mode_file:
        try:
            raw = Path(mode_file).expanduser().read_text(encoding="utf-8")
        except OSError:
            raw = ""
        for line in raw.splitlines():
            val = line.split("#", 1)[0].strip().lower()
            if not val:
                continue
            try:
                parsed = normalize_stream_mode(val)
            except ValueError:
                parsed = None
            if parsed in VALID_STREAM_MODES:
                return {
                    "mode": parsed,
                    "enabled": parsed != "off",
                    "source": mode_file,
                    "progress_interval_seconds": interval,
                    "default_detach_after_seconds": default_detach,
                }
            break

    try:
        cfg_mode = normalize_stream_mode(getattr(cfg, "stream_default_mode", "summary"), default="summary") or "summary"
    except ValueError:
        cfg_mode = "summary"
    return {
        "mode": cfg_mode,
        "enabled": cfg_mode != "off",
        "source": "config.stream_default_mode",
        "progress_interval_seconds": interval,
        "default_detach_after_seconds": default_detach,
    }


def resolve_effective_stream_mode(
    cfg: "GatewayConfig",
    *,
    stream: Any = None,
    stream_mode: Any = None,
) -> Tuple[str, str]:
    """Resolve effective streaming mode for a single execution.

    Precedence: per-call `stream_mode` > per-call `stream` boolean > server hot-reload / config default.
    Returns `(mode, source)`.
    """
    if stream_mode is not None:
        resolved = normalize_stream_mode(stream_mode)
        assert resolved is not None
        return resolved, "call.stream_mode"
    if stream is not None:
        resolved = normalize_stream_mode(stream)
        assert resolved is not None
        return resolved, "call.stream"
    state = stream_mode_state(cfg)
    return str(state["mode"]), str(state["source"])



_DIAGNOSTIC_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(r"://[^/\s:@]+:[^/\s@]+@"),
    re.compile(
        r"(?i)\b(token|secret|password|passwd|api[_-]?key|runtime[_-]?key|hmac[_-]?secret|client[_-]?secret)"
        r"(\s*[:=]\s*['\"]?)([^'\"\s,;]+)"
    ),
    re.compile(r"\bdots_gw_(?:tok|token|secret|key)[A-Za-z0-9_-]{6,}\b"),
    re.compile(r"\b(?:sk|xai)-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bya29\.[A-Za-z0-9._-]{16,}\b"),
    re.compile(r"pbkdf2_sha256\$[^\s'\"]+"),
)


def redact_diagnostic_text(
    text: str,
    cfg: Optional["GatewayConfig"] = None,
    extra_secrets: Sequence[str] = (),
) -> str:
    """Scrub credentials, tokens, and secret literals from diagnostic and error messages."""
    out = str(text or "")
    if not out:
        return out

    literals: List[str] = []
    if cfg is not None:
        for tok in getattr(cfg, "api_tokens", None) or ():
            if isinstance(tok, str) and len(tok) >= 6:
                literals.append(tok)
        hmac_val = getattr(cfg, "hmac_secret", None)
        if isinstance(hmac_val, str) and len(hmac_val) >= 6:
            literals.append(hmac_val)
        users_map = getattr(cfg, "users", None)
        if isinstance(users_map, dict):
            for u_secret in users_map.values():
                if isinstance(u_secret, str) and len(u_secret) >= 6:
                    literals.append(u_secret)
    for item in extra_secrets:
        if isinstance(item, str) and len(item) >= 6:
            literals.append(item)

    for lit in sorted(set(literals), key=len, reverse=True):
        out = out.replace(lit, "[REDACTED]")

    out = _DIAGNOSTIC_SECRET_PATTERNS[0].sub(r"\1 [REDACTED]", out)
    out = _DIAGNOSTIC_SECRET_PATTERNS[1].sub("://[REDACTED]@", out)
    out = _DIAGNOSTIC_SECRET_PATTERNS[2].sub(r"\1\2[REDACTED]", out)
    for rx in _DIAGNOSTIC_SECRET_PATTERNS[3:]:
        out = rx.sub("[REDACTED]", out)
    return out


def _load_plugins_registry_state(
    cfg: "GatewayConfig",
    *,
    file_attr: str,
    enabled_attr: str,
    dirs_attr: str,
    config_source_label: str,
) -> Dict[str, Any]:
    """Load and fail-closed validate hot-reloadable plugin registration state."""
    raw_pf = str(getattr(cfg, file_attr, "") or "").strip()
    if raw_pf:
        pf_path = os.path.expanduser(raw_pf)
        try:
            lst = os.lstat(pf_path)
        except FileNotFoundError:
            lst = None
        except OSError as exc:
            return {
                "enabled": True,
                "configured": True,
                "source": redact_diagnostic_text(pf_path, cfg),
                "raw_dirs": [],
                "config_error": redact_diagnostic_text(
                    f"Cannot inspect {file_attr} '{pf_path}': {exc}", cfg
                ),
            }
        if lst is not None:
            if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
                return {
                    "enabled": True,
                    "configured": True,
                    "source": redact_diagnostic_text(pf_path, cfg),
                    "raw_dirs": [],
                    "config_error": redact_diagnostic_text(
                        f"{file_attr} '{pf_path}' must be a regular file, not a symlink or special file",
                        cfg,
                    ),
                }
            if lst.st_mode & 0o002:
                return {
                    "enabled": True,
                    "configured": True,
                    "source": redact_diagnostic_text(pf_path, cfg),
                    "raw_dirs": [],
                    "config_error": redact_diagnostic_text(
                        f"{file_attr} '{pf_path}' must not be world-writable",
                        cfg,
                    ),
                }
            if hasattr(os, "getuid") and lst.st_uid not in (os.getuid(), 0):
                return {
                    "enabled": True,
                    "configured": True,
                    "source": redact_diagnostic_text(pf_path, cfg),
                    "raw_dirs": [],
                    "config_error": redact_diagnostic_text(
                        f"{file_attr} '{pf_path}' is owned by untrusted uid {lst.st_uid}",
                        cfg,
                    ),
                }
            try:
                raw_json = Path(pf_path).read_text(encoding="utf-8")
                parsed = json.loads(raw_json)
            except Exception as exc:
                return {
                    "enabled": True,
                    "configured": True,
                    "source": redact_diagnostic_text(pf_path, cfg),
                    "raw_dirs": [],
                    "config_error": redact_diagnostic_text(
                        f"Invalid JSON in {file_attr} '{pf_path}': {exc}",
                        cfg,
                    ),
                }
            if not isinstance(parsed, dict):
                return {
                    "enabled": True,
                    "configured": True,
                    "source": redact_diagnostic_text(pf_path, cfg),
                    "raw_dirs": [],
                    "config_error": redact_diagnostic_text(
                        f"{file_attr} '{pf_path}' must contain a JSON object",
                        cfg,
                    ),
                }
            raw_enabled = parsed.get("enabled", False)
            if not isinstance(raw_enabled, bool):
                return {
                    "enabled": True,
                    "configured": True,
                    "source": redact_diagnostic_text(pf_path, cfg),
                    "raw_dirs": [],
                    "config_error": redact_diagnostic_text(
                        f"{file_attr} '{pf_path}' field 'enabled' must be a boolean",
                        cfg,
                    ),
                }
            raw_list = parsed.get("plugin_dirs", [])
            if not isinstance(raw_list, list) or any(not isinstance(x, str) for x in raw_list):
                return {
                    "enabled": True,
                    "configured": True,
                    "source": redact_diagnostic_text(pf_path, cfg),
                    "raw_dirs": [],
                    "config_error": redact_diagnostic_text(
                        f"{file_attr} '{pf_path}' field 'plugin_dirs' must be a list of strings",
                        cfg,
                    ),
                }
            clean_dirs = [x.strip() for x in raw_list if x.strip()]
            return {
                "enabled": raw_enabled,
                "configured": bool(raw_enabled or clean_dirs),
                "source": redact_diagnostic_text(pf_path, cfg),
                "raw_dirs": clean_dirs,
                "config_error": None,
            }

    cfg_enabled = getattr(cfg, enabled_attr, False)
    cfg_dirs = getattr(cfg, dirs_attr, [])
    if not isinstance(cfg_enabled, bool):
        return {
            "enabled": True,
            "configured": True,
            "source": config_source_label,
            "raw_dirs": [],
            "config_error": f"config field '{enabled_attr}' must be a boolean",
        }
    if not isinstance(cfg_dirs, (list, tuple)) or any(not isinstance(x, str) for x in cfg_dirs):
        return {
            "enabled": True,
            "configured": True,
            "source": config_source_label,
            "raw_dirs": [],
            "config_error": f"config field '{dirs_attr}' must be a list of strings",
        }
    clean_cfg_dirs = [x.strip() for x in cfg_dirs if x.strip()]
    return {
        "enabled": cfg_enabled,
        "configured": bool(cfg_enabled or clean_cfg_dirs),
        "source": config_source_label,
        "raw_dirs": clean_cfg_dirs,
        "config_error": None,
    }


def agy_plugins_config_state(cfg: "GatewayConfig") -> Dict[str, Any]:
    """Return hot-reloaded AGY plugin registration config state.

    Precedence: `agy_plugins_file` (JSON `{"enabled": bool, "plugin_dirs": [...]}` managed by
    `dots-gateway agy-plugins`, mode 0600) > `cfg.agy_plugins_enabled` + `cfg.agy_plugin_dirs`.
    Defaults to disabled (`enabled=False`) when neither is configured. Any corrupted, symlinked,
    or world-writable `agy_plugins_file` returns `enabled=True` with `config_error` so AGY
    sessions fail closed rather than silently bypassing operator policy.
    """
    return _load_plugins_registry_state(
        cfg,
        file_attr="agy_plugins_file",
        enabled_attr="agy_plugins_enabled",
        dirs_attr="agy_plugin_dirs",
        config_source_label="config.agy_plugins",
    )


def codex_plugins_config_state(cfg: "GatewayConfig") -> Dict[str, Any]:
    """Return hot-reloaded OpenAI Codex plugin registration config state.

    Precedence: `codex_plugins_file` (JSON `{"enabled": bool, "plugin_dirs": [...]}` managed by
    `dots-gateway codex-plugins`, mode 0600) > `cfg.codex_plugins_enabled` + `cfg.codex_plugin_dirs`.
    Defaults to disabled (`enabled=False`) when neither is configured. Any corrupted, symlinked,
    or world-writable `codex_plugins_file` returns `enabled=True` with `config_error` so Codex
    sessions fail closed rather than silently bypassing operator policy.
    """
    return _load_plugins_registry_state(
        cfg,
        file_attr="codex_plugins_file",
        enabled_attr="codex_plugins_enabled",
        dirs_attr="codex_plugin_dirs",
        config_source_label="config.codex_plugins",
    )


def claude_plugins_config_state(cfg: "GatewayConfig") -> Dict[str, Any]:
    """Return hot-reloaded Anthropic Claude Code plugin registration config state.

    Precedence: `claude_plugins_file` (JSON `{"enabled": bool, "plugin_dirs": [...]}` managed by
    `dots-gateway claude-plugins`, mode 0600) > `cfg.claude_plugins_enabled` + `cfg.claude_plugin_dirs`.
    Defaults to disabled (`enabled=False`) when neither is configured. Any corrupted, symlinked,
    or world-writable `claude_plugins_file` returns `enabled=True` with `config_error` so Claude
    sessions fail closed rather than silently bypassing operator policy.
    """
    return _load_plugins_registry_state(
        cfg,
        file_attr="claude_plugins_file",
        enabled_attr="claude_plugins_enabled",
        dirs_attr="claude_plugin_dirs",
        config_source_label="config.claude_plugins",
    )


def effective_plugin_state_dir(cfg: "GatewayConfig") -> str:
    """Return configured `plugin_state_dir` or default `<sandbox_state_dir>/plugin_state`."""
    raw_override = str(getattr(cfg, "plugin_state_dir", "") or "").strip()
    if raw_override:
        return raw_override
    base_sb = str(getattr(cfg, "sandbox_state_dir", "") or "").strip()
    if not base_sb:
        base_sb = detect_default_sandbox_state_dir()
    return os.path.join(os.path.expanduser(base_sb), "plugin_state")

