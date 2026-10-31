"""Configuration management for the Dots Gateway."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

GATEWAY_ROOT: Path = Path(__file__).resolve().parent.parent
HOME_DIR: str = str(Path.home())
DEFAULT_AGY_BIN: str = shutil.which("agy") or str(Path.home() / ".local" / "bin" / "agy")


DEFAULT_ALLOWED_COMMANDS: List[str] = [
    # Antigravity CLI
    "agy",
    DEFAULT_AGY_BIN,
    # Shell & builtins
    "bash",
    "sh",
    "cd",
    "export",
    "unset",
    "true",
    "false",
    "test",
    "[",
    "source",
    ".",
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
    "poetry",
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
    str(GATEWAY_ROOT / "config.json"),
    str(GATEWAY_ROOT / "client.json"),
    str(GATEWAY_ROOT / "certs"),
    str(Path.home() / ".config" / "dots-gateway"),
    str(Path.home() / ".ssh"),
    str(Path.home() / ".gnupg"),
]


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
    # Command & workspace policy settings
    enforce_allowlist: bool = True
    allowed_commands: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_COMMANDS))
    blocked_commands: List[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_COMMANDS))
    blocked_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_PATTERNS))
    allowed_workdirs: List[str] = field(default_factory=lambda: [HOME_DIR, "/tmp"])
    protected_paths: List[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED_PATHS))
    default_workdir: str = HOME_DIR
    # Antigravity (agy) specific settings
    agy_binary: str = DEFAULT_AGY_BIN
    agy_default_skip_permissions: bool = True
    max_concurrent_agy: int = field(default_factory=detect_recommended_max_agy)
    agy_queue_timeout_seconds: float = 1800.0
    # Execution, connection & memory limits
    default_timeout_seconds: float = 600.0
    max_timeout_seconds: float = 7200.0
    max_concurrent_sessions: int = 32
    max_concurrent_connections: int = 128
    max_output_buffer_events: int = 5000
    max_output_bytes: int = 32 * 1024 * 1024  # 32 MiB per stream
    sse_keepalive_seconds: float = 15.0
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
        if os.environ.get("GATEWAY_WORKDIR"):
            cfg.default_workdir = os.environ["GATEWAY_WORKDIR"]
        if os.environ.get("GATEWAY_AGY_BIN"):
            cfg.agy_binary = os.environ["GATEWAY_AGY_BIN"]
        if os.environ.get("GATEWAY_MAX_AGY"):
            cfg.max_concurrent_agy = max(1, int(os.environ["GATEWAY_MAX_AGY"]))
        if os.environ.get("GATEWAY_TLS_CERT"):
            cfg.tls_certfile = os.environ["GATEWAY_TLS_CERT"]
        if os.environ.get("GATEWAY_TLS_KEY"):
            cfg.tls_keyfile = os.environ["GATEWAY_TLS_KEY"]
        if os.environ.get("GATEWAY_TLS_CA"):
            cfg.tls_ca_file = os.environ["GATEWAY_TLS_CA"]
        if os.environ.get("GATEWAY_TLS_MTLS", "").lower() in ("1", "true", "yes"):
            cfg.tls_require_client_cert = True

        return cfg

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
