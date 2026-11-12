"""Hermetic test isolation: keep all tests away from live gateway state, env files, and sandbox disk."""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

_TEST_ISOLATION_DIR = tempfile.mkdtemp(prefix="dots_test_isolation_")
atexit.register(shutil.rmtree, _TEST_ISOLATION_DIR, True)

os.environ.setdefault("GATEWAY_DOCKER_MODE_FILE", os.path.join(_TEST_ISOLATION_DIR, "docker.mode"))
os.environ.setdefault(
    "GATEWAY_DOCKER_PROXY_SOCKET", os.path.join(_TEST_ISOLATION_DIR, "docker-proxy.sock")
)
os.environ.setdefault("GATEWAY_SANDBOX_STATE_DIR", os.path.join(_TEST_ISOLATION_DIR, "sandbox"))
os.environ.setdefault("GATEWAY_SANDBOX_CLEANUP_ENABLED", "0")
os.environ.setdefault("GATEWAY_AGY_ENV_FILE", os.path.join(_TEST_ISOLATION_DIR, "agy.env"))
os.environ.setdefault("GATEWAY_AGY_MODEL_FILE", os.path.join(_TEST_ISOLATION_DIR, "agy.model"))
os.environ.setdefault("GATEWAY_CODEX_ENV_FILE", os.path.join(_TEST_ISOLATION_DIR, "codex.env"))
