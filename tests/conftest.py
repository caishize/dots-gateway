"""Pytest isolation: keep tests away from the live gateway's hot-reload Docker state & proxy socket."""

import os
import tempfile

_DOCKER_TEST_DIR = tempfile.mkdtemp(prefix="dots_docker_isolation_")
os.environ.setdefault("GATEWAY_DOCKER_MODE_FILE", os.path.join(_DOCKER_TEST_DIR, "docker.mode"))
os.environ.setdefault("GATEWAY_DOCKER_PROXY_SOCKET", os.path.join(_DOCKER_TEST_DIR, "docker-proxy.sock"))
