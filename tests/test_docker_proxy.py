"""Tests for the policy-filtering Docker proxy, sandbox socket masking, and hot docker toggle."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

from gateway.config import GatewayConfig, docker_access_enabled
from gateway.docker_proxy import MANAGED_FILTER, MANAGED_LABEL, DockerProxy
from gateway.policy import CommandPolicy
from gateway.sandbox import build_mount_ns_argv


class _FakeDaemon:
    """Minimal Docker daemon stand-in recording every forwarded request."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.requests: List[Dict[str, Any]] = []
        self._server: Any = None

    async def start(self) -> None:
        self._server = await asyncio.start_unix_server(self._handle, path=self.path)

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        head = (await r.readuntil(b"\r\n\r\n")).decode("latin-1")
        lines = head.split("\r\n")
        method, target, _ = lines[0].split(" ")
        hdrs = {}
        for ln in lines[1:]:
            if ln:
                k, _, v = ln.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        body = b""
        if "content-length" in hdrs:
            body = await r.readexactly(int(hdrs["content-length"]))
        self.requests.append({"method": method, "target": target, "headers": hdrs, "body": body})
        status, payload = 200, {"ok": True}
        path = target.split("?", 1)[0]
        if path == "/containers/managed1/json":
            payload = {
                "Config": {"Labels": {MANAGED_LABEL: "true"}},
                "HostConfig": {"Binds": [], "NetworkMode": "bridge", "CgroupnsMode": "host"},
                "Mounts": [],
            }
        elif path == "/containers/foreign/json":
            payload = {"Config": {"Labels": {}}, "HostConfig": {"Privileged": True}}
        elif path.startswith("/containers/missing"):
            status, payload = 404, {"message": "No such container: missing"}
        elif path == "/volumes/hostvol":
            payload = {"Name": "hostvol", "Driver": "local", "Options": {"type": "none", "o": "bind", "device": "/"}, "Labels": {}}
        elif path == "/volumes/newvol":
            status, payload = 404, {"message": "no such volume"}
        data = json.dumps(payload).encode()
        w.write(
            f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n"
            f"Connection: close\r\n\r\n".encode() + data
        )
        await w.drain()
        w.close()


async def _call(sock: str, method: str, target: str, body: Any = None) -> Tuple[int, Any]:
    r, w = await asyncio.open_unix_connection(sock)
    raw = json.dumps(body).encode() if body is not None else b""
    head = f"{method} {target} HTTP/1.1\r\nHost: docker\r\n"
    if body is not None:
        head += f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n"
    w.write(head.encode() + b"\r\n" + raw)
    await w.drain()
    resp = await asyncio.wait_for(r.read(), timeout=10)
    w.close()
    head_b, _, payload = resp.partition(b"\r\n\r\n")
    status = int(head_b.split(b" ")[1])
    try:
        return status, json.loads(payload) if payload else None
    except ValueError:
        return status, payload


class DockerProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dots_docker_test_")
        self.ws = os.path.join(self.tmp, "ws")
        os.makedirs(os.path.join(self.ws, "proj"))
        os.makedirs(os.path.join(self.ws, "secret"))
        os.symlink("/etc", os.path.join(self.ws, "proj", "etc_link"))
        self.mode_file = os.path.join(self.tmp, "docker.mode")
        Path(self.mode_file).write_text("on\n")
        self.cfg = GatewayConfig(
            allowed_workdirs=[self.ws],
            default_workdir=self.ws,
            protected_paths=[os.path.join(self.ws, "secret")],
            docker_mode_file=self.mode_file,
            docker_upstream_socket=os.path.join(self.tmp, "up.sock"),
            docker_proxy_socket=os.path.join(self.tmp, "proxy.sock"),
        )
        self.daemon = _FakeDaemon(self.cfg.docker_upstream_socket)
        await self.daemon.start()
        self.proxy = DockerProxy(self.cfg, CommandPolicy(self.cfg))
        self.assertTrue(await self.proxy.start())
        self.sock = self.cfg.docker_proxy_socket

    async def asyncTearDown(self) -> None:
        await self.proxy.stop()
        await self.daemon.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _forwarded(self, path_prefix: str) -> List[Dict[str, Any]]:
        return [r for r in self.daemon.requests if r["target"].startswith(path_prefix)]

    async def test_hot_toggle_off_denies_everything(self) -> None:
        Path(self.mode_file).write_text("off\n")
        status, body = await _call(self.sock, "GET", "/_ping")
        self.assertEqual(status, 403)
        self.assertIn("OFF", body["message"])
        self.assertEqual(self.daemon.requests, [])
        Path(self.mode_file).write_text("on\n")
        status, _ = await _call(self.sock, "GET", "/v1.47/version")
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.requests[-1]["headers"].get("connection"), "close")

    async def test_create_rejects_escalation_vectors(self) -> None:
        bad_host_configs = [
            {"Privileged": True},
            {"CapAdd": ["SYS_ADMIN"]},
            {"Devices": [{"PathOnHost": "/dev/sda"}]},
            {"PidMode": "host"},
            {"SecurityOpt": ["apparmor=unconfined"]},
            {"Binds": ["/:/host"]},
            {"Binds": ["/etc:/x:ro"]},
            {"Binds": [f"{self.ws}/proj/etc_link:/x"]},
            {"Binds": [f"{self.ws}/secret:/x"]},
            {"Mounts": [{"Type": "bind", "Source": "/home", "Target": "/h"}]},
            {"Mounts": [{"Type": "volume", "Target": "/v", "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"type": "none", "o": "bind", "device": "/"}}}}]},
            {"Binds": ["hostvol:/data"]},
            {"PidMode": "container:foreign"},
            {"PublishAllPorts": True},
            {"PortBindings": {"80/tcp": [{"HostIp": "10.0.0.5", "HostPort": "80"}]}},
            {"Runtime": "sysbox"},
        ]
        for hc in bad_host_configs:
            with self.subTest(hc=hc):
                status, body = await _call(
                    self.sock, "POST", "/v1.47/containers/create", {"Image": "alpine", "HostConfig": hc}
                )
                self.assertEqual(status, 403, body)
        self.assertEqual(self._forwarded("/v1.47/containers/create"), [])

    async def test_create_allowed_is_labelled_and_ports_loopback(self) -> None:
        status, _ = await _call(
            self.sock,
            "POST",
            "/v1.47/containers/create?name=web",
            {
                "Image": "nginx",
                "Labels": {"a": "b"},
                "HostConfig": {
                    "Binds": [f"{self.ws}/proj:/app", "newvol:/data"],
                    "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]},
                    "NetworkMode": "host",
                },
            },
        )
        self.assertEqual(status, 200)
        fwd = self._forwarded("/v1.47/containers/create")
        self.assertEqual(len(fwd), 1)
        sent = json.loads(fwd[0]["body"])
        self.assertEqual(sent["Labels"], {"a": "b", MANAGED_LABEL: "true"})
        self.assertEqual(sent["HostConfig"]["PortBindings"]["80/tcp"][0]["HostIp"], "127.0.0.1")
        self.assertEqual(fwd[0]["target"], "/v1.47/containers/create?name=web")

    async def test_ownership_and_list_scoping(self) -> None:
        status, _ = await _call(self.sock, "POST", "/v1.47/containers/foreign/start")
        self.assertEqual(status, 403)
        status, _ = await _call(self.sock, "POST", "/v1.47/containers/foreign/exec", {"Cmd": ["sh"]})
        self.assertEqual(status, 403)
        status, body = await _call(self.sock, "GET", "/v1.47/containers/missing/json")
        self.assertEqual(status, 404)
        self.assertIn("No such container", body["message"])
        status, _ = await _call(self.sock, "POST", "/v1.47/containers/managed1/start")
        self.assertEqual(status, 200)
        self.assertEqual(len(self._forwarded("/v1.47/containers/managed1/start")), 1)
        status, _ = await _call(
            self.sock, "POST", "/v1.47/containers/managed1/exec", {"Cmd": ["sh"], "Privileged": True}
        )
        self.assertEqual(status, 403)

        status, _ = await _call(
            self.sock, "GET", '/v1.47/containers/json?all=1&filters={"label":["x=y"]}'
        )
        self.assertEqual(status, 200)
        target = self._forwarded("/v1.47/containers/json")[0]["target"]
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(target).query)
        self.assertEqual(json.loads(q["filters"][0])["label"], ["x=y", MANAGED_FILTER])
        self.assertEqual(q["all"], ["1"])

    async def test_unknown_and_swarm_routes_denied(self) -> None:
        for method, target in (
            ("POST", "/v1.47/swarm/init"),
            ("GET", "/v1.47/plugins"),
            ("POST", "/v1.47/services/create"),
            ("GET", "/v1.47/containers/../../etc"),
        ):
            with self.subTest(target=target):
                status, _ = await _call(self.sock, method, target, {} if method == "POST" else None)
                self.assertIn(status, (400, 403))
        status, _ = await _call(self.sock, "POST", "/v1.47/networks/create", {"Name": "n", "Driver": "macvlan"})
        self.assertEqual(status, 403)
        status, _ = await _call(self.sock, "POST", "/v1.47/volumes/create", {"Name": "v", "DriverOpts": {"type": "none", "o": "bind", "device": "/root"}})
        self.assertEqual(status, 403)

    async def test_policy_and_sandbox_hot_toggle(self) -> None:
        policy = CommandPolicy(self.cfg)
        self.assertTrue(docker_access_enabled(self.cfg))
        self.assertTrue(policy.validate_command("docker compose up -d", cwd=self.ws).allowed)
        self.assertTrue(
            policy.validate_command(f"docker run --rm -v {self.ws}:/root/.config alpine true", cwd=self.ws).allowed
        )
        self.assertFalse(
            policy.validate_command(f"docker run --rm -v {self.ws}/secret:/app alpine true", cwd=self.ws).allowed
        )
        self.assertNotIn("command(docker)", policy.get_agy_denied_rules())
        Path(self.mode_file).write_text("off\n")
        self.assertFalse(policy.validate_command("docker ps", cwd=self.ws).allowed)
        self.assertIn("command(docker)", policy.get_agy_denied_rules())
        self.assertFalse(policy.validate_command("podman ps", cwd=self.ws).allowed)

        argv = build_mount_ns_argv(
            ["true"], self.ws, [self.ws], [], sandbox_state_dir=os.path.join(self.tmp, "sb"),
            docker_mask_paths=["/run/docker.sock"], docker_proxy_socket=None,
        )
        script = argv[argv.index("-c") + 1]
        self.assertIn("--bind /dev/null", script)
        self.assertIn("/run/docker.sock", script)
        argv = build_mount_ns_argv(
            ["true"], self.ws, [self.ws], [], sandbox_state_dir=os.path.join(self.tmp, "sb"),
            docker_mask_paths=["/run/docker.sock"], docker_proxy_socket=self.sock,
        )
        script = argv[argv.index("-c") + 1]
        self.assertIn(f"--bind {self.sock}", script)


if __name__ == "__main__":
    unittest.main()
