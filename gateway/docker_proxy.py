"""Policy-enforcing Docker Engine API proxy for sandboxed gateway sessions.

Why: the real `/var/run/docker.sock` is root-equivalent (`docker run -v /:/host --privileged`).
Sandboxed sessions never see it (masked by `sandbox.build_mount_ns_argv`); instead, while Docker
access is ON, they get this proxy's unix socket bind-mounted at `/run/docker.sock`.

Enforcement model (default-deny on unknown API routes):
  * Only containers / volumes / networks created THROUGH the proxy (label
    `io.dots-gateway.managed=true`) may be inspected, started, exec'd, attached, copied,
    committed, or removed; list/prune endpoints are transparently scoped to that label.
  * `containers/create`, `containers/{id}/update`, `containers/{id}/exec`, `volumes/create`
    and `networks/create` bodies are parsed and validated:
      - no `Privileged`, devices, `CapAdd` outside `docker_allowed_capabilities`, custom
        runtimes, cgroup parents, non-`no-new-privileges` security options, unmasked /proc paths;
      - no host PID/IPC/UTS/userns/cgroupns namespaces (`container:<id>` only for managed ids);
      - bind mounts / bind-backed volumes only inside `allowed_workdirs`
        (+ `docker_extra_bind_roots`) and never inside `protected_paths` (symlinks resolved);
      - published ports are rewritten to `127.0.0.1` when `docker_force_loopback_ports`.
  * Bind mounts are re-validated at `containers/{id}/start` to narrow symlink-swap races.
  * Swarm, plugins, secrets/configs, and any unknown route are rejected.

One HTTP request is served per client connection (`Connection: close` is forced upstream), so a
client can never smuggle an unvalidated second request through a validated keep-alive stream.
Hijacked streams (attach / exec start / BuildKit session) become raw bidirectional pipes only
after their (validated) request has been forwarded.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from .config import GatewayConfig, docker_access_state
from .policy import CommandPolicy

logger = logging.getLogger("dots_gateway.docker_proxy")

MANAGED_LABEL = "io.dots-gateway.managed"
MANAGED_VALUE = "true"
MANAGED_FILTER = f"{MANAGED_LABEL}={MANAGED_VALUE}"

_MAX_HEAD_BYTES = 64 * 1024
_MAX_JSON_BODY_BYTES = 8 * 1024 * 1024
_UPSTREAM_TIMEOUT = 30.0
_PIPE_CHUNK = 64 * 1024
_VERSION_PREFIX_RE = re.compile(r"^/v\d+(?:\.\d+)?(?=/)")
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
    "upgrade",
}
_SAFE_SECURITY_OPTS = {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
_ALLOWED_RUNTIMES = {"", "runc", "io.containerd.runc.v2"}
_ALLOWED_VOLUME_DRIVERS = {"", "local"}
_ALLOWED_NETWORK_DRIVERS = {"", "bridge"}
_REMOTE_FS_TYPES = {"nfs", "nfs4", "cifs", "smb3"}
_REASONS = {
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    413: "Payload Too Large",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


class DockerPolicyError(Exception):
    """Request rejected by the gateway Docker policy (rendered as a Docker-style JSON error)."""

    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _deny(message: str) -> DockerPolicyError:
    return DockerPolicyError(f"dots-gateway docker policy: {message}", 403)


class _Request:
    __slots__ = ("method", "target", "version", "headers", "path", "query", "segments")

    def __init__(self, method: str, target: str, version: str, headers: List[Tuple[str, str]]):
        self.method = method
        self.target = target
        self.version = version
        self.headers = headers
        split = urlsplit(target)
        if split.scheme or split.netloc or not split.path.startswith("/"):
            raise DockerPolicyError("absolute-form or invalid request target", 400)
        raw_path = split.path
        decoded = unquote(raw_path)
        if "%" in decoded or "\x00" in decoded or "\\" in decoded:
            raise DockerPolicyError("ambiguous percent-encoding in request path", 400)
        self.path = raw_path
        self.query: List[Tuple[str, str]] = parse_qsl(split.query, keep_blank_values=True)
        norm = _VERSION_PREFIX_RE.sub("", decoded, count=1)
        segs = norm.strip("/").split("/") if norm.strip("/") else []
        for seg in segs:
            if seg in ("", ".", ".."):
                raise DockerPolicyError("non-canonical request path", 400)
        self.segments = segs

    def header(self, name: str) -> Optional[str]:
        lname = name.lower()
        vals = [v for k, v in self.headers if k.lower() == lname]
        if len(vals) > 1:
            raise DockerPolicyError(f"duplicate '{name}' header", 400)
        return vals[0] if vals else None

    def query_value(self, name: str) -> Optional[str]:
        for k, v in self.query:
            if k == name:
                return v
        return None

    def target_with_query(self, query: List[Tuple[str, str]]) -> str:
        return self.path + ("?" + urlencode(query) if query else "")


def _inject_label_filter(query: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Scope list/prune endpoints to proxy-managed objects (AND-ed with caller label filters)."""
    raw = None
    rest: List[Tuple[str, str]] = []
    for k, v in query:
        if k == "filters":
            if raw is not None:
                raise DockerPolicyError("duplicate 'filters' query parameter", 400)
            raw = v
        else:
            rest.append((k, v))
    filters: Any = {}
    if raw:
        try:
            filters = json.loads(raw)
        except ValueError as exc:
            raise DockerPolicyError(f"invalid 'filters' JSON: {exc}", 400) from exc
    if not isinstance(filters, dict):
        raise DockerPolicyError("'filters' must be a JSON object", 400)
    labels = filters.get("label")
    if labels is None:
        filters["label"] = [MANAGED_FILTER]
    elif isinstance(labels, list):
        filters["label"] = [*labels, MANAGED_FILTER]
    elif isinstance(labels, dict):
        labels[MANAGED_FILTER] = True
    else:
        raise DockerPolicyError("unsupported 'filters.label' shape", 400)
    rest.append(("filters", json.dumps(filters, separators=(",", ":"))))
    return rest


def _with_managed_label(body: Dict[str, Any], key: str = "Labels") -> None:
    labels = body.get(key)
    if labels is None:
        labels = {}
    if not isinstance(labels, dict):
        raise DockerPolicyError(f"'{key}' must be an object", 400)
    labels[MANAGED_LABEL] = MANAGED_VALUE
    body[key] = labels


class DockerRequestPolicy:
    """Pure validation logic (no I/O except filesystem path resolution)."""

    def __init__(self, config: GatewayConfig, policy: CommandPolicy) -> None:
        self.config = config
        self.policy = policy

    # ---- paths ---------------------------------------------------------------------------
    def _extra_roots(self) -> List[str]:
        roots: List[str] = []
        for raw in self.config.docker_extra_bind_roots or ():
            try:
                roots.append(str(Path(str(raw)).expanduser().resolve()))
            except OSError:
                continue
        return roots

    def check_host_path(self, src: Any, what: str = "bind mount") -> None:
        if not isinstance(src, str) or not src.startswith("/"):
            raise _deny(f"{what} source must be an absolute host path (got {src!r})")
        lex = os.path.abspath(src)
        real = os.path.realpath(src)
        extra = self._extra_roots()
        for cand in (lex, real):
            if self.policy.is_protected_path(cand):
                raise _deny(f"{what} source '{src}' is inside a protected path")
            inside = self.policy.is_within_allowed_workdirs(cand) or any(
                cand == r or cand.startswith(r.rstrip("/") + "/") for r in extra
            )
            if not inside:
                raise _deny(
                    f"{what} source '{src}' (resolved '{cand}') is outside the gateway "
                    f"allowed_workdirs {list(self.config.allowed_workdirs)}"
                )

    def check_volume_driver_opts(self, driver: Any, opts: Any, what: str) -> None:
        if driver not in (None, *_ALLOWED_VOLUME_DRIVERS):
            raise _deny(f"{what}: volume driver '{driver}' is not allowed (only 'local')")
        if opts is None:
            return
        if not isinstance(opts, dict):
            raise DockerPolicyError(f"{what}: driver options must be an object", 400)
        device = opts.get("device")
        if device in (None, ""):
            return
        fstype = str(opts.get("type") or "").strip().lower()
        if fstype == "tmpfs":
            return
        if fstype in _REMOTE_FS_TYPES and not str(device).startswith("/"):
            return
        self.check_host_path(device, f"{what} device")

    # ---- host config ---------------------------------------------------------------------
    def _check_namespace_mode(
        self, hc: Dict[str, Any], key: str, managed_refs: List[str], mutate: bool
    ) -> None:
        val = hc.get(key)
        if val in (None, ""):
            return
        if key == "CgroupnsMode" and not mutate:
            # Daemon-filled default on re-inspection (cgroup v1 hosts report "host").
            return
        if not isinstance(val, str):
            raise DockerPolicyError(f"HostConfig.{key} must be a string", 400)
        if val.startswith("container:"):
            managed_refs.append(val.split(":", 1)[1])
            return
        if val == "host":
            if key == "NetworkMode" and self.config.docker_allow_host_network:
                return
            raise _deny(f"HostConfig.{key}=host is not allowed")
        if key == "NetworkMode":
            return
        if key == "IpcMode" and val in ("private", "shareable", "none"):
            return
        if key in ("CgroupnsMode",) and val == "private":
            return
        raise _deny(f"HostConfig.{key}={val!r} is not allowed")

    def check_host_config(
        self,
        hc: Any,
        *,
        mutate: bool,
        managed_refs: List[str],
        volume_refs: Optional[List[str]] = None,
        where: str = "HostConfig",
    ) -> None:
        """Validate (and when `mutate`, normalize) a container HostConfig."""
        if hc is None:
            return
        if not isinstance(hc, dict):
            raise DockerPolicyError(f"{where} must be an object", 400)
        if hc.get("Privileged"):
            raise _deny("privileged containers are not allowed")
        allowed_caps = {
            str(c).upper().removeprefix("CAP_") for c in self.config.docker_allowed_capabilities
        }
        for cap in hc.get("CapAdd") or []:
            norm = str(cap).upper().removeprefix("CAP_")
            if norm == "ALL" or norm not in allowed_caps:
                raise _deny(f"capability '{cap}' is not in docker_allowed_capabilities")
        for key in ("Devices", "DeviceRequests", "DeviceCgroupRules"):
            if hc.get(key):
                raise _deny(f"{where}.{key} (host devices) is not allowed")
        for opt in hc.get("SecurityOpt") or []:
            if str(opt).strip().lower() not in _SAFE_SECURITY_OPTS:
                raise _deny(f"security option '{opt}' is not allowed")
        for key in ("MaskedPaths", "ReadonlyPaths"):
            if hc.get(key) is not None and mutate:
                raise _deny(f"{where}.{key} override (unmasking /proc) is not allowed")
        if hc.get("CgroupParent"):
            raise _deny("custom CgroupParent is not allowed")
        if str(hc.get("Runtime") or "") not in _ALLOWED_RUNTIMES:
            raise _deny(f"container runtime '{hc.get('Runtime')}' is not allowed")
        if str(hc.get("VolumeDriver") or "") not in _ALLOWED_VOLUME_DRIVERS:
            raise _deny(f"volume driver '{hc.get('VolumeDriver')}' is not allowed")
        for key in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode", "NetworkMode"):
            self._check_namespace_mode(hc, key, managed_refs, mutate)
        for ref in hc.get("VolumesFrom") or []:
            managed_refs.append(str(ref).split(":", 1)[0])

        for bind in hc.get("Binds") or []:
            if not isinstance(bind, str):
                raise DockerPolicyError("HostConfig.Binds entries must be strings", 400)
            src = bind.split(":", 1)[0]
            if src.startswith("/"):
                self.check_host_path(src)
            elif "/" in src or src in (".", ".."):
                raise _deny(f"bind source '{src}' must be an absolute path or a volume name")
            elif volume_refs is not None and src:
                volume_refs.append(src)

        for mnt in hc.get("Mounts") or []:
            if not isinstance(mnt, dict):
                raise DockerPolicyError("HostConfig.Mounts entries must be objects", 400)
            mtype = str(mnt.get("Type") or "volume").lower()
            if mtype == "bind":
                self.check_host_path(mnt.get("Source"))
            elif mtype == "volume":
                vopts = mnt.get("VolumeOptions") or {}
                dcfg = (vopts.get("DriverConfig") or {}) if isinstance(vopts, dict) else {}
                if not isinstance(dcfg, dict):
                    raise DockerPolicyError("invalid VolumeOptions.DriverConfig", 400)
                self.check_volume_driver_opts(dcfg.get("Name"), dcfg.get("Options"), "mount volume")
                if volume_refs is not None and mnt.get("Source") and not dcfg:
                    volume_refs.append(str(mnt.get("Source")))
            elif mtype in ("tmpfs", "image"):
                pass
            else:
                raise _deny(f"mount type '{mtype}' is not allowed")

        port_bindings = hc.get("PortBindings") or {}
        if not isinstance(port_bindings, dict):
            raise DockerPolicyError("HostConfig.PortBindings must be an object", 400)
        if self.config.docker_force_loopback_ports:
            if hc.get("PublishAllPorts"):
                raise _deny("PublishAllPorts (-P) is not allowed; publish explicit 127.0.0.1 ports")
            for _port, bindings in port_bindings.items():
                for b in bindings or []:
                    if not isinstance(b, dict):
                        raise DockerPolicyError("invalid PortBindings entry", 400)
                    host_ip = str(b.get("HostIp") or "")
                    if host_ip in ("", "0.0.0.0", "::"):
                        if mutate:
                            b["HostIp"] = "127.0.0.1"
                        else:
                            raise _deny("published port is not bound to loopback")
                    elif host_ip not in ("127.0.0.1", "::1") and not host_ip.startswith("127."):
                        raise _deny(f"publishing ports on {host_ip} is not allowed (loopback only)")

    def validate_container_create(
        self, body: Dict[str, Any], managed_refs: List[str], volume_refs: List[str]
    ) -> None:
        _with_managed_label(body)
        self.check_host_config(
            body.get("HostConfig"), mutate=True, managed_refs=managed_refs, volume_refs=volume_refs
        )

    def validate_container_update(self, body: Dict[str, Any]) -> None:
        for key in ("Devices", "DeviceRequests", "DeviceCgroupRules"):
            if body.get(key):
                raise _deny(f"updating {key} is not allowed")
        if body.get("CgroupParent"):
            raise _deny("custom CgroupParent is not allowed")

    def validate_exec_create(self, body: Dict[str, Any]) -> None:
        if body.get("Privileged"):
            raise _deny("privileged exec is not allowed")

    def validate_volume_create(self, body: Dict[str, Any]) -> None:
        self.check_volume_driver_opts(body.get("Driver"), body.get("DriverOpts"), "volume create")
        if body.get("ClusterVolumeSpec"):
            raise _deny("cluster volumes are not allowed")
        _with_managed_label(body)

    def validate_network_create(self, body: Dict[str, Any]) -> None:
        if str(body.get("Driver") or "") not in _ALLOWED_NETWORK_DRIVERS:
            raise _deny(f"network driver '{body.get('Driver')}' is not allowed (bridge only)")
        opts = body.get("Options") or {}
        if not isinstance(opts, dict):
            raise DockerPolicyError("network Options must be an object", 400)
        if "com.docker.network.bridge.name" in opts:
            raise _deny("custom bridge interface names are not allowed")
        if body.get("ConfigFrom") or body.get("Scope") == "swarm":
            raise _deny("swarm / config-from networks are not allowed")
        _with_managed_label(body)

    def revalidate_inspected_container(self, data: Dict[str, Any]) -> None:
        """Re-check an existing managed container before `start` (narrows symlink races)."""
        self.check_host_config(data.get("HostConfig"), mutate=False, managed_refs=[])
        for mnt in data.get("Mounts") or []:
            if isinstance(mnt, dict) and str(mnt.get("Type") or "").lower() == "bind":
                self.check_host_path(mnt.get("Source"))


class DockerProxy:
    """Asyncio unix-socket server forwarding policy-approved requests to the Docker daemon."""

    def __init__(self, config: GatewayConfig, policy: CommandPolicy) -> None:
        self.config = config
        self.rules = DockerRequestPolicy(config, policy)
        self.socket_path = str(Path(config.docker_proxy_socket).expanduser())
        self.upstream_path = str(config.docker_upstream_socket)
        self._server: Optional[asyncio.AbstractServer] = None
        self._conn_sem = asyncio.Semaphore(64)
        self.stats: Dict[str, int] = {"requests": 0, "denied": 0, "errors": 0}

    @property
    def is_listening(self) -> bool:
        return self._server is not None and self._server.is_serving()

    async def start(self) -> bool:
        sock_p = Path(self.socket_path)
        try:
            sock_p.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(sock_p.parent, 0o700)
        except OSError:
            pass
        try:
            if sock_p.is_symlink():
                sock_p.unlink()
            elif sock_p.exists() and stat.S_ISSOCK(sock_p.stat().st_mode):
                if await self._socket_alive(self.socket_path):
                    # Another live gateway (e.g. production instance while tests run) owns it.
                    logger.warning(
                        "Docker proxy socket %s is already served by another process; "
                        "not taking it over",
                        self.socket_path,
                    )
                    return False
                sock_p.unlink()
        except OSError:
            pass
        old_umask = os.umask(0o177)
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_client, path=self.socket_path, limit=_MAX_HEAD_BYTES * 2
            )
        except OSError as exc:
            logger.warning("Docker proxy failed to listen on %s: %s", self.socket_path, exc)
            self._server = None
            return False
        finally:
            os.umask(old_umask)
        try:
            os.chmod(self.socket_path, 0o600)
        except OSError:
            pass
        logger.info(
            "Docker filtering proxy listening on %s -> %s", self.socket_path, self.upstream_path
        )
        return True

    @staticmethod
    async def _socket_alive(path: str) -> bool:
        try:
            _r, w = await asyncio.wait_for(asyncio.open_unix_connection(path), timeout=2.0)
        except (OSError, asyncio.TimeoutError):
            return False
        w.close()
        return True

    async def stop(self) -> None:
        if self._server is None:
            return
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        try:
            if stat.S_ISSOCK(os.lstat(self.socket_path).st_mode):
                os.unlink(self.socket_path)
        except OSError:
            pass

    # ---- connection handling -------------------------------------------------------------
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._conn_sem:
            try:
                await self._serve_one(reader, writer)
            except DockerPolicyError as exc:
                if exc.status == 403:
                    self.stats["denied"] += 1
                    logger.warning("Docker proxy denied request: %s", exc.message)
                await self._send_error(writer, exc.status, exc.message)
            except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
                pass
            except Exception:
                self.stats["errors"] += 1
                logger.exception("Docker proxy request failed")
                await self._send_error(writer, 502, "dots-gateway docker proxy internal error")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _send_error(self, writer: asyncio.StreamWriter, status: int, message: str) -> None:
        if writer.is_closing():
            return
        payload = json.dumps({"message": message}).encode("utf-8")
        head = (
            f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            writer.write(head + payload)
            await writer.drain()
        except Exception:
            pass

    async def _read_request(self, reader: asyncio.StreamReader) -> Optional[_Request]:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                return None
            raise DockerPolicyError("truncated request head", 400) from exc
        except asyncio.LimitOverrunError as exc:
            raise DockerPolicyError("request head too large", 400) from exc
        if len(head) > _MAX_HEAD_BYTES:
            raise DockerPolicyError("request head too large", 400)
        lines = head[:-4].decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not _TOKEN_RE.match(parts[0]) or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
            raise DockerPolicyError("malformed request line", 400)
        headers: List[Tuple[str, str]] = []
        for line in lines[1:]:
            if not line or line[0] in " \t":
                raise DockerPolicyError("malformed header (obs-fold)", 400)
            name, sep, value = line.partition(":")
            if not sep or not _TOKEN_RE.match(name):
                raise DockerPolicyError("malformed header", 400)
            headers.append((name, value.strip(" \t")))
        return _Request(parts[0].upper(), parts[1], parts[2], headers)

    @staticmethod
    def _body_mode(req: _Request) -> Tuple[str, int]:
        te = req.header("Transfer-Encoding")
        cl = req.header("Content-Length")
        if te is not None:
            if cl is not None:
                raise DockerPolicyError("both Transfer-Encoding and Content-Length present", 400)
            if te.strip().lower() != "chunked":
                raise DockerPolicyError(f"unsupported Transfer-Encoding '{te}'", 400)
            return "chunked", 0
        if cl is not None:
            if not cl.isdigit():
                raise DockerPolicyError("invalid Content-Length", 400)
            return "length", int(cl)
        return "none", 0

    @staticmethod
    async def _read_body(reader: asyncio.StreamReader, mode: str, length: int, limit: int) -> bytes:
        if mode == "none":
            return b""
        if mode == "length":
            if length > limit:
                raise DockerPolicyError("request body too large for policy inspection", 413)
            return await reader.readexactly(length)
        chunks: List[bytes] = []
        total = 0
        while True:
            size_line = await reader.readuntil(b"\r\n")
            try:
                size = int(size_line.split(b";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise DockerPolicyError("malformed chunk size", 400) from exc
            if size == 0:
                while (await reader.readuntil(b"\r\n")) != b"\r\n":
                    pass
                return b"".join(chunks)
            total += size
            if total > limit:
                raise DockerPolicyError("request body too large for policy inspection", 413)
            chunks.append(await reader.readexactly(size))
            if await reader.readexactly(2) != b"\r\n":
                raise DockerPolicyError("malformed chunk terminator", 400)

    @staticmethod
    async def _relay_body(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter, mode: str, length: int
    ) -> None:
        if mode == "length":
            remaining = length
            while remaining > 0:
                data = await reader.read(min(_PIPE_CHUNK, remaining))
                if not data:
                    raise asyncio.IncompleteReadError(b"", remaining)
                writer.write(data)
                remaining -= len(data)
                await writer.drain()
        elif mode == "chunked":
            while True:
                size_line = await reader.readuntil(b"\r\n")
                try:
                    size = int(size_line.split(b";", 1)[0].strip(), 16)
                except ValueError as exc:
                    raise DockerPolicyError("malformed chunk size", 400) from exc
                writer.write(b"%x\r\n" % size)
                if size == 0:
                    writer.write(b"\r\n")
                    while (await reader.readuntil(b"\r\n")) != b"\r\n":
                        pass
                    await writer.drain()
                    return
                remaining = size
                while remaining > 0:
                    data = await reader.read(min(_PIPE_CHUNK, remaining))
                    if not data:
                        raise asyncio.IncompleteReadError(b"", remaining)
                    writer.write(data)
                    remaining -= len(data)
                    await writer.drain()
                if await reader.readexactly(2) != b"\r\n":
                    raise DockerPolicyError("malformed chunk terminator", 400)
                writer.write(b"\r\n")

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, half_close: bool) -> None:
        try:
            while True:
                data = await src.read(_PIPE_CHUNK)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            if half_close:
                try:
                    if dst.can_write_eof() and not dst.is_closing():
                        dst.write_eof()
                except (OSError, RuntimeError):
                    pass

    async def _open_upstream(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.wait_for(
                asyncio.open_unix_connection(self.upstream_path, limit=_MAX_HEAD_BYTES * 2),
                timeout=_UPSTREAM_TIMEOUT,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise DockerPolicyError(
                f"Docker daemon unreachable at {self.upstream_path}: {exc}", 502
            ) from exc

    async def _upstream_json(self, method: str, path: str) -> Tuple[int, Any]:
        """Small internal request (inspect) to the real daemon; returns `(status, json)`."""
        up_r, up_w = await self._open_upstream()
        try:
            up_w.write(
                (
                    f"{method} {path} HTTP/1.1\r\nHost: docker\r\n"
                    "User-Agent: dots-gateway-docker-proxy\r\nConnection: close\r\n\r\n"
                ).encode("latin-1")
            )
            await up_w.drain()
            raw = await asyncio.wait_for(up_r.read(_MAX_JSON_BODY_BYTES * 2), timeout=_UPSTREAM_TIMEOUT)
            while True:
                more = await asyncio.wait_for(up_r.read(_PIPE_CHUNK), timeout=_UPSTREAM_TIMEOUT)
                if not more:
                    break
                raw += more
                if len(raw) > _MAX_JSON_BODY_BYTES * 2:
                    raise DockerPolicyError("upstream inspect response too large", 502)
        finally:
            up_w.close()
        head, sep, body = raw.partition(b"\r\n\r\n")
        if not sep:
            raise DockerPolicyError("malformed upstream response", 502)
        head_lines = head.decode("latin-1").split("\r\n")
        try:
            status = int(head_lines[0].split(" ")[1])
        except (IndexError, ValueError) as exc:
            raise DockerPolicyError("malformed upstream status line", 502) from exc
        chunked = any(
            ln.lower().startswith("transfer-encoding:") and "chunked" in ln.lower()
            for ln in head_lines[1:]
        )
        if chunked:
            out = bytearray()
            rest = body
            while rest:
                size_line, _, rest = rest.partition(b"\r\n")
                try:
                    size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
                except ValueError:
                    break
                if size == 0:
                    break
                out += rest[:size]
                rest = rest[size + 2 :]
            body = bytes(out)
        try:
            return status, (json.loads(body) if body.strip() else None)
        except ValueError:
            return status, None

    async def _require_managed(self, kind: str, ref: str) -> Dict[str, Any]:
        """Ensure the referenced object exists and carries the proxy-managed label."""
        if not ref or "/" in ref:
            raise _deny(f"invalid {kind} reference {ref!r}")
        api = {"container": "containers", "volume": "volumes", "network": "networks"}[kind]
        status, data = await self._upstream_json("GET", f"/{api}/{quote(ref, safe='')}" + (
            "/json" if kind == "container" else ""
        ))
        if status == 404:
            raise DockerPolicyError(f"No such {kind}: {ref}", 404)
        if status != 200 or not isinstance(data, dict):
            raise DockerPolicyError(f"failed to inspect {kind} {ref!r} (HTTP {status})", 502)
        labels = (data.get("Config") or {}).get("Labels") if kind == "container" else data.get("Labels")
        if not isinstance(labels, dict) or labels.get(MANAGED_LABEL) != MANAGED_VALUE:
            raise _deny(
                f"{kind} {ref!r} was not created through the dots-gateway sandbox and is off-limits"
            )
        return data

    async def _require_managed_refs(self, refs: Sequence[str]) -> None:
        for ref in refs:
            await self._require_managed("container", ref)

    async def _check_volume_refs(self, names: Sequence[str]) -> None:
        """Existing named volumes must not be host-created bind/device volumes."""
        for name in names:
            if "/" in name:
                raise _deny(f"invalid volume name {name!r}")
            status, data = await self._upstream_json("GET", f"/volumes/{quote(name, safe='')}")
            if status == 404:
                continue  # daemon will create a plain local volume
            if status != 200 or not isinstance(data, dict):
                raise DockerPolicyError(f"failed to inspect volume {name!r} (HTTP {status})", 502)
            labels = data.get("Labels") or {}
            if isinstance(labels, dict) and labels.get(MANAGED_LABEL) == MANAGED_VALUE:
                continue
            self.rules.check_volume_driver_opts(
                data.get("Driver"), data.get("Options"), f"existing volume {name!r}"
            )

    # ---- routing -------------------------------------------------------------------------
    async def _route(self, req: _Request) -> Tuple[str, Optional[List[Tuple[str, str]]], Optional[str], bool]:
        """Return `(body_handling, new_query, json_validator, hijack)` or raise DockerPolicyError.

        body_handling: "stream" (relay as-is) or "json" (buffer, validate via `json_validator`).
        """
        m, s = req.method, req.segments
        n = len(s)
        read_only = m in ("GET", "HEAD")
        if n == 0:
            raise _deny("unsupported Docker API route '/'")
        top = s[0]
        if top in ("_ping", "version", "info") and n == 1:
            return "stream", None, None, False
        if top == "events" and n == 1 and read_only:
            return "stream", None, None, False
        if top == "system" and s == ["system", "df"] and read_only:
            return "stream", None, None, False
        if top == "auth" and n == 1 and m == "POST":
            return "stream", None, None, False
        if top == "distribution" and n >= 3 and s[-1] == "json" and read_only:
            return "stream", None, None, False
        if top == "images":
            return "stream", None, None, False
        if top == "build":
            if n == 1 and m == "POST":
                return "stream", None, None, False
            if n == 2 and s[1] in ("prune", "cancel") and m == "POST":
                return "stream", None, None, False
        if top in ("session", "grpc") and n == 1 and m == "POST":
            return "stream", None, None, True
        if top == "commit" and n == 1 and m == "POST":
            await self._require_managed("container", req.query_value("container") or "")
            return "stream", None, None, False
        if top == "containers":
            if s == ["containers", "json"] and read_only:
                return "stream", _inject_label_filter(req.query), None, False
            if s == ["containers", "create"] and m == "POST":
                return "json", None, "container_create", False
            if s == ["containers", "prune"] and m == "POST":
                return "stream", _inject_label_filter(req.query), None, False
            if n >= 2:
                data = await self._require_managed("container", s[1])
                rest = s[2:]
                if rest == ["exec"] and m == "POST":
                    return "json", None, "exec_create", False
                if rest == ["update"] and m == "POST":
                    return "json", None, "container_update", False
                if rest == ["start"] and m == "POST":
                    self.rules.revalidate_inspected_container(data)
                    return "stream", None, None, False
                if rest in (["attach"], ["attach", "ws"]):
                    return "stream", None, None, True
                return "stream", None, None, False
        if top == "exec" and n == 3:
            status, data = await self._upstream_json("GET", f"/exec/{quote(s[1], safe='')}/json")
            if status == 404:
                raise DockerPolicyError(f"No such exec instance: {s[1]}", 404)
            if status != 200 or not isinstance(data, dict):
                raise DockerPolicyError(f"failed to inspect exec {s[1]!r} (HTTP {status})", 502)
            await self._require_managed("container", str(data.get("ContainerID") or ""))
            if s[2] == "start" and m == "POST":
                return "stream", None, None, True
            if s[2] in ("resize", "json"):
                return "stream", None, None, False
        if top == "volumes":
            if n == 1 and read_only:
                return "stream", None, None, False
            if s == ["volumes", "create"] and m == "POST":
                return "json", None, "volume_create", False
            if s == ["volumes", "prune"] and m == "POST":
                return "stream", _inject_label_filter(req.query), None, False
            if n == 2 and read_only:
                return "stream", None, None, False
            if n == 2 and m == "DELETE":
                await self._require_managed("volume", s[1])
                return "stream", None, None, False
        if top == "networks":
            if n == 1 and read_only:
                return "stream", None, None, False
            if s == ["networks", "create"] and m == "POST":
                return "json", None, "network_create", False
            if s == ["networks", "prune"] and m == "POST":
                return "stream", _inject_label_filter(req.query), None, False
            if n == 2 and read_only:
                return "stream", None, None, False
            if n == 2 and m == "DELETE":
                await self._require_managed("network", s[1])
                return "stream", None, None, False
            if n == 3 and s[2] in ("connect", "disconnect") and m == "POST":
                return "json", None, "network_connect", False
        raise _deny(f"Docker API route '{m} /{'/'.join(s)}' is not permitted")

    async def _apply_json_validator(self, name: str, body: Any) -> Any:
        if body is None:
            body = {}
        if not isinstance(body, dict):
            raise DockerPolicyError("request body must be a JSON object", 400)
        refs: List[str] = []
        volume_refs: List[str] = []
        if name == "container_create":
            self.rules.validate_container_create(body, refs, volume_refs)
        elif name == "container_update":
            self.rules.validate_container_update(body)
        elif name == "exec_create":
            self.rules.validate_exec_create(body)
        elif name == "volume_create":
            self.rules.validate_volume_create(body)
        elif name == "network_create":
            self.rules.validate_network_create(body)
        elif name == "network_connect":
            refs.append(str(body.get("Container") or ""))
        await self._require_managed_refs(refs)
        await self._check_volume_refs(volume_refs)
        return body

    async def _serve_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        req = await self._read_request(reader)
        if req is None:
            return
        self.stats["requests"] += 1
        if not docker_access_state(self.config)["enabled"]:
            raise DockerPolicyError(
                "dots-gateway docker access is OFF (enable with `dots-gateway docker on`)", 403
            )
        body_handling, new_query, validator, hijack = await self._route(req)
        mode, length = self._body_mode(req)

        body: Optional[bytes] = None
        if body_handling == "json" or (hijack and mode != "none"):
            raw = await self._read_body(reader, mode, length, _MAX_JSON_BODY_BYTES)
            if validator:
                try:
                    parsed = json.loads(raw) if raw.strip() else None
                except ValueError as exc:
                    raise DockerPolicyError(f"invalid JSON body: {exc}", 400) from exc
                parsed = await self._apply_json_validator(validator, parsed)
                raw = json.dumps(parsed, separators=(",", ":")).encode("utf-8")
            body = raw

        target = req.target_with_query(new_query) if new_query is not None else req.target
        out_headers = [(k, v) for k, v in req.headers if k.lower() not in _HOP_HEADERS]
        if body is not None:
            out_headers.append(("Content-Length", str(len(body))))
        elif mode == "length":
            out_headers.append(("Content-Length", str(length)))
        elif mode == "chunked":
            out_headers.append(("Transfer-Encoding", "chunked"))
        upgrade = req.header("Upgrade")
        if hijack and upgrade:
            out_headers.append(("Connection", "Upgrade"))
            out_headers.append(("Upgrade", upgrade))
        elif not hijack:
            out_headers.append(("Connection", "close"))
        head = f"{req.method} {target} HTTP/1.1\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in out_headers
        ) + "\r\n"

        up_r, up_w = await self._open_upstream()
        try:
            up_w.write(head.encode("latin-1"))
            if body:
                up_w.write(body)
            await up_w.drain()
            response_task = asyncio.create_task(self._pipe(up_r, writer, half_close=False))
            if hijack:
                upload_task = asyncio.create_task(self._pipe(reader, up_w, half_close=True))
                try:
                    await response_task
                finally:
                    upload_task.cancel()
                    try:
                        await upload_task
                    except asyncio.CancelledError:
                        pass
            else:
                if body is None and mode != "none":
                    try:
                        await self._relay_body(reader, up_w, mode, length)
                    except BaseException:
                        response_task.cancel()
                        raise
                await response_task
        finally:
            try:
                up_w.close()
            except Exception:
                pass
