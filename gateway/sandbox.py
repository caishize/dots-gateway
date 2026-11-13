"""Zero-dependency Linux User + Mount Namespace (`unshare` + `pivot_root` + `setpriv`) jail.

Isolates `exec_command` and `run_agy` child processes at the kernel VFS layer so that
directories outside `allowed_workdirs` (such as `~/gateway`, `~/.ssh`, `~/.gnupg`,
`~/.aliyun`, `~/.config/dots-gateway`, `~/.config/tunnel-client`, `~/.config/systemd`,
`~/oh-my-agents`, and host `/tmp`) do not exist inside the child process's filesystem tree,
while selectively exposing `~/.config/gh`, read-only `~/.gitconfig` & `~/.local/bin`, and
persistent isolated sandbox caches (`~/.cache/dots-sandbox`).
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import fcntl
from functools import lru_cache
import os
import re
import shlex
import shutil
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .config import redact_diagnostic_text

SANDBOX_SUBDIRS: Tuple[str, ...] = (
    "tmp",
    "cache",
    "npm",
    "local_share",
    "pub_cache",
    "flutter_cfg",
    "dart_tool",
    "dart_server",
    "docker_cfg",
)
SANDBOX_MANAGED_SUBDIRS: Tuple[str, ...] = (
    "tmp",
    "cache",
    "npm",
    "local_share",
    "pub_cache",
    "dart_tool",
    "dart_server",
)
_SAFE_PLUGIN_MOUNT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class SandboxStorageError(RuntimeError):
    """Raised when sandbox runtime directories are unwritable, corrupt, or hit disk faults."""


class SandboxLockTimeoutError(SandboxStorageError):
    """Raised when acquiring the sandbox runtime state lock exceeds the configured timeout."""


def _paths_overlap_strict(path_a: str, path_b: str) -> bool:
    a = path_a.rstrip("/") or "/"
    b = path_b.rstrip("/") or "/"
    if a == "/" or b == "/":
        return True
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def prepare_sandbox_runtime_state(
    sandbox_state_dir: str,
    lock_timeout_seconds: float = 5.0,
    subdirs: Sequence[str] = SANDBOX_SUBDIRS,
    forbidden_roots: Sequence[str] = (),
) -> Path:
    """Create, lock, and actively probe `sandbox_state_dir` before spawning a session.

    Fails closed (`SandboxLockTimeoutError` / `SandboxStorageError`) on lock contention
    timeouts, read-only filesystems (`EROFS`), out-of-space (`ENOSPC`/`EDQUOT`), permission
    denials (`EACCES`), I/O faults (`EIO`), symlink swaps, or overlap with `HOME` root /
    plugin directories, never silently falling back to `HOME` or plugin paths.
    """
    raw = str(sandbox_state_dir or "").strip()
    if not raw:
        raise SandboxStorageError(
            "sandbox_state_dir is empty; refusing to fall back to HOME or plugin directories"
        )
    expanded = os.path.expanduser(raw)
    if not expanded.startswith("/"):
        raise SandboxStorageError(
            f"sandbox_state_dir must be an absolute path (got '{redact_diagnostic_text(raw)}')"
        )
    lex_abs = os.path.abspath(expanded)
    home_lex = os.path.abspath(str(Path.home()))
    try:
        home_res = str(Path.home().resolve())
    except OSError:
        home_res = home_lex

    if lex_abs in ("/", "/home", home_lex, home_res):
        raise SandboxStorageError(
            f"sandbox_state_dir '{redact_diagnostic_text(lex_abs)}' cannot equal system or HOME root"
        )

    norm_forbidden: List[str] = []
    for raw_forb in forbidden_roots:
        if not raw_forb:
            continue
        try:
            f_exp = os.path.expanduser(str(raw_forb))
            norm_forbidden.append(os.path.abspath(f_exp))
            if os.path.exists(f_exp):
                norm_forbidden.append(os.path.realpath(f_exp))
        except OSError:
            continue

    for forb in norm_forbidden:
        if _paths_overlap_strict(lex_abs, forb):
            raise SandboxStorageError(
                f"sandbox_state_dir '{redact_diagnostic_text(lex_abs)}' overlaps protected/plugin directory "
                f"'{redact_diagnostic_text(forb)}'"
            )

    if os.path.islink(lex_abs):
        raise SandboxStorageError(
            f"sandbox_state_dir '{redact_diagnostic_text(lex_abs)}' must not be a symlink"
        )

    newly_created_root = not os.path.lexists(lex_abs)
    try:
        Path(lex_abs).mkdir(mode=0o700, parents=True, exist_ok=True)
        if newly_created_root:
            os.chmod(lex_abs, 0o700)
        st_root = os.lstat(lex_abs)
    except OSError as exc:
        err_code = errno.errorcode.get(exc.errno or 0, "OS_ERROR")
        raise SandboxStorageError(
            f"Failed to prepare sandbox_state_dir '{redact_diagnostic_text(lex_abs)}' ({err_code}): "
            f"{redact_diagnostic_text(str(exc))}"
        ) from exc

    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        raise SandboxStorageError(
            f"sandbox_state_dir '{redact_diagnostic_text(lex_abs)}' is not a real directory"
        )
    if st_root.st_mode & 0o002:
        raise SandboxStorageError(
            f"sandbox_state_dir '{redact_diagnostic_text(lex_abs)}' must not be world-writable"
        )

    real_root = os.path.realpath(lex_abs)
    if real_root in ("/", "/home", home_lex, home_res):
        raise SandboxStorageError(
            f"sandbox_state_dir '{redact_diagnostic_text(real_root)}' resolves to system or HOME root"
        )
    for forb in norm_forbidden:
        if _paths_overlap_strict(real_root, forb):
            raise SandboxStorageError(
                f"sandbox_state_dir '{redact_diagnostic_text(real_root)}' resolves inside protected/plugin "
                f"directory '{redact_diagnostic_text(forb)}'"
            )

    sandbox_state = Path(real_root)
    lock_path = sandbox_state / ".sandbox-init.lock"
    open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(str(lock_path), open_flags, 0o600)
    except OSError as exc:
        err_code = errno.errorcode.get(exc.errno or 0, "OS_ERROR")
        raise SandboxStorageError(
            f"Cannot open sandbox lock file '{redact_diagnostic_text(str(lock_path))}' ({err_code}): "
            f"{redact_diagnostic_text(str(exc))}"
        ) from exc

    timeout_s = max(0.05, float(lock_timeout_seconds))
    deadline = time.monotonic() + timeout_s
    locked = False
    try:
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise SandboxLockTimeoutError(
                        f"Timed out after {timeout_s:.2f}s waiting for sandbox state lock "
                        f"'{redact_diagnostic_text(str(lock_path))}'"
                    ) from exc
                time.sleep(min(0.025, max(0.005, deadline - time.monotonic())))
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EACCES):
                    if time.monotonic() >= deadline:
                        raise SandboxLockTimeoutError(
                            f"Timed out after {timeout_s:.2f}s waiting for sandbox state lock "
                            f"'{redact_diagnostic_text(str(lock_path))}'"
                        ) from exc
                    time.sleep(min(0.025, max(0.005, deadline - time.monotonic())))
                    continue
                err_code = errno.errorcode.get(exc.errno or 0, "OS_ERROR")
                raise SandboxStorageError(
                    f"Failed acquiring sandbox state lock '{redact_diagnostic_text(str(lock_path))}' "
                    f"({err_code}): {redact_diagnostic_text(str(exc))}"
                ) from exc

        try:
            for sub in subdirs:
                sub_p = sandbox_state / sub
                if os.path.islink(sub_p):
                    raise SandboxStorageError(
                        f"Sandbox subdirectory '{redact_diagnostic_text(str(sub_p))}' must not be a symlink"
                    )
                sub_new = not os.path.lexists(sub_p)
                sub_p.mkdir(mode=0o700, parents=True, exist_ok=True)
                if sub_new:
                    os.chmod(sub_p, 0o1777 if sub == "tmp" else 0o700)
                sub_st = os.lstat(sub_p)
                if stat.S_ISLNK(sub_st.st_mode) or not stat.S_ISDIR(sub_st.st_mode):
                    raise SandboxStorageError(
                        f"Sandbox subdirectory '{redact_diagnostic_text(str(sub_p))}' is not a directory"
                    )
            tmp_dir = sandbox_state / "tmp"

            probe_file = tmp_dir / f".gw_write_probe_{os.getpid()}_{uuid.uuid4().hex[:12]}"
            probe_fd = os.open(
                str(probe_file),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                written = os.write(probe_fd, b"ok\n")
                if written != 3:
                    raise OSError(errno.ENOSPC, "Short write during sandbox disk health probe")
            finally:
                try:
                    os.close(probe_fd)
                finally:
                    try:
                        os.unlink(probe_file)
                    except OSError:
                        pass
        except SandboxStorageError:
            raise
        except OSError as exc:
            err_code = errno.errorcode.get(exc.errno or 0, "OS_ERROR")
            raise SandboxStorageError(
                f"Sandbox runtime directory '{redact_diagnostic_text(str(sandbox_state))}' is not writable "
                f"or encountered a disk fault ({err_code}): {redact_diagnostic_text(str(exc))}"
            ) from exc
    finally:
        if locked:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(lock_fd)
        except OSError:
            pass

    return sandbox_state


def _find_sys_bin(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for prefix in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        cand = os.path.join(prefix, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


@lru_cache(maxsize=1)
def can_use_mount_namespace() -> bool:
    """Return True if unprivileged Linux user+mount namespaces + pivot_root + setpriv work."""
    if os.name != "posix":
        return False
    unshare_bin = _find_sys_bin("unshare")
    pivot_bin = _find_sys_bin("pivot_root")
    mount_bin = _find_sys_bin("mount")
    umount_bin = _find_sys_bin("umount")
    setpriv_bin = _find_sys_bin("setpriv")
    if not all((unshare_bin, pivot_bin, mount_bin, umount_bin, setpriv_bin)) or not os.path.exists(
        "/bin/bash"
    ):
        return False
    try:
        res = subprocess.run(
            [
                str(unshare_bin),
                "--user",
                "--map-current-user",
                "--keep-caps",
                "--mount",
                "true",
            ],
            capture_output=True,
            timeout=3.0,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def _is_covered_by_roots(target: str, roots: Sequence[str]) -> bool:
    for r in roots:
        if target == r or target.startswith(r.rstrip("/") + "/"):
            return True
    return False


def _select_stage_mountpoint(source_paths: Sequence[str]) -> str:
    """Pick an existing top-level directory for staging newroot before `pivot_root`
    that does not shadow any host path needed during mount construction.
    """
    normalized = [p.rstrip("/") or "/" for p in source_paths if p]
    for cand in ("/media", "/srv", "/boot", "/mnt"):
        if os.path.islink(cand) or not os.path.isdir(cand):
            continue
        conflict = any(src == cand or src.startswith(cand + "/") for src in normalized)
        if not conflict:
            return cand
    return "/dev/shm"


def _docker_socket_mask_lines(
    stage_dir: str,
    q_mount: str,
    mask_paths: Sequence[str],
    proxy_socket: Optional[str],
) -> List[str]:
    """Shell lines masking host container-runtime sockets (optionally swapping in the proxy)."""
    lines: List[str] = []
    seen: set[str] = set()
    proxy_src: Optional[str] = None
    if proxy_socket:
        try:
            cand = str(Path(proxy_socket).expanduser().resolve())
            if stat.S_ISSOCK(os.stat(cand).st_mode):
                proxy_src = cand
        except OSError:
            proxy_src = None
    proxy_used = False
    for raw in mask_paths:
        try:
            host_path = os.path.realpath(str(raw))
        except OSError:
            continue
        if not host_path.startswith("/") or host_path in seen:
            continue
        seen.add(host_path)
        q_dst = shlex.quote(f"{stage_dir}{host_path}")
        src = "/dev/null"
        if proxy_src and not proxy_used and os.path.basename(host_path) == "docker.sock":
            src = proxy_src
            proxy_used = True
        lines.append(
            f"if [ -e {q_dst} ] && [ ! -d {q_dst} ]; then {q_mount} --bind {shlex.quote(src)} {q_dst}; fi"
        )
    return lines


def _validate_plugin_mounts_for_vfs(
    agy_plugin_mounts: Optional[Sequence[Tuple[str, str]]],
) -> List[Tuple[str, str]]:
    if not agy_plugin_mounts:
        raise SandboxStorageError(
            "AGY plugins are enabled, but no validated plugin mounts were provided to VFS sandbox"
        )
    validated: List[Tuple[str, str]] = []
    seen_names: set[str] = set()
    for raw_name, raw_src in agy_plugin_mounts:
        name = str(raw_name or "").strip()
        src = str(raw_src or "").strip()
        if not _SAFE_PLUGIN_MOUNT_NAME_RE.match(name):
            raise SandboxStorageError(
                f"Invalid AGY plugin mount name '{redact_diagnostic_text(name)}'"
            )
        if name in seen_names:
            raise SandboxStorageError(
                f"Duplicate AGY plugin mount name '{redact_diagnostic_text(name)}'"
            )
        if not src.startswith("/") or os.path.islink(src):
            raise SandboxStorageError(
                f"AGY plugin source '{redact_diagnostic_text(src)}' must be a non-symlink absolute directory"
            )
        real_src = os.path.realpath(src)
        if real_src != os.path.abspath(src) or not os.path.isdir(real_src):
            raise SandboxStorageError(
                f"AGY plugin source '{redact_diagnostic_text(src)}' does not exist or contains symlink components"
            )
        seen_names.add(name)
        validated.append((name, real_src))
    return validated


def _ensure_safe_gemini_plugin_mountpoint(home_dir: str, home_covered: bool) -> None:
    """Verify `$HOME`, `~/.gemini`, `~/.gemini/config`, and `plugins` do not traverse unsafe symlinks."""
    home_lex = os.path.abspath(str(Path.home()))
    if os.path.islink(home_lex) or home_lex != home_dir:
        raise SandboxStorageError(
            f"AGY plugins require a non-symlink HOME directory (got '{redact_diagnostic_text(home_lex)}' -> '{redact_diagnostic_text(home_dir)}')"
        )
    gem_lex = os.path.join(home_dir, ".gemini")
    if home_covered and os.path.islink(gem_lex):
        raise SandboxStorageError(
            "AGY plugins forbid symlinked '~/.gemini' when $HOME is covered by allowed_workdirs"
        )
    if not os.path.exists(gem_lex):
        if os.path.islink(gem_lex):
            raise SandboxStorageError("Dangling symlink at '~/.gemini' is forbidden")
        Path(gem_lex).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(gem_lex, 0o700)
        except OSError:
            pass
    gem_real = Path(os.path.realpath(gem_lex))
    if not gem_real.is_dir():
        raise SandboxStorageError("'~/.gemini' must be a directory")
    for sub_parts, label in (
        (("config",), "~/.gemini/config"),
        (("config", "plugins"), "~/.gemini/config/plugins"),
    ):
        cur = gem_real.joinpath(*sub_parts)
        if os.path.islink(str(cur)):
            raise SandboxStorageError(
                f"Symlink at '{label}' is forbidden when AGY plugins are enabled"
            )
        if not cur.exists():
            cur.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(cur, 0o700)
            except OSError:
                pass
        elif not cur.is_dir():
            raise SandboxStorageError(f"'{label}' must be a directory")


def _agy_registered_plugin_mount_lines(
    stage_dir: str,
    home_dir: str,
    q_mount: str,
    plugin_mounts: Sequence[Tuple[str, str]],
) -> List[str]:
    """Build fail-closed shell lines mounting registered AGY plugins read-only in VFS."""
    gem_vfs = os.path.join(home_dir, ".gemini")
    gem_cfg_vfs = os.path.join(gem_vfs, "config")
    plugins_vfs_root = os.path.join(gem_cfg_vfs, "plugins")
    q_gem_vfs = shlex.quote(f"{stage_dir}{gem_vfs}")
    q_gem_cfg_vfs = shlex.quote(f"{stage_dir}{gem_cfg_vfs}")
    q_plg_root = shlex.quote(f"{stage_dir}{plugins_vfs_root}")
    out: List[str] = [
        f"[ ! -L {q_gem_vfs} ] && [ ! -L {q_gem_cfg_vfs} ] && [ ! -L {q_plg_root} ]",
        f"mkdir -p {q_plg_root}",
        f"[ ! -L {q_gem_vfs} ] && [ ! -L {q_gem_cfg_vfs} ] && [ ! -L {q_plg_root} ]",
        f"{q_mount} -t tmpfs -o size=4m,mode=0755,nosuid,nodev tmpfs {q_plg_root}",
    ]
    for plg_name, plg_src in plugin_mounts:
        q_src = shlex.quote(plg_src)
        q_dst_canon = shlex.quote(f"{stage_dir}{plg_src}")
        q_dst_disc = shlex.quote(f"{stage_dir}{os.path.join(plugins_vfs_root, plg_name)}")
        out.extend(
            [
                f"[ ! -L {q_src} ] && [ -d {q_src} ]",
                f"[ ! -L {q_dst_canon} ]",
                f"[ -d {q_dst_canon} ] || mkdir -p {q_dst_canon}",
                f"[ ! -L {q_dst_canon} ] && [ -d {q_dst_canon} ]",
                f"{q_mount} --bind {q_src} {q_dst_canon}",
                f"{q_mount} -o remount,bind,ro,nosuid,nodev {q_dst_canon} 2>/dev/null || {q_mount} -o remount,bind,ro {q_dst_canon} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_canon}",
                f"mkdir -p {q_dst_disc}",
                f"{q_mount} --bind {q_src} {q_dst_disc}",
                f"{q_mount} -o remount,bind,ro,nosuid,nodev {q_dst_disc} 2>/dev/null || {q_mount} -o remount,bind,ro {q_dst_disc} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_disc}",
            ]
        )
    out.append(
        f"{q_mount} -o remount,ro,nosuid,nodev {q_plg_root} 2>/dev/null || {q_mount} -o remount,ro {q_plg_root} 2>/dev/null || {q_mount} -o bind,remount,ro {q_plg_root}"
    )
    return out


def build_mount_ns_argv(
    target_argv: Sequence[str],
    cwd: str,
    allowed_workdirs: Sequence[str],
    protected_paths: Sequence[str],
    is_agy: bool = False,
    is_codex: bool = False,
    readonly_subpaths: Optional[Sequence[str]] = None,
    sandbox_state_dir: Optional[str] = None,
    docker_mask_paths: Optional[Sequence[str]] = None,
    docker_proxy_socket: Optional[str] = None,
    mount_gcloud_adc: bool = True,
    agy_plugins_enabled: bool = False,
    agy_plugin_mounts: Optional[Sequence[Tuple[str, str]]] = None,
    masked_plugin_paths: Optional[Sequence[str]] = None,
    sandbox_lock_timeout_seconds: float = 5.0,
    prevalidated_sandbox_state: Optional[Path] = None,
) -> List[str]:
    """Wrap `target_argv` in an unprivileged user+mount namespace `pivot_root` jail.

    Container-runtime sockets listed in `docker_mask_paths` are always masked (bind `/dev/null`)
    because the caller's supplementary `docker` group would otherwise grant root-equivalent daemon
    access. When `docker_proxy_socket` is given, it is bind-mounted over the first existing
    `docker.sock` mask path so `docker`/`docker compose` reach only the gateway filtering proxy.
    """
    if not can_use_mount_namespace():
        raise RuntimeError(
            "Linux mount-namespace isolation is enabled (isolate_mount_namespace=True), "
            "but unprivileged user/mount namespaces are unavailable on this host."
        )

    validated_plugin_mounts: List[Tuple[str, str]] = []
    if is_agy and agy_plugins_enabled:
        validated_plugin_mounts = _validate_plugin_mounts_for_vfs(agy_plugin_mounts)
    active_plugin_srcs = {src for _, src in validated_plugin_mounts}

    unshare_bin = _find_sys_bin("unshare") or "/usr/bin/unshare"
    pivot_bin = _find_sys_bin("pivot_root") or "/usr/sbin/pivot_root"
    mount_bin = _find_sys_bin("mount") or "/usr/bin/mount"
    umount_bin = _find_sys_bin("umount") or "/usr/bin/umount"
    setpriv_bin = _find_sys_bin("setpriv") or "/usr/bin/setpriv"

    allowed_roots: List[str] = []
    for raw_dir in allowed_workdirs:
        p = Path(raw_dir).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        allowed_roots.append(str(p.resolve()))

    resolved_cwd = str(Path(cwd).expanduser().resolve())
    if not os.path.isdir(resolved_cwd):
        raise FileNotFoundError(f"Working directory does not exist: {resolved_cwd}")

    home_dir = str(Path.home().resolve())
    home_covered = _is_covered_by_roots(home_dir, allowed_roots)

    raw_sb_target = (
        str(sandbox_state_dir).strip()
        if sandbox_state_dir
        else str(Path(home_dir) / ".cache" / "dots-sandbox")
    )
    forbidden_sb_roots = [
        *list(protected_paths or ()),
        os.path.join(home_dir, ".gemini"),
        os.path.join(home_dir, ".config"),
        *(src for _, src in validated_plugin_mounts),
        *list(masked_plugin_paths or ()),
    ]
    gh_cfg_dir = Path(home_dir) / ".config" / "gh"
    if not home_covered:
        if prevalidated_sandbox_state is not None:
            sandbox_state = prevalidated_sandbox_state
        else:
            sandbox_state = prepare_sandbox_runtime_state(
                raw_sb_target,
                lock_timeout_seconds=sandbox_lock_timeout_seconds,
                subdirs=SANDBOX_SUBDIRS,
                forbidden_roots=forbidden_sb_roots,
            )
        gh_cfg_dir.mkdir(parents=True, exist_ok=True)
        if is_agy:
            (Path(home_dir) / ".config" / "antigravity").mkdir(parents=True, exist_ok=True)
            if agy_plugins_enabled:
                _ensure_safe_gemini_plugin_mountpoint(home_dir, home_covered=False)
        if is_codex:
            codex_dir_p = Path(home_dir) / ".codex"
            codex_dir_p.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(codex_dir_p, 0o700)
            except OSError:
                pass
    else:
        sandbox_state = Path(os.path.realpath(os.path.expanduser(raw_sb_target)))
        if is_agy and agy_plugins_enabled:
            _ensure_safe_gemini_plugin_mountpoint(home_dir, home_covered=True)

    stage_sources: List[str] = [
        *allowed_roots,
        str(sandbox_state),
        home_dir,
        *(src for _, src in validated_plugin_mounts),
    ]
    for dot_rel in (
        os.path.join(".local", "bin"),
        os.path.join(".config", "gh"),
        ".gemini",
        os.path.join(".config", "antigravity"),
        os.path.join(".config", "gcloud"),
        ".codex",
    ):
        dot_cand = os.path.join(home_dir, dot_rel)
        if os.path.exists(dot_cand):
            try:
                stage_sources.append(os.path.realpath(dot_cand))
            except OSError:
                pass

    stage_dir = _select_stage_mountpoint(stage_sources)
    q_stage = shlex.quote(stage_dir)
    q_mount = shlex.quote(mount_bin)
    q_umount = shlex.quote(umount_bin)
    q_pivot = shlex.quote(pivot_bin)
    q_setpriv = shlex.quote(setpriv_bin)

    lines: List[str] = [
        "set -euo pipefail",
        f"{q_mount} -t tmpfs -o size=64m,mode=0755 tmpfs {q_stage}",
    ]
    if stage_dir == "/dev/shm":
        lines.extend(
            [
                f"mkdir -p {shlex.quote(f'{stage_dir}/dev')}",
                f"{q_mount} --rbind /dev {shlex.quote(f'{stage_dir}/dev')}",
                f"{q_mount} -t tmpfs -o size=64m,mode=1777 tmpfs {shlex.quote(f'{stage_dir}/dev/shm')}",
                "for d in usr bin sbin lib lib64 etc var opt proc sys run; do",
            ]
        )
    else:
        lines.append("for d in usr bin sbin lib lib64 etc var opt proc dev sys run; do")

    lines.extend(
        [
            '  if [ -L "/$d" ]; then',
            f'    ln -s "$(readlink "/$d")" "{stage_dir}/$d"',
            '  elif [ -d "/$d" ]; then',
            f'    mkdir -p "{stage_dir}/$d"',
            f'    {q_mount} --rbind "/$d" "{stage_dir}/$d"',
            "  fi",
            "done",
            # Lock /opt and any submounts under /opt read-only by default while keeping Flutter's bin/cache writable
            f'if [ -d "/opt" ] && [ -d "{stage_dir}/opt" ]; then',
            f'  {q_mount} -o remount,bind,ro "{stage_dir}/opt" 2>/dev/null || {q_mount} -o bind,remount,ro "{stage_dir}/opt"',
            f'  while read -r _src _mp _rest; do case "$_mp" in {stage_dir}/opt/*) [ -d "$_mp" ] && ({q_mount} -o remount,bind,ro "$_mp" 2>/dev/null || {q_mount} -o bind,remount,ro "$_mp" || true) ;; esac; done < /proc/self/mounts',
            "fi",
            "for ro_opt in /opt/codex /opt/devtools /opt/uv-python /opt/uv-tools /opt/flutter; do",
            f'  if [ -d "$ro_opt" ] && [ -d "{stage_dir}$ro_opt" ]; then',
            f'    {q_mount} --bind "$ro_opt" "{stage_dir}$ro_opt"',
            f'    {q_mount} -o remount,bind,ro "{stage_dir}$ro_opt" 2>/dev/null || {q_mount} -o bind,remount,ro "{stage_dir}$ro_opt"',
            "  fi",
            "done",
            f'if [ -d "/opt/flutter/bin/cache" ] && [ -d "{stage_dir}/opt/flutter/bin/cache" ]; then',
            f'  {q_mount} --rbind "/opt/flutter/bin/cache" "{stage_dir}/opt/flutter/bin/cache"',
            "fi",
            # Mask host per-user runtime sockets (/run/user/$UID/systemd, /run/user/$UID/gnupg)
            # while preserving /run/systemd/resolve DNS and a private XDG_RUNTIME_DIR
            f'if [ -d "{stage_dir}/run/user" ]; then',
            f'  {q_mount} -t tmpfs -o size=8m,mode=0755 tmpfs {shlex.quote(f"{stage_dir}/run/user")}',
            f'  mkdir -p "{stage_dir}/run/user/$(id -u)" && chmod 0700 "{stage_dir}/run/user/$(id -u)"',
            "fi",
            *_docker_socket_mask_lines(
                stage_dir, q_mount, docker_mask_paths or (), docker_proxy_socket
            ),
            f"mkdir -p {shlex.quote(f'{stage_dir}/tmp')} {shlex.quote(f'{stage_dir}/mnt')} {shlex.quote(f'{stage_dir}/media')} {shlex.quote(f'{stage_dir}/home')}",
            f"chmod 1777 {shlex.quote(f'{stage_dir}/tmp')}",
        ]
    )

    # Mask configured AGY plugin directories under system trees (/opt, /usr, /var, /etc) whenever
    # they are NOT actively mounted for an AGY session (`exec_command`, `run_codex`, disabled/staged plugins).
    if masked_plugin_paths:
        seen_masked: set[str] = set()
        for raw_mp in masked_plugin_paths:
            try:
                mp_exp = os.path.expanduser(str(raw_mp).strip())
                cands = [os.path.abspath(mp_exp)]
                if os.path.exists(mp_exp):
                    cands.append(os.path.realpath(mp_exp))
            except OSError:
                continue
            for mp_cand in cands:
                if (
                    mp_cand in seen_masked
                    or mp_cand in active_plugin_srcs
                    or mp_cand in ("/", "/opt", "/usr", "/var", "/etc")
                    or not mp_cand.startswith(("/opt/", "/usr/", "/var/", "/etc/"))
                ):
                    continue
                seen_masked.add(mp_cand)
                q_dst_mp = shlex.quote(f"{stage_dir}{mp_cand}")
                lines.append(
                    f"if [ -d {q_dst_mp} ]; then {q_mount} -t tmpfs -o size=4k,mode=0555,ro tmpfs {q_dst_mp}; fi"
                )

    # Back /tmp by persistent isolated disk dir when allowed_roots are outside /tmp
    # (prevents 64m tmpfs ENOSPC on large pip/npm/cargo builds while hiding host /tmp)
    if not home_covered and not any(w == "/tmp" or w.startswith("/tmp/") for w in allowed_roots):
        q_sb_tmp = shlex.quote(str(sandbox_state / "tmp"))
        q_dst_tmp = shlex.quote(f"{stage_dir}/tmp")
        lines.append(f"{q_mount} --rbind {q_sb_tmp} {q_dst_tmp}")
        lines.append(f"chmod 1777 {q_dst_tmp} 2>/dev/null || true")

    # Bind-mount each explicitly allowed workspace directory read-write
    for wdir in allowed_roots:
        q_wdir = shlex.quote(wdir)
        q_dst = shlex.quote(f"{stage_dir}{wdir}")
        lines.append(f"mkdir -p {q_dst}")
        lines.append(f"{q_mount} --rbind {q_wdir} {q_dst}")

    # Lock sensitive subpaths inside allowed workspaces (e.g. `.git/hooks` for Codex) read-only
    for raw_ro_sub in readonly_subpaths or ():
        try:
            ro_lex = os.path.abspath(os.path.expanduser(str(raw_ro_sub)))
            if os.path.islink(ro_lex) or not os.path.isdir(ro_lex):
                continue
            ro_res = str(Path(ro_lex).resolve())
        except OSError:
            continue
        if ro_res != ro_lex or not _is_covered_by_roots(ro_res, allowed_roots):
            continue
        q_ro_src = shlex.quote(ro_res)
        q_ro_dst = shlex.quote(f"{stage_dir}{ro_res}")
        lines.extend(
            [
                f"if [ ! -L {q_ro_src} ] && [ -d {q_ro_src} ] && [ -d {q_ro_dst} ]; then",
                f"  {q_mount} --bind {q_ro_src} {q_ro_dst}",
                f"  {q_mount} -o remount,bind,ro {q_ro_dst} 2>/dev/null || {q_mount} -o bind,remount,ro {q_ro_dst}",
                "fi",
            ]
        )

    if not home_covered:
        q_stage_home = shlex.quote(f"{stage_dir}{home_dir}")
        lines.append(f"mkdir -p {q_stage_home}")

        # Persistent isolated caches so pip/uv/npm/flutter/dart/go don't lose state or hit tmpfs limits
        for src_sub, dst_rel in (
            ("cache", ".cache"),
            ("npm", ".npm"),
            ("local_share", os.path.join(".local", "share")),
            ("pub_cache", ".pub-cache"),
            ("flutter_cfg", os.path.join(".config", "flutter")),
            ("dart_tool", ".dart-tool"),
            ("dart_server", ".dartServer"),
            ("docker_cfg", ".docker"),
        ):
            q_src = shlex.quote(str(sandbox_state / src_sub))
            q_dst = shlex.quote(f"{stage_dir}{os.path.join(home_dir, dst_rel)}")
            lines.extend(
                [
                    f"mkdir -p {q_dst}",
                    f"{q_mount} --rbind {q_src} {q_dst}",
                ]
            )

        # Read-only ~/.local/bin so user-installed developer CLIs & agy can execute safely
        local_bin = os.path.join(home_dir, ".local", "bin")
        if os.path.isdir(local_bin):
            q_lb = shlex.quote(os.path.realpath(local_bin))
            q_dst_lb = shlex.quote(f"{stage_dir}{local_bin}")
            lines.extend(
                [
                    f"mkdir -p {q_dst_lb}",
                    f"{q_mount} --bind {q_lb} {q_dst_lb}",
                    f"{q_mount} -o remount,bind,ro {q_dst_lb} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_lb}",
                ]
            )

        # Read-only ~/.gitconfig so `git` credential helper & author settings work inside workspaces
        gitconfig = os.path.join(home_dir, ".gitconfig")
        if os.path.isfile(gitconfig):
            q_gc = shlex.quote(os.path.realpath(gitconfig))
            q_dst_gc = shlex.quote(f"{stage_dir}{gitconfig}")
            lines.extend(
                [
                    f"touch {q_dst_gc}",
                    f"{q_mount} --bind {q_gc} {q_dst_gc}",
                    f"{q_mount} -o remount,bind,ro {q_dst_gc} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_gc}",
                ]
            )

        # Persistent ~/.config/gh so `gh` CLI and `gh auth git-credential` work & persist across commands
        # while ~/.config/dots-gateway, ~/.config/tunnel-client, and ~/.config/systemd remain invisible
        q_gh = shlex.quote(os.path.realpath(str(gh_cfg_dir)))
        q_dst_gh = shlex.quote(f"{stage_dir}{gh_cfg_dir}")
        lines.extend(
            [
                f"mkdir -p {q_dst_gh}",
                f"{q_mount} --rbind {q_gh} {q_dst_gh}",
            ]
        )

        if is_agy:
            # Antigravity CLI requires ~/.gemini (for OAuth & trajectory store) and ~/.config/antigravity.
            # When explicit plugin registration (`agy_plugins_enabled`) is OFF, preserve legacy read-only
            # remount of `~/.gemini/config/plugins`. When ON, mount an isolated read-only tmpfs view
            # populated strictly with operator-registered `agy_plugin_mounts` plus canonical read-only mounts.
            gemini_dir = os.path.join(home_dir, ".gemini")
            if os.path.isdir(gemini_dir):
                q_gem = shlex.quote(os.path.realpath(gemini_dir))
                q_dst_gem = shlex.quote(f"{stage_dir}{gemini_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_gem}",
                        f"{q_mount} --rbind {q_gem} {q_dst_gem}",
                    ]
                )
                if not agy_plugins_enabled:
                    plugins_dir = os.path.join(gemini_dir, "config", "plugins")
                    if os.path.isdir(plugins_dir):
                        q_plg = shlex.quote(os.path.realpath(plugins_dir))
                        q_dst_plg = shlex.quote(f"{stage_dir}{plugins_dir}")
                        lines.extend(
                            [
                                f"{q_mount} --bind {q_plg} {q_dst_plg}",
                                f"{q_mount} -o remount,bind,ro {q_dst_plg} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_plg}",
                            ]
                        )

            if agy_plugins_enabled:
                lines.extend(
                    _agy_registered_plugin_mount_lines(
                        stage_dir, home_dir, q_mount, validated_plugin_mounts
                    )
                )

            agy_cfg_dir = os.path.join(home_dir, ".config", "antigravity")
            if os.path.isdir(agy_cfg_dir):
                q_ac = shlex.quote(os.path.realpath(agy_cfg_dir))
                q_dst_ac = shlex.quote(f"{stage_dir}{agy_cfg_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_ac}",
                        f"{q_mount} --rbind {q_ac} {q_dst_ac}",
                    ]
                )

            # Read-only ~/.config/gcloud only when `AGY_ADC_AUTH=true` needs application_default_credentials.json
            gcloud_cfg_dir = os.path.join(home_dir, ".config", "gcloud")
            if mount_gcloud_adc and os.path.isdir(gcloud_cfg_dir):
                q_gc_dir = shlex.quote(os.path.realpath(gcloud_cfg_dir))
                q_dst_gc_dir = shlex.quote(f"{stage_dir}{gcloud_cfg_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_gc_dir}",
                        f"{q_mount} --bind {q_gc_dir} {q_dst_gc_dir}",
                        f"{q_mount} -o remount,bind,ro {q_dst_gc_dir} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_gc_dir}",
                    ]
                )

        if is_codex:
            # OpenAI Codex CLI requires ~/.codex (for auth.json, config.toml, session history &
            # codex-linux-sandbox helper) while ~/gateway, ~/.gemini, ~/.ssh, and ~/.config/* stay hidden.
            codex_dir = os.path.join(home_dir, ".codex")
            if os.path.isdir(codex_dir):
                q_cx = shlex.quote(os.path.realpath(codex_dir))
                q_dst_cx = shlex.quote(f"{stage_dir}{codex_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_cx}",
                        f"{q_mount} --rbind {q_cx} {q_dst_cx}",
                    ]
                )
    else:
        # Even if an admin explicitly put $HOME in allowed_workdirs, mask protected_paths inside VFS
        for raw_prot in protected_paths:
            try:
                prot = str(Path(raw_prot).expanduser().resolve())
            except Exception:
                continue
            if is_agy and (
                prot == os.path.join(home_dir, ".local")
                or prot == os.path.join(home_dir, ".gemini")
                or prot == os.path.join(home_dir, ".config")
            ):
                continue
            if is_codex and prot == os.path.join(home_dir, ".codex"):
                continue
            dst_prot = f"{stage_dir}{prot}"
            if os.path.isdir(prot):
                q_dp = shlex.quote(dst_prot)
                lines.append(
                    f'[ -d {q_dp} ] && {q_mount} -t tmpfs -o size=4k,mode=0555,ro tmpfs {q_dp} || true'
                )
            elif os.path.isfile(prot):
                q_dp = shlex.quote(dst_prot)
                lines.append(
                    f'[ -f {q_dp} ] && {q_mount} --bind /dev/null {q_dp} || true'
                )
        for raw_mp in masked_plugin_paths or ():
            try:
                mp_res = str(Path(raw_mp).expanduser().resolve())
            except Exception:
                continue
            if (
                mp_res in active_plugin_srcs
                or mp_res in ("/", home_dir)
                or not os.path.isdir(mp_res)
            ):
                continue
            q_mp_dst = shlex.quote(f"{stage_dir}{mp_res}")
            lines.append(
                f'[ -d {q_mp_dst} ] && {q_mount} -t tmpfs -o size=4k,mode=0555,ro tmpfs {q_mp_dst} || true'
            )
        if is_agy and agy_plugins_enabled:
            lines.extend(
                _agy_registered_plugin_mount_lines(
                    stage_dir, home_dir, q_mount, validated_plugin_mounts
                )
            )

    q_cwd = shlex.quote(resolved_cwd)
    lines.extend(
        [
            f"mkdir -p {shlex.quote(f'{stage_dir}/.oldroot')}",
            f"cd {q_stage}",
            f"{q_pivot} . .oldroot",
            f"{q_umount} -l /.oldroot",
            "rmdir /.oldroot",
            f"cd {q_cwd}",
        ]
    )

    if is_agy or is_codex:
        # Clear effective/permitted/ambient caps (CapEff=0 -> cannot unmount), while keeping
        # unprivileged nested userns capability available for `agy --sandbox` / `codex-linux-sandbox`.
        lines.append(f'exec {q_setpriv} --inh-caps=-all --ambient-caps=-all -- "$@"')
    else:
        # Drop all capabilities AND empty the capability bounding set for raw exec commands.
        lines.append(
            f'exec {q_setpriv} --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- "$@"'
        )

    bootstrap_script = "\n".join(lines)
    return [
        unshare_bin,
        "--user",
        "--map-current-user",
        "--keep-caps",
        "--mount",
        "/bin/bash",
        "-c",
        bootstrap_script,
        "--",
        *[str(a) for a in target_argv],
    ]


@dataclass
class _SandboxCandidate:
    path: Path
    category: str
    last_active_at: float
    size_bytes: int
    companion_paths: Tuple[Path, ...] = ()


def _unescape_mountinfo(token: str) -> str:
    return (
        token.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _discover_protected_mount_dirs(sandbox_root: Path) -> set[str]:
    """Return canonical directory paths inside/at `sandbox_root` that must never be `rmdir`'d."""
    protected: set[str] = {os.path.abspath(str(sandbox_root))}
    for sub in SANDBOX_SUBDIRS:
        protected.add(os.path.abspath(str(sandbox_root / sub)))

    mountinfo_p = Path("/proc/self/mountinfo")
    try:
        if mountinfo_p.is_file():
            raw_lines = mountinfo_p.read_text(encoding="utf-8", errors="replace").splitlines()
            dev_root_mounts: Dict[str, str] = {}
            sub_entries: List[Tuple[str, str, str]] = []
            for ln in raw_lines:
                parts = ln.split()
                if len(parts) < 5:
                    continue
                dev_id = parts[2]
                m_root = _unescape_mountinfo(parts[3])
                m_point = _unescape_mountinfo(parts[4])
                protected.add(os.path.abspath(m_point))
                if m_root == "/" and dev_id not in dev_root_mounts:
                    dev_root_mounts[dev_id] = m_point
                elif m_root != "/":
                    sub_entries.append((dev_id, m_root, m_point))
            for dev_id, m_root, _ in sub_entries:
                base_mp = dev_root_mounts.get(dev_id)
                if base_mp:
                    src_cand = os.path.normpath(base_mp.rstrip("/") + "/" + m_root.lstrip("/"))
                    protected.add(os.path.abspath(src_cand))
    except OSError:
        pass
    return protected


def _default_disk_usage(target_dir: Path) -> Tuple[int, int]:
    """Return `(total_bytes, unprivileged_avail_bytes)` for the filesystem backing `target_dir`."""
    probe = target_dir
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    st = os.statvfs(probe)
    total_b = int(st.f_frsize) * int(st.f_blocks)
    avail_b = int(st.f_frsize) * int(st.f_bavail)
    return total_b, avail_b


def get_sandbox_disk_status(
    sandbox_dir: str | Path,
    low_space_free_gb: float = 8.0,
    low_space_free_percent: float = 15.0,
    disk_usage_fn: Optional[Callable[[Path], Tuple[int, int]]] = None,
) -> Dict[str, Any]:
    """Inspect current disk space and low-space watermark status for `sandbox_dir`."""
    raw_p = Path(sandbox_dir).expanduser()
    try:
        resolved_p = raw_p.resolve()
    except OSError:
        resolved_p = raw_p
    usage_getter = disk_usage_fn or _default_disk_usage
    try:
        total_b, avail_b = usage_getter(resolved_p)
    except OSError:
        total_b, avail_b = 0, 0

    req_by_gb = int(max(0.0, float(low_space_free_gb)) * (1024 ** 3))
    req_by_pct = int(total_b * (max(0.0, float(low_space_free_percent)) / 100.0))
    required_free = max(req_by_gb, req_by_pct)
    free_pct = round((avail_b / total_b) * 100.0, 2) if total_b > 0 else 100.0
    return {
        "sandbox_state_dir": str(resolved_p),
        "exists": resolved_p.is_dir(),
        "total_bytes": total_b,
        "avail_bytes": avail_b,
        "free_gb": round(avail_b / (1024 ** 3), 2),
        "free_percent": free_pct,
        "required_free_bytes": required_free,
        "low_space": bool(total_b > 0 and avail_b < required_free),
    }


def _scan_entry_activity(
    path: Path, cancel_event: Optional[threading.Event] = None
) -> Tuple[float, int]:
    """Compute `(last_active_at, total_size_bytes)` without following symlinks."""
    st = os.lstat(path)
    latest = max(float(st.st_mtime), float(st.st_atime))
    if stat.S_ISLNK(st.st_mode):
        return latest, 0
    if not stat.S_ISDIR(st.st_mode):
        return latest, int(st.st_size) if stat.S_ISREG(st.st_mode) else 0

    total_bytes = 0
    dirs_scanned = 0
    stack: List[str] = [str(path)]
    while stack:
        if cancel_event is not None and cancel_event.is_set():
            break
        cur_dir = stack.pop()
        dirs_scanned += 1
        if dirs_scanned % 1024 == 0:
            time.sleep(0)
        try:
            with os.scandir(cur_dir) as it:
                for entry in it:
                    try:
                        est = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    ts = max(float(est.st_mtime), float(est.st_atime))
                    if ts > latest:
                        latest = ts
                    mode = est.st_mode
                    if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
                        stack.append(entry.path)
                    elif stat.S_ISREG(mode):
                        total_bytes += int(est.st_size)
        except OSError:
            continue
    return latest, total_bytes


def _remove_path_safe(target: Path, protected_mounts: set[str]) -> bool:
    """Delete a file, symlink, or directory tree without crossing symlinks or mountpoints."""
    abs_t = os.path.abspath(str(target))
    if abs_t in protected_mounts or os.path.ismount(abs_t):
        return False
    try:
        lst = os.lstat(target)
    except FileNotFoundError:
        return True
    except OSError:
        return False

    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
        try:
            os.unlink(target)
            return True
        except OSError:
            return False

    # Post-order non-symlink directory removal that skips nested mountpoints safely
    ok_all = True
    try:
        with os.scandir(target) as it:
            children = [Path(e.path) for e in it]
    except OSError:
        return False

    for ch in children:
        if not _remove_path_safe(ch, protected_mounts):
            ok_all = False

    if ok_all:
        try:
            os.rmdir(target)
            return True
        except OSError:
            return False
    return False


def _collect_sandbox_candidates(
    sandbox_root: Path,
    protected_mounts: set[str],
    cancel_event: Optional[threading.Event] = None,
) -> List[_SandboxCandidate]:
    """Enumerate coherent, cache-integrity-safe candidate entries inside `sandbox_root`."""
    candidates: List[_SandboxCandidate] = []

    def _add_candidate(
        entry_p: Path, category: str, companions: Tuple[Path, ...] = ()
    ) -> None:
        if cancel_event is not None and cancel_event.is_set():
            return
        abs_e = os.path.abspath(str(entry_p))
        if abs_e in protected_mounts or os.path.ismount(abs_e):
            if entry_p.is_dir() and not entry_p.is_symlink():
                try:
                    with os.scandir(entry_p) as sub_it:
                        for sub_e in sub_it:
                            _add_candidate(Path(sub_e.path), category)
                except OSError:
                    pass
            return
        try:
            last_active, size_b = _scan_entry_activity(entry_p, cancel_event=cancel_event)
        except OSError:
            return
        if cancel_event is not None and cancel_event.is_set():
            return
        for comp in companions:
            try:
                if os.path.lexists(comp):
                    c_ts, c_sz = _scan_entry_activity(comp, cancel_event=cancel_event)
                    if c_ts > last_active:
                        last_active = c_ts
                    size_b += c_sz
            except OSError:
                pass
        candidates.append(
            _SandboxCandidate(
                path=entry_p,
                category=category,
                last_active_at=last_active,
                size_bytes=size_b,
                companion_paths=companions,
            )
        )

    for sub in SANDBOX_MANAGED_SUBDIRS:
        if cancel_event is not None and cancel_event.is_set():
            break
        sub_dir = sandbox_root / sub
        if sub_dir.is_symlink() or not sub_dir.is_dir():
            continue

        if sub == "pub_cache":
            try:
                with os.scandir(sub_dir) as pub_it:
                    pub_children = [Path(e.path) for e in pub_it]
            except OSError:
                continue
            for pch in pub_children:
                name = pch.name
                if name in ("README.md", "hosted-hashes"):
                    continue
                if name == "_temp" and pch.is_dir() and not pch.is_symlink():
                    try:
                        with os.scandir(pch) as tmp_it:
                            for te in tmp_it:
                                _add_candidate(Path(te.path), "pub_cache")
                    except OSError:
                        pass
                elif name == "hosted" and pch.is_dir() and not pch.is_symlink():
                    try:
                        with os.scandir(pch) as reg_it:
                            reg_dirs = [
                                Path(re_e.path)
                                for re_e in reg_it
                                if re_e.is_dir(follow_symlinks=False)
                            ]
                    except OSError:
                        reg_dirs = []
                    for reg_dir in reg_dirs:
                        hashes_reg = sub_dir / "hosted-hashes" / reg_dir.name
                        try:
                            with os.scandir(reg_dir) as pkg_it:
                                for pkg_e in pkg_it:
                                    pkg_p = Path(pkg_e.path)
                                    hash_f = hashes_reg / f"{pkg_p.name}.sha256"
                                    _add_candidate(
                                        pkg_p, "pub_cache", companions=(hash_f,)
                                    )
                        except OSError:
                            continue
                else:
                    _add_candidate(pch, "pub_cache")
            continue

        try:
            with os.scandir(sub_dir) as it:
                for entry in it:
                    _add_candidate(Path(entry.path), sub)
        except OSError:
            continue

    return candidates


def cleanup_sandbox_state(
    sandbox_dir: str | Path,
    max_retention_days: float = 30.0,
    min_retention_days: float = 7.0,
    low_space_free_gb: float = 8.0,
    low_space_free_percent: float = 15.0,
    now: Optional[float] = None,
    disk_usage_fn: Optional[Callable[[Path], Tuple[int, int]]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    """Enforce two-tier LRU (`last_active_at`) lifecycle policy on `sandbox_dir`.

    1. Entries inactive longer than `max_retention_days` (default: 30d) are always evicted.
    2. If free disk space is still below `max(low_space_free_gb, low_space_free_percent)`,
       oldest inactive entries (`> min_retention_days`) are evicted in ascending
       `last_active_at` order until free space recovers, keeping the newest entries.
    3. Entries active within `min_retention_days` (default: 7d) are NEVER deleted.
    """
    eff_now = time.time() if now is None else float(now)
    eff_min_days = max(0.0, float(min_retention_days))
    eff_max_days = max(eff_min_days, float(max_retention_days))
    max_cutoff = eff_now - eff_max_days * 86400.0
    min_cutoff = eff_now - eff_min_days * 86400.0

    raw_root = Path(sandbox_dir).expanduser()
    try:
        sandbox_root = raw_root.resolve()
    except OSError:
        sandbox_root = raw_root

    usage_getter = disk_usage_fn or _default_disk_usage
    if not sandbox_root.is_dir():
        status = get_sandbox_disk_status(
            sandbox_root,
            low_space_free_gb=low_space_free_gb,
            low_space_free_percent=low_space_free_percent,
            disk_usage_fn=usage_getter,
        )
        return {
            **status,
            "checked_entries": 0,
            "deleted_expired_count": 0,
            "deleted_low_space_count": 0,
            "reclaimed_bytes": 0,
            "retained_entries": 0,
            "protected_recent_entries": 0,
            "low_space_before": status["low_space"],
            "low_space_after": status["low_space"],
            "last_run_at": round(eff_now, 3),
        }

    protected_mounts = _discover_protected_mount_dirs(sandbox_root)
    candidates = _collect_sandbox_candidates(
        sandbox_root, protected_mounts, cancel_event=cancel_event
    )
    if cancel_event is not None and cancel_event.is_set():
        aborted_status = get_sandbox_disk_status(
            sandbox_root,
            low_space_free_gb=low_space_free_gb,
            low_space_free_percent=low_space_free_percent,
            disk_usage_fn=usage_getter,
        )
        return {
            **aborted_status,
            "checked_entries": len(candidates),
            "deleted_expired_count": 0,
            "deleted_low_space_count": 0,
            "reclaimed_bytes": 0,
            "retained_entries": len(candidates),
            "protected_recent_entries": 0,
            "low_space_before": aborted_status["low_space"],
            "low_space_after": aborted_status["low_space"],
            "cancelled": True,
            "last_run_at": round(eff_now, 3),
        }
    # Sort strictly by last active timestamp ascending (oldest inactive first, newest active last)
    candidates.sort(key=lambda c: (c.last_active_at, str(c.path)))

    deleted_expired = 0
    deleted_low_space = 0
    reclaimed_bytes = 0
    remaining: List[_SandboxCandidate] = []

    def _evict(cand: _SandboxCandidate) -> bool:
        removed = _remove_path_safe(cand.path, protected_mounts)
        for comp in cand.companion_paths:
            if os.path.lexists(comp):
                _remove_path_safe(comp, protected_mounts)
        return removed

    # Phase 1: Always evict entries inactive longer than max_retention_days (30d)
    for cand in candidates:
        if cancel_event is not None and cancel_event.is_set():
            remaining.append(cand)
            continue
        if cand.last_active_at < max_cutoff:
            if _evict(cand):
                deleted_expired += 1
                reclaimed_bytes += cand.size_bytes
            else:
                remaining.append(cand)
        else:
            remaining.append(cand)

    # Phase 2: Check disk space; if tight, evict oldest entries (> min_retention_days = 7d)
    pre_status = get_sandbox_disk_status(
        sandbox_root,
        low_space_free_gb=low_space_free_gb,
        low_space_free_percent=low_space_free_percent,
        disk_usage_fn=usage_getter,
    )
    low_space_before = pre_status["low_space"]
    still_kept: List[_SandboxCandidate] = []

    if low_space_before and not (cancel_event is not None and cancel_event.is_set()):
        need_more_space = True
        for cand in remaining:
            if (
                not need_more_space
                or cand.last_active_at >= min_cutoff
                or (cancel_event is not None and cancel_event.is_set())
            ):
                still_kept.append(cand)
                continue
            if _evict(cand):
                deleted_low_space += 1
                reclaimed_bytes += cand.size_bytes
                cur_status = get_sandbox_disk_status(
                    sandbox_root,
                    low_space_free_gb=low_space_free_gb,
                    low_space_free_percent=low_space_free_percent,
                    disk_usage_fn=usage_getter,
                )
                if not cur_status["low_space"]:
                    need_more_space = False
            else:
                still_kept.append(cand)
    else:
        still_kept = remaining

    post_status = get_sandbox_disk_status(
        sandbox_root,
        low_space_free_gb=low_space_free_gb,
        low_space_free_percent=low_space_free_percent,
        disk_usage_fn=usage_getter,
    )
    protected_recent = sum(1 for c in still_kept if c.last_active_at >= min_cutoff)
    return {
        **post_status,
        "checked_entries": len(candidates),
        "deleted_expired_count": deleted_expired,
        "deleted_low_space_count": deleted_low_space,
        "reclaimed_bytes": reclaimed_bytes,
        "retained_entries": len(still_kept),
        "protected_recent_entries": protected_recent,
        "low_space_before": low_space_before,
        "low_space_after": post_status["low_space"],
        "last_run_at": round(eff_now, 3),
    }
