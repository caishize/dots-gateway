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
from functools import lru_cache
import os
import shlex
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

SANDBOX_SUBDIRS: Tuple[str, ...] = (
    "tmp",
    "cache",
    "npm",
    "local_share",
    "pub_cache",
    "flutter_cfg",
    "dart_tool",
    "dart_server",
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


def build_mount_ns_argv(
    target_argv: Sequence[str],
    cwd: str,
    allowed_workdirs: Sequence[str],
    protected_paths: Sequence[str],
    is_agy: bool = False,
    is_codex: bool = False,
    readonly_subpaths: Optional[Sequence[str]] = None,
    sandbox_state_dir: Optional[str] = None,
) -> List[str]:
    """Wrap `target_argv` in an unprivileged user+mount namespace `pivot_root` jail."""
    if not can_use_mount_namespace():
        raise RuntimeError(
            "Linux mount-namespace isolation is enabled (isolate_mount_namespace=True), "
            "but unprivileged user/mount namespaces are unavailable on this host."
        )

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

    sandbox_state = (
        Path(sandbox_state_dir).expanduser().resolve()
        if sandbox_state_dir
        else (Path(home_dir) / ".cache" / "dots-sandbox")
    )
    gh_cfg_dir = Path(home_dir) / ".config" / "gh"
    if not home_covered:
        for sub in SANDBOX_SUBDIRS:
            (sandbox_state / sub).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(sandbox_state, 0o700)
            os.chmod(sandbox_state / "tmp", 0o1777)
        except OSError:
            pass
        gh_cfg_dir.mkdir(parents=True, exist_ok=True)
        if is_agy:
            (Path(home_dir) / ".config" / "antigravity").mkdir(parents=True, exist_ok=True)
        if is_codex:
            codex_dir_p = Path(home_dir) / ".codex"
            codex_dir_p.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(codex_dir_p, 0o700)
            except OSError:
                pass

    stage_dir = _select_stage_mountpoint([*allowed_roots, str(sandbox_state), home_dir])
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
            # Protect /opt SDK installations as read-only while keeping Flutter's bin/cache writable
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
            # while preserving /run/systemd/resolve DNS and a clean private XDG_RUNTIME_DIR
            f'if [ -d "{stage_dir}/run/user" ]; then',
            f'  {q_mount} -t tmpfs -o size=8m,mode=0755 tmpfs {shlex.quote(f"{stage_dir}/run/user")}',
            f'  mkdir -p "{stage_dir}/run/user/$(id -u)" && chmod 0700 "{stage_dir}/run/user/$(id -u)"',
            "fi",
            f"mkdir -p {shlex.quote(f'{stage_dir}/tmp')} {shlex.quote(f'{stage_dir}/mnt')} {shlex.quote(f'{stage_dir}/media')} {shlex.quote(f'{stage_dir}/home')}",
            f"chmod 1777 {shlex.quote(f'{stage_dir}/tmp')}",
        ]
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
            q_lb = shlex.quote(local_bin)
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
            q_gc = shlex.quote(gitconfig)
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
        q_gh = shlex.quote(str(gh_cfg_dir))
        q_dst_gh = shlex.quote(f"{stage_dir}{gh_cfg_dir}")
        lines.extend(
            [
                f"mkdir -p {q_dst_gh}",
                f"{q_mount} --rbind {q_gh} {q_dst_gh}",
            ]
        )

        if is_agy:
            # Antigravity CLI requires ~/.gemini (for OAuth & trajectory store) and ~/.config/antigravity,
            # while ~/.gemini/config/plugins is remounted READ-ONLY so oh-my-agents hooks cannot be tampered with.
            gemini_dir = os.path.join(home_dir, ".gemini")
            if os.path.isdir(gemini_dir):
                q_gem = shlex.quote(gemini_dir)
                q_dst_gem = shlex.quote(f"{stage_dir}{gemini_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_gem}",
                        f"{q_mount} --rbind {q_gem} {q_dst_gem}",
                    ]
                )
                plugins_dir = os.path.join(gemini_dir, "config", "plugins")
                if os.path.isdir(plugins_dir):
                    q_plg = shlex.quote(plugins_dir)
                    q_dst_plg = shlex.quote(f"{stage_dir}{plugins_dir}")
                    lines.extend(
                        [
                            f"{q_mount} --bind {q_plg} {q_dst_plg}",
                            f"{q_mount} -o remount,bind,ro {q_dst_plg} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_plg}",
                        ]
                    )

            agy_cfg_dir = os.path.join(home_dir, ".config", "antigravity")
            if os.path.isdir(agy_cfg_dir):
                q_ac = shlex.quote(agy_cfg_dir)
                q_dst_ac = shlex.quote(f"{stage_dir}{agy_cfg_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_ac}",
                        f"{q_mount} --rbind {q_ac} {q_dst_ac}",
                    ]
                )

        if is_codex:
            # OpenAI Codex CLI requires ~/.codex (for auth.json, config.toml, session history &
            # codex-linux-sandbox helper) while ~/gateway, ~/.gemini, ~/.ssh, and ~/.config/* stay hidden.
            codex_dir = os.path.join(home_dir, ".codex")
            if os.path.isdir(codex_dir):
                q_cx = shlex.quote(codex_dir)
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


def _scan_entry_activity(path: Path) -> Tuple[float, int]:
    """Compute `(last_active_at, total_size_bytes)` without following symlinks."""
    st = os.lstat(path)
    latest = max(float(st.st_mtime), float(st.st_atime))
    if stat.S_ISLNK(st.st_mode):
        return latest, 0
    if not stat.S_ISDIR(st.st_mode):
        return latest, int(st.st_size) if stat.S_ISREG(st.st_mode) else 0

    total_bytes = 0
    stack: List[str] = [str(path)]
    while stack:
        cur_dir = stack.pop()
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
    sandbox_root: Path, protected_mounts: set[str]
) -> List[_SandboxCandidate]:
    """Enumerate coherent, cache-integrity-safe candidate entries inside `sandbox_root`."""
    candidates: List[_SandboxCandidate] = []

    def _add_candidate(
        entry_p: Path, category: str, companions: Tuple[Path, ...] = ()
    ) -> None:
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
            last_active, size_b = _scan_entry_activity(entry_p)
        except OSError:
            return
        for comp in companions:
            try:
                if os.path.lexists(comp):
                    c_ts, c_sz = _scan_entry_activity(comp)
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
    candidates = _collect_sandbox_candidates(sandbox_root, protected_mounts)
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

    if low_space_before:
        need_more_space = True
        for cand in remaining:
            if not need_more_space or cand.last_active_at >= min_cutoff:
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
