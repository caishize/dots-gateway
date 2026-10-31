"""Zero-dependency Linux User + Mount Namespace (`unshare` + `pivot_root` + `setpriv`) jail.

Isolates `exec_command` and `run_agy` child processes at the kernel VFS layer so that
directories outside `allowed_workdirs` (such as `~/gateway`, `~/.ssh`, `~/.gnupg`,
`~/.config/dots-gateway`, `~/.config/systemd`, `~/.config/gh`, `~/oh-my-agents`, and
host `/tmp`) do not exist inside the child process's filesystem tree.
"""

from __future__ import annotations

from functools import lru_cache
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence


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


def build_mount_ns_argv(
    target_argv: Sequence[str],
    cwd: str,
    allowed_workdirs: Sequence[str],
    protected_paths: Sequence[str],
    is_agy: bool = False,
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

    if is_agy and not home_covered:
        (Path(home_dir) / ".config" / "antigravity").mkdir(parents=True, exist_ok=True)

    q_mount = shlex.quote(mount_bin)
    q_umount = shlex.quote(umount_bin)
    q_pivot = shlex.quote(pivot_bin)
    q_setpriv = shlex.quote(setpriv_bin)

    lines: List[str] = [
        "set -euo pipefail",
        f"{q_mount} -t tmpfs -o size=64m,mode=0755 tmpfs /mnt",
        "for d in usr bin sbin lib lib64 etc var opt proc dev sys run; do",
        '  if [ -L "/$d" ]; then',
        '    ln -s "$(readlink "/$d")" "/mnt/$d"',
        '  elif [ -d "/$d" ]; then',
        '    mkdir -p "/mnt/$d"',
        f'    {q_mount} --rbind "/$d" "/mnt/$d"',
        "  fi",
        "done",
        "mkdir -p /mnt/tmp /mnt/mnt /mnt/home",
        "chmod 1777 /mnt/tmp",
    ]

    # Bind-mount each explicitly allowed workspace directory read-write
    for wdir in allowed_roots:
        q_wdir = shlex.quote(wdir)
        q_dst = shlex.quote(f"/mnt{wdir}")
        lines.append(f"mkdir -p {q_dst}")
        lines.append(f"{q_mount} --rbind {q_wdir} {q_dst}")

    if not home_covered:
        q_mnt_home = shlex.quote(f"/mnt{home_dir}")
        lines.append(f"mkdir -p {q_mnt_home}")

        # Read-only ~/.local/bin so user-installed developer CLIs & agy can execute safely
        local_bin = os.path.join(home_dir, ".local", "bin")
        if os.path.isdir(local_bin):
            q_lb = shlex.quote(local_bin)
            q_dst_lb = shlex.quote(f"/mnt{local_bin}")
            lines.extend(
                [
                    f"mkdir -p {q_dst_lb}",
                    f"{q_mount} --bind {q_lb} {q_dst_lb}",
                    f"{q_mount} -o remount,bind,ro {q_dst_lb} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_lb}",
                ]
            )

        # Read-only ~/.gitconfig so `git commit` inside workspaces preserves author metadata
        gitconfig = os.path.join(home_dir, ".gitconfig")
        if os.path.isfile(gitconfig):
            q_gc = shlex.quote(gitconfig)
            q_dst_gc = shlex.quote(f"/mnt{gitconfig}")
            lines.extend(
                [
                    f"touch {q_dst_gc}",
                    f"{q_mount} --bind {q_gc} {q_dst_gc}",
                    f"{q_mount} -o remount,bind,ro {q_dst_gc} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_gc}",
                ]
            )

        if is_agy:
            # Antigravity CLI requires ~/.gemini (for OAuth & trajectory store) and ~/.config/antigravity,
            # while ~/.gemini/config/plugins is remounted READ-ONLY so oh-my-agents hooks cannot be tampered with.
            gemini_dir = os.path.join(home_dir, ".gemini")
            if os.path.isdir(gemini_dir):
                q_gem = shlex.quote(gemini_dir)
                q_dst_gem = shlex.quote(f"/mnt{gemini_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_gem}",
                        f"{q_mount} --rbind {q_gem} {q_dst_gem}",
                    ]
                )
                plugins_dir = os.path.join(gemini_dir, "config", "plugins")
                if os.path.isdir(plugins_dir):
                    q_plg = shlex.quote(plugins_dir)
                    q_dst_plg = shlex.quote(f"/mnt{plugins_dir}")
                    lines.extend(
                        [
                            f"{q_mount} --bind {q_plg} {q_dst_plg}",
                            f"{q_mount} -o remount,bind,ro {q_dst_plg} 2>/dev/null || {q_mount} -o bind,remount,ro {q_dst_plg}",
                        ]
                    )

            agy_cfg_dir = os.path.join(home_dir, ".config", "antigravity")
            if os.path.isdir(agy_cfg_dir):
                q_ac = shlex.quote(agy_cfg_dir)
                q_dst_ac = shlex.quote(f"/mnt{agy_cfg_dir}")
                lines.extend(
                    [
                        f"mkdir -p {q_dst_ac}",
                        f"{q_mount} --rbind {q_ac} {q_dst_ac}",
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
            dst_prot = f"/mnt{prot}"
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
            "mkdir -p /mnt/.oldroot",
            "cd /mnt",
            f"{q_pivot} . .oldroot",
            f"{q_umount} -l /.oldroot",
            "rmdir /.oldroot",
            f"cd {q_cwd}",
        ]
    )

    if is_agy:
        # Clear effective/permitted/ambient caps (CapEff=0 -> cannot unmount), while keeping
        # unprivileged nested userns capability available for `agy --sandbox`.
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
