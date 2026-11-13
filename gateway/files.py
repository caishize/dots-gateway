"""Workspace-confined file read/write/patch/list/stat/delete operations for `dots`."""

from __future__ import annotations

import base64
import hashlib
import os
import stat as stat_mod
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .policy import CommandPolicy

MAX_FILE_READ_BYTES = 32 * 1024 * 1024  # 32 MiB per read call


class FileService:
    """Provides safe, symlink-checked file operations within `allowed_workdirs`."""

    def __init__(self, policy: CommandPolicy) -> None:
        self.policy = policy

    def _resolve_safe_path(self, path_str: str, cwd: Optional[str] = None) -> Path:
        if not path_str or not str(path_str).strip():
            raise ValueError("Missing required 'path'")
        ok, err, resolved = self.policy.validate_path(str(path_str), base_cwd=cwd)
        if not ok:
            raise PermissionError(err)
        return Path(resolved)

    def stat(self, path_str: str, cwd: Optional[str] = None) -> Dict[str, Any]:
        target = self._resolve_safe_path(path_str, cwd=cwd)
        raw_p = Path(str(path_str)).expanduser()
        if not raw_p.is_absolute():
            anchor = Path(cwd or self.policy.config.default_workdir).expanduser().resolve()
            raw_p = anchor / raw_p
        lex_p = Path(os.path.abspath(str(raw_p)))

        try:
            st = target.stat()
        except OSError:
            if lex_p.is_symlink():
                try:
                    lst = lex_p.lstat()
                    return {
                        "exists": False,
                        "broken_symlink": True,
                        "path": str(lex_p),
                        "resolved_path": str(target),
                        "type": "symlink",
                        "size": lst.st_size,
                        "mode": oct(lst.st_mode & 0o777),
                        "mtime": lst.st_mtime,
                    }
                except OSError:
                    pass
            return {"exists": False, "path": str(target)}

        kind = "dir" if stat_mod.S_ISDIR(st.st_mode) else "file"
        info: Dict[str, Any] = {
            "exists": True,
            "path": str(target),
            "type": kind,
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o777),
            "mtime": st.st_mtime,
        }
        if kind == "file" and st.st_size <= MAX_FILE_READ_BYTES:
            h = hashlib.sha256()
            with target.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            info["sha256"] = h.hexdigest()
        return info

    def list_dir(
        self,
        path_str: str,
        cwd: Optional[str] = None,
        recursive: bool = False,
        max_entries: int = 1000,
    ) -> Dict[str, Any]:
        target = self._resolve_safe_path(path_str, cwd=cwd)
        if not target.exists():
            raise FileNotFoundError(f"Directory not found: {target}")
        if not target.is_dir():
            raise NotADirectoryError(f"Not a directory: {target}")

        max_entries = max(1, min(int(max_entries), 10000))
        entries: List[Dict[str, Any]] = []
        truncated = False

        def _is_hidden_entry(p: Path) -> bool:
            lex = os.path.abspath(str(p))
            if self.policy.is_protected_path(lex) or self.policy.is_agy_plugin_path(lex):
                return True
            try:
                res = str(p.resolve())
            except OSError:
                return True
            return self.policy.is_protected_path(res) or self.policy.is_agy_plugin_path(res)

        if recursive:
            for root, dirs, files in os.walk(target):
                dirs.sort()
                files.sort()
                # Skip protected and AGY-only plugin directories
                dirs[:] = [
                    d
                    for d in dirs
                    if not _is_hidden_entry(Path(root) / d)
                ]
                for name in dirs + files:
                    full = Path(root) / name
                    rel = str(full.relative_to(target))
                    if _is_hidden_entry(full):
                        continue
                    try:
                        st = full.lstat()
                        entries.append(
                            {
                                "name": rel,
                                "type": "dir" if stat_mod.S_ISDIR(st.st_mode) else "file",
                                "size": st.st_size,
                                "mtime": st.st_mtime,
                            }
                        )
                    except OSError:
                        continue
                    if len(entries) >= max_entries:
                        truncated = True
                        break
                if truncated:
                    break
        else:
            for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name)):
                if _is_hidden_entry(child):
                    continue
                try:
                    st = child.lstat()
                    entries.append(
                        {
                            "name": child.name,
                            "type": "dir" if stat_mod.S_ISDIR(st.st_mode) else "file",
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                        }
                    )
                except OSError:
                    continue
                if len(entries) >= max_entries:
                    truncated = True
                    break

        return {
            "path": str(target),
            "entries": entries,
            "truncated": truncated,
        }

    def read(
        self,
        path_str: str,
        cwd: Optional[str] = None,
        encoding: str = "utf-8",
        offset: int = 0,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        target = self._resolve_safe_path(path_str, cwd=cwd)
        if not target.exists():
            raise FileNotFoundError(f"File not found: {target}")
        if not target.is_file():
            raise IsADirectoryError(f"Not a regular file: {target}")

        total_size = target.stat().st_size
        offset = max(0, int(offset))
        read_len = MAX_FILE_READ_BYTES if limit is None else min(int(limit), MAX_FILE_READ_BYTES)

        with target.open("rb") as f:
            if offset > 0:
                f.seek(offset)
            raw = f.read(read_len)

        enc = encoding.lower().strip()
        if enc == "base64":
            content = base64.b64encode(raw).decode("ascii")
        else:
            content = raw.decode(enc, errors="replace")

        return {
            "path": str(target),
            "encoding": enc,
            "size": total_size,
            "offset": offset,
            "bytes_read": len(raw),
            "eof": (offset + len(raw)) >= total_size,
            "content": content,
        }

    def write(
        self,
        path_str: str,
        content: str,
        cwd: Optional[str] = None,
        encoding: str = "utf-8",
        append: bool = False,
        mkdir_parents: bool = True,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        target = self._resolve_safe_path(path_str, cwd=cwd)
        parent = target.parent
        # Re-verify parent after resolving any symlinks
        ok_parent, err_parent, _ = self.policy.validate_path(str(parent))
        if not ok_parent:
            raise PermissionError(err_parent)

        if mkdir_parents:
            parent.mkdir(parents=True, exist_ok=True)

        enc = encoding.lower().strip()
        if enc == "base64":
            raw = base64.b64decode(content)
        else:
            raw = content.encode(enc)

        existing_mode: Optional[int] = None
        if target.exists():
            existing_mode = target.stat().st_mode & 0o777

        if append:
            with target.open("ab") as f:
                f.write(raw)
        else:
            tmp_path = parent / f".dots_tmp_{uuid.uuid4().hex[:10]}_{target.name}"
            try:
                with tmp_path.open("wb") as f:
                    f.write(raw)
                if mode is not None:
                    os.chmod(tmp_path, int(str(mode), 8))
                elif existing_mode is not None:
                    os.chmod(tmp_path, existing_mode)
                os.replace(tmp_path, target)
            finally:
                tmp_path.unlink(missing_ok=True)

        if mode is not None and append:
            os.chmod(target, int(str(mode), 8))

        st = target.stat()
        return {
            "path": str(target),
            "bytes_written": len(raw),
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o777),
        }

    def patch(
        self,
        path_str: str,
        edits: List[Dict[str, str]],
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        target = self._resolve_safe_path(path_str, cwd=cwd)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(f"File not found: {target}")
        if not edits or not isinstance(edits, list):
            raise ValueError("Provide a non-empty list of 'edits' [{'target': ..., 'replacement': ...}]")

        text = target.read_text(encoding="utf-8")
        applied = 0
        for idx, edit in enumerate(edits):
            old = edit.get("target")
            new = edit.get("replacement", "")
            replace_all = bool(edit.get("replace_all", False))
            if not old:
                raise ValueError(f"Edit #{idx} is missing non-empty 'target'")
            if old not in text:
                raise ValueError(f"Edit #{idx} target snippet not found in {target}")
            count = text.count(old)
            if count > 1 and not replace_all:
                raise ValueError(
                    f"Edit #{idx} target snippet matched {count} times in {target}; "
                    "provide more surrounding context or set replace_all=true"
                )
            if replace_all:
                text = text.replace(old, new)
                applied += count
            else:
                text = text.replace(old, new, 1)
                applied += 1

        res = self.write(str(target), text, encoding="utf-8", append=False)
        res["replacements_applied"] = applied
        return res

    def delete(
        self,
        path_str: str,
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        target = self._resolve_safe_path(path_str, cwd=cwd)
        # Never allow deleting workspace roots themselves
        for root in self.policy._allowed_roots:
            if str(target) == root:
                raise PermissionError(f"Refusing to delete workspace root '{target}'")

        if not target.exists() and not target.is_symlink():
            return {"deleted": False, "path": str(target), "reason": "not_found"}

        if target.is_dir() and not target.is_symlink():
            target.rmdir()  # Only removes empty directories for safety
        else:
            target.unlink()
        return {"deleted": True, "path": str(target)}
