"""Asynchronous process & bidirectional session manager for the Dots Gateway."""

from __future__ import annotations

import asyncio
import fcntl
import json
import math
import os
import pty
import shlex
import signal
import struct
import termios
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Deque,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from .config import (
    GATEWAY_ROOT,
    GatewayConfig,
    agy_plugins_config_state,
    codex_plugins_config_state,
    docker_access_enabled,
    docker_access_state,
    effective_plugin_state_dir,
    redact_diagnostic_text,
)
from .hook_jail import (
    PreparedAgentPluginRuntime,
    cleanup_prepared_plugin_runtime,
    prepare_agy_plugin_runtime,
    prepare_codex_plugin_runtime,
)
from .policy import CommandPolicy
from .sandbox import (
    build_mount_ns_argv,
    cleanup_sandbox_state,
    get_sandbox_disk_status,
    prepare_sandbox_runtime_state,
)

STREAM_LINE_LIMIT = 16 * 1024 * 1024  # 16 MiB asyncio StreamReader buffer limit
_PERSISTED_TAIL_CHARS = 65536  # Max stdout/stderr characters retained in on-disk session ledger
_PERSIST_THROTTLE_SECONDS = 2.0
_SESSION_ID_SAFE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def _read_boot_id() -> str:
    """Return the Linux kernel boot UUID (`/proc/sys/kernel/random/boot_id`), or empty string."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _read_proc_start_ticks(pid: int) -> Optional[int]:
    """Return kernel `starttime` ticks (field 22 of `/proc/<pid>/stat`) for live non-zombie `pid`."""
    if not pid or pid <= 0:
        return None
    try:
        raw = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    rparen = raw.rfind(")")
    if rparen < 0:
        return None
    fields = raw[rparen + 2 :].split()
    if len(fields) < 20:
        return None
    #Zombie ('Z') or Dead ('X'/'x') processes have already terminated execution
    if fields[0] in ("Z", "X", "x"):
        return None
    try:
        return int(fields[19])
    except ValueError:
        return None


def is_process_instance_alive(
    pid: Optional[int],
    boot_id: Optional[str],
    proc_start_ticks: Optional[int],
) -> bool:
    """Verify whether the exact process `(boot_id, pid, proc_start_ticks)` is still alive (PID-reuse safe)."""
    if not pid or pid <= 0 or proc_start_ticks is None:
        return False
    cur_boot = _read_boot_id()
    if boot_id and cur_boot and cur_boot != boot_id:
        return False
    cur_ticks = _read_proc_start_ticks(pid)
    return cur_ticks is not None and cur_ticks == proc_start_ticks


def _extract_initial_agent_id(
    argv: Sequence[str], is_agy: bool, is_codex: bool
) -> Optional[str]:
    """Extract resumed conversation/session ID from `agy` or `codex` CLI arguments when present."""
    if is_agy:
        for i, tok in enumerate(argv):
            if tok in ("--conversation", "--resume") and i + 1 < len(argv):
                cand = argv[i + 1].strip()
                if cand and not cand.startswith("-"):
                    return cand
            elif tok.startswith(("--conversation=", "--resume=")):
                cand = tok.split("=", 1)[1].strip()
                if cand:
                    return cand
    if is_codex:
        for i, tok in enumerate(argv):
            if tok == "resume" and i + 1 < len(argv):
                for sub in argv[i + 1 :]:
                    if sub == "--":
                        break
                    if sub.startswith("-") or sub == "-":
                        continue
                    return sub.strip() or None
    return None


def _extract_stream_agent_id(text: str) -> Optional[str]:
    """Extract `thread_id` / `conversation_id` from JSONL agent stdout lines when available."""
    for raw_line in text.splitlines():
        s = raw_line.strip()
        if not s.startswith("{") or not s.endswith("}"):
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        for key in ("thread_id", "conversation_id", "conversationId"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        if obj.get("type") == "session_meta" and isinstance(obj.get("payload"), dict):
            pid_val = obj["payload"].get("id")
            if isinstance(pid_val, str) and pid_val.strip():
                return pid_val.strip()
    return None


def _discover_codex_rollout_id(cwd: str, started_at: float) -> Optional[str]:
    """Best-effort lookup of unambiguous Codex rollout UUID matching `(cwd, started_at)`."""
    sessions_root = Path.home() / ".codex" / "sessions"
    if not sessions_root.is_dir():
        return None
    try:
        resolved_cwd = str(Path(cwd).resolve())
    except OSError:
        resolved_cwd = cwd

    candidates: List[Tuple[float, Path]] = []
    try:
        year_dirs = sorted(
            (p for p in sessions_root.iterdir() if p.is_dir()), reverse=True
        )[:2]
        for y_dir in year_dirs:
            month_dirs = sorted((p for p in y_dir.iterdir() if p.is_dir()), reverse=True)[:2]
            for m_dir in month_dirs:
                day_dirs = sorted(
                    (p for p in m_dir.iterdir() if p.is_dir()), reverse=True
                )[:3]
                for d_dir in day_dirs:
                    for f in d_dir.glob("rollout-*.jsonl"):
                        try:
                            st = f.stat()
                        except OSError:
                            continue
                        if st.st_mtime >= started_at - 5.0:
                            candidates.append((st.st_mtime, f))
    except OSError:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    matched_ids: List[str] = []
    for _, fpath in candidates[:25]:
        try:
            with fpath.open("r", encoding="utf-8", errors="replace") as fh:
                first_line = fh.readline(16384).strip()
            if not first_line:
                continue
            meta = json.loads(first_line)
            if not isinstance(meta, dict) or meta.get("type") != "session_meta":
                continue
            payload = meta.get("payload")
            if not isinstance(payload, dict):
                continue
            p_cwd = str(payload.get("cwd") or "")
            if p_cwd != resolved_cwd and p_cwd != cwd:
                continue
            ts_raw = str(payload.get("timestamp") or meta.get("timestamp") or "")
            if not ts_raw:
                continue
            dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if abs(dt.timestamp() - started_at) <= 45.0:
                rid = str(payload.get("id") or "").strip()
                if rid and rid not in matched_ids:
                    matched_ids.append(rid)
        except Exception:
            continue

    return matched_ids[0] if len(matched_ids) == 1 else None
_STRIPPED_ENV_KEYS = {
    "GATEWAY_TOKEN",
    "GATEWAY_PASSWORD",
    "GATEWAY_HMAC_SECRET",
    "GATEWAY_TLS_KEY",
    "OPENAI_API_" + "KEY",
    "CODEX_API_" + "KEY",
    "CODEX_ACCESS_TOKEN",
    "AGY_ADC_AUTH",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    # Never let host cloud credentials or VM metadata overrides leak into sandboxed sessions
    "GOOGLE_APPLICATION_CREDENTIALS",
    "CLOUDSDK_CONFIG",
    "GCE_METADATA_HOST",
    "GCE_METADATA_ROOT",
    "GCE_METADATA_IP",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    # Never let host Docker endpoints leak into sandboxed sessions (daemon access goes via proxy)
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    # Never let unverified plugin/project roots leak from host or caller environments
    "AGY_PLUGIN_ROOT",
    "AGY_PLUGIN_DIRS",
    "AGY_REGISTERED_PLUGINS",
    "CODEX_PLUGIN_ROOT",
    "CODEX_PLUGIN_DIRS",
    "CODEX_REGISTERED_PLUGINS",
    "PLUGIN_ROOT",
    "PLUGIN_DATA",
    "CLAUDE_PLUGIN_ROOT",
    "CLAUDE_PLUGIN_DATA",
    "CLAUDE_PROJECT_DIR",
    "AGY_PROJECT_DIR",
    "HARNESS_PROJECT_DIR",
    "OH_MY_AGENTS_ROOT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
}
_BLOCKED_CALLER_ENV_KEYS = _STRIPPED_ENV_KEYS | {
    "PATH",
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "GLIBC_TUNABLES",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "CDPATH",
    "NO_GCE_CHECK",
    "AWS_EC2_METADATA_DISABLED",
    "CONTAINER_HOST",
    "HOME",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "PYTHONHOME",
    "PYTHONPYCACHEPREFIX",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_EXTERNAL_MODULE",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_TEMPLATE_DIR",
}


async def _safe_readline(stream: asyncio.StreamReader, max_line_bytes: int = 32 * 1024 * 1024) -> bytes:
    """Read a newline-terminated line from `stream` without crashing on >64KB/16MB lines."""
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            part = await stream.readuntil(b"\n")
            if total < max_line_bytes:
                chunks.append(part[: max_line_bytes - total])
            return b"".join(chunks)
        except asyncio.IncompleteReadError as exc:
            if exc.partial and total < max_line_bytes:
                chunks.append(exc.partial[: max_line_bytes - total])
            return b"".join(chunks)
        except (asyncio.LimitOverrunError, ValueError) as exc:
            consumed = getattr(exc, "consumed", 65536) or 65536
            part = await stream.read(consumed)
            if not part:
                return b"".join(chunks)
            if total < max_line_bytes:
                chunks.append(part[: max_line_bytes - total])
            total += len(part)


@dataclass
class SessionEvent:
    seq: int
    type: str  # "started" | "stdout" | "stderr" | "agy_event" | "stdin" | "exit" | "error"
    timestamp: float
    session_id: str
    data: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "type": self.type,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "data": self.data,
        }


class ExecutionSession:
    """Represents a running or completed local command / `agy` session with bidirectional I/O."""

    def __init__(
        self,
        session_id: str,
        argv: List[str],
        cwd: str,
        env: Dict[str, str],
        shell_cmd: Optional[str] = None,
        use_pty: bool = False,
        stream_json: bool = False,
        timeout: Optional[float] = None,
        max_buffer_events: int = 5000,
        max_output_bytes: int = 32 * 1024 * 1024,
        slot_sem: Optional[asyncio.Semaphore] = None,
        queue_timeout: float = 1800.0,
        is_agy: bool = False,
        is_codex: bool = False,
        spawn_argv: Optional[List[str]] = None,
        on_persist: Optional[Callable[["ExecutionSession", bool], None]] = None,
        pre_spawn_check: Optional[Callable[[], None]] = None,
        prepare_spawn: Optional[Callable[[], Optional[List[str]]]] = None,
        on_cleanup: Optional[Callable[[], None]] = None,
        error_redactor: Optional[Callable[[str], str]] = None,
    ) -> None:
        self.session_id = session_id
        self.argv = argv
        self.shell_cmd = shell_cmd
        self._spawn_argv = spawn_argv
        self.cwd = cwd
        self.env = env
        self.use_pty = use_pty
        self.stream_json = stream_json
        self.timeout = timeout
        self.max_buffer_events = max_buffer_events
        self.max_output_bytes = max_output_bytes
        self.is_agy = is_agy
        self.is_codex = is_codex
        self._on_persist = on_persist
        self._pre_spawn_check = pre_spawn_check
        self._prepare_spawn = prepare_spawn
        self._on_cleanup = on_cleanup
        self._cleanup_done = False
        self._error_redactor = error_redactor

        self.status: str = "starting"
        self.pid: Optional[int] = None
        self.boot_id: str = _read_boot_id()
        self.proc_start_ticks: Optional[int] = None
        self.agent_conversation_id: Optional[str] = _extract_initial_agent_id(
            argv, is_agy=is_agy, is_codex=is_codex
        )
        self.returncode: Optional[int] = None
        self.started_at: float = time.time()
        self.ended_at: Optional[float] = None
        self._last_persist_mono: float = 0.0

        self._slot_sem = slot_sem
        self._queue_timeout = queue_timeout
        self._slot_acquired = False
        self._pending_stdin: List[Tuple[bytes, bool]] = []
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._pty_master_fd: Optional[int] = None
        self._seq: int = 0
        self._events: Deque[SessionEvent] = deque(maxlen=max_buffer_events)
        self._stdout_chunks: Deque[Tuple[int, str]] = deque()
        self._stdout_bytes: int = 0
        self.stdout_truncated: bool = False
        self._stderr_chunks: Deque[Tuple[int, str]] = deque()
        self._stderr_bytes: int = 0
        self.stderr_truncated: bool = False
        self._subscribers: List[asyncio.Queue[Optional[SessionEvent]]] = []
        self._done_event = asyncio.Event()
        self._watch_tasks: List[asyncio.Task[Any]] = []

    def _run_cleanup(self) -> None:
        if self._cleanup_done:
            return
        self._cleanup_done = True
        if self._on_cleanup is not None:
            try:
                self._on_cleanup()
            except Exception:
                pass

    def _notify_persist(self, force: bool = False) -> None:
        if self._on_persist is None:
            return
        now_m = time.monotonic()
        if not force and (now_m - self._last_persist_mono) < _PERSIST_THROTTLE_SECONDS:
            return
        self._last_persist_mono = now_m
        try:
            self._on_persist(self, force)
        except Exception:
            pass

    def _append_stdout(self, text: str) -> None:
        b_len = len(text.encode("utf-8", errors="replace"))
        self._stdout_chunks.append((b_len, text))
        self._stdout_bytes += b_len
        while self._stdout_bytes > self.max_output_bytes and len(self._stdout_chunks) > 1:
            old_len, _ = self._stdout_chunks.popleft()
            self._stdout_bytes -= old_len
            self.stdout_truncated = True
        found_id = False
        if (self.is_codex or self.is_agy) and not self.agent_conversation_id:
            cand_id = _extract_stream_agent_id(text)
            if cand_id:
                self.agent_conversation_id = cand_id
                found_id = True
        self._notify_persist(force=found_id)

    def _append_stderr(self, text: str) -> None:
        b_len = len(text.encode("utf-8", errors="replace"))
        self._stderr_chunks.append((b_len, text))
        self._stderr_bytes += b_len
        while self._stderr_bytes > self.max_output_bytes and len(self._stderr_chunks) > 1:
            old_len, _ = self._stderr_chunks.popleft()
            self._stderr_bytes -= old_len
            self.stderr_truncated = True
        self._notify_persist(force=False)

    def _emit(self, event_type: str, data: Any) -> SessionEvent:
        self._seq += 1
        ev = SessionEvent(
            seq=self._seq,
            type=event_type,
            timestamp=time.time(),
            session_id=self.session_id,
            data=data,
        )
        self._events.append(ev)

        for q in list(self._subscribers):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                pass
        return ev

    async def start(self, initial_stdin: Optional[str] = None, close_stdin: bool = False) -> None:
        """Acquire concurrency slot (queueing asynchronously if busy) and spawn the child process."""
        if self._slot_sem is not None and self._slot_sem.locked():
            self.status = "queued"
            if initial_stdin is not None:
                self._pending_stdin.append((initial_stdin.encode("utf-8"), close_stdin))
            slot_kind = "codex" if self.is_codex else "agy"
            self._emit(
                "queued",
                {"message": f"Waiting for available {slot_kind} concurrency slot", "cwd": self.cwd},
            )
            self._notify_persist(force=True)
            self._watch_tasks.append(
                asyncio.create_task(self._queued_start_loop(close_stdin=close_stdin))
            )
            return

        if self._slot_sem is not None:
            await self._slot_sem.acquire()
            self._slot_acquired = True

        try:
            await self._spawn_process(initial_stdin=initial_stdin, close_stdin=close_stdin)
        except BaseException:
            self._release_slot()
            self._run_cleanup()
            raise

    def _release_slot(self) -> None:
        if self._slot_acquired and self._slot_sem is not None:
            self._slot_acquired = False
            self._slot_sem.release()

    async def _queued_start_loop(self, close_stdin: bool = False) -> None:
        assert self._slot_sem is not None
        try:
            await asyncio.wait_for(self._slot_sem.acquire(), timeout=self._queue_timeout)
            self._slot_acquired = True
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self._run_cleanup()
            self.ended_at = time.time()
            self.returncode = -9
            if self.status != "killed":
                self.status = "timeout"
            self._emit(
                "exit",
                {
                    "returncode": self.returncode,
                    "status": self.status,
                    "duration_seconds": round(self.ended_at - self.started_at, 4),
                },
            )
            self._notify_persist(force=True)
            self._done_event.set()
            for q in list(self._subscribers):
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
            return

        if self.status == "killed":
            self._release_slot()
            self._run_cleanup()
            self.ended_at = time.time()
            self.returncode = -9
            self._emit(
                "exit",
                {
                    "returncode": self.returncode,
                    "status": "killed",
                    "duration_seconds": round(self.ended_at - self.started_at, 4),
                },
            )
            self._notify_persist(force=True)
            self._done_event.set()
            for q in list(self._subscribers):
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
            return

        try:
            if self._pre_spawn_check is not None:
                await asyncio.to_thread(self._pre_spawn_check)
            if self._prepare_spawn is not None:
                rebuilt = await asyncio.to_thread(self._prepare_spawn)
                if rebuilt is not None:
                    self._spawn_argv = rebuilt
            self.started_at = time.time()
            await self._spawn_process(initial_stdin=None, close_stdin=False)
            should_close = close_stdin
            pending = list(self._pending_stdin)
            self._pending_stdin.clear()
            for chunk, ca in pending:
                should_close = should_close or ca
                await self.write_stdin(chunk, close_after=False)
            if should_close and not self.use_pty and self._proc and self._proc.stdin:
                self._proc.stdin.close()
        except Exception as exc:
            self._release_slot()
            self._run_cleanup()
            self.ended_at = time.time()
            self.returncode = -1
            self.status = "failed"
            err_msg = self._error_redactor(str(exc)) if self._error_redactor else str(exc)
            self._append_stderr(err_msg + "\n")
            self._emit("error", err_msg)
            self._emit("exit", {"returncode": -1, "status": "failed", "duration_seconds": 0.0})
            self._notify_persist(force=True)
            self._done_event.set()
            for q in list(self._subscribers):
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass

    async def _spawn_process(
        self, initial_stdin: Optional[str] = None, close_stdin: bool = False
    ) -> None:
        """Spawn the child process and begin streaming stdout/stderr."""
        if self.use_pty:
            master_fd, slave_fd = pty.openpty()
            self._pty_master_fd = master_fd
            stdin_arg: Any = slave_fd
            stdout_arg: Any = slave_fd
            stderr_arg: Any = slave_fd
        else:
            slave_fd = None
            stdin_arg = asyncio.subprocess.PIPE
            stdout_arg = asyncio.subprocess.PIPE
            stderr_arg = asyncio.subprocess.PIPE

        try:
            if self._spawn_argv is not None:
                self._proc = await asyncio.create_subprocess_exec(
                    *self._spawn_argv,
                    stdin=stdin_arg,
                    stdout=stdout_arg,
                    stderr=stderr_arg,
                    cwd="/",
                    env=self.env,
                    start_new_session=True,
                    limit=STREAM_LINE_LIMIT,
                )
            elif self.shell_cmd is not None:
                bash_exe = "/bin/bash" if os.path.exists("/bin/bash") else None
                self._proc = await asyncio.create_subprocess_shell(
                    self.shell_cmd,
                    stdin=stdin_arg,
                    stdout=stdout_arg,
                    stderr=stderr_arg,
                    cwd=self.cwd,
                    env=self.env,
                    executable=bash_exe,
                    start_new_session=True,
                    limit=STREAM_LINE_LIMIT,
                )
            else:
                self._proc = await asyncio.create_subprocess_exec(
                    *self.argv,
                    stdin=stdin_arg,
                    stdout=stdout_arg,
                    stderr=stderr_arg,
                    cwd=self.cwd,
                    env=self.env,
                    start_new_session=True,
                    limit=STREAM_LINE_LIMIT,
                )
        except BaseException:
            if self._pty_master_fd is not None:
                try:
                    os.close(self._pty_master_fd)
                except OSError:
                    pass
                self._pty_master_fd = None
            raise
        finally:
            if slave_fd is not None:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass

        self.pid = self._proc.pid
        self.boot_id = _read_boot_id()
        self.proc_start_ticks = _read_proc_start_ticks(self.pid) if self.pid else None
        self.status = "running"
        self._emit(
            "started",
            {
                "pid": self.pid,
                "argv": self.argv,
                "shell_cmd": self.shell_cmd,
                "cwd": self.cwd,
                "use_pty": self.use_pty,
                "stream_json": self.stream_json,
            },
        )
        self._notify_persist(force=True)

        if initial_stdin is not None:
            await self.write_stdin(initial_stdin, close_after=close_stdin)
        elif close_stdin and not self.use_pty and self._proc.stdin:
            self._proc.stdin.close()

        if self.use_pty and self._pty_master_fd is not None:
            self._watch_tasks.append(asyncio.create_task(self._read_pty_loop()))
        else:
            if self._proc.stdout:
                self._watch_tasks.append(
                    asyncio.create_task(self._read_stream_loop(self._proc.stdout, "stdout"))
                )
            if self._proc.stderr:
                self._watch_tasks.append(
                    asyncio.create_task(self._read_stream_loop(self._proc.stderr, "stderr"))
                )

        self._watch_tasks.append(asyncio.create_task(self._wait_process_loop()))

    async def _read_pty_loop(self) -> None:
        loop = asyncio.get_running_loop()
        fd = self._pty_master_fd
        if fd is None:
            return
        queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()

        def _on_readable() -> None:
            try:
                chunk = os.read(fd, 4096)
                if not chunk:
                    loop.remove_reader(fd)
                    queue.put_nowait(None)
                else:
                    queue.put_nowait(chunk)
            except OSError:
                try:
                    loop.remove_reader(fd)
                except Exception:
                    pass
                queue.put_nowait(None)

        loop.add_reader(fd, _on_readable)
        try:
            while True:
                chunk = await queue.get()
                if chunk is None:
                    break
                text = chunk.decode("utf-8", errors="replace")
                self._append_stdout(text)
                self._emit("stdout", text)
        finally:
            try:
                loop.remove_reader(fd)
            except Exception:
                pass

    async def _read_stream_loop(
        self, stream: asyncio.StreamReader, stream_name: str
    ) -> None:
        if self.stream_json and stream_name == "stdout":
            while True:
                line = await _safe_readline(stream, max_line_bytes=self.max_output_bytes)
                if not line:
                    break
                text = line.decode("utf-8", errors="replace")
                self._append_stdout(text)
                self._emit("stdout", text)
                stripped = text.strip()
                if stripped:
                    try:
                        parsed = json.loads(stripped)
                        self._emit("agy_event", parsed)
                    except json.JSONDecodeError:
                        pass
            return

        while True:
            chunk = await stream.read(8192)
            if not chunk:
                break
            text = chunk.decode("utf-8", errors="replace")
            if stream_name == "stdout":
                self._append_stdout(text)
            else:
                self._append_stderr(text)
            self._emit(stream_name, text)

    async def _wait_process_loop(self) -> None:
        assert self._proc is not None
        timed_out = False
        try:
            if self.timeout and self.timeout > 0:
                await asyncio.wait_for(self._proc.wait(), timeout=self.timeout)
            else:
                await self._proc.wait()
        except asyncio.TimeoutError:
            timed_out = True
            await self.send_signal("SIGKILL")
            await self._proc.wait()
        finally:
            self._release_slot()

        for t in self._watch_tasks:
            if t is not asyncio.current_task():
                try:
                    await asyncio.wait_for(t, timeout=1.5)
                except Exception:
                    pass

        if self._pty_master_fd is not None:
            try:
                os.close(self._pty_master_fd)
            except OSError:
                pass
            self._pty_master_fd = None

        self.returncode = self._proc.returncode
        self.ended_at = time.time()
        if timed_out:
            self.status = "timeout"
        elif self.status != "killed":
            self.status = "completed" if self.returncode == 0 else "failed"

        if self.is_codex and not self.agent_conversation_id:
            self.agent_conversation_id = _discover_codex_rollout_id(self.cwd, self.started_at)

        self._run_cleanup()
        self._emit(
            "exit",
            {
                "returncode": self.returncode,
                "status": self.status,
                "duration_seconds": round(self.ended_at - self.started_at, 4),
            },
        )
        self._notify_persist(force=True)
        self._done_event.set()
        for q in list(self._subscribers):
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass

    def resize_pty(self, rows: int, cols: int) -> None:
        """Resize the terminal window if this session uses a PTY."""
        if not self.use_pty or self._pty_master_fd is None:
            raise RuntimeError("Session does not have an active PTY")
        winsize = struct.pack("HHHH", max(1, int(rows)), max(1, int(cols)), 0, 0)
        fcntl.ioctl(self._pty_master_fd, termios.TIOCSWINSZ, winsize)

    async def write_stdin(self, data: Union[str, bytes], close_after: bool = False) -> None:
        """Write raw bytes or text to the running (or queued) process's stdin."""
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if self.status == "queued":
            self._pending_stdin.append((raw, close_after))
            self._emit("stdin", {"bytes_written": len(raw), "closed": close_after, "queued": True})
            return

        if self.status != "running" or self._proc is None:
            raise RuntimeError(f"Session {self.session_id} is not running (status={self.status})")
        if self.use_pty and self._pty_master_fd is not None:
            os.write(self._pty_master_fd, raw)
        elif self._proc.stdin is not None:
            self._proc.stdin.write(raw)
            await self._proc.stdin.drain()
            if close_after:
                self._proc.stdin.close()
        else:
            raise RuntimeError("Process stdin is not available")

        self._emit("stdin", {"bytes_written": len(raw), "closed": close_after})

    async def send_agy_turn(self, prompt: str, close_after: bool = False) -> None:
        """Send a user turn to an interactive or stream-json `agy` session."""
        if self.stream_json:
            payload = (
                json.dumps(
                    {"event": "user", "message": {"content": prompt}},
                    ensure_ascii=False,
                )
                + "\n"
            )
            await self.write_stdin(payload, close_after=close_after)
        else:
            line = prompt if prompt.endswith("\n") else prompt + "\n"
            await self.write_stdin(line, close_after=close_after)

    async def send_signal(self, sig_name: str = "SIGTERM") -> None:
        """Send a POSIX signal to the process group (or cancel a queued session)."""
        if self.status == "queued":
            self.status = "killed"
            for t in list(self._watch_tasks):
                t.cancel()
            return
        if self._proc is None or self._proc.returncode is not None:
            return
        sig_map = {
            "SIGINT": signal.SIGINT,
            "SIGTERM": signal.SIGTERM,
            "SIGKILL": signal.SIGKILL,
            "SIGHUP": signal.SIGHUP,
        }
        sig = sig_map.get(sig_name.upper(), signal.SIGTERM)
        if sig == signal.SIGKILL:
            self.status = "killed"
        try:
            if self.pid:
                os.killpg(os.getpgid(self.pid), sig)
            else:
                self._proc.send_signal(sig)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                self._proc.send_signal(sig)
            except Exception:
                pass

    async def wait(self) -> Dict[str, Any]:
        """Wait for session completion and return summary."""
        await self._done_event.wait()
        return self.to_summary(include_output=True)

    async def subscribe_with_heartbeat(
        self, after_seq: int = 0, heartbeat_seconds: float = 15.0
    ) -> AsyncIterator[Optional[SessionEvent]]:
        """Yield buffered and live `SessionEvent`s, or `None` on idle heartbeat intervals."""
        q: asyncio.Queue[Optional[SessionEvent]] = asyncio.Queue(maxsize=4096)
        self._subscribers.append(q)
        try:
            last_sent = after_seq
            for ev in list(self._events):
                if ev.seq > last_sent:
                    last_sent = ev.seq
                    yield ev

            if self._done_event.is_set() and q.empty():
                return

            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=heartbeat_seconds)
                except asyncio.TimeoutError:
                    if self._done_event.is_set() and q.empty():
                        break
                    yield None
                    continue

                if ev is None:
                    break
                if ev.seq > last_sent:
                    last_sent = ev.seq
                    yield ev
        finally:
            if q in self._subscribers:
                self._subscribers.remove(q)

    async def subscribe(self, after_seq: int = 0) -> AsyncIterator[SessionEvent]:
        """Yield buffered events with seq > after_seq, then live events until exit."""
        async for ev in self.subscribe_with_heartbeat(after_seq=after_seq, heartbeat_seconds=30.0):
            if ev is not None:
                yield ev

    def to_summary(self, include_output: bool = True, after_seq: int = 0) -> Dict[str, Any]:
        if self.is_codex and not self.agent_conversation_id and self.pid is not None:
            self.agent_conversation_id = _discover_codex_rollout_id(self.cwd, self.started_at)
        proc_alive = bool(
            self._proc is not None
            and self._proc.returncode is None
            and self.status == "running"
        )
        res: Dict[str, Any] = {
            "session_id": self.session_id,
            "session_kind": "agy" if self.is_agy else ("codex" if self.is_codex else "exec"),
            "status": self.status,
            "process_alive": proc_alive,
            "reconciled_after_restart": False,
            "agent_conversation_id": self.agent_conversation_id,
            "pid": self.pid,
            "argv": self.argv,
            "shell_cmd": self.shell_cmd,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": (
                round((self.ended_at or time.time()) - self.started_at, 4)
            ),
            "last_seq": self._seq,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }
        if include_output:
            res["stdout"] = "".join(t for _, t in self._stdout_chunks)
            res["stderr"] = "".join(t for _, t in self._stderr_chunks)
            res["events"] = [
                ev.to_dict() for ev in self._events if ev.seq > after_seq
            ]
        return res

    def to_persisted_dict(self, max_tail_chars: int = _PERSISTED_TAIL_CHARS) -> Dict[str, Any]:
        """Serialize session metadata and bounded output tail for crash/restart recovery."""
        full_out = "".join(t for _, t in self._stdout_chunks)
        full_err = "".join(t for _, t in self._stderr_chunks)
        out_trunc = self.stdout_truncated or (len(full_out) > max_tail_chars)
        err_trunc = self.stderr_truncated or (len(full_err) > max_tail_chars)
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "session_kind": "agy" if self.is_agy else ("codex" if self.is_codex else "exec"),
            "is_agy": self.is_agy,
            "is_codex": self.is_codex,
            "status": self.status,
            "pid": self.pid,
            "boot_id": self.boot_id,
            "proc_start_ticks": self.proc_start_ticks,
            "agent_conversation_id": self.agent_conversation_id,
            "argv": self.argv,
            "shell_cmd": self.shell_cmd,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "last_seq": self._seq,
            "stdout": full_out[-max_tail_chars:] if max_tail_chars > 0 else "",
            "stderr": full_err[-max_tail_chars:] if max_tail_chars > 0 else "",
            "stdout_truncated": out_trunc,
            "stderr_truncated": err_trunc,
            "reconciled_after_restart": False,
        }


class PersistedSession:
    """Disk-backed historical or restart-reconciled session record."""

    def __init__(
        self,
        record: Dict[str, Any],
        on_update: Optional[Callable[["PersistedSession"], None]] = None,
    ) -> None:
        self.session_id: str = str(record["session_id"])
        self.is_agy: bool = bool(record.get("is_agy") or record.get("session_kind") == "agy")
        self.is_codex: bool = bool(
            record.get("is_codex") or record.get("session_kind") == "codex"
        )
        self.status: str = str(record.get("status") or "completed")
        raw_pid = record.get("pid")
        self.pid: Optional[int] = int(raw_pid) if raw_pid is not None else None
        self.boot_id: str = str(record.get("boot_id") or "")
        raw_ticks = record.get("proc_start_ticks")
        self.proc_start_ticks: Optional[int] = (
            int(raw_ticks) if raw_ticks is not None else None
        )
        raw_conv = record.get("agent_conversation_id")
        self.agent_conversation_id: Optional[str] = (
            str(raw_conv) if raw_conv else None
        )
        self.argv: List[str] = [str(x) for x in (record.get("argv") or [])]
        raw_sc = record.get("shell_cmd")
        self.shell_cmd: Optional[str] = str(raw_sc) if raw_sc is not None else None
        self.cwd: str = str(record.get("cwd") or "")
        raw_rc = record.get("returncode")
        self.returncode: Optional[int] = int(raw_rc) if raw_rc is not None else None
        self.started_at: float = float(record.get("started_at") or time.time())
        raw_end = record.get("ended_at")
        self.ended_at: Optional[float] = float(raw_end) if raw_end is not None else None
        self._seq: int = max(1, int(record.get("last_seq") or 1))
        self.stdout: str = str(record.get("stdout") or "")
        self.stderr: str = str(record.get("stderr") or "")
        self.stdout_truncated: bool = bool(record.get("stdout_truncated", False))
        self.stderr_truncated: bool = bool(record.get("stderr_truncated", False))
        self.reconciled_after_restart: bool = bool(
            record.get("reconciled_after_restart", True)
        )
        self._on_update = on_update

    def is_alive(self) -> bool:
        """Check kernel `(boot_id, pid, proc_start_ticks)` identity and auto-transition if exited."""
        if self.status not in ("queued", "starting", "running", "orphaned_running"):
            return False
        alive = is_process_instance_alive(
            self.pid, self.boot_id, self.proc_start_ticks
        )
        if not alive:
            if self.status != "killed":
                self.status = "interrupted_by_restart"
            if self.ended_at is None:
                self.ended_at = time.time()
            if self.returncode is None:
                self.returncode = -15
            self._seq += 1
            if self._on_update is not None:
                try:
                    self._on_update(self)
                except Exception:
                    pass
        return alive

    def _build_events(self, after_seq: int = 0) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if self._seq > after_seq:
            ev_ts = self.ended_at or self.started_at
            events.append(
                {
                    "seq": self._seq,
                    "type": "exit" if not self.is_alive() else "reconciled",
                    "timestamp": ev_ts,
                    "session_id": self.session_id,
                    "data": {
                        "status": self.status,
                        "returncode": self.returncode,
                        "process_alive": self.is_alive(),
                        "reconciled_after_restart": self.reconciled_after_restart,
                        "agent_conversation_id": self.agent_conversation_id,
                    },
                }
            )
        return events

    def to_summary(self, include_output: bool = True, after_seq: int = 0) -> Dict[str, Any]:
        alive = self.is_alive()
        if self.is_codex and not self.agent_conversation_id:
            self.agent_conversation_id = _discover_codex_rollout_id(self.cwd, self.started_at)
        res: Dict[str, Any] = {
            "session_id": self.session_id,
            "session_kind": "agy" if self.is_agy else ("codex" if self.is_codex else "exec"),
            "status": self.status,
            "process_alive": alive,
            "reconciled_after_restart": self.reconciled_after_restart,
            "agent_conversation_id": self.agent_conversation_id,
            "pid": self.pid,
            "argv": self.argv,
            "shell_cmd": self.shell_cmd,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": (
                round((self.ended_at or time.time()) - self.started_at, 4)
            ),
            "last_seq": self._seq,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }
        if include_output:
            res["stdout"] = self.stdout
            res["stderr"] = self.stderr
            res["events"] = self._build_events(after_seq=after_seq)
        return res

    def to_persisted_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "session_kind": "agy" if self.is_agy else ("codex" if self.is_codex else "exec"),
            "is_agy": self.is_agy,
            "is_codex": self.is_codex,
            "status": self.status,
            "pid": self.pid,
            "boot_id": self.boot_id,
            "proc_start_ticks": self.proc_start_ticks,
            "agent_conversation_id": self.agent_conversation_id,
            "argv": self.argv,
            "shell_cmd": self.shell_cmd,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "last_seq": self._seq,
            "stdout": self.stdout[-_PERSISTED_TAIL_CHARS:],
            "stderr": self.stderr[-_PERSISTED_TAIL_CHARS:],
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "reconciled_after_restart": self.reconciled_after_restart,
        }

    async def subscribe_with_heartbeat(
        self, after_seq: int = 0, heartbeat_seconds: float = 15.0
    ) -> AsyncIterator[Optional[SessionEvent]]:
        for raw_ev in self._build_events(after_seq=after_seq):
            yield SessionEvent(
                seq=raw_ev["seq"],
                type=raw_ev["type"],
                timestamp=raw_ev["timestamp"],
                session_id=self.session_id,
                data=raw_ev["data"],
            )
        idle_elapsed = 0.0
        while self.is_alive():
            await asyncio.sleep(0.25)
            idle_elapsed += 0.25
            if not self.is_alive():
                yield SessionEvent(
                    seq=self._seq,
                    type="exit",
                    timestamp=self.ended_at or time.time(),
                    session_id=self.session_id,
                    data={
                        "status": self.status,
                        "returncode": self.returncode,
                        "process_alive": False,
                    },
                )
                break
            if idle_elapsed >= heartbeat_seconds:
                idle_elapsed = 0.0
                yield None

    async def subscribe(self, after_seq: int = 0) -> AsyncIterator[SessionEvent]:
        async for ev in self.subscribe_with_heartbeat(after_seq=after_seq, heartbeat_seconds=30.0):
            if ev is not None:
                yield ev

    async def send_signal(self, sig_name: str = "SIGTERM") -> None:
        """Signal an orphaned process ONLY if its `(boot_id, pid, proc_start_ticks)` identity matches."""
        if not self.is_alive() or not self.pid:
            return
        sig_map = {
            "SIGINT": signal.SIGINT,
            "SIGTERM": signal.SIGTERM,
            "SIGKILL": signal.SIGKILL,
            "SIGHUP": signal.SIGHUP,
        }
        sig = sig_map.get(sig_name.upper(), signal.SIGTERM)
        # Re-verify PID identity immediately prior to killpg/kill
        if not is_process_instance_alive(self.pid, self.boot_id, self.proc_start_ticks):
            self.is_alive()
            return
        try:
            os.killpg(os.getpgid(self.pid), sig)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                os.kill(self.pid, sig)
            except Exception:
                pass
        if sig == signal.SIGKILL:
            self.status = "killed"
        await asyncio.sleep(0.05)
        if not is_process_instance_alive(self.pid, self.boot_id, self.proc_start_ticks):
            self.status = "killed"
            self.ended_at = self.ended_at or time.time()
            if self.returncode is None:
                self.returncode = -int(sig)
            self._seq += 1
        if self._on_update is not None:
            try:
                self._on_update(self)
            except Exception:
                pass

    async def write_stdin(self, data: Union[str, bytes], close_after: bool = False) -> None:
        raise RuntimeError(
            f"Session {self.session_id} cannot accept interactive stdin after gateway restart "
            f"(status={self.status}, process_alive={self.is_alive()})"
        )

    async def send_agy_turn(self, prompt: str, close_after: bool = False) -> None:
        raise RuntimeError(
            f"Session {self.session_id} cannot accept follow-up turns after gateway restart "
            f"(status={self.status}, process_alive={self.is_alive()}); resume via conversation_id instead"
        )

    def resize_pty(self, rows: int, cols: int) -> None:
        raise RuntimeError("Persisted session does not have an active PTY")


class SessionManager:
    """Manages active and historical ExecutionSessions with policy validation and disk ledger."""

    def __init__(self, config: GatewayConfig, policy: CommandPolicy) -> None:
        self.config = config
        self.policy = policy
        self._sessions: Dict[str, ExecutionSession] = {}
        self._persisted: Dict[str, PersistedSession] = {}
        self._agy_sem = asyncio.Semaphore(max(1, config.max_concurrent_agy))
        self._codex_sem = asyncio.Semaphore(max(1, config.max_concurrent_codex))
        self._sandbox_cleanup_lock = asyncio.Lock()
        self._last_sandbox_cleanup: Optional[Dict[str, Any]] = None
        self._agy_models_lock = asyncio.Lock()
        self._agy_models_cache: Optional[Tuple[float, Tuple[str, str], Dict[str, Any]]] = None
        # Optional policy-filtering Docker proxy (duck-typed: `.is_listening`, `.socket_path`, `.status()`)
        self.docker_proxy: Optional[Any] = None
        self._state_dir: Optional[Path] = (
            Path(config.session_state_dir).expanduser()
            if config.session_state_dir
            else None
        )
        if self._state_dir is not None:
            self._init_and_reconcile_ledger()

    def _session_file_path(self, session_id: str) -> Optional[Path]:
        if self._state_dir is None or not session_id:
            return None
        if not all(ch in _SESSION_ID_SAFE_CHARS for ch in session_id):
            return None
        return self._state_dir / f"{session_id}.json"

    def _write_ledger_record(self, session_id: str, payload: Dict[str, Any]) -> None:
        target = self._session_file_path(session_id)
        if target is None or self._state_dir is None:
            return
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self._state_dir, 0o700)
            except OSError:
                pass
            tmp_p = target.with_suffix(f".{os.getpid()}.tmp")
            tmp_p.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            os.chmod(tmp_p, 0o600)
            os.replace(tmp_p, target)
        except OSError:
            pass

    def _on_live_session_persist(self, session: ExecutionSession, _force: bool) -> None:
        self._write_ledger_record(session.session_id, session.to_persisted_dict())

    def _on_persisted_session_update(self, psession: PersistedSession) -> None:
        self._write_ledger_record(psession.session_id, psession.to_persisted_dict())

    def _prune_ledger_files(self) -> None:
        if self._state_dir is None or not self._state_dir.is_dir():
            return
        max_keep = max(10, int(self.config.max_persisted_sessions or 200))
        try:
            files = sorted(
                self._state_dir.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return
        for stale in files[max_keep:]:
            sid = stale.stem
            if sid in self._sessions and self._sessions[sid].status in (
                "queued",
                "starting",
                "running",
            ):
                continue
            self._persisted.pop(sid, None)
            try:
                stale.unlink()
            except OSError:
                pass

    def _init_and_reconcile_ledger(self) -> None:
        assert self._state_dir is not None
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self._state_dir, 0o700)
        except OSError:
            return

        max_keep = max(10, int(self.config.max_persisted_sessions or 200))
        try:
            files = sorted(
                self._state_dir.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return

        for fpath in files[:max_keep]:
            try:
                raw = json.loads(fpath.read_text(encoding="utf-8"))
                if not isinstance(raw, dict) or not raw.get("session_id"):
                    continue
                file_mtime = fpath.stat().st_mtime
            except Exception:
                continue

            saved_status = str(raw.get("status") or "")
            dirty = False
            if raw.get("is_codex") and not raw.get("agent_conversation_id") and raw.get("cwd"):
                cand_cid = _discover_codex_rollout_id(
                    str(raw["cwd"]), float(raw.get("started_at") or file_mtime)
                )
                if cand_cid:
                    raw["agent_conversation_id"] = cand_cid
                    dirty = True

            if saved_status in ("queued", "starting", "running", "orphaned_running"):
                pid_val = int(raw["pid"]) if raw.get("pid") is not None else None
                boot_val = str(raw.get("boot_id") or "")
                ticks_val = (
                    int(raw["proc_start_ticks"])
                    if raw.get("proc_start_ticks") is not None
                    else None
                )
                if is_process_instance_alive(pid_val, boot_val, ticks_val):
                    raw["status"] = "orphaned_running"
                else:
                    raw["status"] = "interrupted_by_restart"
                    if raw.get("ended_at") is None:
                        raw["ended_at"] = file_mtime
                    if raw.get("returncode") is None:
                        raw["returncode"] = -15
                    note = (
                        "\n[dots-gateway] Session interrupted by gateway restart; "
                        "kernel /proc identity check confirmed prior process exited.\n"
                    )
                    existing_err = str(raw.get("stderr") or "")
                    if "[dots-gateway] Session interrupted by gateway restart" not in existing_err:
                        raw["stderr"] = (existing_err + note)[-_PERSISTED_TAIL_CHARS:]
                    raw["last_seq"] = int(raw.get("last_seq") or 1) + 1
                raw["reconciled_after_restart"] = True
                dirty = True
            elif not raw.get("reconciled_after_restart"):
                raw["reconciled_after_restart"] = True

            ps = PersistedSession(raw, on_update=self._on_persisted_session_update)
            self._persisted[ps.session_id] = ps
            if dirty:
                self._write_ledger_record(ps.session_id, ps.to_persisted_dict())

        self._prune_ledger_files()

    def flush_all(self) -> None:
        """Persist current state of all live in-memory sessions before shutdown."""
        if self._state_dir is None:
            return
        for s in list(self._sessions.values()):
            self._write_ledger_record(s.session_id, s.to_persisted_dict())
        self._prune_ledger_files()

    def get_sandbox_lifecycle_info(self) -> Dict[str, Any]:
        """Return configured sandbox storage location, disk status, retention rules, and last sweep."""
        disk = get_sandbox_disk_status(
            self.config.sandbox_state_dir,
            low_space_free_gb=self.config.sandbox_low_space_free_gb,
            low_space_free_percent=self.config.sandbox_low_space_free_percent,
        )
        return {
            **disk,
            "cleanup_enabled": self.config.sandbox_cleanup_enabled,
            "cleanup_interval_seconds": self.config.sandbox_cleanup_interval_seconds,
            "max_retention_days": self.config.sandbox_max_retention_days,
            "min_retention_days": self.config.sandbox_min_retention_days,
            "low_space_free_gb": self.config.sandbox_low_space_free_gb,
            "low_space_free_percent": self.config.sandbox_low_space_free_percent,
            "last_cleanup": self._last_sandbox_cleanup,
        }

    async def run_sandbox_cleanup(
        self, cancel_event: Optional[threading.Event] = None
    ) -> Dict[str, Any]:
        """Run non-blocking sandbox LRU lifecycle sweep in a worker thread."""
        async with self._sandbox_cleanup_lock:
            summary = await asyncio.to_thread(
                cleanup_sandbox_state,
                self.config.sandbox_state_dir,
                self.config.sandbox_max_retention_days,
                self.config.sandbox_min_retention_days,
                self.config.sandbox_low_space_free_gb,
                self.config.sandbox_low_space_free_percent,
                None,
                None,
                cancel_event,
            )
            self._last_sandbox_cleanup = summary
            return summary

    def _resolve_timeout(self, timeout: Optional[float], default: float) -> float:
        """Validate a caller-supplied timeout (`> 0` and finite) and clamp to `max_timeout_seconds`."""
        if timeout is None:
            val = float(default)
        else:
            try:
                val = float(timeout)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid timeout value: {timeout!r}") from exc
            if not math.isfinite(val) or val <= 0:
                raise ValueError("timeout must be a positive finite number (or omit for default)")
        return min(val, float(self.config.max_timeout_seconds))

    def _sandbox_forbidden_roots(self) -> List[str]:
        home_lex = os.path.abspath(str(Path.home()))
        home_dir = str(Path.home().resolve())
        non_home_prot: List[str] = []
        for raw_p in self.config.protected_paths or ():
            try:
                p_exp = os.path.expanduser(str(raw_p).strip())
                p_lex = os.path.abspath(p_exp)
                p_res = os.path.realpath(p_exp)
            except Exception:
                continue
            if p_lex in (home_lex, home_dir) or p_res in (home_lex, home_dir):
                continue
            non_home_prot.append(str(raw_p))
        return [
            str(GATEWAY_ROOT),
            *non_home_prot,
            os.path.join(home_dir, ".gemini"),
            os.path.join(home_dir, ".config"),
            os.path.join(home_dir, ".codex"),
            *self.policy.get_configured_agy_plugin_paths(),
            *self.policy.get_configured_codex_plugin_paths(),
        ]

    def _hook_jail_masked_paths(self) -> List[str]:
        """Return resolved protected roots masked inside `dots-hook-jail.py`."""
        home_lex = os.path.abspath(str(Path.home()))
        home_dir = str(Path.home().resolve())
        masked: List[str] = [str(GATEWAY_ROOT)]
        extra_mandatory = [
            *(self.config.protected_paths or ()),
            os.path.join(home_dir, ".gemini"),
            os.path.join(home_dir, ".codex"),
            os.path.join(home_dir, ".config"),
            os.path.join(home_dir, ".ssh"),
            os.path.join(home_dir, ".gnupg"),
            os.path.join(home_dir, ".aws"),
            os.path.join(home_dir, ".kube"),
            effective_plugin_state_dir(self.config),
        ]
        if self.config.sandbox_state_dir:
            extra_mandatory.append(
                os.path.join(str(self.config.sandbox_state_dir), "plugin_bundles")
            )
        for raw_p in extra_mandatory:
            if not raw_p:
                continue
            try:
                p_exp = os.path.expanduser(str(raw_p).strip())
                p_lex = os.path.abspath(p_exp)
                p_res = os.path.realpath(p_exp)
            except Exception:
                continue
            if p_lex not in ("/", home_lex, home_dir) and p_lex not in masked:
                masked.append(p_lex)
            if p_res not in ("/", home_lex, home_dir) and p_res not in masked:
                masked.append(p_res)
        return masked

    def _ensure_codex_workspace_metadata_dirs(self, workspace_dir: str) -> None:
        """Safely pre-create non-symlink `.codex/signals` and `.codex/metrics` for Codex plugins."""
        dot_codex = os.path.join(workspace_dir, ".codex")
        if os.path.islink(dot_codex):
            raise PermissionError(
                redact_diagnostic_text(
                    f"Refusing to prepare Codex plugin workspace metadata: '{dot_codex}' is a symlink",
                    self.config,
                )
            )
        if os.path.exists(dot_codex):
            if not os.path.isdir(dot_codex):
                raise PermissionError(
                    redact_diagnostic_text(
                        f"Refusing to prepare Codex plugin workspace metadata: '{dot_codex}' is not a directory",
                        self.config,
                    )
                )
        else:
            os.mkdir(dot_codex, 0o755)
            try:
                os.chmod(dot_codex, 0o755)
            except OSError:
                pass
        for sub_name in ("signals", "metrics"):
            sub_p = os.path.join(dot_codex, sub_name)
            if os.path.islink(sub_p):
                raise PermissionError(
                    redact_diagnostic_text(
                        f"Refusing to prepare Codex plugin workspace metadata: '{sub_p}' is a symlink",
                        self.config,
                    )
                )
            if os.path.exists(sub_p):
                if not os.path.isdir(sub_p):
                    raise PermissionError(
                        redact_diagnostic_text(
                            f"Refusing to prepare Codex plugin workspace metadata: '{sub_p}' is not a directory",
                            self.config,
                        )
                    )
            else:
                os.mkdir(sub_p, 0o755)
                try:
                    os.chmod(sub_p, 0o755)
                except OSError:
                    pass

    def _prepare_env(
        self,
        extra_env: Optional[Dict[str, str]] = None,
        trusted_env: Optional[Dict[str, str]] = None,
        check_sandbox_storage: bool = False,
        prevalidated_sandbox_state: Optional[Path] = None,
    ) -> Dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in _STRIPPED_ENV_KEYS and not k.startswith("GATEWAY_")
        }
        home_dir = str(Path.home().resolve())
        local_bin = os.path.join(home_dir, ".local", "bin")
        current_path = env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        parts = [p for p in current_path.split(os.pathsep) if p]
        for required_dir in ("/usr/local/bin", local_bin):
            if required_dir not in parts:
                parts.insert(0, required_dir)
        env["PATH"] = os.pathsep.join(parts)
        if env.get("TERM") in (None, "", "dumb"):
            env["TERM"] = "xterm-256color"
        if self.config.isolate_mount_namespace:
            if check_sandbox_storage and prevalidated_sandbox_state is None:
                home_covered = any(
                    home_dir == r or home_dir.startswith(r.rstrip("/") + "/")
                    for r in self.policy._allowed_roots
                )
                if not home_covered:
                    prepare_sandbox_runtime_state(
                        self.config.sandbox_state_dir,
                        lock_timeout_seconds=self.config.sandbox_lock_timeout_seconds,
                        forbidden_roots=self._sandbox_forbidden_roots(),
                    )
            env["TMPDIR"] = "/tmp"
        elif check_sandbox_storage:
            sb_state = prevalidated_sandbox_state or prepare_sandbox_runtime_state(
                self.config.sandbox_state_dir,
                lock_timeout_seconds=self.config.sandbox_lock_timeout_seconds,
                forbidden_roots=self._sandbox_forbidden_roots(),
            )
            env["TMPDIR"] = str(sb_state / "tmp")
        elif self.config.sandbox_state_dir:
            sb_tmp_p = Path(self.config.sandbox_state_dir).expanduser() / "tmp"
            if sb_tmp_p.is_dir():
                env["TMPDIR"] = str(sb_tmp_p)
        # Prevent cloud SDKs (google-auth, boto3, etc.) from probing host VM instance metadata
        # (169.254.169.254 / fd20:ce::254) when application credentials are intentionally absent.
        env["NO_GCE_CHECK"] = "true"
        env["GCE_METADATA_HOST"] = "127.0.0.1:1"
        env["GCE_METADATA_ROOT"] = "127.0.0.1:1"
        env["AWS_EC2_METADATA_DISABLED"] = "true"
        # Apply untrusted caller extra_env BEFORE operator trusted_env so operator settings always win
        if extra_env:
            for k, v in extra_env.items():
                ks = str(k)
                if (
                    ks in _BLOCKED_CALLER_ENV_KEYS
                    or ks.startswith("GATEWAY_")
                    or ks.startswith("LD_")
                ):
                    continue
                env[ks] = str(v)
        if trusted_env:
            for k, v in trusted_env.items():
                ks = str(k)
                if ks in ("DOCKER_HOST", "DOCKER_CONTEXT") or ks.startswith("GATEWAY_"):
                    continue
                env[ks] = str(v)
        eff_home = env.get("HOME", "")
        if eff_home and eff_home != home_dir:
            iso_local_bin = os.path.join(eff_home, ".local", "bin")
            cur_parts = [p for p in env.get("PATH", "").split(os.pathsep) if p]
            if iso_local_bin not in cur_parts:
                cur_parts.insert(0, iso_local_bin)
                env["PATH"] = os.pathsep.join(cur_parts)
        docker_sock = self._active_docker_proxy_socket()
        if docker_sock:
            env["DOCKER_HOST"] = (
                "unix:///var/run/docker.sock"
                if self.config.isolate_mount_namespace
                else f"unix://{docker_sock}"
            )
        # Ensure loopback traffic (e.g. Flutter `flutter_tester` WebSocket on `127.0.0.1:<port>`)
        # bypasses outbound sandbox HTTP proxies (`agy --sandbox`'s `HTTP_PROXY`/`connectd`)
        for np_key in ("NO_PROXY", "no_proxy"):
            existing_np = [x.strip() for x in env.get(np_key, "").split(",") if x.strip()]
            if "*" not in existing_np:
                for host in ("localhost", "127.0.0.1", "::1"):
                    if host not in existing_np:
                        existing_np.append(host)
                env[np_key] = ",".join(existing_np)
        return env

    def _load_agy_env(self) -> Dict[str, str]:
        """Load hot-reloadable Antigravity (`agy`) auth/env overrides from `agy_env_file` (`0600`)."""
        out: Dict[str, str] = {}
        raw_path = (self.config.agy_env_file or "").strip()
        if not raw_path:
            return out
        env_p = Path(raw_path).expanduser()
        if not env_p.is_file():
            return out
        try:
            for raw_line in env_p.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("unset "):
                    ukey = line[6:].strip()
                    if ukey:
                        out.pop(ukey, None)
                    continue
                if "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                    v = v[1:-1]
                if not k:
                    continue
                if v:
                    out[k] = v
                else:
                    out.pop(k, None)
        except OSError:
            pass
        if "AGY_ADC_AUTH" in out and out["AGY_ADC_AUTH"].strip().lower() in (
            "0",
            "false",
            "no",
            "off",
        ):
            out.pop("AGY_ADC_AUTH", None)
            out.pop("GOOGLE_CLOUD_QUOTA_PROJECT", None)
        return out

    def attach_docker_proxy(self, proxy: Optional[Any]) -> None:
        """Register the gateway Docker filtering proxy used for new sandboxed sessions."""
        self.docker_proxy = proxy

    def _active_docker_proxy_socket(self) -> Optional[str]:
        """Proxy socket path when Docker access is ON (hot-reloaded) and the proxy is listening."""
        proxy = self.docker_proxy
        if proxy is None or not getattr(proxy, "is_listening", False):
            return None
        if not docker_access_enabled(self.config):
            return None
        return str(getattr(proxy, "socket_path", "") or "") or None

    def get_docker_info(self) -> Dict[str, Any]:
        """Return live Docker access state for status endpoints."""
        state = docker_access_state(self.config)
        info: Dict[str, Any] = {
            "enabled": bool(state["enabled"]),
            "source": state["source"],
            "upstream_socket": self.config.docker_upstream_socket,
            "upstream_present": os.path.exists(self.config.docker_upstream_socket),
            "proxy_socket": self.config.docker_proxy_socket,
            "proxy_listening": bool(
                self.docker_proxy is not None and getattr(self.docker_proxy, "is_listening", False)
            ),
            "masked_paths": list(self.config.docker_mask_paths),
            "force_loopback_ports": bool(self.config.docker_force_loopback_ports),
            "allow_host_network": bool(self.config.docker_allow_host_network),
            "allowed_capabilities": list(self.config.docker_allowed_capabilities),
        }
        if self.docker_proxy is not None and hasattr(self.docker_proxy, "stats"):
            try:
                info["proxy_stats"] = dict(self.docker_proxy.stats)
            except Exception:
                pass
        return info

    def get_agy_auth_info(self) -> Dict[str, Any]:
        """Return live Antigravity (`agy`) authentication mode & ADC status from `agy.env`."""
        env_map = self._load_agy_env()
        adc_raw = env_map.get("AGY_ADC_AUTH", "").strip().lower()
        adc_enabled = adc_raw in ("1", "true", "yes", "on")
        quota_project = env_map.get("GOOGLE_CLOUD_QUOTA_PROJECT") or None
        adc_json = (
            Path.home()
            / ".config"
            / "gcloud"
            / "application_default_credentials.json"
        )
        try:
            adc_creds_present = adc_json.is_file() and adc_json.stat().st_size > 10
        except OSError:
            adc_creds_present = False
        default_model, default_source = self.get_agy_default_model()
        return {
            "mode": "adc" if adc_enabled else "oauth",
            "adc_enabled": adc_enabled,
            "quota_project": quota_project,
            "adc_credentials_present": adc_creds_present,
            "env_file": self.config.agy_env_file,
            "default_model": default_model,
            "default_model_source": default_source,
        }

    def get_agy_default_model(self) -> Tuple[Optional[str], str]:
        """Return `(model, source)` used when callers omit `model` (hot-reloaded per call).

        Precedence: `agy_model_file` (written by `dots-gateway agy-model`) >
        `agy_default_model` (config.json) > agy's own `settings.json` selection.
        """
        raw_path = (self.config.agy_model_file or "").strip()
        if raw_path:
            model_p = Path(raw_path).expanduser()
            try:
                if model_p.is_file():
                    for raw_line in model_p.read_text(encoding="utf-8").splitlines():
                        cand = raw_line.strip()
                        if cand and not cand.startswith("#"):
                            return cand[:128], "agy_model_file"
            except OSError:
                pass
        cfg_model = (self.config.agy_default_model or "").strip()
        if cfg_model:
            return cfg_model[:128], "config"
        return None, "agy_settings"

    async def list_agy_models(self, refresh: bool = False) -> Dict[str, Any]:
        """List models available to `agy` under the current (hot-reloaded) auth profile.

        Runs the fixed host-side command `agy models` (no caller-supplied arguments) and
        caches results per `(auth_mode, quota_project)` for `agy_models_cache_seconds`.
        """
        auth = self.get_agy_auth_info()
        cache_key = (str(auth.get("mode") or ""), str(auth.get("quota_project") or ""))
        default_model, default_source = self.get_agy_default_model()
        ttl = max(0.0, float(self.config.agy_models_cache_seconds or 0.0))

        async with self._agy_models_lock:
            now_m = time.monotonic()
            cached = self._agy_models_cache
            if (
                not refresh
                and cached is not None
                and cached[1] == cache_key
                and (now_m - cached[0]) < ttl
            ):
                payload = dict(cached[2])
                payload["cached"] = True
            else:
                agy_bin = (
                    self.config.agy_binary
                    if os.path.exists(self.config.agy_binary)
                    else "agy"
                )
                env = self._prepare_env(trusted_env=self._load_agy_env())
                try:
                    proc = await asyncio.create_subprocess_exec(
                        agy_bin,
                        "models",
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                        cwd=str(Path.home()),
                    )
                    try:
                        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=60.0)
                    except asyncio.TimeoutError as exc:
                        proc.kill()
                        await proc.wait()
                        raise RuntimeError("`agy models` timed out after 60s") from exc
                except FileNotFoundError as exc:
                    raise RuntimeError(f"agy binary not found: {agy_bin}") from exc

                out_txt = out_b.decode("utf-8", errors="replace")
                err_txt = err_b.decode("utf-8", errors="replace")
                if proc.returncode != 0:
                    raise RuntimeError(
                        f"`agy models` exited with code {proc.returncode}: "
                        f"{(err_txt or out_txt).strip()[-500:]}"
                    )
                models: List[Dict[str, str]] = []
                for line in out_txt.splitlines():
                    if "\t" not in line:
                        continue
                    mid, _, mname = line.partition("\t")
                    mid, mname = mid.strip(), mname.strip()
                    if mid:
                        models.append({"id": mid, "name": mname or mid})
                payload = {
                    "models": models,
                    "auth_mode": cache_key[0],
                    "quota_project": cache_key[1] or None,
                    "fetched_at": time.time(),
                    "cached": False,
                }
                self._agy_models_cache = (now_m, cache_key, dict(payload))

        payload["default_model"] = default_model
        payload["default_model_source"] = default_source
        ids = {m["id"] for m in payload.get("models", [])}
        names = {m["name"] for m in payload.get("models", [])}
        payload["default_model_available"] = (
            None if default_model is None else (default_model in ids or default_model in names)
        )
        return payload

    def _load_codex_env(self) -> Dict[str, str]:
        """Load isolated Codex credentials/env overrides from `codex_env_file` (`0600`)."""
        out: Dict[str, str] = {}
        raw_path = (self.config.codex_env_file or "").strip()
        if not raw_path:
            return out
        env_p = Path(raw_path).expanduser()
        if not env_p.is_file():
            return out
        try:
            for raw_line in env_p.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                    v = v[1:-1]
                if k and v:
                    out[k] = v
        except OSError:
            pass
        return out

    def has_codex_auth(self) -> bool:
        """Return True if Codex CLI credentials exist in `codex.env` or `~/.codex/auth.json`."""
        env_map = self._load_codex_env()
        if any(
            env_map.get(k)
            for k in ("OPENAI_API_" + "KEY", "CODEX_API_" + "KEY", "CODEX_ACCESS_TOKEN")
        ):
            return True
        auth_json = Path.home() / ".codex" / "auth.json"
        try:
            return auth_json.is_file() and auth_json.stat().st_size > 10
        except OSError:
            return False

    def _cleanup_old_sessions(self) -> None:
        if len(self._sessions) > 100:
            completed = [
                s
                for s in self._sessions.values()
                if s.status not in ("queued", "starting", "running")
            ]
            completed.sort(key=lambda s: s.ended_at or 0.0)
            for s in completed[: len(self._sessions) - 100]:
                if self._state_dir is not None:
                    self._persisted[s.session_id] = PersistedSession(
                        s.to_persisted_dict(),
                        on_update=self._on_persisted_session_update,
                    )
                self._sessions.pop(s.session_id, None)
        self._prune_ledger_files()

    def active_count(self) -> int:
        return sum(
            1 for s in self._sessions.values() if s.status in ("queued", "starting", "running")
        )

    def active_agy_count(self) -> int:
        return sum(
            1 for s in self._sessions.values() if s.is_agy and s.status in ("starting", "running")
        )

    def queued_agy_count(self) -> int:
        return sum(
            1 for s in self._sessions.values() if s.is_agy and s.status == "queued"
        )

    def active_codex_count(self) -> int:
        return sum(
            1 for s in self._sessions.values() if s.is_codex and s.status in ("starting", "running")
        )

    def queued_codex_count(self) -> int:
        return sum(
            1 for s in self._sessions.values() if s.is_codex and s.status == "queued"
        )

    async def create_session(
        self,
        command: Union[str, Sequence[str]],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        shell: Optional[bool] = None,
        use_pty: bool = False,
        stream_json: bool = False,
        timeout: Optional[float] = None,
        initial_stdin: Optional[str] = None,
        close_stdin: bool = False,
        slot_sem: Optional[asyncio.Semaphore] = None,
        queue_timeout: Optional[float] = None,
        is_agy: bool = False,
        is_codex: bool = False,
        readonly_subpaths: Optional[Sequence[str]] = None,
        readonly_subpaths_getter: Optional[Callable[[], Sequence[str]]] = None,
        trusted_env: Optional[Dict[str, str]] = None,
        agy_plugins_enabled: bool = False,
        agy_plugin_mounts: Optional[Sequence[Tuple[str, str]]] = None,
        codex_plugins_enabled: bool = False,
        codex_plugin_mounts: Optional[Sequence[Tuple[str, str]]] = None,
        prepared_plugin_runtime: Optional[PreparedAgentPluginRuntime] = None,
        prevalidated_sandbox_state: Optional[Path] = None,
        pre_spawn_check: Optional[Callable[[], None]] = None,
        refresh_plugin_runtime: Optional[Callable[[], Optional[PreparedAgentPluginRuntime]]] = None,
        on_cleanup: Optional[Callable[[], None]] = None,
        session_id_override: Optional[str] = None,
        session_workdirs: Optional[Sequence[str]] = None,
    ) -> ExecutionSession:
        """Validate command against security policy and start an ExecutionSession."""
        if self.active_count() >= self.config.max_concurrent_sessions:
            raise RuntimeError(
                f"Maximum concurrent sessions ({self.config.max_concurrent_sessions}) reached"
            )

        decision = self.policy.validate_command(
            command,
            cwd=cwd,
            _trusted_agy_argv=is_agy,
            _trusted_codex_argv=is_codex,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)

        assert decision.normalized_argv is not None
        effective_timeout = self._resolve_timeout(
            timeout, self.config.default_timeout_seconds
        )
        home_dir = os.path.realpath(str(Path.home()))
        home_covered = any(
            home_dir == r or home_dir.startswith(r.rstrip("/") + "/")
            for r in self.policy._allowed_roots
        )
        prevalidated_sb: Optional[Path] = prevalidated_sandbox_state
        if prevalidated_sb is None and (
            not self.config.isolate_mount_namespace
            or not home_covered
            or is_agy
            or is_codex
            or agy_plugins_enabled
            or codex_plugins_enabled
        ):
            prevalidated_sb = await asyncio.to_thread(
                prepare_sandbox_runtime_state,
                self.config.sandbox_state_dir,
                lock_timeout_seconds=self.config.sandbox_lock_timeout_seconds,
                forbidden_roots=self._sandbox_forbidden_roots(),
            )
        prepared_env = self._prepare_env(
            extra_env=env,
            trusted_env=trusted_env,
            check_sandbox_storage=True,
            prevalidated_sandbox_state=prevalidated_sb,
        )

        # Auto-enable shell execution when a string command uses pipes/chaining/builtins
        use_shell = decision.requires_shell if shell is None else bool(shell)

        shell_cmd: Optional[str] = None
        if use_shell:
            if isinstance(command, str):
                shell_cmd = command
                stripped_leading = shell_cmd.lstrip()
                if stripped_leading.startswith("agy ") and os.path.exists(self.config.agy_binary):
                    shell_cmd = self.config.agy_binary + stripped_leading[3:]
                elif stripped_leading.startswith("codex ") and os.path.exists(self.config.codex_binary):
                    shell_cmd = self.config.codex_binary + stripped_leading[5:]
                elif stripped_leading.startswith("bwrap ") and os.path.exists(self.config.bwrap_binary):
                    shell_cmd = self.config.bwrap_binary + stripped_leading[5:]
            else:
                shell_cmd = " ".join(shlex.quote(x) for x in decision.normalized_argv)

        def _compute_mount_ns_spawn_argv(
            active_runtime: Optional[PreparedAgentPluginRuntime],
        ) -> Optional[List[str]]:
            if not self.config.isolate_mount_namespace:
                return None
            target_exec = (
                ["/bin/bash", "-c", shell_cmd]
                if shell_cmd is not None
                else list(decision.normalized_argv)
            )
            adc_active = bool(
                is_agy
                and str(prepared_env.get("AGY_ADC_AUTH", "")).strip().lower()
                in ("1", "true", "yes", "on")
            )
            masked_plugins = [
                *self.policy.get_configured_agy_plugin_paths(),
                *self.policy.get_configured_codex_plugin_paths(),
            ]
            active_ro_subpaths = (
                readonly_subpaths_getter()
                if readonly_subpaths_getter is not None
                else readonly_subpaths
            )
            return build_mount_ns_argv(
                target_argv=target_exec,
                cwd=decision.resolved_cwd,
                allowed_workdirs=self.config.allowed_workdirs,
                protected_paths=self.config.protected_paths,
                is_agy=is_agy,
                is_codex=is_codex,
                readonly_subpaths=active_ro_subpaths,
                sandbox_state_dir=self.config.sandbox_state_dir,
                docker_mask_paths=self.config.docker_mask_paths,
                docker_proxy_socket=self._active_docker_proxy_socket(),
                mount_gcloud_adc=adc_active,
                agy_plugins_enabled=agy_plugins_enabled,
                agy_plugin_mounts=agy_plugin_mounts,
                codex_plugins_enabled=codex_plugins_enabled,
                codex_plugin_mounts=codex_plugin_mounts,
                prepared_plugin_runtime=active_runtime,
                agent_runtime_home_root=self.config.agent_runtime_home_root,
                masked_plugin_paths=masked_plugins,
                sandbox_lock_timeout_seconds=self.config.sandbox_lock_timeout_seconds,
                prevalidated_sandbox_state=prevalidated_sb,
                session_workdirs=session_workdirs,
                plugin_state_dir=effective_plugin_state_dir(self.config),
            )

        spawn_argv = await asyncio.to_thread(
            _compute_mount_ns_spawn_argv, prepared_plugin_runtime
        )

        def _prepare_spawn_after_queue() -> Optional[List[str]]:
            active_rt = prepared_plugin_runtime
            if refresh_plugin_runtime is not None:
                active_rt = refresh_plugin_runtime()
            return _compute_mount_ns_spawn_argv(active_rt)

        self._cleanup_old_sessions()
        session_id = session_id_override or f"sess_{uuid.uuid4().hex[:16]}"
        session = ExecutionSession(
            session_id=session_id,
            argv=decision.normalized_argv,
            cwd=decision.resolved_cwd,
            env=prepared_env,
            shell_cmd=shell_cmd,
            use_pty=use_pty,
            stream_json=stream_json,
            timeout=effective_timeout,
            max_buffer_events=self.config.max_output_buffer_events,
            max_output_bytes=self.config.max_output_bytes,
            slot_sem=slot_sem,
            queue_timeout=(
                self.config.agy_queue_timeout_seconds
                if queue_timeout is None
                else float(queue_timeout)
            ),
            is_agy=is_agy,
            is_codex=is_codex,
            spawn_argv=spawn_argv,
            on_persist=(
                self._on_live_session_persist if self._state_dir is not None else None
            ),
            pre_spawn_check=pre_spawn_check,
            prepare_spawn=(
                _prepare_spawn_after_queue
                if (self.config.isolate_mount_namespace or refresh_plugin_runtime is not None)
                else None
            ),
            on_cleanup=on_cleanup,
            error_redactor=lambda s: redact_diagnostic_text(s, self.config),
        )
        self._sessions[session_id] = session
        try:
            await session.start(initial_stdin=initial_stdin, close_stdin=close_stdin)
        except BaseException:
            self._sessions.pop(session_id, None)
            raise
        return session

    async def create_agy_session(
        self,
        prompt: Optional[str] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: Optional[bool] = None,
        print_mode: bool = True,
        output_format: Optional[str] = None,
        input_format: Optional[str] = None,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        mode: Optional[str] = None,
        conversation_id: Optional[str] = None,
        continue_last: bool = False,
        add_dirs: Optional[Sequence[str]] = None,
        use_pty: bool = False,
        timeout: Optional[float] = None,
        initial_stdin: Optional[str] = None,
        close_stdin: bool = True,
    ) -> ExecutionSession:
        """Create a dedicated `agy` session with `--dangerously-skip-permissions` enabled by default."""
        eff_model = model
        if not eff_model and not any(
            str(a) == "--model" or str(a).startswith("--model=") for a in (args or [])
        ):
            eff_model, _ = self.get_agy_default_model()

        def _validate_and_build_agy_inputs() -> Tuple[
            List[str], List[str], List[Any], List[str], Dict[str, str]
        ]:
            plugins_state = agy_plugins_config_state(self.config)
            val_plgs: List[Any] = []
            if plugins_state.get("config_error") or plugins_state.get("enabled"):
                val_plgs = self.policy.validate_agy_plugins(
                    cwd=cwd, add_dirs=add_dirs, require_mount_ns_check=True
                )
            built_argv = self.policy.build_agy_argv(
                prompt=prompt,
                args=args,
                skip_permissions=skip_permissions,
                print_mode=print_mode,
                output_format=output_format,
                input_format=input_format,
                model=eff_model,
                effort=effort,
                mode=mode,
                conversation_id=conversation_id,
                continue_last=continue_last,
                add_dirs=add_dirs,
                cwd=cwd,
                _validated_plugins=val_plgs,
            )
            ws_dirs = self.policy.get_agy_workspace_dirs(cwd=cwd, add_dirs=add_dirs)
            _, ro_hooks = self.policy.resolve_codex_git_metadata_dirs(
                cwd=cwd, add_dirs=add_dirs
            )
            loaded_env = self._load_agy_env()
            return built_argv, ws_dirs, val_plgs, ro_hooks, loaded_env

        (
            argv,
            session_ws_agy,
            validated_plugins,
            ro_hook_dirs,
            trusted_agy_env,
        ) = await asyncio.to_thread(_validate_and_build_agy_inputs)
        for strip_plg_key in (
            "HOME",
            "CODEX_HOME",
            "AGY_PLUGIN_ROOT",
            "AGY_PLUGIN_DIRS",
            "AGY_REGISTERED_PLUGINS",
            "CODEX_PLUGIN_ROOT",
            "CODEX_PLUGIN_DIRS",
            "CODEX_REGISTERED_PLUGINS",
            "PLUGIN_ROOT",
            "PLUGIN_DATA",
            "CLAUDE_PLUGIN_ROOT",
            "CLAUDE_PLUGIN_DATA",
            "CLAUDE_PROJECT_DIR",
            "AGY_PROJECT_DIR",
            "HARNESS_PROJECT_DIR",
            "OH_MY_AGENTS_ROOT",
        ):
            trusted_agy_env.pop(strip_plg_key, None)

        caller_env: Dict[str, str] = {}
        if env:
            for k, v in env.items():
                ks = str(k)
                vs = "" if v is None else str(v)
                if ks == "AGY_ADC_AUTH" and (
                    not vs or vs.strip().lower() in ("0", "false", "no", "off")
                ):
                    trusted_agy_env.pop("AGY_ADC_AUTH", None)
                    trusted_agy_env.pop("GOOGLE_CLOUD_QUOTA_PROJECT", None)
                elif vs:
                    caller_env[ks] = vs

        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        prevalidated_sb: Optional[Path] = None
        prepared_agy_runtime: Optional[PreparedAgentPluginRuntime] = None
        allowed_ws: List[str] = []
        if validated_plugins:
            ok_cwd, cwd_err, resolved_cwd = self.policy.validate_workdir(cwd)
            if not ok_cwd:
                raise PermissionError(cwd_err)
            for ws_cand in (
                resolved_cwd,
                *session_ws_agy,
                *self.policy._allowed_roots,
            ):
                if ws_cand and ws_cand not in allowed_ws:
                    allowed_ws.append(ws_cand)
            prevalidated_sb = await asyncio.to_thread(
                prepare_sandbox_runtime_state,
                self.config.sandbox_state_dir,
                lock_timeout_seconds=self.config.sandbox_lock_timeout_seconds,
                forbidden_roots=self._sandbox_forbidden_roots(),
            )
            prepared_agy_runtime = await asyncio.to_thread(
                prepare_agy_plugin_runtime,
                self.config,
                validated_plugins=validated_plugins,
                sandbox_state_root=prevalidated_sb,
                allowed_workspaces=allowed_ws,
                masked_paths=self._hook_jail_masked_paths(),
                readonly_subpaths=ro_hook_dirs,
                session_tag=session_id,
            )
            trusted_agy_env["HOME"] = prepared_agy_runtime.isolated_home_dir
            trusted_agy_env["PYTHONDONTWRITEBYTECODE"] = "1"
            agy_settings_env = await asyncio.to_thread(
                self.policy.build_agy_sandbox_settings,
                cwd=cwd,
                add_dirs=add_dirs,
                _validated_plugins=validated_plugins,
            )
            deny_read_roots: List[str] = []
            for r_str in (agy_settings_env.get("permissions") or {}).get("deny") or []:
                s_rule = str(r_str).strip()
                if s_rule.startswith("read_file(") and s_rule.endswith(")"):
                    deny_read_roots.append(
                        os.path.abspath(
                            os.path.expanduser(s_rule[len("read_file(") : -1].strip())
                        )
                    )

            def _eff_agy_plugin_dir(plg_item: Any) -> str:
                src_p = str(plg_item.source_dir)
                if self.policy.is_protected_path(src_p) or any(
                    src_p == dr or src_p.startswith(dr.rstrip("/") + "/")
                    for dr in deny_read_roots
                ):
                    return str(plg_item.vfs_discovery_dir)
                return src_p

            oma_plg = next(
                (p for p in validated_plugins if p.name == "oh-my-agents"), None
            )
            primary_plg = oma_plg or (
                validated_plugins[0] if len(validated_plugins) == 1 else None
            )
            if primary_plg is not None:
                trusted_agy_env["AGY_PLUGIN_ROOT"] = _eff_agy_plugin_dir(primary_plg)
            trusted_agy_env["AGY_REGISTERED_PLUGINS"] = os.pathsep.join(
                _eff_agy_plugin_dir(p) for p in validated_plugins
            )

        runtime_holder: List[Optional[PreparedAgentPluginRuntime]] = [prepared_agy_runtime]
        ro_subpaths_holder: List[List[str]] = [list(ro_hook_dirs)]
        expected_plugin_mounts = [(p.name, p.source_dir) for p in validated_plugins]
        expected_plugin_specs = [
            (p.name, p.source_dir, p.has_hooks, p.hooks_relpath)
            for p in validated_plugins
        ]

        def _revalidate_agy_plugins_before_spawn() -> None:
            latest_state = agy_plugins_config_state(self.config)
            current_plugins = []
            if latest_state.get("config_error") or latest_state.get("enabled"):
                current_plugins = self.policy.validate_agy_plugins(
                    cwd=cwd, add_dirs=add_dirs, require_mount_ns_check=True
                )
            current_specs = [
                (p.name, p.source_dir, p.has_hooks, p.hooks_relpath)
                for p in current_plugins
            ]
            if current_specs != expected_plugin_specs:
                raise PermissionError(
                    redact_diagnostic_text(
                        "AGY plugin registration changed while session was queued; "
                        "aborting queued session fail-closed.",
                        self.config,
                    )
                )

        def _refresh_agy_runtime_after_queue() -> Optional[PreparedAgentPluginRuntime]:
            _, fresh_ro_hook_dirs = self.policy.resolve_codex_git_metadata_dirs(
                cwd=cwd, add_dirs=add_dirs
            )
            ro_subpaths_holder[0] = list(fresh_ro_hook_dirs)
            if not validated_plugins or prevalidated_sb is None:
                return runtime_holder[0]
            current_plugins = self.policy.validate_agy_plugins(
                cwd=cwd, add_dirs=add_dirs, require_mount_ns_check=True
            )
            refreshed = prepare_agy_plugin_runtime(
                self.config,
                validated_plugins=current_plugins,
                sandbox_state_root=prevalidated_sb,
                allowed_workspaces=allowed_ws,
                masked_paths=self._hook_jail_masked_paths(),
                readonly_subpaths=fresh_ro_hook_dirs,
                session_tag=session_id,
            )
            runtime_holder[0] = refreshed
            return refreshed

        is_stream_json = output_format == "stream-json" or "--output-format=stream-json" in argv
        eff_timeout = self._resolve_timeout(
            timeout, self.config.agent_default_timeout_seconds
        )
        try:
            return await self.create_session(
                command=argv,
                cwd=cwd,
                env=caller_env,
                shell=False,
                use_pty=use_pty,
                stream_json=is_stream_json,
                timeout=eff_timeout,
                initial_stdin=initial_stdin,
                close_stdin=close_stdin,
                slot_sem=self._agy_sem,
                queue_timeout=self.config.agy_queue_timeout_seconds,
                is_agy=True,
                readonly_subpaths=ro_hook_dirs,
                readonly_subpaths_getter=lambda: ro_subpaths_holder[0],
                trusted_env=trusted_agy_env,
                agy_plugins_enabled=bool(validated_plugins),
                agy_plugin_mounts=expected_plugin_mounts,
                prepared_plugin_runtime=prepared_agy_runtime,
                prevalidated_sandbox_state=prevalidated_sb,
                pre_spawn_check=_revalidate_agy_plugins_before_spawn,
                refresh_plugin_runtime=_refresh_agy_runtime_after_queue,
                on_cleanup=lambda: cleanup_prepared_plugin_runtime(runtime_holder[0]),
                session_id_override=session_id,
                session_workdirs=session_ws_agy,
            )
        except BaseException:
            cleanup_prepared_plugin_runtime(runtime_holder[0])
            raise

    async def create_codex_session(
        self,
        prompt: Optional[str] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        args: Optional[Sequence[str]] = None,
        skip_permissions: Optional[bool] = None,
        sandbox_mode: Optional[str] = None,
        json_events: bool = False,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        search: bool = False,
        session_id: Optional[str] = None,
        continue_last: bool = False,
        review: bool = False,
        skip_git_repo_check: bool = True,
        ephemeral: bool = False,
        add_dirs: Optional[Sequence[str]] = None,
        use_pty: bool = False,
        timeout: Optional[float] = None,
        initial_stdin: Optional[str] = None,
        close_stdin: bool = True,
    ) -> ExecutionSession:
        """Create a dedicated `codex exec` session jailed to allowed_workdirs + isolated runtime."""
        def _validate_and_build_codex_inputs() -> Tuple[
            List[Any], str, List[str], List[str], List[str], Dict[str, str]
        ]:
            codex_plugins_state = codex_plugins_config_state(self.config)
            val_cx_plgs: List[Any] = []
            if codex_plugins_state.get("config_error") or codex_plugins_state.get("enabled"):
                val_cx_plgs = self.policy.validate_codex_plugins(
                    cwd=cwd, add_dirs=add_dirs, require_mount_ns_check=True
                )
            eff_sb = (
                self.config.codex_default_sandbox
                if sandbox_mode is None
                else str(sandbox_mode).strip()
            )
            ok_cwd_cx, cwd_err_cx, res_cwd_cx = self.policy.validate_workdir(cwd)
            if not ok_cwd_cx:
                raise PermissionError(cwd_err_cx)
            val_add_cx: List[str] = []
            if add_dirs:
                for d in add_dirs:
                    ok_d, d_err, resolved_d = self.policy.validate_workdir(str(d))
                    if not ok_d:
                        raise PermissionError(d_err)
                    if resolved_d not in val_add_cx:
                        val_add_cx.append(resolved_d)
            if val_cx_plgs and eff_sb == "workspace-write":
                self._ensure_codex_workspace_metadata_dirs(res_cwd_cx)
            built_cx_argv = self.policy.build_codex_argv(
                prompt=prompt,
                args=args,
                skip_permissions=skip_permissions,
                sandbox_mode=sandbox_mode,
                json_events=json_events,
                model=model,
                effort=effort,
                search=search,
                session_id=session_id,
                continue_last=continue_last,
                review=review,
                skip_git_repo_check=skip_git_repo_check,
                ephemeral=ephemeral,
                add_dirs=add_dirs,
                cwd=cwd,
            )
            _, ro_hooks_cx = self.policy.resolve_codex_git_metadata_dirs(
                cwd=cwd, add_dirs=add_dirs
            )
            loaded_cx_env = self._load_codex_env()
            return (
                val_cx_plgs,
                res_cwd_cx,
                val_add_cx,
                built_cx_argv,
                ro_hooks_cx,
                loaded_cx_env,
            )

        (
            validated_codex_plugins,
            resolved_cwd_codex,
            validated_add_dirs_codex,
            argv,
            ro_hook_dirs,
            trusted_codex_env,
        ) = await asyncio.to_thread(_validate_and_build_codex_inputs)
        for strip_plg_key in (
            "HOME",
            "AGY_PLUGIN_ROOT",
            "AGY_PLUGIN_DIRS",
            "AGY_REGISTERED_PLUGINS",
            "CODEX_PLUGIN_ROOT",
            "CODEX_PLUGIN_DIRS",
            "CODEX_REGISTERED_PLUGINS",
            "PLUGIN_ROOT",
            "PLUGIN_DATA",
            "CLAUDE_PLUGIN_ROOT",
            "CLAUDE_PLUGIN_DATA",
            "CLAUDE_PROJECT_DIR",
            "AGY_PROJECT_DIR",
            "HARNESS_PROJECT_DIR",
            "OH_MY_AGENTS_ROOT",
        ):
            trusted_codex_env.pop(strip_plg_key, None)

        gw_session_id = f"sess_{uuid.uuid4().hex[:16]}"
        prevalidated_sb: Optional[Path] = None
        prepared_codex_runtime: Optional[PreparedAgentPluginRuntime] = None
        allowed_ws_codex: List[str] = []
        if validated_codex_plugins:
            trusted_codex_env.pop("CODEX_HOME", None)
            for ws_cand in (
                resolved_cwd_codex,
                *validated_add_dirs_codex,
                *self.policy._allowed_roots,
            ):
                if ws_cand and ws_cand not in allowed_ws_codex:
                    allowed_ws_codex.append(ws_cand)
            prevalidated_sb = await asyncio.to_thread(
                prepare_sandbox_runtime_state,
                self.config.sandbox_state_dir,
                lock_timeout_seconds=self.config.sandbox_lock_timeout_seconds,
                forbidden_roots=self._sandbox_forbidden_roots(),
            )
            prepared_codex_runtime = await asyncio.to_thread(
                prepare_codex_plugin_runtime,
                self.config,
                validated_plugins=validated_codex_plugins,
                sandbox_state_root=prevalidated_sb,
                allowed_workspaces=allowed_ws_codex,
                masked_paths=self._hook_jail_masked_paths(),
                readonly_subpaths=ro_hook_dirs,
                session_tag=gw_session_id,
            )
            trusted_codex_env["HOME"] = prepared_codex_runtime.isolated_home_dir
            trusted_codex_env["CODEX_HOME"] = str(
                prepared_codex_runtime.vfs_codex_home_dir
            )
            trusted_codex_env["PYTHONDONTWRITEBYTECODE"] = "1"
            oma_plg = next(
                (p for p in validated_codex_plugins if p.name == "oh-my-agents"), None
            )
            primary_plg = oma_plg or (
                validated_codex_plugins[0] if len(validated_codex_plugins) == 1 else None
            )
            if primary_plg is not None:
                trusted_codex_env["CODEX_PLUGIN_ROOT"] = (
                    primary_plg.vfs_discovery_dir
                    if self.policy.is_protected_path(primary_plg.source_dir)
                    else primary_plg.source_dir
                )
            trusted_codex_env["CODEX_REGISTERED_PLUGINS"] = os.pathsep.join(
                (
                    p.vfs_discovery_dir
                    if self.policy.is_protected_path(p.source_dir)
                    else p.source_dir
                )
                for p in validated_codex_plugins
            )

        codex_runtime_holder: List[Optional[PreparedAgentPluginRuntime]] = [prepared_codex_runtime]
        codex_ro_subpaths_holder: List[List[str]] = [list(ro_hook_dirs)]
        expected_codex_mounts = [(p.name, p.source_dir) for p in validated_codex_plugins]
        expected_codex_specs = [
            (p.name, p.source_dir, p.marketplace_name, p.version, p.has_hooks, p.hooks_relpath)
            for p in validated_codex_plugins
        ]

        def _revalidate_codex_plugins_before_spawn() -> None:
            latest_state = codex_plugins_config_state(self.config)
            current_plugins = []
            if latest_state.get("config_error") or latest_state.get("enabled"):
                current_plugins = self.policy.validate_codex_plugins(
                    cwd=cwd, add_dirs=add_dirs, require_mount_ns_check=True
                )
            current_specs = [
                (p.name, p.source_dir, p.marketplace_name, p.version, p.has_hooks, p.hooks_relpath)
                for p in current_plugins
            ]
            if current_specs != expected_codex_specs:
                raise PermissionError(
                    redact_diagnostic_text(
                        "Codex plugin registration changed while session was queued; "
                        "aborting queued session fail-closed.",
                        self.config,
                    )
                )

        def _refresh_codex_runtime_after_queue() -> Optional[PreparedAgentPluginRuntime]:
            _, fresh_ro_hook_dirs = self.policy.resolve_codex_git_metadata_dirs(
                cwd=cwd, add_dirs=add_dirs
            )
            codex_ro_subpaths_holder[0] = list(fresh_ro_hook_dirs)
            if not validated_codex_plugins or prevalidated_sb is None:
                return codex_runtime_holder[0]
            current_plugins = self.policy.validate_codex_plugins(
                cwd=cwd, add_dirs=add_dirs, require_mount_ns_check=True
            )
            refreshed = prepare_codex_plugin_runtime(
                self.config,
                validated_plugins=current_plugins,
                sandbox_state_root=prevalidated_sb,
                allowed_workspaces=allowed_ws_codex,
                masked_paths=self._hook_jail_masked_paths(),
                readonly_subpaths=fresh_ro_hook_dirs,
                session_tag=gw_session_id,
            )
            codex_runtime_holder[0] = refreshed
            return refreshed

        caller_env = {str(k): str(v) for k, v in env.items()} if env else {}
        is_stream_json = json_events or "--json" in argv
        eff_timeout = self._resolve_timeout(
            timeout, self.config.agent_default_timeout_seconds
        )
        try:
            return await self.create_session(
                command=argv,
                cwd=cwd,
                env=caller_env,
                shell=False,
                use_pty=use_pty,
                stream_json=is_stream_json,
                timeout=eff_timeout,
                initial_stdin=initial_stdin,
                close_stdin=close_stdin,
                slot_sem=self._codex_sem,
                queue_timeout=self.config.agy_queue_timeout_seconds,
                is_codex=True,
                readonly_subpaths=ro_hook_dirs,
                readonly_subpaths_getter=lambda: codex_ro_subpaths_holder[0],
                trusted_env=trusted_codex_env,
                codex_plugins_enabled=bool(validated_codex_plugins),
                codex_plugin_mounts=expected_codex_mounts,
                prepared_plugin_runtime=prepared_codex_runtime,
                prevalidated_sandbox_state=prevalidated_sb,
                pre_spawn_check=_revalidate_codex_plugins_before_spawn,
                refresh_plugin_runtime=_refresh_codex_runtime_after_queue,
                on_cleanup=lambda: cleanup_prepared_plugin_runtime(codex_runtime_holder[0]),
                session_id_override=gw_session_id,
                session_workdirs=[resolved_cwd_codex, *validated_add_dirs_codex],
            )
        except BaseException:
            cleanup_prepared_plugin_runtime(codex_runtime_holder[0])
            raise

    def get_session(
        self, session_id: str
    ) -> Optional[Union[ExecutionSession, PersistedSession]]:
        live = self._sessions.get(session_id)
        if live is not None:
            return live
        return self._persisted.get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        combined: List[Union[ExecutionSession, PersistedSession]] = list(
            self._sessions.values()
        )
        for sid, ps in self._persisted.items():
            if sid not in self._sessions:
                combined.append(ps)
        combined.sort(key=lambda x: x.started_at, reverse=True)
        return [s.to_summary(include_output=False) for s in combined]
