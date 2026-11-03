"""Asynchronous process & bidirectional session manager for the Dots Gateway."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import shlex
import signal
import struct
import termios
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

from .config import GatewayConfig
from .policy import CommandPolicy
from .sandbox import (
    build_mount_ns_argv,
    cleanup_sandbox_state,
    get_sandbox_disk_status,
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
            if tok == "--resume" and i + 1 < len(argv):
                cand = argv[i + 1].strip()
                if cand and not cand.startswith("-"):
                    return cand
            elif tok.startswith("--resume="):
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
        except Exception:
            self._release_slot()
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
            self.ended_at = time.time()
            self.returncode = -1
            self.status = "failed"
            self._emit("error", str(exc))
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

    async def run_sandbox_cleanup(self) -> Dict[str, Any]:
        """Run non-blocking sandbox LRU lifecycle sweep in a worker thread."""
        async with self._sandbox_cleanup_lock:
            summary = await asyncio.to_thread(
                cleanup_sandbox_state,
                self.config.sandbox_state_dir,
                self.config.sandbox_max_retention_days,
                self.config.sandbox_min_retention_days,
                self.config.sandbox_low_space_free_gb,
                self.config.sandbox_low_space_free_percent,
            )
            self._last_sandbox_cleanup = summary
            return summary

    def _prepare_env(self, extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in _STRIPPED_ENV_KEYS
        }
        local_bin = str(os.path.expanduser("~/.local/bin"))
        current_path = env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        parts = [p for p in current_path.split(os.pathsep) if p]
        for required_dir in ("/usr/local/bin", local_bin):
            if required_dir not in parts:
                parts.insert(0, required_dir)
        env["PATH"] = os.pathsep.join(parts)
        if env.get("TERM") in (None, "", "dumb"):
            env["TERM"] = "xterm-256color"
        if self.config.isolate_mount_namespace:
            env["TMPDIR"] = "/tmp"
        elif self.config.sandbox_state_dir:
            try:
                sb_tmp_p = Path(self.config.sandbox_state_dir).expanduser().resolve() / "tmp"
                sb_tmp_p.mkdir(parents=True, exist_ok=True)
                env["TMPDIR"] = str(sb_tmp_p)
            except OSError:
                pass
        if extra_env:
            for k, v in extra_env.items():
                env[str(k)] = str(v)
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
    ) -> ExecutionSession:
        """Validate command against security policy and start an ExecutionSession."""
        if self.active_count() >= self.config.max_concurrent_sessions:
            raise RuntimeError(
                f"Maximum concurrent sessions ({self.config.max_concurrent_sessions}) reached"
            )

        decision = self.policy.validate_command(
            command, cwd=cwd, _trusted_agy_argv=is_agy
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)

        assert decision.normalized_argv is not None
        effective_timeout = (
            self.config.default_timeout_seconds if timeout is None else float(timeout)
        )
        if effective_timeout > self.config.max_timeout_seconds:
            effective_timeout = self.config.max_timeout_seconds

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

        spawn_argv: Optional[List[str]] = None
        if self.config.isolate_mount_namespace:
            target_exec = (
                ["/bin/bash", "-c", shell_cmd]
                if shell_cmd is not None
                else list(decision.normalized_argv)
            )
            spawn_argv = build_mount_ns_argv(
                target_argv=target_exec,
                cwd=decision.resolved_cwd,
                allowed_workdirs=self.config.allowed_workdirs,
                protected_paths=self.config.protected_paths,
                is_agy=is_agy,
                is_codex=is_codex,
                readonly_subpaths=readonly_subpaths,
                sandbox_state_dir=self.config.sandbox_state_dir,
            )

        self._cleanup_old_sessions()
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        session = ExecutionSession(
            session_id=session_id,
            argv=decision.normalized_argv,
            cwd=decision.resolved_cwd,
            env=self._prepare_env(env),
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
        )
        self._sessions[session_id] = session
        await session.start(initial_stdin=initial_stdin, close_stdin=close_stdin)
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
        argv = self.policy.build_agy_argv(
            prompt=prompt,
            args=args,
            skip_permissions=skip_permissions,
            print_mode=print_mode,
            output_format=output_format,
            input_format=input_format,
            model=model,
            effort=effort,
            mode=mode,
            conversation_id=conversation_id,
            continue_last=continue_last,
            add_dirs=add_dirs,
            cwd=cwd,
        )
        _, ro_hook_dirs = self.policy.resolve_codex_git_metadata_dirs(
            cwd=cwd, add_dirs=add_dirs
        )
        is_stream_json = output_format == "stream-json" or "--output-format=stream-json" in argv
        eff_timeout = (
            self.config.agent_default_timeout_seconds
            if timeout is None
            else float(timeout)
        )
        return await self.create_session(
            command=argv,
            cwd=cwd,
            env=env,
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
        )

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
        """Create a dedicated `codex exec` session jailed to allowed_workdirs + `~/.codex`."""
        argv = self.policy.build_codex_argv(
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
        _, ro_hook_dirs = self.policy.resolve_codex_git_metadata_dirs(
            cwd=cwd, add_dirs=add_dirs
        )
        merged_env = self._load_codex_env()
        if env:
            for k, v in env.items():
                merged_env[str(k)] = str(v)
        is_stream_json = json_events or "--json" in argv
        eff_timeout = (
            self.config.agent_default_timeout_seconds
            if timeout is None
            else float(timeout)
        )
        return await self.create_session(
            command=argv,
            cwd=cwd,
            env=merged_env,
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
        )

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
