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
from pathlib import Path
from typing import Any, AsyncIterator, Deque, Dict, List, Optional, Sequence, Tuple, Union

from .config import GatewayConfig
from .policy import CommandPolicy
from .sandbox import build_mount_ns_argv

STREAM_LINE_LIMIT = 16 * 1024 * 1024  # 16 MiB asyncio StreamReader buffer limit
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

        self.status: str = "starting"
        self.pid: Optional[int] = None
        self.returncode: Optional[int] = None
        self.started_at: float = time.time()
        self.ended_at: Optional[float] = None

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

    def _append_stdout(self, text: str) -> None:
        b_len = len(text.encode("utf-8", errors="replace"))
        self._stdout_chunks.append((b_len, text))
        self._stdout_bytes += b_len
        while self._stdout_bytes > self.max_output_bytes and len(self._stdout_chunks) > 1:
            old_len, _ = self._stdout_chunks.popleft()
            self._stdout_bytes -= old_len
            self.stdout_truncated = True

    def _append_stderr(self, text: str) -> None:
        b_len = len(text.encode("utf-8", errors="replace"))
        self._stderr_chunks.append((b_len, text))
        self._stderr_bytes += b_len
        while self._stderr_bytes > self.max_output_bytes and len(self._stderr_chunks) > 1:
            old_len, _ = self._stderr_chunks.popleft()
            self._stderr_bytes -= old_len
            self.stderr_truncated = True

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
            self._emit(
                "queued",
                {"message": "Waiting for available agy concurrency slot", "cwd": self.cwd},
            )
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

        self._emit(
            "exit",
            {
                "returncode": self.returncode,
                "status": self.status,
                "duration_seconds": round(self.ended_at - self.started_at, 4),
            },
        )
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
        res: Dict[str, Any] = {
            "session_id": self.session_id,
            "status": self.status,
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


class SessionManager:
    """Manages active and historical ExecutionSessions with policy validation."""

    def __init__(self, config: GatewayConfig, policy: CommandPolicy) -> None:
        self.config = config
        self.policy = policy
        self._sessions: Dict[str, ExecutionSession] = {}
        self._agy_sem = asyncio.Semaphore(max(1, config.max_concurrent_agy))

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
        if extra_env:
            for k, v in extra_env.items():
                env[str(k)] = str(v)
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
        if len(self._sessions) <= 100:
            return
        completed = [
            s for s in self._sessions.values() if s.status not in ("queued", "starting", "running")
        ]
        completed.sort(key=lambda s: s.ended_at or 0.0)
        for s in completed[: len(self._sessions) - 100]:
            self._sessions.pop(s.session_id, None)

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
    ) -> ExecutionSession:
        """Validate command against security policy and start an ExecutionSession."""
        if self.active_count() >= self.config.max_concurrent_sessions:
            raise RuntimeError(
                f"Maximum concurrent sessions ({self.config.max_concurrent_sessions}) reached"
            )

        decision = self.policy.validate_command(command, cwd=cwd)
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
                if shell_cmd.strip().startswith("agy ") and os.path.exists(self.config.agy_binary):
                    shell_cmd = self.config.agy_binary + shell_cmd.strip()[3:]
                elif shell_cmd.strip().startswith("codex ") and os.path.exists(self.config.codex_binary):
                    shell_cmd = self.config.codex_binary + shell_cmd.strip()[5:]
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
        )
        is_stream_json = output_format == "stream-json" or "--output-format=stream-json" in argv
        return await self.create_session(
            command=argv,
            cwd=cwd,
            env=env,
            shell=False,
            use_pty=use_pty,
            stream_json=is_stream_json,
            timeout=timeout,
            initial_stdin=initial_stdin,
            close_stdin=close_stdin,
            slot_sem=self._agy_sem,
            queue_timeout=self.config.agy_queue_timeout_seconds,
            is_agy=True,
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
        )
        merged_env = self._load_codex_env()
        if env:
            for k, v in env.items():
                merged_env[str(k)] = str(v)
        is_stream_json = json_events or "--json" in argv
        eff_timeout = 1800.0 if timeout is None else float(timeout)
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
            slot_sem=self._agy_sem,
            queue_timeout=self.config.agy_queue_timeout_seconds,
            is_codex=True,
        )

    def get_session(self, session_id: str) -> Optional[ExecutionSession]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return [
            s.to_summary(include_output=False)
            for s in sorted(
                self._sessions.values(), key=lambda x: x.started_at, reverse=True
            )
        ]
