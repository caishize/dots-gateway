"""Unified real-time progress tracking, semantic summarization, and final output extraction."""

from __future__ import annotations

import json
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple


def _compact_text(text: Any, max_len: int = 180) -> str:
    """Collapse whitespace and truncate text to a single readable summary line."""
    if text is None:
        return ""
    s = " ".join(str(text).split()).strip()
    if len(s) > max_len:
        return s[: max_len - 3].rstrip() + "..."
    return s


def _summarize_tool_input(tool_name: str, tool_input: Any) -> str:
    """Extract a concise human-readable hint from a tool_use input dict."""
    if isinstance(tool_input, str):
        return _compact_text(tool_input, 120)
    if not isinstance(tool_input, dict):
        return ""
    for key in (
        "command",
        "cmd",
        "file_path",
        "path",
        "target_file",
        "pattern",
        "query",
        "url",
        "description",
        "prompt",
        "cwd",
    ):
        val = tool_input.get(key)
        if isinstance(val, str) and val.strip():
            return _compact_text(val, 120)
    # Fallback: first short non-blob string field
    skip_keys = {
        "content",
        "new_string",
        "old_string",
        "replacement",
        "target",
        "diff",
        "patch",
        "code",
        "body",
        "token",
        "secret",
        "password",
        "api_key",
    }
    for k, v in tool_input.items():
        if str(k).lower() in skip_keys:
            continue
        if isinstance(v, str) and v.strip():
            return _compact_text(f"{k}={v}", 120)
    return ""


def _extract_content_blocks(content: Any) -> Tuple[List[Tuple[str, str, bool]], List[str]]:
    """Parse Anthropic/AGY-style message content (str or list of content blocks).

    Returns `(activities, text_parts)` where each activity is `(kind, summary, is_milestone)`.
    """
    activities: List[Tuple[str, str, bool]] = []
    text_parts: List[str] = []

    if isinstance(content, str):
        if content.strip():
            text_parts.append(content)
        return activities, text_parts

    if not isinstance(content, list):
        return activities, text_parts

    for block in content:
        if isinstance(block, str):
            if block.strip():
                text_parts.append(block)
            continue
        if not isinstance(block, dict):
            continue
        btype = str(block.get("type") or "").strip().lower()
        if btype == "text":
            txt = block.get("text")
            if isinstance(txt, str) and txt.strip():
                text_parts.append(txt)
        elif btype == "thinking":
            thinking = block.get("thinking") or block.get("text") or ""
            hint = _compact_text(thinking, 120)
            activities.append(
                ("thinking", f"Thinking: {hint}" if hint else "Thinking...", False)
            )
        elif btype in ("tool_use", "tool_call", "function_call"):
            tname = str(block.get("name") or block.get("tool") or "tool").strip()
            hint = _summarize_tool_input(tname, block.get("input") or block.get("arguments"))
            summary = f"Tool {tname}: {hint}" if hint else f"Tool {tname}"
            activities.append(("tool_use", summary, True))
        elif btype == "tool_result":
            is_err = bool(block.get("is_error", False))
            res_content = block.get("content")
            if isinstance(res_content, list):
                joined = " ".join(
                    str(c.get("text") or "") for c in res_content if isinstance(c, dict)
                )
            else:
                joined = str(res_content or "")
            hint = _compact_text(joined, 120)
            if is_err:
                activities.append(
                    ("tool_result", f"Tool error: {hint}" if hint else "Tool error", True)
                )
            else:
                activities.append(
                    ("tool_result", f"Tool done: {hint}" if hint else "Tool finished", False)
                )

    return activities, text_parts


def parse_agent_event(session_kind: str, obj: Any) -> Dict[str, Any]:
    """Parse a structured NDJSON event emitted by `claude`, `agy`, or `codex`.

    Returns:
      {
        "recognized": bool,
        "activities": List[Tuple[str, str, bool]],  # (kind, summary, is_milestone)
        "assistant_text": Optional[str],
        "final_text": Optional[str],
        "is_step": bool,
      }
    """
    result: Dict[str, Any] = {
        "recognized": False,
        "activities": [],
        "assistant_text": None,
        "final_text": None,
        "is_step": False,
    }
    if not isinstance(obj, dict):
        return result

    ev_type = str(obj.get("type") or "").strip()
    ev_name = str(obj.get("event") or "").strip()
    kind_tag = (ev_type or ev_name).lower()

    if not kind_tag:
        return result

    activities: List[Tuple[str, str, bool]] = result["activities"]

    # ------------------------------------------------------------------
    # 1. OpenAI Codex (`codex exec --json`) events
    # ------------------------------------------------------------------
    if kind_tag == "thread.started":
        result["recognized"] = True
        tid = str(obj.get("thread_id") or "").strip()
        activities.append(
            ("init", f"Codex thread started ({tid[:12]})" if tid else "Codex thread started", True)
        )
        return result

    if kind_tag == "turn.started":
        result["recognized"] = True
        activities.append(("turn", "Codex turn started", True))
        return result

    if kind_tag == "turn.completed":
        result["recognized"] = True
        result["is_step"] = True
        usage = obj.get("usage") if isinstance(obj.get("usage"), dict) else {}
        out_tok = usage.get("output_tokens")
        msg = f"Codex turn completed ({out_tok} output tokens)" if out_tok else "Codex turn completed"
        activities.append(("result", msg, True))
        return result

    if kind_tag in ("turn.failed", "thread.failed"):
        result["recognized"] = True
        err = obj.get("error")
        err_msg = err.get("message") if isinstance(err, dict) else str(err or obj.get("message") or "")
        activities.append(("error", f"Codex error: {_compact_text(err_msg, 160)}", True))
        return result

    if kind_tag in ("item.started", "item.updated", "item.completed") and isinstance(
        obj.get("item"), dict
    ):
        result["recognized"] = True
        item = obj["item"]
        itype = str(item.get("type") or "").strip().lower()
        is_completed = kind_tag == "item.completed"

        if itype == "command_execution":
            cmd = _compact_text(item.get("command") or "", 120)
            if is_completed:
                result["is_step"] = True
                rc = item.get("exit_code")
                rc_str = f" (exit {rc})" if rc is not None else ""
                activities.append(("tool_result", f"Command finished{rc_str}: {cmd}", True))
            elif kind_tag == "item.started":
                activities.append(("tool_use", f"Running command: {cmd}", True))
        elif itype == "file_change":
            changes = item.get("changes") if isinstance(item.get("changes"), list) else []
            paths = [
                str(c.get("path") or "")
                for c in changes[:4]
                if isinstance(c, dict) and c.get("path")
            ]
            suffix = f" (+{len(changes) - 4} more)" if len(changes) > 4 else ""
            summary = f"Edited files: {', '.join(paths)}{suffix}" if paths else "Edited files"
            if is_completed:
                result["is_step"] = True
            activities.append(("tool_use", summary, True))
        elif itype == "mcp_tool_call":
            srv = str(item.get("server") or "").strip()
            tool = str(item.get("tool") or "").strip()
            label = f"{srv}.{tool}".strip(".") or "mcp_tool"
            if is_completed:
                result["is_step"] = True
                activities.append(("tool_result", f"MCP tool finished: {label}", True))
            elif kind_tag == "item.started":
                activities.append(("tool_use", f"MCP tool: {label}", True))
        elif itype == "web_search":
            q = _compact_text(item.get("query") or "", 120)
            if is_completed:
                result["is_step"] = True
            activities.append(("tool_use", f"Web search: {q}" if q else "Web search", True))
        elif itype == "reasoning":
            rtxt = _compact_text(item.get("text") or "", 140)
            if rtxt:
                activities.append(("thinking", f"Reasoning: {rtxt}", False))
        elif itype == "agent_message":
            msg_text = item.get("text")
            if isinstance(msg_text, str) and msg_text.strip():
                result["assistant_text"] = msg_text
                if is_completed:
                    result["final_text"] = msg_text
                    result["is_step"] = True
                activities.append(
                    ("assistant", f"Assistant: {_compact_text(msg_text, 160)}", is_completed)
                )
        elif itype == "error":
            err_txt = _compact_text(item.get("message") or item.get("text") or "", 160)
            activities.append(("error", f"Error: {err_txt}", True))
        return result

    # ------------------------------------------------------------------
    # 2. Claude Code (`claude -p --output-format stream-json --verbose`)
    #    & Antigravity (`agy --output-format stream-json`)
    # ------------------------------------------------------------------
    if kind_tag in ("system", "init", "session", "session_meta"):
        result["recognized"] = True
        subtype = str(obj.get("subtype") or "").strip()
        model = str(obj.get("model") or "").strip()
        if subtype == "init" or kind_tag in ("init", "session"):
            label = f"Session initialized (model={model})" if model else "Session initialized"
            activities.append(("init", label, True))
        elif subtype:
            activities.append(("status", f"System: {subtype}", False))
        return result

    if kind_tag in ("assistant", "message"):
        result["recognized"] = True
        msg_obj = obj.get("message") if isinstance(obj.get("message"), dict) else obj
        content = msg_obj.get("content")
        blk_acts, txt_parts = _extract_content_blocks(content)
        if not txt_parts and isinstance(obj.get("text"), str) and obj["text"].strip():
            txt_parts.append(obj["text"])
        for act in blk_acts:
            activities.append(act)
            if act[0] == "tool_use":
                result["is_step"] = True
        if txt_parts:
            joined = "\n".join(txt_parts).strip()
            result["assistant_text"] = joined
            activities.append(("assistant", f"Assistant: {_compact_text(joined, 160)}", False))
        return result

    if kind_tag == "user":
        msg_obj = obj.get("message") if isinstance(obj.get("message"), dict) else obj
        blk_acts, _ = _extract_content_blocks(msg_obj.get("content"))
        if blk_acts:
            result["recognized"] = True
            activities.extend(blk_acts)
        return result

    if kind_tag in ("tool_use", "tool_call", "function_call"):
        result["recognized"] = True
        result["is_step"] = True
        tname = str(obj.get("name") or obj.get("tool") or obj.get("tool_name") or "tool").strip()
        hint = _summarize_tool_input(
            tname, obj.get("input") or obj.get("arguments") or obj.get("args")
        )
        activities.append(("tool_use", f"Tool {tname}: {hint}" if hint else f"Tool {tname}", True))
        return result

    if kind_tag == "tool_result":
        result["recognized"] = True
        tname = str(obj.get("name") or obj.get("tool") or "").strip()
        is_err = bool(obj.get("is_error", False))
        hint = _compact_text(obj.get("output") or obj.get("content") or obj.get("result") or "", 120)
        prefix = f"Tool {tname}" if tname else "Tool"
        if is_err:
            activities.append(("tool_result", f"{prefix} error: {hint}" if hint else f"{prefix} error", True))
        else:
            activities.append(("tool_result", f"{prefix} done: {hint}" if hint else f"{prefix} finished", False))
        return result

    if kind_tag in ("stream_event", "content_block_delta", "delta", "assistant_delta"):
        result["recognized"] = True
        inner = obj.get("event") if isinstance(obj.get("event"), dict) else obj
        delta = inner.get("delta") if isinstance(inner.get("delta"), dict) else {}
        dtxt = delta.get("text") or obj.get("text") or obj.get("delta")
        if isinstance(dtxt, str) and dtxt.strip():
            activities.append(("delta", _compact_text(dtxt, 140), False))
        return result

    if kind_tag in ("result", "done", "complete", "completed", "turn_complete"):
        result["recognized"] = True
        result["is_step"] = True
        res_val = obj.get("result")
        if not isinstance(res_val, str):
            res_val = obj.get("text")
        if not isinstance(res_val, str) and isinstance(obj.get("message"), dict):
            _, parts = _extract_content_blocks(obj["message"].get("content"))
            res_val = "\n".join(parts) if parts else None
        if isinstance(res_val, str):
            result["final_text"] = res_val
        num_turns = obj.get("num_turns")
        is_err = bool(obj.get("is_error", False))
        if is_err:
            err_preview = _compact_text(res_val or obj.get("error") or "failed", 160)
            activities.append(("error", f"Result error: {err_preview}", True))
        else:
            turn_note = f" ({num_turns} turns)" if num_turns else ""
            activities.append(("result", f"Completed{turn_note}", True))
        return result

    if kind_tag == "error":
        # Only recognize standard agent error envelopes (avoid matching arbitrary user JSON)
        if any(k in obj for k in ("message", "error", "detail")):
            result["recognized"] = True
            err_val = obj.get("message") or obj.get("error") or obj.get("detail")
            if isinstance(err_val, dict):
                err_val = err_val.get("message") or json.dumps(err_val, ensure_ascii=False)
            activities.append(("error", f"Error: {_compact_text(err_val, 160)}", True))
        return result

    return result


def extract_final_output_from_text(session_kind: str, stdout: str) -> Tuple[Optional[str], bool]:
    """Parse buffered NDJSON stdout to extract clean final assistant output.

    Returns `(final_output_or_None, recognized_structured_events)`.
    """
    if not stdout or session_kind == "exec":
        return None, False

    recognized = False
    final_text: Optional[str] = None
    last_assistant: Optional[str] = None

    for raw_line in stdout.splitlines():
        s = raw_line.strip()
        if not s.startswith("{") or not s.endswith("}"):
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        parsed = parse_agent_event(session_kind, obj)
        if parsed["recognized"]:
            recognized = True
            if parsed["final_text"] is not None:
                final_text = parsed["final_text"]
            if parsed["assistant_text"]:
                last_assistant = parsed["assistant_text"]

    if not recognized:
        return None, False
    if final_text is not None:
        return final_text, True
    if last_assistant is not None:
        return last_assistant, True
    return "", True


class SessionProgressTracker:
    """Real-time structured progress tracker embedded in each `ExecutionSession`."""

    def __init__(
        self,
        session_kind: str,
        *,
        stream_json: bool = False,
        max_recent_activities: int = 25,
    ) -> None:
        self.session_kind = session_kind
        self.stream_json = stream_json
        self.phase: str = "starting"
        self.steps_completed: int = 0
        self.current_activity: str = "Starting..."
        self.recent_activities: Deque[Dict[str, Any]] = deque(maxlen=max_recent_activities)
        self.last_output_line: str = ""
        self.last_event_at: float = time.time()
        self.recognized_structured_events: bool = False
        self._explicit_final_output: Optional[str] = None
        self._last_assistant_text: Optional[str] = None
        self._event_summaries: Dict[int, Tuple[str, bool]] = {}

    _KIND_PRIORITY: Dict[str, int] = {
        "error": 70,
        "result": 60,
        "tool_use": 50,
        "init": 45,
        "turn": 40,
        "assistant": 30,
        "tool_result": 20,
        "thinking": 10,
        "delta": 5,
    }

    def _record_activity(
        self,
        seq: int,
        ts: float,
        kind: str,
        summary: str,
        milestone: bool,
        *,
        update_seq_summary: bool = True,
    ) -> None:
        clean = _compact_text(summary, 240)
        if not clean:
            return
        self.current_activity = clean
        if self.recent_activities and self.recent_activities[-1]["summary"] == clean:
            self.recent_activities[-1]["ts"] = ts
            self.recent_activities[-1]["seq"] = seq
        else:
            self.recent_activities.append(
                {"seq": seq, "ts": ts, "kind": kind, "summary": clean}
            )
        if update_seq_summary:
            self._event_summaries[seq] = (clean, milestone)
            if len(self._event_summaries) > 4096:
                # Keys are strictly monotonic `seq` integers; trim oldest half in O(1) slice
                for k in list(self._event_summaries.keys())[:2048]:
                    self._event_summaries.pop(k, None)

    def on_event(self, ev: Any) -> Optional[Tuple[str, bool]]:
        """Update live progress from a `SessionEvent`.

        Returns `(summary_message, is_milestone)` if this event yields a readable summary,
        or `None` when the event is suppressed (e.g., duplicate raw JSON stdout line).
        """
        self.last_event_at = ev.timestamp
        etype = ev.type

        if etype == "queued":
            self.phase = "queued"
            raw_msg = (
                ev.data.get("message")
                if isinstance(ev.data, dict) and ev.data.get("message")
                else "Waiting for available concurrency slot"
            )
            msg = f"[queued] {raw_msg}"
            self._record_activity(ev.seq, ev.timestamp, "queued", msg, True)
            return msg, True

        if etype == "started":
            self.phase = "running"
            pid = ev.data.get("pid") if isinstance(ev.data, dict) else None
            msg = (
                f"[started] {self.session_kind} (pid={pid})"
                if pid
                else f"[started] {self.session_kind}"
            )
            self._record_activity(ev.seq, ev.timestamp, "started", msg, True)
            return msg, True

        if etype == "agy_event":
            parsed = parse_agent_event(self.session_kind, ev.data)
            if parsed["recognized"]:
                self.recognized_structured_events = True
                if parsed["is_step"]:
                    self.steps_completed += 1
                if parsed["final_text"] is not None:
                    self._explicit_final_output = parsed["final_text"]
                if parsed["assistant_text"]:
                    self._last_assistant_text = parsed["assistant_text"]
                best_choice: Optional[Tuple[int, str, bool]] = None
                for act_kind, act_summary, is_ms in parsed["activities"]:
                    self._record_activity(
                        ev.seq,
                        ev.timestamp,
                        act_kind,
                        act_summary,
                        is_ms,
                        update_seq_summary=False,
                    )
                    prio = (100 if is_ms else 0) + self._KIND_PRIORITY.get(act_kind, 15)
                    clean = _compact_text(act_summary, 240)
                    if clean and (best_choice is None or prio >= best_choice[0]):
                        best_choice = (prio, clean, is_ms)
                if best_choice is not None:
                    self.current_activity = best_choice[1]
                    self._event_summaries[ev.seq] = (best_choice[1], best_choice[2])
                    if len(self._event_summaries) > 4096:
                        for k in list(self._event_summaries.keys())[:2048]:
                            self._event_summaries.pop(k, None)
                    return best_choice[1], best_choice[2]
                return None
            # Unrecognized JSON object in stream_json mode (e.g. custom CLI JSON output)
            snippet = _compact_text(json.dumps(ev.data, ensure_ascii=False), 180)
            if snippet:
                self.last_output_line = snippet
                self._record_activity(ev.seq, ev.timestamp, "output", snippet, False)
                return snippet, False
            return None

        if etype == "stdout":
            text = str(ev.data or "")
            if self.stream_json:
                # When stream_json=True, valid JSON lines are immediately followed by `agy_event`.
                # Suppress duplicate summary here so subscribers never receive double progress.
                stripped = text.strip()
                if stripped.startswith("{") and stripped.endswith("}"):
                    try:
                        json.loads(stripped)
                        return None
                    except json.JSONDecodeError:
                        pass
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if lines:
                last_ln = _compact_text(lines[-1], 220)
                self.last_output_line = last_ln
                self._record_activity(ev.seq, ev.timestamp, "stdout", last_ln, False)
                return last_ln, False
            return None

        if etype == "stderr":
            text = str(ev.data or "")
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if lines:
                last_ln = _compact_text(lines[-1], 220)
                self.last_output_line = last_ln
                msg = f"stderr: {last_ln}"
                self._record_activity(ev.seq, ev.timestamp, "stderr", msg, False)
                return msg, False
            return None

        if etype == "error":
            msg = f"[error] {_compact_text(ev.data, 200)}"
            self._record_activity(ev.seq, ev.timestamp, "error", msg, True)
            return msg, True

        if etype == "exit":
            status = (
                str(ev.data.get("status") or "completed")
                if isinstance(ev.data, dict)
                else "completed"
            )
            rc = ev.data.get("returncode") if isinstance(ev.data, dict) else None
            dur = ev.data.get("duration_seconds") if isinstance(ev.data, dict) else None
            self.phase = status
            dur_str = f" in {dur}s" if dur is not None else ""
            msg = f"[exit] Finished ({status}, exit={rc}{dur_str})"
            self._record_activity(ev.seq, ev.timestamp, "exit", msg, True)
            return msg, True

        return None

    def get_summary_for_event(self, ev: Any) -> Optional[Tuple[str, bool]]:
        """Retrieve cached `(summary, is_milestone)` for an already-emitted `SessionEvent`."""
        return self._event_summaries.get(ev.seq)

    def get_final_output(self, raw_stdout: str) -> str:
        """Return clean extracted final assistant text if structured events were seen, else raw stdout."""
        if not self.recognized_structured_events:
            return raw_stdout
        if self._explicit_final_output is not None:
            return self._explicit_final_output
        if self._last_assistant_text is not None:
            return self._last_assistant_text
        return raw_stdout

    def to_dict(
        self,
        *,
        session_id: str,
        status: str,
        process_alive: bool,
        stream_mode: str,
        started_at: float,
        ended_at: Optional[float],
        stdout_bytes: int,
        stderr_bytes: int,
        last_seq: int,
        agent_conversation_id: Optional[str],
        returncode: Optional[int],
        after_seq: int = 0,
    ) -> Dict[str, Any]:
        recent_all = list(self.recent_activities)
        new_acts = [a for a in recent_all if a["seq"] > after_seq] if after_seq > 0 else recent_all
        return {
            "session_id": session_id,
            "session_kind": self.session_kind,
            "status": status,
            "phase": self.phase if status in ("queued", "starting", "running") else status,
            "process_alive": process_alive,
            "stream_mode": stream_mode,
            "elapsed_seconds": round((ended_at or time.time()) - started_at, 2),
            "steps_completed": self.steps_completed,
            "current_activity": self.current_activity,
            "recent_activities": recent_all[-10:],
            "new_activities": new_acts,
            "last_output_line": self.last_output_line,
            "output_bytes": {"stdout": stdout_bytes, "stderr": stderr_bytes},
            "last_event_at": self.last_event_at,
            "last_seq": last_seq,
            "agent_conversation_id": agent_conversation_id,
            "returncode": returncode,
        }
