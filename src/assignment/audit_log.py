"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
import time

def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        key = request_id or user_id
        self._open[key] = {
            "user_id": user_id,
            "input": text,
            "start": time.perf_counter(),
            "timestamp": utc_now_iso(),
        }


    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        key = request_id or user_id
        pending = self._open.pop(key, None)  # lấy ra và xoá khỏi danh sách đang mở

        if pending is None:  # gọi output mà chưa gọi input → vẫn ghi, không crash
            pending = {"user_id": user_id, "input": None,
                       "start": time.perf_counter(), "timestamp": utc_now_iso()}

        latency_ms = (time.perf_counter() - pending["start"]) * 1000

        # Đây là lúc dùng list: thêm 1 bản ghi hoàn chỉnh
        self.logs.append({
            "timestamp": pending["timestamp"],
            "request_id": request_id,
            "user_id": user_id,
            "input": pending["input"],
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round(latency_ms, 2),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)
        return str(path)



def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
