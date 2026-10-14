"""Append-only JSONL decision log. One file per UTC day under ./logs/.

Usage from __main__.py:
    from trident.audit import AuditLog
    audit = AuditLog("logs")
    ...
    audit.write({"pid": pid, "name": name, "action": action,
                 "trust": trust, "conf": conf, "tier": tier})
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, log_dir: str | os.PathLike = "logs") -> None:
        self._dir = Path(log_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._fh = None
        self._current_date: str | None = None

    def _roll(self) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if today == self._current_date and self._fh is not None:
            return
        if self._fh is not None:
            self._fh.close()
        path = self._dir / f"decisions-{today}.jsonl"
        self._fh = open(path, "a", encoding="utf-8", newline="\n")
        self._current_date = today

    def write(self, record: dict[str, Any]) -> None:
        self._roll()
        record.setdefault(
            "ts", datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        )
        self._fh.write(json.dumps(record, ensure_ascii=False, default=str))
        self._fh.write("\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None