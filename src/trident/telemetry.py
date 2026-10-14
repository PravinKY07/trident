"""Layer 1 - Process telemetry via psutil polling."""
from __future__ import annotations

import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable

import psutil

from .contracts import ProcessEvent

SYSTEM_PATH_PREFIXES = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files\\windows",
    "c:\\program files (x86)\\windows",
)


def _is_system_path(path: str | None) -> bool:
    """True if the path sits under a Windows system directory."""
    if not path:
        return False
    low = path.lower()
    return any(low.startswith(p) for p in SYSTEM_PATH_PREFIXES)


class TelemetrySession:
    """Polls the process table once per interval and emits new starts."""

    def __init__(
        self,
        ring_buffer_size: int = 256,
        poll_interval: float = 0.5,
    ) -> None:
        """Create the ring buffer and tracking state. Call start() to run."""
        self._buffer: deque[ProcessEvent] = deque(maxlen=ring_buffer_size)
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._subscribers: list[Callable[[ProcessEvent], None]] = []
        self._seen: dict[int, float | None] = {}
        self._poll_interval = poll_interval

    def start(self) -> None:
        """Take a baseline snapshot, then start the polling thread."""
        if self._thread and self._thread.is_alive():
            return
        self._seen = self._snapshot_baseline()
        self._running = True
        self._thread = threading.Thread(
            target=self._watch,
            daemon=True,
            name="trident-telemetry",
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the polling thread to exit and wait for it."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)

    def subscribe(self, callback: Callable[[ProcessEvent], None]) -> None:
        """Register a callback fired on each new process event."""
        self._subscribers.append(callback)

    def next_batch(self, max_size: int) -> list[ProcessEvent]:
        """Drain up to max_size events from the ring buffer."""
        with self._lock:
            out: list[ProcessEvent] = []
            while self._buffer and len(out) < max_size:
                out.append(self._buffer.popleft())
            return out

    def _snapshot_baseline(self) -> dict[int, float | None]:
        """Record pid -> create_time for every process currently running."""
        seen: dict[int, float | None] = {}
        for p in psutil.process_iter(["pid", "create_time"]):
            try:
                info = p.info
                seen[int(info["pid"])] = info.get("create_time")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return seen

    def _enqueue(self, event: ProcessEvent) -> None:
        """Append to the buffer under lock, then notify subscribers."""
        with self._lock:
            self._buffer.append(event)
        for cb in self._subscribers:
            try:
                cb(event)
            except Exception:
                pass

    def _watch(self) -> None:
        """Poll psutil, diff against _seen, emit new events. Never dies.

        Two-pass design for low CPU overhead on slow hardware (i3):
          1. Cheap pass: fetch only pid + create_time for all processes.
          2. Expensive pass: fetch full info (exe, cmdline, ppid, name)
             ONLY for the pids that are new since the last poll.

        On a machine with 150 running processes and few new starts per
        second, this cuts per-poll cost by roughly 4x compared to
        fetching all fields for every process on every tick.
        """
        while self._running:
            try:
                # Cheap pass: pid + create_time only.
                current_pids: dict[int, float | None] = {}
                for p in psutil.process_iter(["pid", "create_time"]):
                    try:
                        info = p.info
                        current_pids[int(info["pid"])] = info.get("create_time")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Diff against previous snapshot to find new or reused pids.
                new_pids: list[int] = []
                for pid, ct in current_pids.items():
                    old_ct = self._seen.get(pid)
                    if pid not in self._seen:
                        new_pids.append(pid)
                    elif old_ct is not None and ct is not None and old_ct != ct:
                        new_pids.append(pid)

                # Expensive pass: full info ONLY for the new pids.
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        info = proc.as_dict(
                            attrs=[
                                "pid",
                                "ppid",
                                "exe",
                                "cmdline",
                                "name",
                                "create_time",
                            ]
                        )
                        ev = self._to_event(info)
                        if ev is not None:
                            self._enqueue(ev)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                self._seen = current_pids

            except Exception as exc:
                print(
                    f"[TRIDENT][telemetry] poll error: {exc!r}",
                    file=sys.stderr,
                )

            end = time.monotonic() + self._poll_interval
            while self._running and time.monotonic() < end:
                time.sleep(0.05)

    @staticmethod
    def _to_event(info: dict) -> ProcessEvent | None:
        """Map a psutil info dict to a ProcessEvent. None on failure."""
        try:
            pid = int(info.get("pid") or 0)
            ppid = int(info.get("ppid") or 0)
            image_path = info.get("exe")
            raw_cmd = info.get("cmdline")
            if isinstance(raw_cmd, list):
                cmdline = " ".join(str(x) for x in raw_cmd) if raw_cmd else None
            elif isinstance(raw_cmd, str):
                cmdline = raw_cmd
            else:
                cmdline = None
            return ProcessEvent(
                pid=pid,
                ppid=ppid,
                image_path=image_path,
                cmdline=cmdline,
                signature=None,
                publisher=None,
                session_id=0,
                timestamp=datetime.now(timezone.utc),
                is_system_path=_is_system_path(image_path),
                sha256=None,
            )
        except Exception:
            return None