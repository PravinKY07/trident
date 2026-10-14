"""Persistent trusted-path store. Small JSON file, atomic writes.

Changes made by external processes (e.g. the toast URI handler) are
detected by poll(), which the daemon calls on each polling tick.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from threading import Lock


class TrustStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self._path = Path(path)
        self._lock = Lock()
        self._data: dict[str, dict] = {}
        self._mtime: float = 0.0
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._data = {}
            self._mtime = 0.0
            return
        try:
            with self._path.open("r", encoding="utf-8-sig") as f:
                self._data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[TRIDENT] trust store: malformed JSON at {self._path}: {e}",
                  file=sys.stderr)
            self._data = {}
        except OSError as e:
            print(f"[TRIDENT] trust store: cannot read {self._path}: {e}",
                  file=sys.stderr)
            self._data = {}
        try:
            self._mtime = self._path.stat().st_mtime
        except OSError:
            self._mtime = 0.0

    def poll(self) -> list[str]:
        """Check for external changes to the store.

        Returns paths that are newly trusted since the last poll. Called
        from the daemon's polling loop so that a toast button click is
        reflected in the running process without a restart.
        """
        if not self._path.exists():
            return []
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return []
        if mtime == self._mtime:
            return []
        with self._lock:
            old = set(self._data.keys())
            self._load()
            new_keys = set(self._data.keys()) - old
            return sorted(new_keys)

    def _atomic_save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".trust-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp, self._path)
            self._mtime = self._path.stat().st_mtime
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    def is_trusted(self, path: str) -> bool:
        with self._lock:
            entry = self._data.get(self._key(path))
            return bool(entry and entry.get("trust"))

    def trust(self, path: str) -> None:
        with self._lock:
            self._data[self._key(path)] = {"trust": True}
            self._atomic_save()

    def untrust(self, path: str) -> None:
        with self._lock:
            self._data.pop(self._key(path), None)
            self._atomic_save()

    def all_trusted(self) -> list[str]:
        with self._lock:
            return sorted(k for k, v in self._data.items() if v.get("trust"))
