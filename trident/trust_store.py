"""Persistent trusted-path store. Small JSON file, atomic writes.

Path locations: choose one and be consistent.
  Repo-visible (judges can open it):   ./config/trusted_paths.json
  User-scoped (survives repo moves):   %LOCALAPPDATA%\\TRIDENT\\trusted_paths.json

For the demo, repo-visible is better -- you can show the file on screen.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from threading import Lock


class TrustStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self._path = Path(path)
        self._lock = Lock()
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                self._data = json.load(f)
        except (json.JSONDecodeError, OSError):
            # Corrupt store: start clean. Do NOT crash the pipeline.
            self._data = {}

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
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _key(path: str) -> str:
        # normcase handles Windows case-insensitivity; abspath handles relative
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