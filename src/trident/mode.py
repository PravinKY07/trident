"""Operating mode: dry-run, monitor, enforce.

Stored as a single word in a text file under the runtime data dir.
The daemon polls it the same way it polls the trust store -- mode
changes take effect on the next loop tick, no restart required.
"""
from __future__ import annotations

from pathlib import Path

from .runtime import _DATA_ROOT

MODE_FILE = _DATA_ROOT / "config" / "mode"
VALID_MODES = ("dry-run", "monitor", "enforce")
DEFAULT_MODE = "dry-run"


class ModeStore:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or MODE_FILE
        self._mode = DEFAULT_MODE
        self._mtime = 0.0
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._mode = DEFAULT_MODE
            self._mtime = 0.0
            return
        try:
            m = self._path.read_text(encoding="ascii").strip().lower()
            self._mode = m if m in VALID_MODES else DEFAULT_MODE
            self._mtime = self._path.stat().st_mtime
        except OSError:
            self._mode = DEFAULT_MODE

    def poll(self) -> str | None:
        """Return the new mode if it changed since the last poll, else None."""
        if not self._path.exists():
            return None
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return None
        if mtime == self._mtime:
            return None
        old = self._mode
        self._load()
        return self._mode if self._mode != old else None

    @property
    def mode(self) -> str:
        return self._mode

    def is_set(self) -> bool:
        return self._path.exists()

    def set(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"invalid mode: {mode!r}")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(mode, encoding="ascii")
        self._mode = mode
        self._mtime = self._path.stat().st_mtime