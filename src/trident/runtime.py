"""Runtime paths and PID/stop file helpers.

Everything the running daemon writes lives under one directory tree:

    %LOCALAPPDATA%\\TRIDENT\\
        config\\           user's trident.toml + trusted_paths.json
        logs\\             per-day decision JSONL
        cleanup-scripts\\  generated .ps1 review files
        runtime\\          daemon.pid, .stop, daemon.log

Resolution is via %LOCALAPPDATA% directly rather than platformdirs,
which would produce a TRIDENT\\TRIDENT duplication.
"""
from __future__ import annotations

import os
from pathlib import Path

_local = os.environ.get("LOCALAPPDATA")
if _local:
    _DATA_ROOT = Path(_local) / "TRIDENT"
else:
    _DATA_ROOT = Path.home() / ".trident"


# Subdirectories.
CONFIG_DIR = _DATA_ROOT / "config"
LOGS_DIR = _DATA_ROOT / "logs"
CLEANUP_DIR = _DATA_ROOT / "cleanup-scripts"
RUNTIME_DIR = _DATA_ROOT / "runtime"

# Well-known files.
PID_FILE = RUNTIME_DIR / "daemon.pid"
STOP_FILE = RUNTIME_DIR / ".stop"
DAEMON_LOG = RUNTIME_DIR / "daemon.log"
USER_CONFIG_FILE = CONFIG_DIR / "trident.toml"
TRUSTED_PATHS_FILE = CONFIG_DIR / "trusted_paths.json"


def ensure_runtime_dir() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


def ensure_user_dirs() -> None:
    """Create every user-data subdir. Idempotent."""
    for d in (CONFIG_DIR, LOGS_DIR, CLEANUP_DIR, RUNTIME_DIR):
        d.mkdir(parents=True, exist_ok=True)


def read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None
    if not _pid_alive(pid):
        return None
    return pid


def write_pid(pid: int) -> None:
    ensure_runtime_dir()
    PID_FILE.write_text(str(pid), encoding="ascii")


def clear_pid() -> None:
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return True


def write_stop_signal() -> None:
    ensure_runtime_dir()
    STOP_FILE.write_text("stop", encoding="ascii")


def clear_stop_signal() -> None:
    try:
        STOP_FILE.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def stop_requested() -> bool:
    return STOP_FILE.exists()