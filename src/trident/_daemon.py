"""Background daemon entry point."""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from .runtime import (
    DAEMON_LOG,
    clear_pid,
    clear_stop_signal,
    ensure_runtime_dir,
    stop_requested,
    write_pid,
)


def _setup_file_logging() -> None:
    ensure_runtime_dir()
    try:
        if DAEMON_LOG.exists() and DAEMON_LOG.stat().st_size > 5_000_000:
            backup = DAEMON_LOG.with_suffix(".log.1")
            if backup.exists():
                backup.unlink()
            DAEMON_LOG.rename(backup)
    except OSError:
        pass

    log_file = open(DAEMON_LOG, "a", encoding="utf-8", buffering=1)
    sys.stdout = log_file
    sys.stderr = log_file

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=log_file,
    )


def main() -> int:
    _setup_file_logging()
    clear_stop_signal()
    write_pid(os.getpid())

    print(f"[TRIDENT daemon] starting pid={os.getpid()}")

    try:
        from . import models as models_mod
        if not models_mod.is_present():
            print(f"[TRIDENT daemon] model not found in {models_mod.model_dir()}")
            print("[TRIDENT daemon] run `trident models fetch` and try again")
            clear_pid()
            return 1
        print(f"[TRIDENT daemon] model present in {models_mod.model_dir()}")
    except Exception as e:
        print(f"[TRIDENT daemon] model check failed: {e}")
        clear_pid()
        return 1

    from . import __main__ as trident_main

    import time as _time
    _original_sleep = _time.sleep

    def _interruptible_sleep(seconds: float) -> None:
        end = _time.monotonic() + seconds
        while _time.monotonic() < end:
            if stop_requested():
                print("[TRIDENT daemon] stop signal received")
                raise KeyboardInterrupt
            _original_sleep(0.1)

    trident_main.time.sleep = _interruptible_sleep

    try:
        return trident_main.main()
    except KeyboardInterrupt:
        print("[TRIDENT daemon] interrupted, shutting down")
        return 0
    finally:
        clear_pid()
        clear_stop_signal()
        print("[TRIDENT daemon] exited")


if __name__ == "__main__":
    sys.exit(main())