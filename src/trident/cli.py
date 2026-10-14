"""TRIDENT command-line interface."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from . import models as models_mod
from .mode import ModeStore, VALID_MODES, DEFAULT_MODE
from .runtime import (
    DAEMON_LOG,
    PID_FILE,
    clear_pid,
    read_pid,
    write_stop_signal,
)

TASK_NAME = "TRIDENT"

_IS_WINDOWS = sys.platform == "win32"
_NO_WINDOW_FLAGS = 0x08000000 if _IS_WINDOWS else 0


def _run_hidden(cmd, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run with no console window on Windows."""
    if _IS_WINDOWS:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        kwargs.setdefault("startupinfo", si)
        kwargs.setdefault("creationflags", _NO_WINDOW_FLAGS)
    return subprocess.run(cmd, **kwargs)


# --- startup folder helpers ------------------------------------------

def _startup_dir() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA not set")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def _startup_cmd_path() -> Path:
    return _startup_dir() / "TRIDENT.cmd"


def _startup_entry_exists() -> bool:
    try:
        return _startup_cmd_path().exists()
    except RuntimeError:
        return False


def _create_startup_entry() -> None:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        pythonw = Path(sys.executable)

    repo = os.environ.get("TRIDENT_REPO", os.getcwd())
    path = _startup_cmd_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    content = (
        "@echo off\r\n"
        f'cd /d "{repo}"\r\n'
        f'set TRIDENT_REPO={repo}\r\n'
        f'start "" "{pythonw}" -m trident._daemon\r\n'
    )
    path.write_text(content, encoding="ascii")


def _delete_startup_entry() -> None:
    try:
        _startup_cmd_path().unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


# --- scheduled task helpers ------------------------------------------

def _scheduled_task_exists() -> bool:
    r = subprocess.run(
        ["schtasks", "/query", "/tn", TASK_NAME],
        capture_output=True, text=True,
    )
    return r.returncode == 0


def _task_exists() -> bool:
    return _scheduled_task_exists() or _startup_entry_exists()


def _try_create_scheduled_task() -> bool:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        pythonw = Path(sys.executable)

    repo = os.environ.get("TRIDENT_REPO", os.getcwd())
    username = os.environ.get("USERNAME", "")

    cmd = [
        "schtasks", "/create",
        "/tn", TASK_NAME,
        "/tr", f'cmd /c "set TRIDENT_REPO={repo} && \"{pythonw}\" -m trident._daemon"',
        "/sc", "logon",
        "/ru", username,
        "/it",
        "/f",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0


def _create_registration() -> str:
    if _try_create_scheduled_task():
        return "task"
    print("schtasks refused (needs admin on this system).")
    print("Using the Startup folder instead...")
    _create_startup_entry()
    return "startup"


def _delete_registration() -> None:
    subprocess.run(
        ["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
        capture_output=True, text=True,
    )
    _delete_startup_entry()


def _launch_now_detached() -> None:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        pythonw = Path(sys.executable)

    repo = os.environ.get("TRIDENT_REPO", os.getcwd())
    env = os.environ.copy()
    env["TRIDENT_REPO"] = repo

    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_NO_WINDOW = 0x08000000

    subprocess.Popen(
        [str(pythonw), "-m", "trident._daemon"],
        cwd=repo,
        env=env,
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )


def _run_task_now() -> bool:
    if _scheduled_task_exists():
        r = subprocess.run(
            ["schtasks", "/run", "/tn", TASK_NAME],
            capture_output=True, text=True,
        )
        return r.returncode == 0
    _launch_now_detached()
    return False


def _end_task() -> None:
    subprocess.run(
        ["schtasks", "/end", "/tn", TASK_NAME],
        capture_output=True, text=True,
    )


# --- first-run wizard -------------------------------------------------

def _first_run_wizard() -> bool:
    print()
    print("Welcome to TRIDENT.")
    print()
    print("TRIDENT watches every process on your machine and scores it")
    print("with a local AI model. In enforce mode, it can terminate")
    print("processes it thinks are malicious.")
    print()
    print("Kill mode is DISABLED by default. TRIDENT will run in dry-run")
    print("mode and record what it would have done. Review with:")
    print()
    print("    trident logs --tail 50")
    print()
    print("Enable enforcement later with:")
    print()
    print("    trident config --mode enforce")
    print()
    try:
        resp = input("[Enter] to continue in dry-run mode\n[q]     to cancel\n> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if resp == "q":
        return False
    return True


# --- commands ---------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> int:
    pid = read_pid()
    if pid is not None:
        print(f"TRIDENT is already running (pid {pid})")
        return 0

    try:
        from .runtime import clear_stop_signal
        clear_stop_signal()
    except Exception:
        pass

    # Preflight: model must be present.
    if not models_mod.is_present():
        print("model not found.")
        print(f"  expected in: {models_mod.model_dir()}")
        print()
        print("Run `trident models fetch` to download it (about 280 MB).")
        return 1

    # First-run wizard.
    ms = ModeStore()
    if not ms.is_set():
        if not _first_run_wizard():
            print("cancelled")
            return 1
        ms.set(DEFAULT_MODE)
        print(f"mode set to {DEFAULT_MODE}")
        print()

    if not _task_exists():
        print("registering background task...")
        mode = _create_registration()
        print(f"using {mode} registration")

    print("starting...")
    _run_task_now()

    for _ in range(150):
        pid = read_pid()
        if pid is not None:
            print(f"TRIDENT running (pid {pid}, mode {ms.mode})")
            print(f"log: {DAEMON_LOG}")
            return 0
        time.sleep(0.1)

    print("TRIDENT failed to start within 15s. Check the log:", file=sys.stderr)
    print(f"  {DAEMON_LOG}", file=sys.stderr)
    return 1


def cmd_stop(args: argparse.Namespace) -> int:
    pid = read_pid()
    if pid is None:
        print("TRIDENT is not running")
        if args.uninstall:
            _delete_registration()
            print("registration removed")
        return 0

    print(f"stopping pid {pid}...")
    write_stop_signal()

    for _ in range(50):
        if read_pid() is None:
            print("stopped")
            if args.uninstall:
                _delete_registration()
                print("registration removed")
            return 0
        time.sleep(0.1)

    print("graceful stop timed out, forcing...")
    _run_hidden(["taskkill", "/PID", str(pid), "/F"],
                capture_output=True, text=True)
    clear_pid()
    _end_task()
    if args.uninstall:
        _delete_registration()
    print("stopped (forced)")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    pid = read_pid()
    if pid is None:
        print("TRIDENT is not running")
        return 0

    ms = ModeStore()
    print(f"TRIDENT running (pid {pid})")
    print(f"mode: {ms.mode}")
    if _scheduled_task_exists():
        print("registration: scheduled task")
    elif _startup_entry_exists():
        print("registration: startup folder")
    else:
        print("registration: none (running manually)")
    print(f"log: {DAEMON_LOG}")

    if DAEMON_LOG.exists():
        try:
            lines = DAEMON_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
            print("--- recent activity ---")
            for line in lines[-5:]:
                print(line)
        except OSError:
            pass
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    if not DAEMON_LOG.exists():
        print("no log yet")
        return 0
    lines = DAEMON_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-args.tail:]:
        print(line)
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    if args.action == "status":
        if models_mod.is_present():
            d = models_mod.model_dir()
            print(f"model present: {d}")
            total = 0
            for name in models_mod.FILES:
                p = d / name
                if p.exists():
                    total += p.stat().st_size
            print(f"total size: {total / 1_000_000:.1f} MB")
            return 0
        else:
            missing = models_mod.missing_files()
            print("model not fetched")
            print(f"destination: {models_mod.model_dir()}")
            print(f"missing: {len(missing)} file(s)")
            for n in missing:
                print(f"  - {n}")
            print()
            print("Run `trident models fetch` to download.")
            return 1

    if args.action == "fetch":
        try:
            models_mod.fetch(verbose=True)
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return 1
        return 0

    return 2


def cmd_config(args: argparse.Namespace) -> int:
    ms = ModeStore()
    if args.mode is not None:
        if args.mode not in VALID_MODES:
            print(f"invalid mode: {args.mode!r}. choose from: {', '.join(VALID_MODES)}",
                  file=sys.stderr)
            return 2
        ms.set(args.mode)
        print(f"mode set to {args.mode}")
        if not read_pid():
            print("(not running -- mode will apply on next `trident start`)")
        return 0

    print(f"mode:        {ms.mode}")
    print(f"config file: {ms._path}")
    print(f"valid modes: {', '.join(VALID_MODES)}")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    try:
        from . import __version__
        print(f"TRIDENT {__version__}")
    except ImportError:
        print("TRIDENT (development)")
    return 0


# --- main -------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trident",
        description="Local AI process security for Windows.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("start", help="start the background watcher")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", help="stop the background watcher")
    p.add_argument("--uninstall", action="store_true",
                   help="also remove the logon registration")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("status", help="show daemon status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("logs", help="tail the decision log")
    p.add_argument("--tail", type=int, default=20)
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("models", help="fetch or inspect the model files")
    p.add_argument("action", choices=["fetch", "status"],
                   help="fetch: download; status: show current state")
    p.set_defaults(func=cmd_models)

    p = sub.add_parser("config", help="view or change operating mode")
    p.add_argument("--mode", choices=VALID_MODES, default=None,
                   help="set the operating mode")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("version", help="print version")
    p.set_defaults(func=cmd_version)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())