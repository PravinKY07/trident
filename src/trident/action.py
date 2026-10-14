"""Layer 4 - Kill sequence and forensic uninstaller.

Kill tree uses psutil + TerminateProcess directly -- no subprocess
calls, so nothing flashes on screen when the daemon runs under
pythonw.exe. PowerShell is only invoked for the rarely-run forensic
lookups (find_matching_services, find_autostart_entries), and those
go through _run_hidden.
"""
from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from .contracts import Action, Evidence, ProcessEvent


_IS_WINDOWS = sys.platform == "win32"
_NO_WINDOW_FLAGS = 0x08000000 if _IS_WINDOWS else 0


def _startup_info() -> subprocess.STARTUPINFO | None:
    if not _IS_WINDOWS:
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return si


def _run_hidden(cmd, **kwargs) -> subprocess.CompletedProcess:
    if _IS_WINDOWS:
        kwargs.setdefault("startupinfo", _startup_info())
        kwargs.setdefault("creationflags", _NO_WINDOW_FLAGS)
    return subprocess.run(cmd, **kwargs)


def _run_ps(cmd: str, timeout: int = 15) -> tuple[int, str]:
    """Run a PowerShell command with no console window.

    Only used for forensic lookups that are not on the kill path.
    """
    try:
        r = _run_hidden(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)


class ActionLayer:
    """Kills process trees and generates forensic cleanup scripts."""

    def __init__(self, ps1_output_dir: Path, safety_whitelist: list[str]) -> None:
        self.ps1_output_dir = Path(ps1_output_dir)
        self.ps1_output_dir.mkdir(parents=True, exist_ok=True)
        self.safety_whitelist = [p.lower() for p in safety_whitelist]

    def _is_whitelisted(self, path: str | None) -> bool:
        if not path:
            return True
        low = path.lower()
        return any(low.startswith(w) for w in self.safety_whitelist)

    def kill_tree(self, root_pid: int) -> bool:
        """Terminate a PID and all its descendants. Pure-Python.

        No subprocess calls, so nothing can flash on screen. Uses
        psutil to walk the tree and psutil.Process.kill() (which on
        Windows maps to TerminateProcess) per node.

        Falls back to `taskkill /T /F` via _run_hidden only if psutil
        raises AccessDenied on a protected child.
        """
        import psutil

        # Collect the tree first. If the root is already gone, we're done.
        try:
            root = psutil.Process(root_pid)
        except psutil.NoSuchProcess:
            return True

        try:
            descendants = root.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            descendants = []

        # Kill children before parents so nothing gets re-parented.
        denied_any = False
        for child in descendants:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                denied_any = True
            except Exception:
                denied_any = True

        try:
            root.kill()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            denied_any = True
        except Exception:
            denied_any = True

        # If any node refused psutil.kill (protected or elevated), fall
        # back to taskkill /T /F for the whole tree. Wrapped with the
        # hidden-window flags so it doesn't flash.
        if denied_any:
            _run_hidden(
                ["taskkill", "/PID", str(root_pid), "/T", "/F"],
                capture_output=True, text=True,
            )

        # Give Windows a moment to reap the processes, then verify.
        time.sleep(0.2)
        return not psutil.pid_exists(root_pid)

    def find_matching_services(self, image_path: str) -> list[str]:
        """List Windows services whose binary path matches image_path."""
        if not image_path:
            return []
        name = Path(image_path).name
        _rc, out = _run_ps(
            f"Get-CimInstance Win32_Service | Where-Object "
            f"{{$_.PathName -like '*{name}*'}} | "
            f"Select-Object -ExpandProperty Name"
        )
        return [s.strip() for s in out.splitlines() if s.strip()]

    def find_autostart_entries(self, image_path: str) -> dict:
        """Return scheduled tasks and autostart entries for this binary."""
        if not image_path:
            return {"run_keys": [], "tasks": [], "startup": []}
        name = Path(image_path).name
        _rc, out = _run_ps(
            f"schtasks /Query /FO CSV /NH | Select-String '{name}' | "
            f"ForEach-Object {{ ($_ -split ',')[0].Trim('\"') }}"
        )
        tasks = [t.strip() for t in out.splitlines() if t.strip()]
        return {"run_keys": [], "tasks": tasks, "startup": []}

    def generate_cleanup_script(
        self, evidence: Evidence, ps1_name: str | None = None
    ) -> Path:
        """Write a reviewable .ps1 that removes the artefact."""
        if ps1_name is None:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            ps1_name = f"trident-cleanup-{ts}.ps1"
        out = self.ps1_output_dir / ps1_name

        root = evidence.process_tree[0] if evidence.process_tree else None
        pid = root.pid if root else 0
        name = Path(root.image_path).name if root and root.image_path else "unknown"
        path = root.image_path if root else ""

        lines = [
            "# TRIDENT Cleanup Script - review before running",
            f"# Generated: {datetime.now().isoformat()}",
            f"# Target: {name} (PID {pid})",
            "",
            "$ErrorActionPreference = 'Stop'",
            "",
            f'Write-Host "[TRIDENT] Stopping PID {pid}..."',
            f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue",
            "Start-Sleep -Milliseconds 500",
            "",
        ]

        if path and not self._is_whitelisted(path):
            lines += [
                f'Write-Host "[TRIDENT] Removing {path}"',
                f'if (Test-Path "{path}") {{ '
                f'Remove-Item -Path "{path}" -Force -ErrorAction SilentlyContinue }}',
                "",
            ]

        lines += ['Write-Host "[TRIDENT] Cleanup complete."', ""]

        out.write_text("\n".join(lines), encoding="utf-8")
        return out

    def execute(self, action: Action) -> Action:
        """Execute a terminate Action. Returns the same Action, mutated."""
        try:
            root_pid = action.target_pid
            root = (
                action.evidence.process_tree[0]
                if action.evidence.process_tree
                else None
            )
            path = root.image_path if root else None

            if path and not self._is_whitelisted(path):
                ps1 = self.generate_cleanup_script(action.evidence)
                action.generated_ps1_path = ps1

            ok = self.kill_tree(root_pid)
            action.executed = ok
            if not ok:
                action.error = "kill_tree returned False"
        except Exception as e:
            action.error = str(e)
        return action
