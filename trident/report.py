"""TRIDENT report viewer.

Launched as a subprocess by toast buttons:

    python -m trident.report <pid>

Reads the audit log, finds the most recent decision for that PID, and
shows it in a tkinter window with a "Trust this path" action.

This runs in a SEPARATE process from the main TRIDENT loop. That's
intentional: winotify toast buttons can only launch executables, not
call back into a running Python process. The two processes coordinate
through the shared trust_store JSON file -- the main loop reads it on
every is_trusted() call, so a trust added here takes effect on the
next scored process without any IPC.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Sibling imports work when run as `python -m trident.report` from repo root.
from .trust_store import TrustStore


def _find_repo_root() -> Path:
    """Walk up from this file to the repo root (contains trident.toml)."""
    here = Path(__file__).resolve()
    for parent in (here.parent, here.parent.parent, here.parent.parent.parent):
        if (parent / "trident.toml").exists():
            return parent
    return Path.cwd()


def _find_decision(repo_root: Path, pid: int) -> dict | None:
    """Return the most recent audit-log record for this PID, or None.

    Searches all decisions-*.jsonl files in reverse chronological order
    and returns the first match. Same PID can appear multiple times
    (PID reuse); we want the most recent.
    """
    log_dir = repo_root / "logs"
    if not log_dir.exists():
        return None
    files = sorted(log_dir.glob("decisions-*.jsonl"), reverse=True)
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("pid") == pid and "action" in rec:
                return rec
    return None


def _show_missing(root, pid: int) -> None:
    import tkinter as tk
    from tkinter import messagebox

    root.withdraw()
    messagebox.showerror(
        "TRIDENT",
        f"No decision found for PID {pid}.\n\n"
        f"The process may have exited before the log was flushed, "
        f"or the PID was reused.",
        parent=root,
    )
    root.destroy()


def _show_report(root, rec: dict, pid: int, trust_store: TrustStore, audit_path: Path) -> None:
    """Render the report window. Caller owns the Tk root."""
    import tkinter as tk

    name = rec.get("name", "?")
    path = rec.get("path") or "unknown"
    action = rec.get("action", "?")
    trust = rec.get("trust", "?")
    conf = rec.get("conf", 0.0)
    score = rec.get("threat_score", 0.0)
    tier = rec.get("tier", "?")
    outcome = rec.get("outcome", "?")
    ts = rec.get("ts", "?")
    is_trusted = bool(rec.get("trusted_path"))

    root.title(f"TRIDENT Report — {name}")
    root.geometry("700x520")
    root.attributes("-topmost", True)

    header = tk.Label(
        root,
        text=f"Decision report — PID {pid}",
        font=("Segoe UI", 13, "bold"),
        anchor="w",
    )
    header.pack(fill="x", padx=18, pady=(16, 8))

    # Two-column layout: label / value
    body = tk.Frame(root)
    body.pack(fill="both", expand=True, padx=18, pady=6)

    rows = [
        ("Process name", name),
        ("Full path", path),
        ("PID", str(pid)),
        ("Timestamp", ts),
        ("", ""),
        ("Model verdict", f"{action} / {trust}"),
        ("Confidence", f"{conf:.1%}"),
        ("Threat score", f"{score:.1f} / 10"),
        ("Cascade tier", f"Tier {tier}"),
        ("Outcome", outcome),
        ("Trusted path", "yes" if is_trusted else "no"),
    ]
    for i, (k, v) in enumerate(rows):
        if not k:
            tk.Frame(body, height=10).grid(row=i, column=0)
            continue
        tk.Label(
            body, text=k, anchor="w", font=("Segoe UI", 9, "bold"),
        ).grid(row=i, column=0, sticky="w", pady=2)
        tk.Label(
            body, text=v, anchor="w", font=("Consolas", 9),
        ).grid(row=i, column=1, sticky="w", padx=(16, 0), pady=2)
    body.columnconfigure(1, weight=1)

    # Status line
    if is_trusted:
        status = "This path is on the trust list. It is still scored, but never acted on."
        status_color = "#0a84ff"
    elif outcome == "killed":
        status = "TRIDENT terminated this process at Tier 1 (high-confidence threat)."
        status_color = "#d13438"
    elif outcome == "toast":
        status = "Flagged for review. The cascade refused to auto-kill — a human decides."
        status_color = "#8a8a8a"
    else:
        status = f"Routed to {outcome}."
        status_color = "#8a8a8a"

    tk.Label(
        root, text=status, anchor="w", font=("Segoe UI", 9, "italic"),
        fg=status_color, wraplength=640, justify="left",
    ).pack(fill="x", padx=18, pady=(6, 4))

    # Button row
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=14)

    def _close() -> None:
        root.destroy()

    def _trust() -> None:
        if not path or path == "unknown":
            _close()
            return
        trust_store.trust(path)
        # Append to the audit log so the main process can see the action.
        try:
            from datetime import datetime, timezone
            entry = {
                "pid": pid,
                "name": name,
                "path": path,
                "user_verdict": "trust_path",
                "source": "report",
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            }
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with audit_path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str))
                f.write("\n")
        except Exception as e:
            print(f"[TRIDENT report] failed to append audit row: {e}", file=sys.stderr)
        print(f"[TRIDENT report] trusted: {path}")
        _close()

    tk.Button(
        btn_frame, text="Close", command=_close, width=14,
    ).pack(side="left", padx=6)

    trust_btn = tk.Button(
        btn_frame, text="Trust this path", command=_trust, width=18,
    )
    if is_trusted or not path or path == "unknown":
        trust_btn.configure(state="disabled")
        trust_btn.configure(text="Already trusted" if is_trusted else "Cannot trust")
    trust_btn.pack(side="left", padx=6)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m trident.report <pid>", file=sys.stderr)
        return 2
    try:
        pid = int(argv[0])
    except ValueError:
        print(f"invalid pid: {argv[0]!r}", file=sys.stderr)
        return 2

    repo_root = _find_repo_root()
    trust_store = TrustStore(repo_root / "config" / "trusted_paths.json")
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    audit_path = repo_root / "logs" / f"decisions-{today}.jsonl"

    import tkinter as tk
    root = tk.Tk()

    rec = _find_decision(repo_root, pid)
    if rec is None:
        _show_missing(root, pid)
        return 1

    _show_report(root, rec, pid, trust_store, audit_path)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())