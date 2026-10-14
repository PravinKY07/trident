"""TRIDENT report viewer.

Launched by the `trident:report:<pid>` URI scheme. Reads the audit log,
finds the most recent decision for that PID, and shows it in a tkinter
window with a "Trust this path" action.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .runtime import LOGS_DIR, TRUSTED_PATHS_FILE
from .trust_store import TrustStore


BG = "#1f1f1f"
FG = "#e8e8e8"
MUTED = "#a0a0a0"
ACCENT = "#0a84ff"
DANGER = "#d13438"
BTN_BG = "#2d2d2d"
BTN_ACTIVE = "#3a3a3a"


def _find_decision(pid: int) -> dict | None:
    """Return the most recent audit-log record for this PID, or None."""
    if not LOGS_DIR.exists():
        return None
    files = sorted(LOGS_DIR.glob("decisions-*.jsonl"), reverse=True)
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

    root.title(f"TRIDENT - {name}")
    root.geometry("700x520")
    root.attributes("-topmost", True)
    root.configure(bg=BG)

    tk.Label(
        root, text=f"Decision report  .  PID {pid}",
        font=("Segoe UI", 13, "bold"),
        bg=BG, fg=FG, anchor="w",
    ).pack(fill="x", padx=20, pady=(18, 4))

    tk.Label(
        root, text=ts,
        font=("Segoe UI", 9),
        bg=BG, fg=MUTED, anchor="w",
    ).pack(fill="x", padx=20, pady=(0, 14))

    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True, padx=20, pady=6)

    rows = [
        ("Process name", name),
        ("Full path", path),
        ("Model verdict", f"{action} / {trust}"),
        ("Confidence", f"{conf:.1%}"),
        ("Threat score", f"{score:.1f} / 10"),
        ("Cascade tier", f"Tier {tier}"),
        ("Outcome", outcome),
        ("Trusted path", "yes" if is_trusted else "no"),
    ]
    for i, (k, v) in enumerate(rows):
        tk.Label(body, text=k, anchor="w", font=("Segoe UI", 9, "bold"),
                 bg=BG, fg=MUTED).grid(row=i, column=0, sticky="w", pady=4)
        tk.Label(body, text=v, anchor="w", font=("Consolas", 9),
                 bg=BG, fg=FG).grid(row=i, column=1, sticky="w", padx=(20, 0), pady=4)
    body.columnconfigure(1, weight=1)

    if is_trusted:
        status = "This path is on the trust list. Still scored, never acted on."
        status_color = ACCENT
    elif outcome == "killed":
        status = "TRIDENT terminated this process at Tier 1 (high-confidence threat)."
        status_color = DANGER
    elif outcome == "toast":
        status = "Flagged for review. The cascade refused to auto-kill - a human decides."
        status_color = MUTED
    else:
        status = f"Routed to {outcome}."
        status_color = MUTED

    tk.Label(root, text=status, anchor="w", font=("Segoe UI", 9, "italic"),
             bg=BG, fg=status_color, wraplength=640, justify="left",
             ).pack(fill="x", padx=20, pady=(10, 4))

    btn_frame = tk.Frame(root, bg=BG)
    btn_frame.pack(pady=16)

    def _close() -> None:
        root.destroy()

    def _trust() -> None:
        if not path or path == "unknown":
            _close()
            return
        try:
            trust_store.trust(path)
        except Exception as e:
            print(f"[TRIDENT report] trust write failed: {e}", file=sys.stderr)
            _close()
            return
        try:
            from .toast import show_trust_confirmation
            show_trust_confirmation(path)
        except Exception as e:
            print(f"[TRIDENT report] toast failed: {e}", file=sys.stderr)
        try:
            entry = {
                "pid": pid, "name": name, "path": path,
                "user_verdict": "trust_path", "source": "report",
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            }
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with audit_path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str))
                f.write("\n")
        except Exception as e:
            print(f"[TRIDENT report] audit append failed: {e}", file=sys.stderr)
        print(f"[TRIDENT report] trusted: {path}")
        _close()

    tk.Button(btn_frame, text="Dismiss", command=_close, width=16,
              bg=BTN_BG, fg=FG, activebackground=BTN_ACTIVE, activeforeground=FG,
              relief="flat", bd=0, font=("Segoe UI", 10), padx=10, pady=6,
              cursor="hand2").pack(side="left", padx=6)

    trust_btn = tk.Button(btn_frame, text="Trust this path", command=_trust,
                          width=20, bg=ACCENT, fg="#ffffff",
                          activebackground="#0066cc", activeforeground="#ffffff",
                          relief="flat", bd=0, font=("Segoe UI", 10),
                          padx=10, pady=6, cursor="hand2")
    if is_trusted or not path or path == "unknown":
        trust_btn.configure(state="disabled", bg=BTN_BG, fg=MUTED,
                            text="Already trusted" if is_trusted else "Cannot trust")
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

    trust_store = TrustStore(TRUSTED_PATHS_FILE)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    audit_path = LOGS_DIR / f"decisions-{today}.jsonl"

    import tkinter as tk
    root = tk.Tk()

    rec = _find_decision(pid)
    if rec is None:
        _show_missing(root, pid)
        return 1

    _show_report(root, rec, pid, trust_store, audit_path)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())