"""Toast notifications and review report. Uses tkinter for portability.

Threading note: tkinter requires all GUI calls to run on the main
thread of the Python process. The pipeline's main loop (in
__main__.py) already runs on the main thread, so show_toast and
open_review_report run synchronously there. Do NOT wrap these in
threading.Thread — that breaks tkinter's event loop.
"""
from __future__ import annotations

import json
from pathlib import Path

from .contracts import Evidence, ProcessEvent


class UI:
    def __init__(
        self,
        strings_file: Path,
        locale: str = "en",
        cascade=None,
        trust_store=None,
        audit=None,
    ) -> None:
        self._strings = json.loads(Path(strings_file).read_text(encoding="utf-8-sig"))
        self._locale = locale
        self._cascade = cascade
        self._trust_store = trust_store
        self._audit = audit
        self._root = None  # lazy Tk root, reused for the process lifetime

    def _s(self, key: str, **kw) -> str:
        loc = self._strings.get(self._locale, self._strings["en"])
        template = loc.get(key) or self._strings["en"].get(key) or key
        if kw:
            try:
                return template.format(**kw)
            except Exception:
                return template
        return template

    def _ensure_root(self):
        """Lazy-init one Tk root and keep it withdrawn for the session."""
        if self._root is not None:
            return self._root
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.update_idletasks()
        self._root = root
        return root

    def show_toast(self, event: ProcessEvent, score: float, confidence: float) -> None:
        if self._cascade is not None and self._cascade.is_suppressed(event.pid):
            print(f"[TRIDENT] Suppressed PID {event.pid} -- no toast")
            return

        name = Path(event.image_path).name if event.image_path else f"PID {event.pid}"
        title = self._s("toast.title", process_name=name)
        body = self._s("toast.body", score=round(score, 1))
        print(f"[TRIDENT] TOAST: {title} - {body}")

        try:
            from tkinter import messagebox
            root = self._ensure_root()
            answer = messagebox.askyesno(
                title,
                f"{body}\n\nReview this process?",
                parent=root,
            )
            if answer:
                self.open_review_report(event, score, confidence)
            else:
                if self._cascade is not None:
                    self._cascade.record_user_response(event.pid, "ignore")
        except Exception as e:
            print(f"[TRIDENT] Toast failed: {e}")

    def open_review_report(
        self, event: ProcessEvent, score: float, confidence: float
    ) -> None:
        try:
            import tkinter as tk
        except Exception as e:
            print(f"[TRIDENT] Review UI unavailable: {e}")
            return

        root = self._ensure_root()
        win = tk.Toplevel(root)
        win.title(self._s("report.header"))
        win.geometry("660x470")
        win.attributes("-topmost", True)

        info = (
            f"Process name : {Path(event.image_path).name if event.image_path else 'unknown'}\n"
            f"Full path    : {event.image_path or 'unknown'}\n"
            f"PID          : {event.pid}\n"
            f"Parent PID   : {event.ppid}\n"
            f"System path  : {event.is_system_path}\n"
            f"Threat score : {score:.1f}/10\n"
            f"Confidence   : {confidence:.2%}\n"
        )
        tk.Label(
            win, text=info, justify="left", anchor="w", font=("Consolas", 10),
        ).pack(padx=16, pady=16, fill="both")

        btn_frame = tk.Frame(win)
        btn_frame.pack(pady=12)

        def _close() -> None:
            win.destroy()

        def _trust() -> None:
            path = event.image_path
            if not path or self._trust_store is None:
                _close()
                return
            self._trust_store.trust(path)
            if self._audit is not None:
                self._audit.write({
                    "pid": event.pid,
                    "name": Path(path).name,
                    "path": path,
                    "user_verdict": "trust_path",
                })
            print(f"[TRIDENT] Trusted path: {path}")
            win.destroy()

        tk.Button(
            btn_frame, text=self._s("report.action.close"),
            command=_close, width=14,
        ).pack(side="left", padx=6)

        trust_enabled = self._trust_store is not None and bool(event.image_path)
        tk.Button(
            btn_frame, text="Trust this path", command=_trust, width=16,
            state=("normal" if trust_enabled else "disabled"),
        ).pack(side="left", padx=6)

        # Wait for the report window to close without tearing down the root.
        win.wait_window()

    def set_tray_state(self, state: str, n: int = 0) -> None:
        msg = (
            self._s(f"tray.tooltip.{state}", n=n)
            if state == "busy"
            else self._s(f"tray.tooltip.{state}")
        )
        print(f"[TRIDENT] TRAY: {msg}")
