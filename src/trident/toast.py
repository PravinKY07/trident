"""Native Windows toast notifications via winotify."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

try:
    from winotify import Notification, audio
    _WINOTIFY_OK = True
except Exception:  # pragma: no cover
    Notification = None  # type: ignore
    audio = None  # type: ignore
    _WINOTIFY_OK = False


APP_ID = "TRIDENT"

_ICON_FILENAMES = {
    "startup":    "trident-safe-preview.png",
    "kill":       "trident-danger-preview.png",
    "escalation": "trident-monitor-preview.png",
    "trust":      "trident-trust-preview.png",
}


def _icon_path(kind: str) -> str | None:
    """Resolve an icon filename inside the shipped data dir."""
    name = _ICON_FILENAMES.get(kind)
    if not name:
        return None
    try:
        from .paths import icons_dir
        p = icons_dir() / name
        if p.exists():
            return str(p)
    except Exception:
        pass
    return None


def _mk(title: str, msg: str, icon_kind: str, duration: str = "short") -> "Notification | None":
    if not _WINOTIFY_OK:
        return None
    try:
        kwargs = dict(app_id=APP_ID, title=title, msg=msg, duration=duration)
        icon = _icon_path(icon_kind)
        if icon:
            kwargs["icon"] = icon
        return Notification(**kwargs)
    except Exception:
        return None


def _show(toast, fallback_msg: str) -> None:
    if toast is None:
        print(f"[TRIDENT] (no toast) {fallback_msg}")
        return
    try:
        toast.set_audio(audio.Default, loop=False)
        toast.show()
    except Exception as e:
        print(f"[TRIDENT] toast failed: {e} -- {fallback_msg}")


def _trust_uri(path: str) -> str:
    b64 = base64.urlsafe_b64encode(path.encode("utf-8")).decode("ascii").rstrip("=")
    return f"trident:trust:{b64}"


def show_startup(trusted_count: int, mode: str = "enforce") -> None:
    parts = [f"Mode: {mode}."]
    if trusted_count:
        parts.append(f"{trusted_count} trusted path(s).")
    msg = " ".join(parts)
    _show(_mk("TRIDENT is running", msg, "startup", duration="short"),
          "engine started")


def show_kill(name: str, pid: int, score: float, tier: int,
              count: int = 1, path: str | None = None) -> None:
    body = f"PID {pid} -- threat {score:.1f}/10, tier {tier}"
    if count > 1:
        body += f" ({count} processes)"
    t = _mk(f"Killed: {name}", body, "kill", duration="long")
    if t is not None and path:
        try:
            t.add_actions(label="Trust this path", launch=_trust_uri(path))
        except Exception:
            pass
    _show(t, f"killed {name} pid={pid}")


def show_escalation(name: str, pid: int, score: float, confidence: float,
                    path: str | None = None) -> None:
    t = _mk(
        f"Flagged: {name}",
        f"Threat {score:.1f}/10, confidence {confidence:.0%}. Review?",
        "escalation",
        duration="long",
    )
    if t is not None and path:
        try:
            t.add_actions(label="Trust this path", launch=_trust_uri(path))
        except Exception:
            pass
    _show(t, f"escalated {name} pid={pid}")


def show_trust_confirmation(path: str) -> None:
    name = Path(path).name if path else "path"
    _show(
        _mk(f"Trusted: {name}", "Won't be scored again. Changes still logged.",
            "trust", duration="short"),
        f"trusted {path}",
    )


def show_suppressed(name: str, pid: int, count: int) -> None:
    _show(
        _mk("Escalation muted",
            f"{name} (PID {pid}) flagged {count} times -- muting further toasts.",
            "escalation", duration="short"),
        f"suppressed {name} pid={pid}",
    )