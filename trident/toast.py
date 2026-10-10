"""Native Windows toast notifications via winotify."""
from __future__ import annotations

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
_PYTHON = sys.executable

# Icon paths. Windows' toast API accepts .png / .jpg / .gif for
# AppLogoOverride -- NOT .ico. The -preview.png files are what we use
# here; the .ico files are for app branding only.
#
# Resolved relative to the repo root at import time. TRIDENT must be
# launched from the repo root for these to resolve.
_ICON_ROOT = Path.cwd() / "assets"
_ICONS = {
    "startup":    _ICON_ROOT / "trident-safe-preview.png",
    "kill":       _ICON_ROOT / "trident-danger-preview.png",
    "escalation": _ICON_ROOT / "trident-monitor-preview.png",
    "trust":      _ICON_ROOT / "trident-trust-preview.png",
}


def _icon_path(kind: str) -> str | None:
    p = _ICONS.get(kind)
    if p is not None and p.exists():
        return str(p)
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


def show_startup(trusted_count: int) -> None:
    msg = (
        f"Watching for process events. {trusted_count} trusted path(s) loaded."
        if trusted_count
        else "Watching for process events."
    )
    _show(_mk("TRIDENT is running", msg, "startup", duration="short"),
          "engine started")


def show_kill(name: str, pid: int, score: float, tier: int, count: int = 1) -> None:
    body = f"PID {pid} -- threat {score:.1f}/10, tier {tier}"
    if count > 1:
        body += f" ({count} processes)"
    t = _mk(f"Killed: {name}", body, "kill", duration="long")
    if t is not None:
        try:
            t.add_actions(label="View report", launch=_report_launch_cmd(pid))
        except Exception:
            pass
    _show(t, f"killed {name} pid={pid}")


def show_escalation(name: str, pid: int, score: float, confidence: float) -> None:
    t = _mk(
        f"Flagged: {name}",
        f"Threat {score:.1f}/10, confidence {confidence:.0%}. Review?",
        "escalation",
        duration="long",
    )
    if t is not None:
        try:
            t.add_actions(label="View report", launch=_report_launch_cmd(pid))
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


def _report_launch_cmd(pid: int) -> str:
    # Do NOT quote the python path here. winotify serializes this into
    # a toast XML attribute, and embedded quotes cause Windows to drop
    # the entire toast silently. This works only because the repo path
    # contains no spaces. If the repo moves somewhere with a space,
    # replace this with a wrapper .cmd file placed at a fixed path.
    return f"{_PYTHON} -m trident.report {pid}"
