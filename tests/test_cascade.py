"""Verify the confidence cascade routing logic."""
from __future__ import annotations

from datetime import datetime, timezone

from trident.cascade import Cascade
from trident.contracts import Decision, ProcessEvent


def _event(pid: int = 1, path: str = r"C:\Users\me\Downloads\evil.exe") -> ProcessEvent:
    return ProcessEvent(
        pid=pid,
        ppid=2,
        image_path=path,
        cmdline=None,
        signature=None,
        publisher=None,
        session_id=0,
        timestamp=datetime.now(timezone.utc),
        is_system_path=path.lower().startswith("c:\\windows"),
        sha256=None,
    )


def _decision(pid: int, action: str, confidence: float, trust: str = "unknown") -> Decision:
    return Decision(
        pid=pid,
        threat_score=8.5 if action == "terminate" else 2.0,
        trust_level=trust,  # type: ignore[arg-type]
        action=action,  # type: ignore[arg-type]
        confidence=confidence,
        model_version="trident-v1",
    )


def test_tier1_high_confidence_terminate() -> None:
    c = Cascade()
    d = _decision(1, "terminate", 0.95)
    assert c.route(d, _event(1)) == 1


def test_tier2_mid_confidence_terminate() -> None:
    c = Cascade()
    d = _decision(1, "terminate", 0.80)
    assert c.route(d, _event(1)) == 2


def test_tier2_mid_confidence_allow() -> None:
    c = Cascade()
    d = _decision(1, "allow", 0.80, trust="known_safe")
    assert c.route(d, _event(1)) == 2


def test_tier3_low_confidence() -> None:
    c = Cascade()
    d = _decision(1, "terminate", 0.50)
    assert c.route(d, _event(1)) == 3
    assert c.should_escalate(d, _event(1)) is True


def test_critical_path_forces_tier3_at_high_confidence() -> None:
    c = Cascade()
    d = _decision(1, "terminate", 0.99, trust="known_unsafe")
    ev = _event(1, r"C:\Windows\System32\svchost.exe")
    assert c.is_critical_path(ev.image_path) is True
    assert c.route(d, ev) == 3


def test_silent_allow_no_toast() -> None:
    c = Cascade()
    d = _decision(1, "allow", 0.99, trust="known_safe")
    assert c.should_escalate(d, _event(1)) is False
    assert c.is_silent_allow(d) is True


def test_suppression_after_three_ignores() -> None:
    c = Cascade(suppression_after=3)
    c.record_user_response(1, "ignore")
    c.record_user_response(1, "ignore")
    assert c.is_suppressed(1) is False
    c.record_user_response(1, "ignore")
    assert c.is_suppressed(1) is True