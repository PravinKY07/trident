"""Verify dataclass shapes for TRIDENT contracts."""
from __future__ import annotations

from datetime import datetime, timezone

from trident.contracts import Action, Decision, Evidence, ProcessEvent


def _make_event() -> ProcessEvent:
    return ProcessEvent(
        pid=1234,
        ppid=5678,
        image_path=r"C:\Windows\System32\svchost.exe",
        cmdline="svchost.exe -k netsvcs",
        signature=None,
        publisher=None,
        session_id=0,
        timestamp=datetime.now(timezone.utc),
        is_system_path=True,
        sha256=None,
    )


def test_process_event_fields() -> None:
    ev = _make_event()
    assert ev.pid == 1234
    assert ev.ppid == 5678
    assert ev.is_system_path is True
    assert ev.sha256 is None


def test_decision_fields() -> None:
    d = Decision(
        pid=1,
        threat_score=8.5,
        trust_level="known_unsafe",
        action="terminate",
        confidence=0.95,
        model_version="trident-v1",
    )
    assert d.pid == 1
    assert d.action == "terminate"
    assert d.trust_level == "known_unsafe"
    assert 0.0 <= d.confidence <= 1.0


def test_evidence_defaults() -> None:
    e = Evidence()
    assert e.process_tree == []
    assert e.hashes == {}
    assert e.network == []
    assert e.registry == []
    assert e.timestamps == []


def test_action_defaults() -> None:
    e = Evidence(process_tree=[_make_event()])
    a = Action(action_type="terminate", target_pid=1234, evidence=e)
    assert a.executed is False
    assert a.error is None
    assert a.generated_ps1_path is None
    assert isinstance(a.evidence.process_tree[0], ProcessEvent)