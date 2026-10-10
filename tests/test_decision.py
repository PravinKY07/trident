"""Verify the ONNX decision kernel shape (no model file needed)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from trident.contracts import ProcessEvent
from trident.decision import (
    ACTION_OPTIONS,
    TRUST_OPTIONS,
    DecisionKernel,
    _softmax,
)


def _event(path: str = r"C:\Users\me\Downloads\evil.exe") -> ProcessEvent:
    return ProcessEvent(
        pid=1234,
        ppid=5678,
        image_path=path,
        cmdline="evil.exe --go",
        signature=None,
        publisher=None,
        session_id=0,
        timestamp=datetime.now(timezone.utc),
        is_system_path=path.lower().startswith("c:\\windows"),
        sha256=None,
    )


def test_softmax_sums_to_one() -> None:
    x = np.array([[1.0, 2.0, 3.0]])
    p = _softmax(x)
    assert np.allclose(p.sum(axis=-1), 1.0)


def test_softmax_stable_for_large_logits() -> None:
    x = np.array([[1e6, 1e6 + 1.0]])
    p = _softmax(x)
    assert np.isfinite(p).all()
    assert np.allclose(p.sum(axis=-1), 1.0)


def test_action_options_order() -> None:
    assert ACTION_OPTIONS == ["allow", "terminate"]


def test_trust_options_order() -> None:
    assert TRUST_OPTIONS == [
        "system_critical",
        "known_safe",
        "unknown",
        "known_unsafe",
    ]


def test_event_to_state_system_path() -> None:
    ev = _event(r"C:\Windows\System32\svchost.exe")
    state = DecisionKernel._event_to_state(ev)
    assert state["process_name"] == "svchost.exe"
    assert state["is_system_directory"] is True
    assert "system directory" in state["description"]
    assert state["parent_pid"] == 5678
    assert state["event_type"] == "process_start"


def test_event_to_state_user_path() -> None:
    ev = _event(r"C:\Users\me\Downloads\evil.exe")
    state = DecisionKernel._event_to_state(ev)
    assert state["process_name"] == "evil.exe"
    assert state["is_system_directory"] is False
    assert "NOT inside" in state["description"]


def test_kernel_constructs_without_model() -> None:
    k = DecisionKernel(
        model_path=Path("nonexistent.onnx"),
        tokenizer_dir=Path("nonexistent_tok"),
        config_path=Path("nonexistent.json"),
    )
    assert k.model_path.name == "nonexistent.onnx"
    assert k._session is None