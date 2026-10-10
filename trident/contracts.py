"""Shared data contracts for TRIDENT."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal


TrustLevel = Literal["known_safe", "known_unsafe", "unknown", "system_critical"]
ActionType = Literal["allow", "monitor", "terminate", "escalate"]
Tier = Literal[1, 2, 3]


@dataclass(frozen=True)
class ProcessEvent:
    pid: int
    ppid: int
    image_path: str | None
    cmdline: str | None
    signature: str | None
    publisher: str | None
    session_id: int
    timestamp: datetime
    is_system_path: bool
    sha256: str | None = None


@dataclass(frozen=True)
class Decision:
    pid: int
    threat_score: float
    trust_level: TrustLevel
    action: ActionType
    confidence: float
    model_version: str


@dataclass
class Evidence:
    process_tree: list[ProcessEvent] = field(default_factory=list)
    hashes: dict[int, str] = field(default_factory=dict)
    network: list[str] = field(default_factory=list)
    registry: list[str] = field(default_factory=list)
    timestamps: list[datetime] = field(default_factory=list)


@dataclass
class Action:
    action_type: ActionType
    target_pid: int
    evidence: Evidence
    generated_ps1_path: Path | None = None
    executed: bool = False
    error: str | None = None
