"""Configuration loader for TRIDENT.

Loads trident.toml, validates with Pydantic, exposes a frozen Config
object.

Resolution order:
  1. Explicit path passed to load().
  2. %LOCALAPPDATA%\\TRIDENT\\config\\trident.toml (user's copy).
     On first call, if missing, seeds from the shipped default.
"""
from __future__ import annotations

import shutil
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ModelConfig(BaseModel):
    repo: str
    filename: str
    expected_sha256: str
    runtime: Literal["onnxruntime"] = "onnxruntime"
    execution_provider: str = "CPUExecutionProvider"
    intra_op_threads: int = 1
    inter_op_threads: int = 1
    execution_mode: Literal["sequential", "parallel"] = "sequential"
    enable_memory_arena: bool = False
    max_len: int = 1024
    head_max_len: int = 256


class TelemetryConfig(BaseModel):
    provider: str = "Microsoft-Windows-Kernel-Process"
    ring_buffer_size: int = 256
    metadata_cache_size: int = 1024
    batch_size_max: int = Field(default=16, ge=1, le=64)
    batch_window_ms: int = 200
    wmi_fallback_enabled: bool = True
    wmi_poll_interval_seconds: int = 10


class CascadeConfig(BaseModel):
    tier1_threshold: float = Field(ge=0.0, le=1.0)
    tier2_threshold: float = Field(ge=0.0, le=1.0)
    tier2_max_cycles: int = 3
    escalation_suppression_after: int = 3
    toast_timeout_seconds: int = 30

    @field_validator("tier2_threshold")
    @classmethod
    def tier2_below_tier1(cls, v: float, info) -> float:
        tier1 = info.data.get("tier1_threshold")
        if tier1 is not None and v >= tier1:
            raise ValueError("tier2_threshold must be < tier1_threshold")
        return v


class ActionConfig(BaseModel):
    safety_whitelist: list[str]
    suspend_timeout_ms: int = 500
    verify_timeout_ms: int = 500
    generate_ps1: bool = True
    ps1_output_dir: Path = Path("./cleanup-scripts")


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["jsonl", "text"] = "jsonl"
    log_dir: Path = Path("./logs")
    prefix: str = "[TRIDENT]"


class UIConfig(BaseModel):
    strings_file: Path = Path("./strings.json")
    default_locale: str = "en"


class Config(BaseModel):
    model: ModelConfig
    telemetry: TelemetryConfig
    cascade: CascadeConfig
    action: ActionConfig
    logging: LoggingConfig
    ui: UIConfig


def _seed_user_config_if_missing() -> Path:
    """Ensure the user's trident.toml exists, seeding from the shipped default."""
    from .runtime import USER_CONFIG_FILE, ensure_user_dirs
    from .paths import default_config_path

    ensure_user_dirs()
    if not USER_CONFIG_FILE.exists():
        src = default_config_path()
        if src.exists():
            shutil.copy2(src, USER_CONFIG_FILE)
    return USER_CONFIG_FILE


def load(path: Path | str | None = None) -> Config:
    """Load and validate the config.

    If path is None, uses the user's config file, seeding it from the
    shipped default on first run.
    """
    if path is None:
        path = _seed_user_config_if_missing()
    path = Path(path)
    with path.open("rb") as f:
        raw = tomllib.load(f)
    return Config(**raw)