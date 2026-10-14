"""Shipped-data resolution via importlib.resources.

The wheel ships `trident/data/` containing trident.toml (default),
strings.json, and icons/*.png|ico. These are read-only at runtime.

User state lives elsewhere -- see runtime.py.
"""
from __future__ import annotations

from pathlib import Path


def bundled_data(filename: str) -> Path:
    """Path to a file inside trident/data/."""
    from importlib.resources import files
    return Path(str(files("trident") / "data" / filename))


def bundled_data_dir(name: str) -> Path:
    """Path to a subdirectory inside trident/data/."""
    from importlib.resources import files
    return Path(str(files("trident") / "data" / name))


def default_config_path() -> Path:
    """The shipped read-only trident.toml default."""
    return bundled_data("trident.toml")


def strings_path() -> Path:
    """The shipped strings.json."""
    return bundled_data("strings.json")


def icons_dir() -> Path:
    """The shipped icons directory."""
    return bundled_data_dir("icons")