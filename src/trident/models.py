"""Model download and verification.

Downloads the ONNX weights from Hugging Face into the user's
LOCALAPPDATA directory. Idempotent -- re-running on an already-fetched
directory is a fast no-op.

The .onnx graph references its external data by the exact filename
`trident-v1-attn4.onnx.data`. Renaming it breaks ONNX Runtime loading.
`huggingface_hub.hf_hub_download` handles resume, retries, and checksum
verification per file.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from .runtime import _DATA_ROOT

MODEL_DIR = _DATA_ROOT / "models"

REPO_ID = "aalok101singh/trident-v1"

# The five files that must exist for the daemon to load the model.
FILES = (
    "trident-v1.onnx",
    "trident-v1-attn4.onnx.data",
    "tokenizer.json",
    "tokenizer_config.json",
    "rl_agent_config.json",
)

# The AutoTokenizer call in decision.py expects a directory containing
# tokenizer.json + tokenizer_config.json. HF stores those flat at the
# repo root, so fetch() mirrors them into this subdir.
TOKENIZER_SUBDIR = "tokenizer"


def model_dir() -> Path:
    return MODEL_DIR


def is_present() -> bool:
    """True if every required file exists on disk with non-zero size."""
    if not MODEL_DIR.exists():
        return False
    for name in FILES:
        p = MODEL_DIR / name
        if not p.exists() or p.stat().st_size == 0:
            return False
    return True


def missing_files() -> list[str]:
    """Return names of required files that are missing or zero-length."""
    if not MODEL_DIR.exists():
        return list(FILES)
    missing = []
    for name in FILES:
        p = MODEL_DIR / name
        if not p.exists() or p.stat().st_size == 0:
            missing.append(name)
    return missing


def _mirror_tokenizer_files() -> None:
    """Copy tokenizer.json + tokenizer_config.json into TOKENIZER_SUBDIR.

    The HF repo stores them flat. AutoTokenizer wants a directory. This
    bridges the two without re-downloading.
    """
    dst_dir = MODEL_DIR / TOKENIZER_SUBDIR
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in ("tokenizer.json", "tokenizer_config.json"):
        src = MODEL_DIR / name
        dst = dst_dir / name
        if not src.exists():
            continue
        if dst.exists() and dst.stat().st_size == src.stat().st_size:
            continue
        shutil.copy2(src, dst)


def fetch(verbose: bool = True) -> Path:
    """Download every required file into MODEL_DIR. Returns MODEL_DIR.

    Safe to call repeatedly -- hf_hub_download skips files whose local
    hash matches the remote. Raises RuntimeError on failure.
    """
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        raise RuntimeError(
            "huggingface_hub is required. Install it with:\n"
            "    pip install huggingface_hub"
        )

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    if verbose:
        print(f"Downloading model from {REPO_ID}")
        print(f"  destination: {MODEL_DIR}")
        print()

    for name in FILES:
        target = MODEL_DIR / name
        if target.exists() and target.stat().st_size > 0:
            if verbose:
                size_mb = target.stat().st_size / 1_000_000
                print(f"  ok  {name} ({size_mb:.1f} MB)")
            continue

        if verbose:
            print(f"  ... {name}", flush=True)
        try:
            hf_hub_download(
                repo_id=REPO_ID,
                filename=name,
                local_dir=str(MODEL_DIR),
            )
        except Exception as e:
            raise RuntimeError(
                f"failed to download {name}: {e}\n"
                f"Check your network connection and try again."
            )

    _mirror_tokenizer_files()

    if verbose:
        print()
        print(f"Model ready in {MODEL_DIR}")
    return MODEL_DIR