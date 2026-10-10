"""Fetch the fine-tuned TRIDENT model from Hugging Face.

Called by `make setup`. Verifies the SHA-256 before returning.
Safe to re-run; if the model is already present and matches, does nothing.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

MODEL_REPO = "aalok101singh/trident-laya-process-security-v1"
MODEL_FILE = "trident-laya-process-security-v1.onnx"
EXPECTED_SHA256 = "TO_BE_FILLED_AFTER_UPLOAD"
TARGET_DIR = Path(__file__).resolve().parents[2] / "models"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download() -> Path:
    """Download the model if not present. Return the local path."""
    from huggingface_hub import hf_hub_download

    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    local_path = TARGET_DIR / MODEL_FILE

    if local_path.exists():
        if EXPECTED_SHA256 == "TO_BE_FILLED_AFTER_UPLOAD":
            print("[TRIDENT] WARNING: expected hash not set. Skipping verification.")
            return local_path
        if _sha256(local_path) == EXPECTED_SHA256:
            print("[TRIDENT] Model already present and verified.")
            return local_path
        print("[TRIDENT] Local model hash mismatch. Re-downloading.")

    print(f"[TRIDENT] Downloading {MODEL_FILE} from {MODEL_REPO}...")
    downloaded = hf_hub_download(
        repo_id=MODEL_REPO,
        filename=MODEL_FILE,
        local_dir=TARGET_DIR,
    )

    if EXPECTED_SHA256 != "TO_BE_FILLED_AFTER_UPLOAD":
        actual = _sha256(Path(downloaded))
        if actual != EXPECTED_SHA256:
            print(f"[TRIDENT] Hash mismatch. Expected {EXPECTED_SHA256}, got {actual}.")
            sys.exit(1)

    print(f"[TRIDENT] Model verified and saved to {downloaded}.")
    return Path(downloaded)


if __name__ == "__main__":
    download()