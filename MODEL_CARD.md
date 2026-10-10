# TRIDENT — Laya Process Security (v1)

A fine-tuned Laya checkpoint for Windows process behavioral classification.

---

## Model Details

| | |
|---|---|
| **Base model** | Laya multilingual checkpoint (322M params) |
| **Fine-tuned** | LoRA rank 16, 3 epochs, QLoRA on Kaggle T4 x2 |
| **Quantization** | Encoder: INT4 (MatMulNBits, block 32, asymmetric). Decision head: FP16. |
| **Size on disk** | ~180 MB (ONNX) |
| **Runtime** | ONNX Runtime, CPU execution provider |
| **License** | Apache 2.0 |
| **Language** | Multilingual (100+ languages) |

## Training Data

The training dataset (`trident-process-behavior-dataset`) was assembled from:

- Clean baseline: 2,000–3,000 process-start events from an isolated Windows 10 VM.
- Threat simulation: Atomic Red Team, Infection Monkey, and one locally compiled XMRig binary for ground-truth malicious behavior. All generation happened in an offline VM with snapshots.
- Sampled public datasets: `[FILL IN — list the datasets you actually used and their licenses]`.
- Laya zero-shot labels, corrected on a 20% sample for consistency.

Total: 6,000–10,000 labeled examples across four classes: `allow`, `monitor`, `terminate`, `escalate`.

## Intended Use

TRIDENT uses this model to classify Windows process-start events. Input is a structured record of process metadata (path, publisher, signature, parent, session, etc.). Output is a threat score (0–10), a trust level, an action proposal, and a calibrated confidence.

**The model proposes. A deterministic confidence cascade disposes.** See `docs/spec/04-cascade.md` for the safety architecture. This model is never used as the sole decision-maker for destructive actions.

## Limitations

- Trained on Windows 10/11. Behavior on other platforms is untested.
- Training data comes from simulated threats, not real-world malware at scale.
- Calibrated on the training distribution. Unusual process metadata may yield low confidence.
- Not a substitute for signature-based antivirus. TRIDENT cooperates with Windows Defender, it does not replace it.

## How to Use

```python
from trident.decision import DecisionKernel

kernel = DecisionKernel(model_path="./models/trident-laya-process-security-v1.onnx")
result = kernel.score(process_event)
# result.threat_score, result.trust_level, result.action, result.confidence

Or from the command line:
  make setup   # fetches this model from Hugging Face
  make run     # starts TRIDENT

Evaluation
[FILL IN after training: accuracy, precision, recall, F1, ECE]

Citation
@software{trident2026,
  title  = {TRIDENT — Laya Process Security (v1)},
  author = {Aalok Singh, PravinKumar Yadav},
  year   = {2026},
  url    = {https://github.com/aalok101singh/trident}
}


---

## Part 2 — Python Package

### `trident/__init__.py`

**Path:** `trident/trident/__init__.py`

```python
"""TRIDENT — The immune layer for Windows."""

__version__ = "0.1.0"
__all__ = [
    "contracts",
    "config",
    "telemetry",
    "decision",
    "cascade",
    "action",
    "ui",
]
