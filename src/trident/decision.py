"""Layer 2 - Laya ONNX decision kernel (2-question model).

The fine-tuned checkpoint exported by Aalok answers two questions
per process:

    Q1 action      (2 options): 0=allow, 1=terminate
    Q2 trust_level (4 options): 0=system_critical, 1=known_safe,
                                2=unknown, 3=known_unsafe

Escalate is NOT a model class. It is a policy decision made by the
cascade based on action + confidence + trust_level.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np

from .contracts import Decision, ProcessEvent

# --- Q1: action ------------------------------------------------------------

ACTION_OPTIONS = ["allow", "terminate"]
ACTION_INSTRUCTIONS = (
    "Given a Windows process start event, decide the correct "
    "defensive action for the system layer."
)
ACTION_CRITERIA = {
    "allow": (
        "Standard Windows binary in a system directory, or a "
        "well-known signed vendor binary in Program Files."
    ),
    "terminate": (
        "Binary from a user-writable location, impersonating a system "
        "binary, or showing clear malware behavior."
    ),
}

# --- Q2: trust_level -------------------------------------------------------

TRUST_OPTIONS = ["system_critical", "known_safe", "unknown", "known_unsafe"]
TRUST_INSTRUCTIONS = "Classify the trust context of this executable."
TRUST_CRITERIA = {
    "system_critical": "Windows OS kernel or core service binary.",
    "known_safe": "Signed application from a trusted publisher.",
    "unknown": "Unsigned binary or unrecognized third-party utility.",
    "known_unsafe": "Identified malware, coin miner, or unauthorized remote access.",
}


# --- UI-only threat score mapping ------------------------------------------

def _threat_score(action: str, probs: np.ndarray) -> float:
    """Compute a 0-10 threat score from action + softmax margin.

    The model is over-confident on terminate decisions (always 0.97+),
    so raw probability produces nearly constant scores. Using the margin
    between the top two classes restores dynamic range.

    terminate margin -> score:
        1.00 -> 10.0   (dead certain)
        0.95 ->  9.7
        0.80 ->  8.6
        0.50 ->  6.5
        0.20 ->  4.4

    allow margin -> score:
        1.00 ->  0.0
        0.90 ->  0.3
        0.70 ->  0.9
        0.40 ->  1.8
        0.20 ->  2.4
    """
    p = np.asarray(probs, dtype=np.float64).ravel()
    if p.size < 2:
        return 5.0
    top2 = np.sort(p)[-2:]
    margin = float(top2[1] - top2[0])  # 0.0 (tie) .. 1.0 (certain)
    margin = max(0.0, min(1.0, margin))

    if action == "terminate":
        return round(3.0 + 7.0 * margin, 1)
    return round(max(0.0, 3.0 * (1.0 - margin)), 1)


def _softmax(x: np.ndarray) -> np.ndarray:
    """Numerically stable softmax over the last axis."""
    x = x - np.max(x, axis=-1, keepdims=True)
    e = np.exp(x)
    return e / np.sum(e, axis=-1, keepdims=True)


class DecisionKernel:
    """ONNX Runtime wrapper around the fine-tuned 2-question Laya model."""

    def __init__(
        self,
        model_path: Path,
        tokenizer_dir: Path,
        config_path: Path,
        temperature: float = 1.0,
        max_len: int = 1024,
        head_max_len: int = 256,
    ) -> None:
        """Store paths and hyperparameters. Call load() before score_batch()."""
        self.model_path = Path(model_path)
        self.tokenizer_dir = Path(tokenizer_dir)
        self.config_path = Path(config_path)
        self.temperature = temperature
        self.max_len = max_len
        self.head_max_len = head_max_len
        self._session = None
        self._tok = None
        self._build_sequence = None
        self._qtypes = None

    # -------------------------------------------------------------- load

    def load(self) -> None:
        """Load the ONNX session, tokenizer, and laya helpers. Idempotent."""
        import onnxruntime as ort
        from transformers import AutoTokenizer
        from laya.common import build_sequence, QTYPES

        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        opts.enable_mem_pattern = False
        # CHANGED: arena on. One allocation pool, reused across calls.
        # Expect ~20-40% faster inference at cost of ~30-50 MB steady-state.
        opts.enable_cpu_mem_arena = False

        self._session = ort.InferenceSession(
            str(self.model_path),
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )
        self._tok = AutoTokenizer.from_pretrained(str(self.tokenizer_dir))
        self._build_sequence = build_sequence
        self._qtypes = QTYPES

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _event_to_state(ev: ProcessEvent) -> dict:
        """Convert a ProcessEvent into the state dict Laya expects.

        CRITICAL: the description strings below must match the training
        data byte-for-byte. The training pipeline (make_training_data.py)
        used these exact fixed short strings. Earlier versions of this
        method templated the process name and path INTO the description,
        which shifted the input distribution and caused the model to
        fall back to its majority-class prior (allow / known_safe) on
        every input, including clear malware.

        Do not change these strings without retraining the model.
        """
        name = Path(ev.image_path).name if ev.image_path else "unknown"
        path = ev.image_path or "unknown"

        if ev.is_system_path:
            desc = (
                "The path is inside a Windows system directory, typical "
                "for legitimate system processes."
            )
        else:
            desc = (
                "The path is NOT inside a Windows system directory, "
                "which warrants additional scrutiny."
            )

        return {
            "process_name": name,
            "full_path": path,
            "is_system_directory": bool(ev.is_system_path),
            "parent_pid": int(ev.ppid),
            "event_type": "process_start",
            "description": desc,
        }

    @staticmethod
    def _question_dict(criteria: dict, instructions: str) -> dict:
        """Build the question dict in the shape laya.common.build_sequence expects."""
        return {
            "t": "choice",
            "ins": instructions,
            "crit": criteria,
        }

    def _score_question(
        self,
        events: list[ProcessEvent],
        criteria: dict,
        instructions: str,
        num_options: int,
    ) -> np.ndarray:
        """Run one forward pass for a single question. Returns [B, num_options]."""
        q_dict = self._question_dict(criteria, instructions)
        q_t = "choice"

        seqs: list[list[int]] = []
        marker_pos_list: list[list[int]] = []
        marker_mask_list: list[list[int]] = []

        for ev in events:
            state = self._event_to_state(ev)
            result = self._build_sequence(
                self._tok, state, q_dict, self.max_len, self.head_max_len
            )
            # Handle multiple possible return shapes from laya.common.
            if len(result) == 4:
                ids, mpos, mmask, _qt = result
            elif len(result) == 3:
                ids, mpos, mmask = result
            elif len(result) == 2:
                ids, mpos = result
                mmask = [True] * len(mpos)
            else:
                raise RuntimeError(
                    f"build_sequence returned {len(result)} items; expected 2-4"
                )
            seqs.append(list(ids))
            marker_pos_list.append(list(mpos))
            marker_mask_list.append(list(mmask))

        B = len(seqs)
        L = max(len(s) for s in seqs)
        K = max(len(m) for m in marker_pos_list)

        pad_id = self._tok.pad_token_id if self._tok.pad_token_id is not None else 0
        input_ids = np.full((B, L), pad_id, dtype=np.int64)
        attention_mask = np.zeros((B, L), dtype=np.int64)
        marker_pos = np.zeros((B, K), dtype=np.int64)
        marker_mask = np.zeros((B, K), dtype=bool)

        for i in range(B):
            seq = seqs[i]
            input_ids[i, : len(seq)] = seq
            attention_mask[i, : len(seq)] = 1
            mp = marker_pos_list[i]
            mm = marker_mask_list[i]
            marker_pos[i, : len(mp)] = mp
            marker_mask[i, : len(mm)] = mm

        qtype_val = self._qtypes[q_t]
        qtype = np.full((B,), qtype_val, dtype=np.int64)

        feed = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "marker_pos": marker_pos,
            "marker_mask": marker_mask,
            "qtype": qtype,
        }
        logits = self._session.run(None, feed)[0]
        if logits.shape[1] < num_options:
            raise RuntimeError(
                f"Model returned {logits.shape[1]} logits; expected at least {num_options}"
            )
        logits = logits[:, :num_options]
        return _softmax(logits / max(self.temperature, 1e-6))

    # ---------------------------------------------------------- inference

    def score_batch(self, events: list[ProcessEvent]) -> list[Decision]:
        """Score a batch of ProcessEvents. Returns one Decision per event."""
        if self._session is None:
            self.load()
        if not events:
            return []

        probs_action = self._score_question(
            events, ACTION_CRITERIA, ACTION_INSTRUCTIONS, len(ACTION_OPTIONS)
        )
        probs_trust = self._score_question(
            events, TRUST_CRITERIA, TRUST_INSTRUCTIONS, len(TRUST_OPTIONS)
        )

        out: list[Decision] = []
        for i, ev in enumerate(events):
            pa = probs_action[i]
            pt = probs_trust[i]
            aidx = int(np.argmax(pa))
            tidx = int(np.argmax(pt))
            action = ACTION_OPTIONS[aidx]
            trust = TRUST_OPTIONS[tidx]
            confidence = float(pa[aidx])
            out.append(
                Decision(
                    pid=ev.pid,
                    threat_score=_threat_score(action, pa),
                    trust_level=trust,  # type: ignore[arg-type]
                    action=action,  # type: ignore[arg-type]
                    confidence=confidence,
                    model_version="trident-v1",
                )
            )
        return out
