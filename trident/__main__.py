"""TRIDENT entry point."""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import Path

from . import toast
from .action import ActionLayer
from .audit import AuditLog
from .cascade import Cascade
from .config import load
from .contracts import Action, Evidence
from .decision import DecisionKernel
from .system_defaults import is_system_safe
from .telemetry import TelemetrySession
from .trust_store import TrustStore


def _resolve_paths(root: Path, cfg) -> dict:
    """Resolve model, tokenizer, and config paths under <root>/models/."""
    model_dir = root / "models"
    return {
        "model_path": model_dir / cfg.model.filename,
        "tokenizer_dir": model_dir / "tokenizer",
        "config_path": model_dir / "rl_agent_config.json",
    }


def _ts() -> str:
    """Wall-clock timestamp for console lines. HH:MM:SS.mmm."""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def main() -> int:
    """Load config, wire all layers, run the watch loop."""
    root = Path.cwd()
    cfg_path = root / "trident.toml"
    if not cfg_path.exists():
        print("[TRIDENT] trident.toml not found. Run from repo root.", file=sys.stderr)
        return 1

    cfg = load(cfg_path)
    paths = _resolve_paths(root, cfg)

    if not paths["model_path"].exists():
        print(f"[TRIDENT] Model not found at {paths['model_path']}.", file=sys.stderr)
        return 1

    print("[TRIDENT] Loading decision kernel...")
    kernel = DecisionKernel(
        model_path=paths["model_path"],
        tokenizer_dir=paths["tokenizer_dir"],
        config_path=paths["config_path"],
        temperature=1.0,
        max_len=cfg.model.max_len,
        head_max_len=cfg.model.head_max_len,
    )
    kernel.load()
    print("[TRIDENT] Model ready.")

    cascade = Cascade(
        tier1_threshold=cfg.cascade.tier1_threshold,
        tier2_threshold=cfg.cascade.tier2_threshold,
        tier2_max_cycles=cfg.cascade.tier2_max_cycles,
        suppression_after=cfg.cascade.escalation_suppression_after,
    )

    action_layer = ActionLayer(
        ps1_output_dir=root / cfg.action.ps1_output_dir,
        safety_whitelist=cfg.action.safety_whitelist,
    )

    audit = AuditLog(root / "logs")
    trust_store = TrustStore(root / "config" / "trusted_paths.json")
    trusted_count = len(trust_store.all_trusted())
    if trusted_count:
        print(f"[TRIDENT] Trust store loaded: {trusted_count} path(s) trusted.")

    telemetry = TelemetrySession(ring_buffer_size=cfg.telemetry.ring_buffer_size)
    telemetry.start()

    self_pid = os.getpid()
    print(f"[TRIDENT] Watching for process events (self pid={self_pid}). Ctrl+C to stop.")

    toast.show_startup(trusted_count)

    suppression_announced: set[int] = set()

    try:
        while True:
            batch = telemetry.next_batch(cfg.telemetry.batch_size_max)
            if not batch:
                time.sleep(0.2)
                continue

            # Self-ancestry filter: drop processes spawned by our own
            # action layer (taskkill.exe and any future helpers).
            filtered = [ev for ev in batch if ev.ppid != self_pid]
            skipped_internal = len(batch) - len(filtered)
            if skipped_internal:
                print(
                    f"[TRIDENT] {_ts()} skipped {skipped_internal} "
                    f"self-spawned process(es)"
                )

            # System-binary filter: conhost, svchost, dllhost, etc. are
            # ~80% of idle inference with zero decision value.
            to_score = []
            skipped_system = 0
            for ev in filtered:
                name = Path(ev.image_path).name if ev.image_path else ""
                if is_system_safe(name, bool(ev.is_system_path)):
                    audit.write({
                        "pid": ev.pid,
                        "name": name,
                        "path": ev.image_path,
                        "outcome": "system_pretrusted",
                    })
                    skipped_system += 1
                    continue
                to_score.append(ev)

            if skipped_system:
                print(
                    f"[TRIDENT] {_ts()} skipped {skipped_system} "
                    f"known system binar{'y' if skipped_system == 1 else 'ies'}"
                )

            if not to_score:
                continue

            decisions = kernel.score_batch(to_score)
            for ev, dec in zip(to_score, decisions):
                name = Path(ev.image_path).name if ev.image_path else "?"
                tier = cascade.route(dec, ev)
                is_trusted = bool(ev.image_path) and trust_store.is_trusted(ev.image_path)

                suffix = " [trusted]" if is_trusted else ""
                print(
                    f"[TRIDENT] {_ts()} {ev.pid} {name} -> "
                    f"action={dec.action} trust={dec.trust_level} "
                    f"conf={dec.confidence:.3f} tier={tier}{suffix}"
                )

                if is_trusted:
                    outcome = (
                        "trusted_override" if dec.action == "terminate"
                        else "trusted_allow"
                    )
                elif tier == 1:
                    evid = Evidence(process_tree=[ev])
                    act = Action(
                        action_type="terminate",
                        target_pid=ev.pid,
                        evidence=evid,
                    )
                    action_layer.execute(act)
                    outcome = "killed"
                    toast.show_kill(name, ev.pid, dec.threat_score, tier)
                elif tier == 2:
                    cascade.record_cycle(dec, ev)
                    outcome = "monitored"
                else:
                    if cascade.should_escalate(dec, ev):
                        toast.show_escalation(
                            name, ev.pid, dec.threat_score, dec.confidence
                        )
                        # Non-blocking toast -- no user callback. Count this
                        # as one escalation shown; after `suppression_after`
                        # the cascade suppresses the PID.
                        cascade.record_user_response(ev.pid, "ignore")
                        outcome = "toast"
                    elif cascade.is_suppressed(ev.pid):
                        outcome = "suppressed"
                        if ev.pid not in suppression_announced:
                            suppression_announced.add(ev.pid)
                            toast.show_suppressed(
                                name, ev.pid, cascade.suppression_after
                            )
                    else:
                        outcome = "silent_allow"

                audit.write({
                    "pid": ev.pid,
                    "name": name,
                    "path": ev.image_path,
                    "action": str(dec.action),
                    "trust": str(dec.trust_level),
                    "conf": round(float(dec.confidence), 4),
                    "threat_score": round(float(dec.threat_score), 3),
                    "tier": tier,
                    "outcome": outcome,
                    "trusted_path": is_trusted,
                })
    except KeyboardInterrupt:
        print("\n[TRIDENT] Shutting down.")
    finally:
        telemetry.stop()
        audit.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
