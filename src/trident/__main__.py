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
from .mode import ModeStore
from .runtime import (
    CLEANUP_DIR,
    LOGS_DIR,
    TRUSTED_PATHS_FILE,
    _DATA_ROOT,
    ensure_user_dirs,
)
from .system_defaults import is_system_safe
from .telemetry import TelemetrySession
from .trust_store import TrustStore


def _resolve_paths(cfg) -> dict:
    """Resolve model, tokenizer, and config paths.

    Model files live in %LOCALAPPDATA%\\TRIDENT\\models, populated by
    `trident models fetch`.
    """
    model_dir = _DATA_ROOT / "models"
    return {
        "model_path": model_dir / cfg.model.filename,
        "tokenizer_dir": model_dir / "tokenizer",
        "config_path": model_dir / "rl_agent_config.json",
    }


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def _is_self_venv(image_path: str | None) -> bool:
    if not image_path:
        return False
    try:
        venv_prefix = os.path.normcase(os.path.abspath(sys.prefix))
        path = os.path.normcase(os.path.abspath(image_path))
        return path.startswith(venv_prefix + os.sep)
    except Exception:
        return False


def main() -> int:
    """Load config, wire all layers, run the watch loop."""
    ensure_user_dirs()

    # Auto-resolves to %LOCALAPPDATA%\TRIDENT\config\trident.toml,
    # seeding from the shipped default on first run.
    cfg = load()
    paths = _resolve_paths(cfg)

    if not paths["model_path"].exists():
        print(f"[TRIDENT] Model not found at {paths['model_path']}.", file=sys.stderr)
        print("[TRIDENT] Run `trident models fetch` to download it.", file=sys.stderr)
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

    mode_store = ModeStore()
    mode = mode_store.mode
    print(f"[TRIDENT] Mode: {mode}")

    cascade = Cascade(
        tier1_threshold=cfg.cascade.tier1_threshold,
        tier2_threshold=cfg.cascade.tier2_threshold,
        tier2_max_cycles=cfg.cascade.tier2_max_cycles,
        suppression_after=cfg.cascade.escalation_suppression_after,
    )

    action_layer = ActionLayer(
        ps1_output_dir=CLEANUP_DIR,
        safety_whitelist=cfg.action.safety_whitelist,
    )

    audit = AuditLog(LOGS_DIR)
    trust_store = TrustStore(TRUSTED_PATHS_FILE)
    trusted_count = len(trust_store.all_trusted())
    if trusted_count:
        print(f"[TRIDENT] Trust store loaded: {trusted_count} path(s) trusted.")

    telemetry = TelemetrySession(ring_buffer_size=cfg.telemetry.ring_buffer_size)
    telemetry.start()

    self_pid = os.getpid()
    print(f"[TRIDENT] Watching for process events (self pid={self_pid}). Ctrl+C to stop.")

    toast.show_startup(trusted_count, mode=mode)

    suppression_announced: set[int] = set()
    runtime_trusted_pids: set[int] = set()

    try:
        while True:
            new_mode = mode_store.poll()
            if new_mode is not None and new_mode != mode:
                mode = new_mode
                print(f"[TRIDENT] {_ts()} mode changed to {mode}")

            newly_trusted = trust_store.poll()
            if newly_trusted:
                import psutil
                for p in newly_trusted:
                    print(f"[TRIDENT] {_ts()} trusted via toast: {p}")
                    try:
                        target = os.path.normcase(os.path.abspath(p))
                    except Exception:
                        continue
                    for proc in psutil.process_iter(["pid", "exe"]):
                        try:
                            exe = proc.info.get("exe")
                            if not exe:
                                continue
                            if os.path.normcase(os.path.abspath(exe)) == target:
                                runtime_trusted_pids.add(proc.info["pid"])
                                print(
                                    f"[TRIDENT] {_ts()} silenced running pid "
                                    f"{proc.info['pid']} (trusted)"
                                )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

            batch = telemetry.next_batch(cfg.telemetry.batch_size_max)
            if not batch:
                time.sleep(0.2)
                continue

            filtered = [ev for ev in batch if ev.ppid != self_pid]
            skipped_internal = len(batch) - len(filtered)
            if skipped_internal:
                print(
                    f"[TRIDENT] {_ts()} skipped {skipped_internal} "
                    f"self-spawned process(es)"
                )

            before = len(filtered)
            filtered = [ev for ev in filtered if not _is_self_venv(ev.image_path)]
            skipped_venv = before - len(filtered)
            if skipped_venv:
                print(
                    f"[TRIDENT] {_ts()} skipped {skipped_venv} "
                    f"self-venv process(es)"
                )

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
                is_runtime_trusted = ev.pid in runtime_trusted_pids

                suffix = ""
                if is_trusted:
                    suffix = " [trusted]"
                elif is_runtime_trusted:
                    suffix = " [trusted:runtime]"

                print(
                    f"[TRIDENT] {_ts()} {ev.pid} {name} -> "
                    f"action={dec.action} trust={dec.trust_level} "
                    f"conf={dec.confidence:.3f} tier={tier}{suffix}"
                )

                if is_trusted or is_runtime_trusted:
                    outcome = (
                        "trusted_override" if dec.action == "terminate"
                        else "trusted_allow"
                    )
                elif tier == 1:
                    if mode == "enforce":
                        evid = Evidence(process_tree=[ev])
                        act = Action(
                            action_type="terminate",
                            target_pid=ev.pid,
                            evidence=evid,
                        )
                        action_layer.execute(act)
                        outcome = "killed"
                        toast.show_kill(
                            name, ev.pid, dec.threat_score, tier,
                            path=ev.image_path,
                        )
                    else:
                        outcome = "would_kill"
                        print(
                            f"[TRIDENT] {_ts()} [{mode}] would kill "
                            f"{name} pid={ev.pid} conf={dec.confidence:.3f}"
                        )
                elif tier == 2:
                    cascade.record_cycle(dec, ev)
                    outcome = "monitored"
                else:
                    if cascade.should_escalate(dec, ev):
                        if mode == "dry-run":
                            outcome = "would_toast"
                            print(
                                f"[TRIDENT] {_ts()} [dry-run] would escalate "
                                f"{name} pid={ev.pid} score={dec.threat_score:.1f}"
                            )
                        else:
                            toast.show_escalation(
                                name, ev.pid, dec.threat_score, dec.confidence,
                                path=ev.image_path,
                            )
                            cascade.record_user_response(ev.pid, "ignore")
                            outcome = "toast"
                    elif cascade.is_suppressed(ev.pid):
                        outcome = "suppressed"
                        if ev.pid not in suppression_announced:
                            suppression_announced.add(ev.pid)
                            if mode != "dry-run":
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
                    "trusted_path": is_trusted or is_runtime_trusted,
                    "mode": mode,
                })
    except KeyboardInterrupt:
        print("\n[TRIDENT] Shutting down.")
    finally:
        telemetry.stop()
        audit.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())