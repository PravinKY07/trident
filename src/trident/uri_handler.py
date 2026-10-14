"""URI protocol handler. Launched by Windows when a toast button is clicked.

Supported URIs:
    trident:trust:<base64url-of-path>    add path to trust list
    trident:report:<pid>                 open the report window
"""
from __future__ import annotations

import base64
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .runtime import LOGS_DIR, TRUSTED_PATHS_FILE
from .trust_store import TrustStore


def _b64_decode(s: str) -> str:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode()).decode("utf-8")


def _audit_append(entry: dict) -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = LOGS_DIR / f"decisions-{today}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str))
        f.write("\n")


def handle_trust(b64_path: str) -> int:
    try:
        path = _b64_decode(b64_path)
    except Exception as e:
        print(f"[TRIDENT uri] decode failed: {e}", file=sys.stderr)
        return 1

    store = TrustStore(TRUSTED_PATHS_FILE)
    try:
        store.trust(path)
    except Exception as e:
        print(f"[TRIDENT uri] trust write failed: {e}", file=sys.stderr)
        return 1

    try:
        _audit_append({
            "path": path,
            "user_verdict": "trust_path",
            "source": "toast",
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        })
    except Exception as e:
        print(f"[TRIDENT uri] audit append failed: {e}", file=sys.stderr)

    try:
        from .toast import show_trust_confirmation
        show_trust_confirmation(path)
        time.sleep(0.8)
    except Exception as e:
        print(f"[TRIDENT uri] confirmation toast failed: {e}", file=sys.stderr)

    print(f"[TRIDENT uri] trusted: {path}")
    return 0


def handle_report(pid_str: str) -> int:
    try:
        pid = int(pid_str)
    except ValueError:
        print(f"[TRIDENT uri] invalid pid: {pid_str!r}", file=sys.stderr)
        return 1
    from .report import main as report_main
    return report_main([str(pid)])


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m trident.uri_handler <uri>", file=sys.stderr)
        return 2

    uri = argv[0].strip('"')

    if not uri.startswith("trident:"):
        print(f"[TRIDENT uri] not a trident uri: {uri!r}", file=sys.stderr)
        return 2

    parts = uri.split(":", 2)
    if len(parts) < 3:
        print(f"[TRIDENT uri] malformed: {uri!r}", file=sys.stderr)
        return 2

    _, action, arg = parts
    if action == "trust":
        return handle_trust(arg)
    if action == "report":
        return handle_report(arg)

    print(f"[TRIDENT uri] unknown action: {action}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())