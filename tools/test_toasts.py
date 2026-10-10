"""Fire every toast type once, with 2-second gaps, so you can eyeball them.

Run:  python tools\test_toasts.py
"""
import sys
import time
from pathlib import Path

# allow running from repo root without install
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trident.toast import (
    show_startup,
    show_kill,
    show_escalation,
    show_trust_confirmation,
    show_suppressed,
)


def main() -> None:
    print("Firing 5 toast types, 3s apart. Watch bottom-right.")
    show_startup(trusted_count=6)
    time.sleep(3)

    show_kill(
        name="xmrig_sim.exe",
        pid=17560,
        score=9.9,
        tier=1,
        count=2,
    )
    time.sleep(3)

    show_escalation(
            name="powershell.exe",
            pid=2732,
            score=9.8,
            confidence=0.985,
    )
    time.sleep(3)

    show_trust_confirmation(r"C:\Users\Aalok\AppData\Local\Programs\Zed\Zed.exe")
    time.sleep(3)

    show_suppressed(name="someapp.exe", pid=9999, count=3)

    print("Done. Check Action Center (Win+A) for history.")


if __name__ == "__main__":
    main()
