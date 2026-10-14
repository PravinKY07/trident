"""Pre-trusted Windows system binaries.

These are processes that appear dozens of times per minute, always
resolve to allow + system_critical, and always route to silent_allow.
Scoring them through the model is 80% of idle inference cost with zero
decision value.

Two allowlists:

  SYSTEM_SAFE_NAMES -- name + is_system_path gated. A file named
      conhost.exe in %TEMP% is NOT trusted by this module and will be
      scored normally. This is the correct gate for system binaries:
      the name is common enough to be worth spoofing.

  SELF_SAFE_NAMES -- name alone, no path gate. Only TRIDENT's own
      artifacts belong here. `trident.exe` is the pip-generated console
      script; it lives in <venv>\\Scripts\\, not a system path. If a
      user has multiple Python environments and runs `trident` from a
      second one, the self-venv filter in __main__ won't catch it (that
      filter is scoped to the daemon's own sys.prefix). Without this
      list, the daemon scores its own CLI.

      Tradeoff: a malicious file named `trident.exe` would bypass the
      model. Accepted because the alternative is the daemon killing the
      command the user just typed.

Do NOT add to either list: powershell.exe, pwsh.exe, cmd.exe,
wscript.exe, cscript.exe, csrss.exe, lsass.exe, winlogon.exe,
services.exe, smss.exe. Those are the processes the model needs to
judge -- they are where the false-positive rate on the model is
meaningful, and where the cascade's safety net is actually exercised.
"""
from __future__ import annotations

SYSTEM_SAFE_NAMES = frozenset({
    # Console / shell hosts
    "conhost.exe",
    "openconsole.exe",
    "windowsterminal.exe",
    # Windows service hosts and infra
    "svchost.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "sppsvc.exe",
    "wmiapsrv.exe",
    "wmiprvse.exe",
    "smartscreen.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    # Vendor system-adjacent binaries that appear in the logs
    "secocl64.exe",
    # Our own kill tool, defense in depth on top of the ancestry filter
    "taskkill.exe",
    "timeout.exe",
})

# Trusted by name alone -- no path gate. TRIDENT's own artifacts only.
SELF_SAFE_NAMES = frozenset({
    "trident.exe",     # pip-generated console script, any venv
    "trident-script.py",  # older setuptools layout (some pip versions)
})


def is_system_safe(name: str, is_system_path: bool) -> bool:
    """True if this process can skip the model.

    SYSTEM_SAFE_NAMES require both a matching name and a system path.
    SELF_SAFE_NAMES match by name only.
    """
    if not name:
        return False
    low = name.lower()
    if low in SELF_SAFE_NAMES:
        return True
    if not is_system_path:
        return False
    return low in SYSTEM_SAFE_NAMES