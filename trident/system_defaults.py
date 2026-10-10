"""Pre-trusted Windows system binaries.

These are processes that appear dozens of times per minute, always
resolve to allow + system_critical, and always route to silent_allow.
Scoring them through the model is 80% of idle inference cost with zero
decision value.

The allowlist is name + is_system_path gated. A file named conhost.exe
in %TEMP% is NOT trusted by this module and will be scored normally.

Do NOT add here: powershell.exe, pwsh.exe, cmd.exe, wscript.exe,
cscript.exe, csrss.exe, lsass.exe, winlogon.exe, services.exe,
smss.exe. Those are the processes the model needs to judge -- they
are where the false-positive rate on the model is meaningful, and
where the cascade's safety net is actually exercised.
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
})


def is_system_safe(name: str, is_system_path: bool) -> bool:
    """True if this process can skip the model.

    Requires both: a name on the allowlist AND a system path.
    """
    if not is_system_path:
        return False
    return name.lower() in SYSTEM_SAFE_NAMES