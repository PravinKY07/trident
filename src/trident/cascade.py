"""Layer 3 - Confidence cascade.

Routes a Decision into one of three tiers:

    Tier 1 (auto-kill) : action=terminate AND confidence > 0.92
    Tier 2 (monitor)   : 0.70 < confidence <= 0.92
    Tier 3 (escalate)  : confidence <= 0.70
                         OR system-critical path (safety net)
                         OR high-confidence allow (silent allow)

Safety net: the model misclassifies ~12% of Windows system binaries
as malware. If the process path starts with a system-critical prefix,
or exactly matches a known-critical file, the cascade forces Tier 3
regardless of model confidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from .contracts import Decision, ProcessEvent, Tier

# Never auto-terminate anything under these prefixes.
CRITICAL_PATH_PREFIXES = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\systemapps",
    "c:\\program files\\windows defender",
    "c:\\program files\\windowsapps",
    "c:\\program files (x86)\\windows defender",
)

# Never auto-terminate these exact files (files directly under C:\Windows\,
# which the prefix list above does not cover).
CRITICAL_EXACT_FILES = (
    "c:\\windows\\explorer.exe",
    "c:\\windows\\notepad.exe",
    "c:\\windows\\regedit.exe",
    "c:\\windows\\write.exe",
    "c:\\windows\\system.ini",
    "c:\\windows\\win.ini",
)


@dataclass
class CascadeState:
    """Per-PID cascade bookkeeping."""

    pid: int
    cycles_in_tier2: int = 0
    escalations_shown: int = 0
    suppressed: bool = False


class Cascade:
    """Three-tier confidence router with a system-path safety net."""

    def __init__(
        self,
        tier1_threshold: float = 0.92,
        tier2_threshold: float = 0.70,
        tier2_max_cycles: int = 3,
        suppression_after: int = 3,
    ) -> None:
        """Configure thresholds. Values come from trident.toml."""
        self.tier1 = tier1_threshold
        self.tier2 = tier2_threshold
        self.tier2_max_cycles = tier2_max_cycles
        self.suppression_after = suppression_after
        self._state: dict[int, CascadeState] = {}

    def _get(self, pid: int) -> CascadeState:
        """Fetch or create per-PID state."""
        st = self._state.get(pid)
        if st is None:
            st = CascadeState(pid=pid)
            self._state[pid] = st
        return st

    @staticmethod
    def is_critical_path(path: str | None) -> bool:
        """Return True if the path is a Windows system-critical location."""
        if not path:
            return False
        low = path.lower()
        if any(low.startswith(p) for p in CRITICAL_PATH_PREFIXES):
            return True
        if low in CRITICAL_EXACT_FILES:
            return True
        return False

    def route(self, decision: Decision, event: ProcessEvent | None = None) -> Tier:
        """Return the cascade tier for a decision.

        If `event` is provided, its path is checked against the critical
        safety net before any auto-kill decision is made.
        """
        st = self._get(decision.pid)
        if st.suppressed:
            return 2

        # Safety net: never auto-kill a system-critical path.
        if event is not None and self.is_critical_path(event.image_path):
            return 3
        if decision.trust_level == "system_critical":
            return 3

        # Silent allow: high-confidence allow is Tier 3 with no toast.
        if decision.action == "allow" and decision.confidence > self.tier1:
            return 3

        # Tier 1: auto-kill.
        if decision.action == "terminate" and decision.confidence > self.tier1:
            return 1

        # Tier 2: monitor.
        if decision.confidence > self.tier2:
            return 2

        # Tier 3: escalate.
        return 3

    def should_escalate(
        self, decision: Decision, event: ProcessEvent | None = None
    ) -> bool:
        """True when Tier 3 should surface a user toast (vs silent allow)."""
        st = self._get(decision.pid)
        if st.suppressed:
            return False
        if self.route(decision, event) != 3:
            return False
        # High-confidence allow is silent: no toast.
        if self.is_silent_allow(decision):
            return False
        return True

    def is_silent_allow(self, decision: Decision) -> bool:
        """True for a high-confidence allow that passes without any UI."""
        return decision.action == "allow" and decision.confidence > self.tier1

    def record_cycle(
        self, decision: Decision, event: ProcessEvent | None = None
    ) -> None:
        """Increment the Tier-2 cycle counter for this PID."""
        st = self._get(decision.pid)
        if self.route(decision, event) == 2:
            st.cycles_in_tier2 += 1

    def record_user_response(self, pid: int, response: str) -> None:
        """Record a user's response to an escalation.

        response='ignore' increments a counter; after N ignores the PID
        is suppressed. response in {'remove','kill'} suppresses instantly.
        """
        st = self._get(pid)
        if response == "ignore":
            st.escalations_shown += 1
            if st.escalations_shown >= self.suppression_after:
                st.suppressed = True
        elif response in ("remove", "kill"):
            st.suppressed = True

    def is_suppressed(self, pid: int) -> bool:
        """Public accessor for suppressed state."""
        return self._get(pid).suppressed