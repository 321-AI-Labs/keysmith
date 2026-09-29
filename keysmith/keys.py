"""Key pool: round-robin over env var aliases with cooldown on auth failure.

Key VALUES are read from the environment at call time by
:func:`read_key_value` — the only function in the codebase that reads key
values (charter security law). Everything else deals in aliases (env var
names), which are safe to log.
"""

from __future__ import annotations

import dataclasses
import os
import threading
from collections.abc import Sequence

AUTH_FAILURE_LIMIT: int = 3  # charter line 17: "fails auth 3 times"


@dataclasses.dataclass(frozen=True)
class KeyState:
    alias: str
    auth_failures: int  # failures since last success or cooldown entry
    cooldown_until: float | None  # time.monotonic() domain; None = not cooling


def read_key_value(alias: str) -> str | None:
    """os.environ.get(alias) AT CALL TIME; None if unset or empty.

    The ONLY function in the codebase that reads key values.
    """
    value = os.environ.get(alias)
    if value is None or value == "":
        return None
    return value


class KeyPool:
    """Round-robin pool with cooldown. All times are time.monotonic().

    CURSOR LAW: the cursor advances to (index_of_returned_alias + 1) % N
    ONLY when an alias is returned; keys skipped mid-scan and empty scans
    leave the cursor unchanged; every call scans forward from the cursor
    and wraps at most once.

    Internally locked (threading.Lock); shared across handler threads.
    """

    def __init__(self, aliases: Sequence[str], cooldown_seconds: float = 60.0) -> None:
        ordered: list[str] = []
        for alias in aliases:
            if alias not in ordered:
                ordered.append(alias)
        self._aliases = tuple(ordered)
        self._cooldown_seconds = float(cooldown_seconds)
        self._lock = threading.Lock()
        self._cursor = 0
        self._states: dict[str, KeyState] = {
            alias: KeyState(alias, 0, None) for alias in self._aliases
        }

    def _cooling(self, state: KeyState, now: float) -> bool:
        return state.cooldown_until is not None and now < state.cooldown_until

    def next_available(self, now: float) -> str | None:
        """Per CURSOR LAW: first alias from the scan that is not cooling at
        ``now`` and has a nonempty env value right now; None after a full
        wrap finds nothing. Does NOT touch failure counters."""
        with self._lock:
            total = len(self._aliases)
            for offset in range(total):
                index = (self._cursor + offset) % total
                alias = self._aliases[index]
                state = self._states[alias]
                if self._cooling(state, now):
                    continue
                if read_key_value(alias) is None:
                    continue
                self._cursor = (index + 1) % total
                return alias
            return None

    def report_auth_failure(self, alias: str, now: float) -> bool:
        """Record one upstream 401/403. At AUTH_FAILURE_LIMIT consecutive
        failures the key enters cooldown and the counter resets to 0 (fresh
        start after cooldown = recovery without restart). Returns True iff
        THIS call triggered cooldown."""
        with self._lock:
            state = self._states[alias]
            failures = state.auth_failures + 1
            if failures >= AUTH_FAILURE_LIMIT:
                self._states[alias] = KeyState(alias, 0, now + self._cooldown_seconds)
                return True
            self._states[alias] = KeyState(alias, failures, state.cooldown_until)
            return False

    def report_success(self, alias: str) -> None:
        """Reset auth_failures to 0 (so '3 times' means 3 in a row).
        No effect on an active cooldown."""
        with self._lock:
            state = self._states[alias]
            self._states[alias] = KeyState(alias, 0, state.cooldown_until)

    def state(self, alias: str) -> KeyState:
        with self._lock:
            return self._states[alias]

    def states(self) -> list[KeyState]:
        with self._lock:
            return [self._states[alias] for alias in self._aliases]
