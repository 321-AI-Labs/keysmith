"""The single redaction primitive every emitted string passes through.

Charter item 7: key material must never appear in logs, error messages, or
tracebacks. Everything keysmith sends to a client, writes to the spend log,
or collects as a diagnostic funnels through :func:`redact` (usually via
:class:`SecretVault`).
"""

from __future__ import annotations

import collections.abc
import threading

REDACTED: str = "***REDACTED***"


def redact(text: str, secrets: collections.abc.Iterable[str]) -> str:
    """Return ``text`` with every occurrence of every secret masked.

    Secrets are applied longest-first, so overlapping secrets are fully
    masked. Empty or whitespace-only secrets are ignored. Matching is a
    case-sensitive exact substring search. Pure function, no global state.
    """
    usable = {secret for secret in secrets if secret and secret.strip()}
    for secret in sorted(usable, key=lambda item: (-len(item), item)):
        text = text.replace(secret, REDACTED)
    return text


class SecretVault:
    """Thread-safe registry of secret values (key values, the client token)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: list[str] = []

    def register(self, secret: str) -> None:
        """Add a secret value; empty/whitespace-only values are ignored."""
        if not secret or not secret.strip():
            return
        with self._lock:
            if secret not in self._secrets:
                self._secrets.append(secret)

    def redact(self, text: str) -> str:
        """Apply :func:`redact` using every registered secret."""
        with self._lock:
            secrets = tuple(self._secrets)
        return redact(text, secrets)

    def __len__(self) -> int:
        """Number of registered secrets (test convenience)."""
        with self._lock:
            return len(self._secrets)
