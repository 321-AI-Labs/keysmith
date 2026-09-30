"""The single redaction primitive every emitted string passes through.

Law: key material must never appear in logs, error messages, or
tracebacks. Everything keysmith sends to a client, writes to the spend log,
or collects as a diagnostic funnels through :func:`redact` (usually via
:class:`SecretVault`).
"""

from __future__ import annotations

import collections.abc
import json
import re
import threading

REDACTED: str = "***REDACTED***"


def json_escaped_twin(secret: str) -> str:
    """The JSON-escaped serialization of ``secret`` as it appears inside a
    JSON string: ``json.dumps(secret)[1:-1]``.

    ``json.dumps`` (ensure_ascii=True) turns non-ASCII into ``\\uXXXX``,
    ``"`` into ``\\"`` and ``\\`` into ``\\\\``. A body that carries a secret
    in this escaped form survives exact-substring redaction of the raw
    value — yet any client that ``json.loads`` the body sees the full
    secret. Registering the twin closes that gap.
    """
    return json.dumps(secret)[1:-1]


def registered_forms(secret: str) -> tuple[str, ...]:
    """Every serialization of ``secret`` the vault registers, DERIVED
    programmatically per secret — no hand-built fixtures:

    * the raw value;
    * the canonical JSON-escaped twin (lowercase hex, ``json.dumps``);
    * the UPPERCASE-hex form of every ``\\uXXXX`` escape — RFC 8259 hex
      digits are case-insensitive, so a body text carrying it is valid
      JSON that decodes to the raw secret;
    * the double-escaped canonical form (the escaped twin itself
      JSON-escaped) — a body text carrying it decodes to the escaped twin,
      one ``json.loads`` away from the raw secret.

    Duplicate forms collapse (a pure-ASCII secret with no JSON escapes
    yields just the raw value)."""
    escaped = json_escaped_twin(secret)
    upper_hex = re.sub(
        r"\\u([0-9a-f]{4})",
        lambda match: "\\u" + match.group(1).upper(),
        escaped,
    )
    double_escaped = json_escaped_twin(escaped)
    forms: list[str] = []
    for form in (secret, escaped, upper_hex, double_escaped):
        if form not in forms:
            forms.append(form)
    return tuple(forms)


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
    """Thread-safe registry of secret values (key values, the client token).

    Every registration covers the raw value and every derived escape form
    (the JSON-escaped twin, its uppercase-hex variant, and the
    double-escaped form — see :func:`registered_forms`), so escaped
    serializations are redacted on every surface keysmith emits
    or relays. For a secret with no JSON escapes (plain ASCII) every form
    is the secret itself and is stored once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: list[str] = []

    def register(self, secret: str) -> None:
        """Add a secret value and every derived escape form; empty or
        whitespace-only values are ignored."""
        if not secret or not secret.strip():
            return
        with self._lock:
            for value in registered_forms(secret):
                if value not in self._secrets:
                    self._secrets.append(value)

    def redact(self, text: str) -> str:
        """Apply :func:`redact` using every registered secret."""
        with self._lock:
            secrets = tuple(self._secrets)
        return redact(text, secrets)

    def __len__(self) -> int:
        """Number of registered secrets (test convenience)."""
        with self._lock:
            return len(self._secrets)
