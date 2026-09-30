"""Decoded-walk leak assertions: the standard every leak test applies.

Raw-byte substring sweeps are structurally blind to serialization escapes:
a key value planted inside a JSON string and re-serialized by ``json.dumps``
(ensure_ascii=True) appears in the body bytes only as ``\\u00e9`` / ``\\"`` /
``\\\\`` escapes, so a raw-value substring check passes while the client —
which ``json.loads`` the body — sees the full key value.

The walk covers every variant form the vault registers (raw; canonical
lowercase-hex escaped; uppercase-hex escaped — RFC 8259 hex digits are
case-insensitive, so valid JSON that decodes identically to the raw
secret; double-escaped canonical — decodes to the escaped form, one
``json.loads`` away from the raw key):

Every leak test therefore must:
  1. ``json.loads`` the client-visible body;
  2. walk EVERY decoded string value (and object keys) recursively;
  3. assert the raw AND every escaped variant form of every planted key —
     canonical lowercase-hex (``json.dumps(k)[1:-1]``), UPPERCASE-hex
     (same escapes, hex digits uppercased; valid JSON per RFC 8259 and
     decodes identically), and double-escaped canonical (the escaped form
     itself JSON-escaped) — is absent from every decoded string;
  4. keep the raw-byte sweep as a secondary check (every form's UTF-8 byte
     serialization must not survive in the bytes either);
  5. where applicable, assert ``upstream_error`` is absent from the
     envelope's error object.

This module is test scaffolding (stdlib only) and is not collected by
``unittest discover`` (filename does not match ``test*.py``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from typing import Any


def escaped_form(secret: str) -> str:
    """The JSON-escaped twin: json.dumps(secret)[1:-1].

    Exactly what ``json.dumps`` emits for the secret inside a JSON string
    with the surrounding quotes stripped: non-ASCII -> ``\\uXXXX`` (lowercase
    hex), ``"`` -> ``\\"``, ``\\`` -> ``\\\\``.
    """
    return json.dumps(secret)[1:-1]


def upper_hex_escaped_form(secret: str) -> str:
    """The canonical escaped form with every ``\\uXXXX`` escape's hex
    digits UPPERCASED.

    RFC 8259 hex digits are case-insensitive, so this is valid JSON that
    DECODES IDENTICALLY to the raw secret — a body text carrying it hands
    the raw key to any client that ``json.loads`` it. For a secret with no
    ``\\uXXXX`` escapes (pure ASCII) this equals :func:`escaped_form`."""
    return re.sub(
        r"\\u([0-9a-f]{4})",
        lambda match: "\\u" + match.group(1).upper(),
        escaped_form(secret),
    )


def double_escaped_form(secret: str) -> str:
    """The canonical escaped form, itself JSON-escaped —
    ``json.dumps(escaped_form(secret))[1:-1]``.

    A body text carrying this form (exactly what ``json.dumps`` emits when
    a value's content IS the escaped form) decodes to the escaped form in
    the client's decoded value — one ``json.loads`` away from the raw
    key."""
    return escaped_form(escaped_form(secret))


def variant_forms(secret: str) -> tuple[tuple[str, str], ...]:
    """Every (label, form) pair the decoded-walk standard asserts for
    ``secret``: raw, canonical lowercase-hex escaped, uppercase-hex escaped,
    double-escaped canonical.

    Duplicate forms collapse onto the first label (for a pure-ASCII secret
    with no JSON escapes all four are the raw value itself). The forms are
    DERIVED programmatically from the secret — never hand-built fixtures
    (registration law)."""
    by_form: dict[str, str] = {}
    for label, form in (
        ("raw", secret),
        ("json-escaped", escaped_form(secret)),
        ("uppercase-hex-escaped", upper_hex_escaped_form(secret)),
        ("double-escaped", double_escaped_form(secret)),
    ):
        by_form.setdefault(form, label)
    return tuple((label, form) for form, label in by_form.items())


def iter_decoded_strings(obj: Any) -> Iterator[str]:
    """Yield every string reachable in a decoded JSON value.

    Walks string leaves, every value of every object, every item of every
    array, AND every object key (a JSON object key is a string that could
    carry planted material just as a value can).
    """
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield key
            yield from iter_decoded_strings(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from iter_decoded_strings(item)


def secret_forms(secret: str) -> tuple[tuple[str, str], tuple[bytes, bytes]]:
    """(raw, json-escaped) string forms and their UTF-8 byte forms."""
    escaped = escaped_form(secret)
    return (secret, escaped), (secret.encode("utf-8"), escaped.encode("utf-8"))


def walk_decoded_body(
    case,
    body: bytes,
    secrets: Iterable[str],
    *,
    context: str = "client-visible body",
    forbid_error_keys: Iterable[str] = (),
) -> dict[str, Any]:
    """Assertion core for one client-visible body.

    * the body MUST parse as UTF-8 JSON (envelope contract);
    * every decoded string must be free of EVERY variant form (raw,
      canonical lowercase-hex escaped, uppercase-hex escaped, double-escaped
      canonical) of every planted secret;
    * the raw bytes must be free of every form's UTF-8 byte serialization
      as well;
    * ``forbid_error_keys`` names keys that must not appear on the envelope's
      ``error`` object (e.g. ``upstream_error``).

    Returns the parsed body for follow-up structural assertions.
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        case.fail(f"{context}: must be valid UTF-8 JSON, got {exc}: {body[:200]!r}")
        raise  # unreachable: case.fail raises
    strings = list(iter_decoded_strings(parsed))
    for secret in secrets:
        for label, form in variant_forms(secret):
            for index, value in enumerate(strings):
                case.assertNotIn(
                    form,
                    value,
                    f"{context}: {label} form of planted key {secret!r} survived "
                    f"JSON decoding in decoded string #{index}: {value[:300]!r}",
                )
            case.assertNotIn(
                form.encode("utf-8"),
                body,
                f"{context}: {label} byte form of planted key {secret!r} survived in the raw body bytes",
            )
    if forbid_error_keys:
        err = parsed.get("error") if isinstance(parsed, dict) else None
        case.assertIsInstance(err, dict, f"{context}: expected an 'error' object")
        for forbidden in forbid_error_keys:
            case.assertNotIn(
                forbidden,
                err,
                f"{context}: envelope error object must not carry {forbidden!r}",
            )
    return parsed


def walk_decoded_jsonl(
    case,
    text: str,
    secrets: Iterable[str],
    *,
    context: str = "spend log",
) -> None:
    """Assertion core for every line of a
    JSONL surface (the spend log): each line must parse, and every decoded
    string in it must be free of every variant form of every planted secret
    (raw, canonical escaped, uppercase-hex escaped, double-escaped), and the
    raw line bytes likewise."""
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        walk_decoded_body(
            case,
            line.encode("utf-8"),
            secrets,
            context=f"{context} line {number}",
        )
