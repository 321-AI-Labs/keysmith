"""Redaction-scope tests: every registered variant form of a secret.

The v0.1 vault registers, programmatically per secret, four forms: the raw
value, the canonical lowercase-hex JSON-escaped twin, the UPPERCASE-hex
twin, and the double-escaped canonical form (implementation:
``registered_forms`` in keysmith/redact.py). This module pins that
contract at the unit level and through two real response paths, so no
planted key in raw, lowercase-escaped, uppercase-hex-escaped, or
double-escaped form survives on any decoded client-visible value.

Why the extra forms exist — the leak classes this scope closes:

* a body TEXT carrying the key SINGLE-escaped with UPPERCASE hex is valid
  JSON per RFC 8259 and decodes identically to the raw key, so an
  uppercase-hex plant must not survive (it matters for the é and CJK
  shapes; for the quote/backslash shapes the uppercase form equals the
  canonical form, which the escaped twin already covers);
* a body text carrying the canonical escaped twin (serialized by
  json.dumps as the DOUBLE-escaped form) leaks the escaped form in the
  DECODED content, so a double-escaped plant must not survive either.

Loopback only, stdlib only, fake keys only (env planted via
unittest.mock.patch.dict).
"""

from __future__ import annotations

import pathlib
import sys
import unittest

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith.redact import REDACTED, SecretVault  # noqa: E402
from tests.decoded_walk import variant_forms, walk_decoded_body  # noqa: E402
from tests.test_round2 import (  # noqa: E402
    ADVERSARIAL_FAILING,
    KEY_CJK_VALUE,
    PLANT_KEYS,
)
from tests.test_server import (  # noqa: E402
    KEY_A_ALIAS,
    KEY_A_VALUE,
    KEY_BACKSLASH_VALUE,
    KEY_NONASCII_ALIAS,
    KEY_NONASCII_VALUE,
    KEY_QUOTE_ALIAS,
    KEY_QUOTE_VALUE,
    KEY_BACKSLASH_ALIAS,
    ServerTestCase,
)

# Keys whose RAW value cannot sit verbatim inside a JSON string: a literal
# '"' would terminate the string, a lone '\' starts an invalid escape. Their
# raw-plant leak positions (decoded values) are covered by the
# test_round2.py envelope tests; here the raw plant rides only the
# text-safe shapes (é, CJK).
RAW_UNPLANTABLE = frozenset((KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE))

# A mixed-script key that appears in NO fixture: registration forms must be
# derived programmatically per secret, so a fresh shape must behave exactly
# like the four planted shapes (forms are derived per secret, never
# hand-built).
EXTRA_DERIVED_KEY = "sk-téßt-Üñï-«ключ-日本»-999"


def json_text_carrying(form: str) -> bytes:
    """UTF-8 JSON whose TEXT carries ``form`` VERBATIM inside a string.

    The plant shape: ``form`` is already a
    run of valid JSON escape sequences (or raw text-safe characters), so it
    is spliced in by CONCATENATION — json.dumps would re-escape it and
    destroy the plant. What the plant proves per form:
      raw                   -> the client's decoded value holds the raw key;
      json-escaped (lower)  -> decodes to the raw key;
      uppercase-hex escaped -> decodes to the raw key (RFC 8259 hex digits
                               are case-insensitive);
      double-escaped        -> decodes to the canonical escaped form (one
                               json.loads away from the raw key).
    """
    return ('{"content": "x ' + form + ' y"}').encode("utf-8")


# ---------------------------------------------------------------------------
# Unit level — the registration contract itself.
# ---------------------------------------------------------------------------


class VaultVariantRegistrationTests(unittest.TestCase):
    """After register(secret), vault.redact masks EVERY derived variant
    form carried verbatim in a body text: the raw value, the canonical
    lowercase-hex twin, the uppercase-hex twin, and the double-escaped
    form (the canonical twin is not a substring of its own double-escaping).
    The extra mixed-script key proves the forms are
    derived per secret, not hand-built for the planted fixtures."""

    def test_register_masks_every_variant_form(self):
        for key in PLANT_KEYS + (EXTRA_DERIVED_KEY,):
            with self.subTest(key=key[:16]):
                vault = SecretVault()
                vault.register(key)
                for label, form in variant_forms(key):
                    with self.subTest(form=label):
                        redacted = vault.redact(
                            json_text_carrying(form).decode("utf-8")
                        )
                        self.assertNotIn(
                            form, redacted,
                            f"{label} form of {key!r} survived vault redaction",
                        )
                        self.assertIn(
                            REDACTED, redacted,
                            f"{label} form must be MASKED, not merely dropped",
                        )

    def test_registration_stays_idempotent(self):
        # Registering the same value twice must not duplicate entries
        # (whatever the per-secret form count is).
        vault = SecretVault()
        vault.register(KEY_NONASCII_VALUE)
        before = len(vault)
        vault.register(KEY_NONASCII_VALUE)
        self.assertEqual(len(vault), before)


# ---------------------------------------------------------------------------
# Probe level, path (a) — the relaying 200 body.
#
# Serving layout: the three latin-1-ridable plant keys (é / quote /
# backslash) fail auth on every request — each attempt registers its value
# in the vault exactly as a real key attempt does (keysmith/server.py:619)
# — and KEY_A serves, so the fake's verbatim success_body_override is
# relayed to the client through _emit's vault redaction
# (keysmith/server.py:262). The CJK value cannot ride the Authorization
# header (putheader latin-1 law — see CjkKeyFlowTests in test_round2.py)
# and is registered directly, exactly as a real attempt would (same
# precedent as ModelEchoDecodedWalkTests).
# ---------------------------------------------------------------------------


class VariantRelay200Tests(ServerTestCase):
    """Every (key, form) plant relays through a REAL 200 body. For the
    uppercase-hex plants of é and CJK a leak would expose the
    RAW key in decoded content, and for the double-escaped plants of ALL
    FOUR shapes it would expose the canonical escaped form. The raw and
    lowercase-escaped plants are pins — the JSON-escaped twin already
    masks those, at probe level."""

    aliases = (KEY_NONASCII_ALIAS, KEY_QUOTE_ALIAS, KEY_BACKSLASH_ALIAS, KEY_A_ALIAS)
    env = {
        KEY_NONASCII_ALIAS: KEY_NONASCII_VALUE,
        KEY_QUOTE_ALIAS: KEY_QUOTE_VALUE,
        KEY_BACKSLASH_ALIAS: KEY_BACKSLASH_VALUE,
        KEY_A_ALIAS: KEY_A_VALUE,
    }
    fake_kwargs = {"fail_auth_values": ADVERSARIAL_FAILING}

    def test_relayed_200_body_leaks_no_variant_form_decoded(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        self.vault.register(KEY_CJK_VALUE)
        for key in PLANT_KEYS:
            for label, form in variant_forms(key):
                if label == "raw" and key in RAW_UNPLANTABLE:
                    continue  # a raw '"'/'\' cannot sit verbatim in JSON text
                with self.subTest(key=key[:14], form=label):
                    self.fake.success_body_override = json_text_carrying(form)
                    try:
                        status, _headers, body = self.post_chat(
                            self.chat_body(content="relay"), token=self.token
                        )
                    finally:
                        self.fake.success_body_override = None
                    self.assertEqual(status, 200)
                    # The relay was served by the non-plant key (the three
                    # plant keys fail auth on every attempt).
                    self.assertEqual(
                        self.fake.requests()[-1].authorization,
                        "Bearer " + KEY_A_VALUE,
                    )
                    # THE decoded walk: after json.loads,
                    # no planted key in raw or ANY variant form may survive
                    # in any decoded string — nor any form's bytes in the body.
                    walk_decoded_body(
                        self, body, (key,),
                        context=f"200 relay carrying {label} plant of {key[:14]!r}",
                    )
                    # Proof the plant was MASKED, not merely dropped.
                    self.assertIn("***REDACTED***", body.decode("utf-8"))
        # Every spend line and diagnostic stays clean of every variant byte
        # form of every planted key.
        spend = self.spend_text().encode("utf-8")
        diagnostics = "\n".join(self.server.diagnostics).encode("utf-8")
        for key in PLANT_KEYS:
            for _label, form in variant_forms(key):
                self.assertNotIn(form.encode("utf-8"), spend)
                self.assertNotIn(form.encode("utf-8"), diagnostics)


# ---------------------------------------------------------------------------
# Probe level, path (b) — the all-keys-fail 502 path.
#
# The fake's 401 bodies are replaced by ONE verbatim body whose text
# carries every text-safe variant form of all four planted keys. The 502
# envelope never relays upstream bytes — these assertions pin that this
# stays true even when the upstream error body carries encodings the vault
# does not know about, and that the spend log and diagnostics stay clean
# too.
# ---------------------------------------------------------------------------


class AllKeysFailVariant502Tests(ServerTestCase):
    aliases = (KEY_NONASCII_ALIAS, KEY_QUOTE_ALIAS, KEY_BACKSLASH_ALIAS)
    env = {
        KEY_NONASCII_ALIAS: KEY_NONASCII_VALUE,
        KEY_QUOTE_ALIAS: KEY_QUOTE_VALUE,
        KEY_BACKSLASH_ALIAS: KEY_BACKSLASH_VALUE,
    }
    fake_kwargs = {"fail_auth_values": ADVERSARIAL_FAILING}

    def test_variant_laden_401s_leak_nothing_through_the_502_path(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        # CJK cannot ride the Authorization header (putheader latin-1 law);
        # register it directly, exactly as a real attempt would, so its
        # forms are vault-known for the sweeps below.
        self.vault.register(KEY_CJK_VALUE)
        forms = [
            form
            for key in PLANT_KEYS
            for label, form in variant_forms(key)
            if not (label == "raw" and key in RAW_UNPLANTABLE)
        ]
        # Built by CONCATENATION, not json.dumps: the variant forms must sit
        # VERBATIM in the 401 body text (json.dumps would re-escape them and
        # destroy the plants). error.code is preserved so the envelope's
        # closed-vocabulary error_kind is still derived deterministically.
        self.fake.auth_error_body_override = (
            '{"error": {"message": "Incorrect API key provided: '
            + " ".join(forms)
            + '.", "type": "invalid_request_error", "code": "invalid_api_key"}}'
        ).encode("utf-8")
        try:
            status, _headers, body = self.post_chat(self.chat_body(), token=self.token)
        finally:
            self.fake.auth_error_body_override = None
        self.assertEqual(status, 502)
        parsed = walk_decoded_body(
            self, body, PLANT_KEYS,
            context="all-keys-fail 502 envelope (variant-laden 401s)",
            forbid_error_keys=("upstream_error",),
        )
        err = parsed["error"]
        self.assertEqual(err["upstream_status"], 401)
        self.assertEqual(err["error_kind"], "invalid_api_key")
        self.assertIn("failed authentication", err["message"])
        # Exactly one routed record for the all-keys-fail request; spend and
        # diagnostics stay clean of every variant byte form.
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, 401)
        self.assertIn(records[0].key_alias, self.aliases)
        spend = self.spend_text().encode("utf-8")
        diagnostics = "\n".join(self.server.diagnostics).encode("utf-8")
        for key in PLANT_KEYS:
            for _label, form in variant_forms(key):
                self.assertNotIn(form.encode("utf-8"), spend)
                self.assertNotIn(form.encode("utf-8"), diagnostics)


if __name__ == "__main__":
    unittest.main()
