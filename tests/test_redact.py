"""Unit tests for redact() and SecretVault: fake keys planted in
header-shaped strings, JSON bodies, error and traceback-shaped multi-line
strings, plus overlap/longest-first, empty-secret guards and boundary
placement cases."""

import json
import pathlib
import sys
import unittest

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith.redact import REDACTED, SecretVault, redact  # noqa: E402


class RedactFunctionTests(unittest.TestCase):
    def test_masks_secret_in_header_shaped_string(self):
        line = "Authorization: Bearer sk-fake-AAA-111"
        out = redact(line, ["sk-fake-AAA-111"])
        self.assertNotIn("sk-fake-AAA-111", out)
        self.assertIn(REDACTED, out)
        self.assertEqual(out, "Authorization: Bearer " + REDACTED)

    def test_masks_secret_inside_json_body(self):
        body = '{"config":{"api_key":"sk-fake-BBB-222"},"note":"sk-fake-BBB-222"}'
        out = redact(body, ["sk-fake-BBB-222"])
        self.assertNotIn("sk-fake-BBB-222", out)
        self.assertEqual(out.count(REDACTED), 2)

    def test_masks_secret_in_error_message_string(self):
        message = "Incorrect API key provided: Bearer sk-fake-CCC-333."
        out = redact(message, ["sk-fake-CCC-333"])
        self.assertNotIn("sk-fake-CCC-333", out)
        self.assertIn("Bearer " + REDACTED, out)

    def test_masks_secret_in_traceback_shaped_multiline_string(self):
        text = (
            "Traceback (most recent call last):\n"
            '  File "upstream.py", line 10, in call\n'
            "    raise RuntimeError('bad key sk-fake-CCC-333')\n"
            "RuntimeError: bad key sk-fake-CCC-333\n"
        )
        out = redact(text, ["sk-fake-CCC-333"])
        self.assertNotIn("sk-fake-CCC-333", out)
        self.assertIn("bad key " + REDACTED, out)
        self.assertEqual(out.count(REDACTED), 2)

    def test_longest_secret_first_masks_overlaps(self):
        out = redact("sk-short and sk-short-long", ["sk-short", "sk-short-long"])
        self.assertNotIn("sk-short", out)
        self.assertEqual(out, f"{REDACTED} and {REDACTED}")

    def test_secret_at_start_and_end(self):
        out = redact("sk-edge-1 hello sk-edge-1", ["sk-edge-1"])
        self.assertEqual(out, f"{REDACTED} hello {REDACTED}")

    def test_repeated_occurrences_all_masked(self):
        out = redact("k k k k", ["k"])
        self.assertEqual(out, " ".join([REDACTED] * 4))

    def test_empty_and_whitespace_secrets_ignored(self):
        self.assertEqual(redact("unchanged", ["", "   ", "\t"]), "unchanged")

    def test_case_sensitive_match(self):
        out = redact("SK-CASE-9 sk-case-9", ["sk-case-9"])
        self.assertIn("SK-CASE-9", out)
        self.assertNotIn("sk-case-9", out)

    def test_no_secrets_returns_text_unchanged(self):
        self.assertEqual(redact("plain text", []), "plain text")

    def test_secret_containing_json_punctuation(self):
        out = redact('{"a": 1}', ['{"a": 1}'])
        self.assertEqual(out, REDACTED)


class SecretVaultTests(unittest.TestCase):
    def test_register_and_redact(self):
        vault = SecretVault()
        vault.register("sk-vault-DDD-444")
        out = vault.redact("key=sk-vault-DDD-444 token=sk-vault-DDD-444")
        self.assertNotIn("sk-vault-DDD-444", out)
        self.assertEqual(out.count(REDACTED), 2)

    def test_empty_registrations_ignored(self):
        vault = SecretVault()
        vault.register("")
        vault.register("   ")
        self.assertEqual(len(vault), 0)
        self.assertEqual(vault.redact("x"), "x")

    def test_duplicate_registration_counted_once(self):
        vault = SecretVault()
        vault.register("sk-dup")
        vault.register("sk-dup")
        self.assertEqual(len(vault), 1)

    def test_multiple_secrets_masked_together(self):
        vault = SecretVault()
        vault.register("sk-one-111")
        vault.register("sk-two-222")
        out = vault.redact("sk-one-111 + sk-two-222")
        self.assertEqual(out, f"{REDACTED} + {REDACTED}")

    def test_vault_redact_without_secrets_is_identity(self):
        vault = SecretVault()
        self.assertEqual(vault.redact("nothing secret"), "nothing secret")


class SecretVaultEscapedTwinTests(unittest.TestCase):
    """SecretVault.register must also register the JSON-escaped twin of
    every secret — ``json.dumps(secret)[1:-1]`` — so escaped serializations
    (``\\u00e9``, ``\\"``, ``\\\\``) are redacted on every surface keysmith
    emits or relays. Without the twin, a JSON body that carries the secret
    escaped survives exact-substring redaction untouched, and the client
    that json.loads the body sees the full secret."""

    TWIN_KEYS = (
        "sk-kéy-üñï-444",        # non-ASCII -> \uXXXX escapes
        'sk-qu"ote-key-555',     # embedded double quote -> \"
        "sk-back\\slash-key-666",  # embedded backslash -> \\
        "sk-日本語-key-777",      # CJK -> \uXXXX escapes
    )

    def test_register_redacts_the_json_escaped_twin(self):
        for key in self.TWIN_KEYS:
            with self.subTest(key=key):
                vault = SecretVault()
                vault.register(key)
                escaped = json.dumps(key)[1:-1]
                self.assertNotIn(escaped, key, "fixture sanity: twin differs from raw")
                out = vault.redact(f"echo {escaped} end")
                self.assertNotIn(escaped, out, "escaped twin must be masked")
                self.assertIn(REDACTED, out)

    def test_register_redacts_raw_and_escaped_simultaneously(self):
        vault = SecretVault()
        vault.register("sk-kéy-üñï-444")
        # The escaped twin in a PYTHON string literal is the literal
        # backslash-u text json.dumps emits:
        escaped_twin = json.dumps("sk-kéy-üñï-444")[1:-1]
        text = f"a sk-kéy-üñï-444 b {escaped_twin} c"
        out = vault.redact(text)
        self.assertNotIn("sk-kéy", out)
        self.assertEqual(out.count(REDACTED), 2)

    def test_pure_ascii_twin_is_deduplicated(self):
        # json.dumps of a plain ASCII secret escapes nothing: the twin IS
        # the secret, and registering it must not double-count.
        vault = SecretVault()
        vault.register("sk-plain-AAA-111")
        self.assertEqual(len(vault), 1)

    def test_empty_and_whitespace_still_register_nothing(self):
        vault = SecretVault()
        vault.register("")
        vault.register("   ")
        self.assertEqual(len(vault), 0)

    def test_twin_registration_survives_multiple_secrets(self):
        vault = SecretVault()
        for key in self.TWIN_KEYS:
            vault.register(key)
        text = " ".join(json.dumps(key)[1:-1] for key in self.TWIN_KEYS)
        out = vault.redact(text)
        for key in self.TWIN_KEYS:
            self.assertNotIn(json.dumps(key)[1:-1], out)
            self.assertNotIn(key, out)
        self.assertEqual(out.count(REDACTED), len(self.TWIN_KEYS))


if __name__ == "__main__":
    unittest.main()
