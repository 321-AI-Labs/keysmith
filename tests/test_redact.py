"""Unit tests for redact() and SecretVault: fake keys planted in
header-shaped strings, JSON bodies, error and traceback-shaped multi-line
strings, plus overlap/longest-first, empty-secret guards and boundary
placement cases."""

import unittest

from keysmith.redact import REDACTED, SecretVault, redact


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


if __name__ == "__main__":
    unittest.main()
