"""The README must carry an honest known-limitations section and a plain
statement of the redaction scope.

Known limitations the README must document:

1. unbounded upstream body reads — a hostile configured endpoint can
   exhaust memory or pin a handler thread (documented, fix-later);
2. thread-per-connection with no cap;
3. the secret vault never evicts (documented: redaction cost grows with
   the key pool).

Redaction scope the README must state plainly:

1. upstream bodies are ASSUMED UTF-8;
2. non-UTF-8 bodies are MANGLED by the scrub path and are OUT OF
   REDACTION SCOPE for v0.1;
3. redaction covers UTF-8 text AND JSON-escaped forms.

Final-review disclosure clauses (DELIB-20260930-keysmith-final-release-
review, owner-approved) the README must keep:

4. loopback is the perimeter: --host beyond it is warn-only, combines
   with uncapped threads / no auth backoff, and the request-header phase
   is PRE-AUTH (client-side slowloris);
5. spend-log durability: per-record flush survives kill -9; POWER LOSS
   may lose the tail;
6. providers.json is TRUSTED INPUT: write access equals key redirect via
   any https base_url;
7. no CHANGELOG file: git log is the changelog.
"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


class ReadmeKnownLimitationsTests(unittest.TestCase):
    """The README must name each documented hardening gap."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
        cls.lowered = cls.text.lower()

    def test_has_known_limitations_section(self):
        self.assertRegex(
            self.lowered,
            re.compile(r"^#{1,6}\s.*known limitations", re.MULTILINE),
            "README must have a 'Known limitations' section",
        )

    def test_documents_unbounded_upstream_body_reads(self):
        self.assertIn(
            "unbounded",
            self.lowered,
            "must name the unbounded upstream body reads limitation",
        )
        self.assertTrue(
            "memory" in self.lowered or "ram" in self.lowered,
            "must state the consequence: memory/RAM exhaustion",
        )

    def test_documents_uncapped_thread_per_connection(self):
        self.assertIn(
            "thread",
            self.lowered,
            "must document thread-per-connection with no cap",
        )

    def test_documents_vault_never_evicts(self):
        self.assertIn(
            "evict",
            self.lowered,
            "must document that the secret vault never evicts",
        )


class ReadmeUtf8ScopeTests(unittest.TestCase):
    """The README must state plainly that

    1. upstream bodies are ASSUMED UTF-8;
    2. non-UTF-8 bodies are MANGLED by the scrub path and are OUT OF
       REDACTION SCOPE for v0.1;
    3. redaction covers UTF-8 text AND JSON-escaped forms.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
        cls.lowered = cls.text.lower()

    def test_states_upstream_bodies_assumed_utf8(self):
        self.assertIn(
            "assumed utf-8",
            self.lowered,
            "must state that upstream bodies are assumed UTF-8",
        )

    def test_states_non_utf8_bodies_mangled_and_out_of_scope(self):
        self.assertTrue(
            "non-utf-8" in self.lowered or "not utf-8" in self.lowered,
            "must name the non-UTF-8 body case",
        )
        self.assertIn(
            "mangl",
            self.lowered,
            "must state that the scrub path mangles non-UTF-8 bodies",
        )
        self.assertIn(
            "scope",
            self.lowered,
            "must state the scope boundary for non-UTF-8 bodies",
        )

    def test_states_redaction_covers_json_escaped_forms(self):
        self.assertTrue(
            "json-escaped" in self.lowered or "json escaped" in self.lowered,
            "must state that redaction covers JSON-escaped forms",
        )
        self.assertIn(
            "redact",
            self.lowered,
            "must keep the redaction claim next to the escaped-forms scope",
        )


class ReadmeTrustBoundaryTests(unittest.TestCase):
    """The final-review disclosure clauses must stay in the README."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
        cls.lowered = cls.text.lower()

    def test_documents_loopback_perimeter_and_pre_auth_slow_clients(self):
        self.assertIn(
            "loopback is the perimeter",
            self.lowered,
            "must name loopback as the perimeter",
        )
        self.assertIn(
            "slowloris",
            self.lowered,
            "must name the client-side slow-header drip variant",
        )
        self.assertIn(
            "before",
            self.lowered,
            "must state the header phase runs before the token check",
        )

    def test_documents_spend_log_durability_tail(self):
        self.assertIn(
            "power loss",
            self.lowered,
            "must state that power loss may lose the spend-log tail",
        )

    def test_documents_providers_json_trusted_input(self):
        self.assertIn(
            "trusted input",
            self.lowered,
            "must state that providers.json is trusted input",
        )
        self.assertIn(
            "https://",
            self.lowered,
            "must name the https base_url repoint as the key-redirect path",
        )

    def test_documents_git_log_is_the_changelog(self):
        self.assertIn(
            "git log is the changelog",
            self.lowered,
            "must state there is no CHANGELOG file",
        )


if __name__ == "__main__":
    unittest.main()
