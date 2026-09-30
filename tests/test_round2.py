"""Hardening tests: escaped-form redaction, decoded-walk leak checks, token
guards, spend-line caps, and upstream error kinds.

What this module pins for v0.1:

* SecretVault registers the JSON-escaped twin of every secret, so escaped
  serializations (``\\uXXXX``, ``\\"``, ``\\\\``) are redacted everywhere,
  not just the raw value;
* decoded-walk leak tests: 200-success bodies, 404 model-echo envelopes and
  spend lines must carry no vault-registered key value in any decoded
  string — raw-byte sweeps alone are structurally blind to JSON escaping,
  which is why every assertion here runs after ``json.loads``;
* KeysmithServer rejects empty and whitespace-only client tokens (with
  token='' a bare 'Authorization: Bearer ' would authenticate because
  hmac.compare_digest('','') is True), and the Bearer scheme match is
  case-insensitive per RFC 7235 while the token comparison stays exact;
* the client-controlled model string is capped at SpendRecord-build time,
  so no client input can produce an unbounded JSONL spend line;
* the all-keys-fail 502 envelope carries a closed-vocabulary error_kind
  derived from the upstream error body's ``error.code`` via an allowlist
  map — never upstream text.

Loopback only, stdlib only, fake keys only (env planted via
unittest.mock.patch.dict).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import urllib.request
from typing import Any
from unittest import mock

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith.config import Config, ProviderConfig  # noqa: E402
from keysmith.redact import SecretVault  # noqa: E402
from keysmith.server import KeysmithServer  # noqa: E402
from keysmith.spendlog import SpendLog, SpendRecord  # noqa: E402
from tests.decoded_walk import walk_decoded_body, walk_decoded_jsonl  # noqa: E402
from tests.fake_upstream import FakeUpstream  # noqa: E402
from tests.test_server import (  # noqa: E402
    KEY_A_ALIAS,
    KEY_A_VALUE,
    KEY_BACKSLASH_ALIAS,
    KEY_BACKSLASH_VALUE,
    KEY_NONASCII_ALIAS,
    KEY_NONASCII_VALUE,
    KEY_QUOTE_ALIAS,
    KEY_QUOTE_VALUE,
    TOKEN,
    ServerTestCase,
    escaped_key_forms,
    make_provider,
)

# ---------------------------------------------------------------------------
# The widened plant set: é + CJK + double-quote + backslash.
#
# HEADER LAW: http.client.putheader encodes outgoing
# header values as latin-1, so a key value containing any character beyond
# U+00FF cannot reach an upstream via the Authorization header — CJK raises
# UnicodeEncodeError at putheader and the attempt becomes a TRANSPORT 502.
# é (U+00E9), '"' and '\' ride the wire fine. Consequences pinned by these
# tests:
#   * é / quote / backslash keys can be the upstream-FAILING keys on the
#     all-keys-fail 502 path (their values ride the header into the fake's
#     echoing 401 body);
#   * a CJK key value still enters the vault — keysmith registers the value
#     BEFORE the upstream call (keysmith/server.py:606) — and must never
#     leak through any client-visible surface afterwards; its leak position
#     is the 200-success body echo (message content) plus every envelope
#     path, exercised below.
# ---------------------------------------------------------------------------

KEY_CJK_ALIAS = "FAKE_KEY_CJK"
KEY_CJK_VALUE = "sk-日本語-key-777"  # U+65E5 U+672C U+8A9E — beyond latin-1
PLANT_KEYS = (KEY_NONASCII_VALUE, KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE, KEY_CJK_VALUE)
ADVERSARIAL_FAILING = frozenset(
    "Bearer " + value for value in (KEY_NONASCII_VALUE, KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE)
)


# ---------------------------------------------------------------------------
# Decoded-walk envelope tests, path (a): all-keys-fail 502.
# ---------------------------------------------------------------------------


class AllKeysFailDecodedWalkTests(ServerTestCase):
    """é + quote + backslash keys ALL fail upstream auth -> the all-keys-fail
    502 envelope. The upstream 401 bodies echo each bearer value
    JSON-escaped; the client-visible envelope must carry only fixed
    vocabulary: upstream_status, a fixed message, and an
    error_kind from the closed enum — never upstream data, never
    ``upstream_error``, never any key form in any decoded string."""

    aliases = (KEY_NONASCII_ALIAS, KEY_QUOTE_ALIAS, KEY_BACKSLASH_ALIAS)
    env = {
        KEY_NONASCII_ALIAS: KEY_NONASCII_VALUE,
        KEY_QUOTE_ALIAS: KEY_QUOTE_VALUE,
        KEY_BACKSLASH_ALIAS: KEY_BACKSLASH_VALUE,
    }
    fake_kwargs = {"fail_auth_values": ADVERSARIAL_FAILING}

    def test_all_keys_fail_502_decoded_walk(self):
        self.reset_spend()
        status, _headers, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 502)
        parsed = walk_decoded_body(
            self,
            body,
            (KEY_NONASCII_VALUE, KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE),
            context="all-keys-fail 502 envelope",
            forbid_error_keys=("upstream_error",),
        )
        err = parsed["error"]
        self.assertEqual(err["upstream_status"], 401)
        self.assertIn("failed authentication", err["message"])
        # Fixed-vocabulary error kind derived from the
        # upstream 401 body's error code ('invalid_api_key' in the fake's
        # default 401 body).
        self.assertEqual(err["error_kind"], "invalid_api_key")
        # Exactly one routed record; spend and diagnostics stay clean of
        # every byte serialization (raw, escaped, 'Bearer '-prefixed).
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, 401)
        self.assertIn(records[0].key_alias, self.aliases)
        spend = self.spend_text()
        diagnostics = "\n".join(self.server.diagnostics)
        for key in (KEY_NONASCII_VALUE, KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE):
            for form in escaped_key_forms(key):
                self.assertNotIn(form, spend.encode("utf-8"), f"spend leak {form!r}")
                self.assertNotIn(form, diagnostics.encode("utf-8"), f"diagnostics leak {form!r}")


# ---------------------------------------------------------------------------
# The CJK plant: cannot ride the Authorization header
# (putheader latin-1 law), so it takes the two flows a CJK key
# value can actually reach.
# ---------------------------------------------------------------------------


class CjkKeyFlowTests(ServerTestCase):
    """One CJK + one ASCII key. Flow 1: the CJK key is attempted first — its
    value IS vault-registered before the call (keysmith/server.py:619), the
    call dies at putheader -> transport 502 whose envelope must stay clean.
    Flow 2: the ASCII key serves a 200 whose message echo
    replants the CJK value JSON-escaped — the decoded walk must catch it."""

    aliases = (KEY_CJK_ALIAS, KEY_A_ALIAS)
    env = {KEY_CJK_ALIAS: KEY_CJK_VALUE, KEY_A_ALIAS: KEY_A_VALUE}

    def test_cjk_transport_502_then_decoded_walk_of_success_echo(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        # --- flow 1: CJK key attempt -> transport 502 (must stay clean) ---
        status, _headers, body = self.post_chat(self.chat_body(content="hi"), token=self.token)
        self.assertEqual(status, 502)
        parsed = walk_decoded_body(
            self, body, (KEY_CJK_VALUE,), context="CJK-key transport 502 envelope"
        )
        err = parsed["error"]
        self.assertEqual(err["message"], "upstream unreachable")
        self.assertIn(err["error_kind"], ("timeout", "connection", "tls", "unknown"))
        records = self.spend_log.read_all()
        self.assertEqual(records[0].status, 0)
        self.assertEqual(records[0].key_alias, KEY_CJK_ALIAS)
        # --- flow 2: ASCII key serves; CJK value planted in the message ---
        status, _headers, body = self.post_chat(
            self.chat_body(content=f"my cjk key is {KEY_CJK_VALUE} ok"), token=self.token
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.fake.requests()[-1].authorization, "Bearer " + KEY_A_VALUE)
        # The echo comes back JSON-escaped (\u65e5...); the decoded walk
        # proves the escaped form is masked, so the client's json.loads
        # yields no key value in the decoded content.
        walk_decoded_body(
            self, body, (KEY_CJK_VALUE, KEY_A_VALUE), context="200 success echo of CJK plant"
        )


# ---------------------------------------------------------------------------
# Decoded-walk envelope tests, path (b): 200-success body
# echo, widened to three shapes.
# ---------------------------------------------------------------------------


class SuccessEchoDecodedWalkTests(ServerTestCase):
    """`echo_auth_in_success_body`: every 200 body replants the SERVING
    key's value JSON-escaped. Rotation serves é, then quote, then backslash
    across three requests, so each shape gets its own 200-echo leak
    assertion."""

    aliases = (KEY_NONASCII_ALIAS, KEY_QUOTE_ALIAS, KEY_BACKSLASH_ALIAS)
    env = {
        KEY_NONASCII_ALIAS: KEY_NONASCII_VALUE,
        KEY_QUOTE_ALIAS: KEY_QUOTE_VALUE,
        KEY_BACKSLASH_ALIAS: KEY_BACKSLASH_VALUE,
    }
    fake_kwargs = {"echo_auth_in_success_body": True}

    def test_each_key_shape_serving_leaks_nothing_decoded(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        expected_order = (KEY_NONASCII_VALUE, KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE)
        for index, serving in enumerate(expected_order):
            with self.subTest(serving_key=serving):
                status, _headers, body = self.post_chat(
                    self.chat_body(content=f"msg-{index}"), token=self.token
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    self.fake.requests()[-1].authorization, "Bearer " + serving
                )
                # THE decoded walk: after json.loads, no planted key in raw
                # or JSON-escaped form may survive in any decoded string.
                walk_decoded_body(
                    self, body, expected_order[: index + 1],
                    context=f"200 echo body (served by {serving!r})",
                )
                # Post-fix proof the plant was MASKED, not merely dropped.
                self.assertIn("***REDACTED***", body.decode("utf-8"))
        # Every spend line and diagnostic stays clean of every form.
        spend = self.spend_text()
        diagnostics = "\n".join(self.server.diagnostics)
        for key in expected_order:
            for form in escaped_key_forms(key):
                self.assertNotIn(form, spend.encode("utf-8"))
                self.assertNotIn(form, diagnostics.encode("utf-8"))


# ---------------------------------------------------------------------------
# A third leak position: the pre-route 404 envelope echoes the
# client-controlled model string and the spend record stores it
# (``str(exc)`` -> _respond_pre_route). With vault-registered
# planted values in the model field, BOTH surfaces must stay clean.
# ---------------------------------------------------------------------------


class ModelEchoDecodedWalkTests(ServerTestCase):
    aliases = (KEY_NONASCII_ALIAS, KEY_QUOTE_ALIAS, KEY_BACKSLASH_ALIAS)
    env = {
        KEY_NONASCII_ALIAS: KEY_NONASCII_VALUE,
        KEY_QUOTE_ALIAS: KEY_QUOTE_VALUE,
        KEY_BACKSLASH_ALIAS: KEY_BACKSLASH_VALUE,
    }
    fake_kwargs = {"fail_auth_values": ADVERSARIAL_FAILING}

    def test_model_field_echo_leaks_nothing_decoded(self):
        self.reset_spend()
        # Request 1: all three é/quote/backslash keys fail auth -> their
        # values are vault-registered before each attempt.
        status, _headers, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 502)
        walk_decoded_body(
            self, body, PLANT_KEYS[:3], context="all-keys-fail 502 before model echo"
        )
        # The CJK value cannot ride the Authorization header (putheader
        # latin-1 law — see CjkKeyFlowTests for its natural registration on
        # a real attempt); register it directly, exactly as a real attempt
        # would (same precedent as HandlerSafetyTests).
        self.vault.register(KEY_CJK_VALUE)
        # Request 2: all four planted values in the client-controlled model
        # field -> unknown provider -> 404 envelope echoes the model, and
        # the spend record stores it.
        planted_model = (
            "nope/x" + KEY_NONASCII_VALUE + "y" + KEY_QUOTE_VALUE
            + "z" + KEY_BACKSLASH_VALUE + "w" + KEY_CJK_VALUE
        )
        status, _headers, body = self.post_chat(
            self.chat_body(model=planted_model), token=self.token
        )
        self.assertEqual(status, 404)
        walk_decoded_body(self, body, PLANT_KEYS, context="404 model-echo envelope")
        walk_decoded_jsonl(self, self.spend_text(), PLANT_KEYS, context="model-echo spend log")


# ---------------------------------------------------------------------------
# Token guards at class level.
# ---------------------------------------------------------------------------


class TokenGuardTests(unittest.TestCase):
    """KeysmithServer.__init__ must reject empty and whitespace-only client
    tokens: with token='' a bare `Authorization: Bearer ` (empty
    credentials) WOULD authenticate because hmac.compare_digest("","") is
    True. The class-level guard makes such a server unconstructible."""

    def _make(self, token: str) -> KeysmithServer:
        cfg = Config(providers={"fake": make_provider("https://api.example.com/v1")})
        spend = SpendLog(pathlib.Path(tempfile.mkdtemp(prefix="keysmith-token-")) / "spend.jsonl")
        return KeysmithServer(cfg, token, spend, SecretVault())

    def test_init_rejects_empty_token(self):
        with self.assertRaises(ValueError):
            self._make("")

    def test_init_rejects_whitespace_only_tokens(self):
        for bad in ("   ", " \t ", "\t\r\n ", " "):
            with self.subTest(token=repr(bad)):
                with self.assertRaises(ValueError):
                    self._make(bad)

    def test_init_accepts_nonempty_token(self):
        server = self._make("tok-nonempty-ok")
        try:
            self.assertEqual(server.token, "tok-nonempty-ok")
        finally:
            server.stop()


class BearerSchemeCaseTests(ServerTestCase):
    """RFC 7235: the auth-scheme production is case-insensitive, so
    `bearer`/`BEARER`/`BeArEr` before a valid token must authenticate. The
    token comparison itself stays exact."""

    def test_lowercase_bearer_scheme_authenticates(self):
        status, _headers, _body = self.request(
            "POST", "/v1/chat/completions", body=self.chat_body(),
            token=None, headers={"Authorization": f"bearer {self.token}"},
        )
        self.assertEqual(status, 200)
        status, _headers, _body = self.request(
            "GET", "/v1/models",
            token=None, headers={"Authorization": f"bearer {self.token}"},
        )
        self.assertEqual(status, 200)

    def test_uppercase_and_mixed_case_schemes_authenticate(self):
        for scheme in ("BEARER", "BeArEr", "bEaReR"):
            with self.subTest(scheme=scheme):
                status, _headers, _body = self.request(
                    "POST", "/v1/chat/completions", body=self.chat_body(),
                    token=None, headers={"Authorization": f"{scheme} {self.token}"},
                )
                self.assertEqual(status, 200)

    def test_cased_scheme_with_wrong_token_is_401(self):
        # Case-insensitive SCHEME, exact TOKEN.
        status, _headers, _body = self.request(
            "POST", "/v1/chat/completions", body=self.chat_body(),
            token=None, headers={"Authorization": f"BeArEr wrong-token"},
        )
        self.assertEqual(status, 401)

    def test_scheme_without_space_or_credentials_is_401(self):
        # The scheme token alone (no space, no credentials) must
        # never authenticate — a bare Bearer header carries no credentials.
        for header in ("Bearer", "bearer", "BEARER"):
            with self.subTest(header=header):
                status, _headers, _body = self.request(
                    "POST", "/v1/chat/completions", body=self.chat_body(),
                    token=None, headers={"Authorization": header},
                )
                self.assertEqual(status, 401)


# ---------------------------------------------------------------------------
# Cap the client-controlled model field at record-build
# time on BOTH the pre-route and routed paths.
#
# Contract specified by these tests (implementation may land elsewhere, but
# the cap must be observable exactly here):
#   * ``keysmith.spendlog.MAX_MODEL_CHARS`` bounds the model field of every
#     SpendRecord at build time; 32 <= MAX_MODEL_CHARS <= 1024 (a cap above
#     1024 would still admit multi-KB lines);
#   * normal model names pass through unchanged;
#   * neither an unknown 200 KB model (pre-route 404) nor a configured
#     5,000-char model (routed 200) may produce a spend line >= 2,000 chars.
# ---------------------------------------------------------------------------


def _record_with_model(model: str) -> SpendRecord:
    return SpendRecord(
        ts="2026-01-01T00:00:00+00:00",
        provider="fake",
        model=model,
        upstream_model="upstream-model-x",
        key_alias="FAKE_KEY_A",
        status=200,
        error_kind=None,
        latency_ms=1.0,
        prompt_tokens=1,
        completion_tokens=1,
        total_tokens=2,
    )


class ModelCapUnitTests(unittest.TestCase):
    def test_cap_constant_bounds(self):
        from keysmith.spendlog import MAX_MODEL_CHARS

        self.assertGreaterEqual(MAX_MODEL_CHARS, 32, "real model names must pass through")
        self.assertLessEqual(MAX_MODEL_CHARS, 1024, "the cap must actually bound line size")

    def test_record_caps_huge_model_at_build_time(self):
        from keysmith.spendlog import MAX_MODEL_CHARS

        record = _record_with_model("x" * 10_000)
        self.assertLessEqual(len(record.model), MAX_MODEL_CHARS)
        line = record.to_json_line()
        self.assertLess(len(line), 2000, "a huge model must not become a huge JSONL line")

    def test_short_model_passes_through_unchanged(self):
        from keysmith.spendlog import MAX_MODEL_CHARS

        self.assertLessEqual(len("glm/glm-4.8"), MAX_MODEL_CHARS)
        record = _record_with_model("glm/glm-4.8")
        self.assertEqual(record.model, "glm/glm-4.8")


class PreRouteModelCapTests(ServerTestCase):
    """Pre-route path: an unknown model string of 200 KB -> 404 -> the spend
    line must be bounded."""

    def test_pre_route_404_spend_line_is_bounded(self):
        from keysmith.spendlog import MAX_MODEL_CHARS

        self.reset_spend()
        huge = "z" * 200_000
        status, _headers, _body = self.post_chat(
            self.chat_body(model=f"{huge}/nope"), token=self.token
        )
        self.assertEqual(status, 404)
        lines = [line for line in self.spend_text().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertLess(len(lines[0]), 2000, "pre-route spend line must be bounded")
        record = self.spend_log.read_all()[0]
        self.assertEqual(record.provider, "")
        self.assertLessEqual(len(record.model), MAX_MODEL_CHARS)


class RoutedModelCapTests(unittest.TestCase):
    """Routed path: a CONFIGURED 5,000-char public model name (allowed by
    config validation: nonempty, no '/') routes and succeeds; its spend
    record must still be capped at record-build time. Own scaffolding because
    the provider config needs the fake's URL, which only exists at runtime.
    """

    LONG_MODEL = "m" * 5_000

    def setUp(self) -> None:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-cap-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.fake = FakeUpstream()
        self.fake.start()
        self.addCleanup(self.fake.stop)
        provider = ProviderConfig(
            name="fake",
            base_url=self.fake.url,
            key_env_vars=(KEY_A_ALIAS,),
            models={"fake-model": "upstream-model-x", self.LONG_MODEL: "upstream-model-long"},
            cooldown_seconds=60.0,
            timeout_seconds=30.0,
            allow_insecure=True,
        )
        self.spend_path = tmp / "spend.jsonl"
        self.spend_log = SpendLog(self.spend_path)
        patcher = mock.patch.dict(os.environ, {KEY_A_ALIAS: KEY_A_VALUE})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.server = KeysmithServer(
            Config(providers={"fake": provider}), TOKEN, self.spend_log, SecretVault(),
            host="127.0.0.1", port=0,
        )
        self.server.start()
        self.addCleanup(self.server.stop)

    def test_routed_spend_line_is_bounded(self):
        from keysmith.spendlog import MAX_MODEL_CHARS

        body = json.dumps(
            {"model": f"fake/{self.LONG_MODEL}", "messages": [{"role": "user", "content": "hi"}]}
        ).encode("utf-8")
        request = urllib.request.Request(
            self.server.url + "/v1/chat/completions", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            self.assertEqual(response.status, 200)
        lines = [line for line in self.spend_text().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertLess(len(lines[0]), 2000, "routed spend line must be bounded")
        record = self.spend_log.read_all()[0]
        self.assertEqual(record.provider, "fake")
        self.assertEqual(record.status, 200)
        self.assertLessEqual(len(record.model), MAX_MODEL_CHARS)
        # The upstream body must carry the REWRITTEN short upstream id, so
        # capping the record cannot corrupt routing itself.
        self.assertEqual(
            json.loads(self.fake.requests()[-1].body)["model"], "upstream-model-long"
        )

    def spend_text(self) -> str:
        return (
            self.spend_path.read_text(encoding="utf-8") if self.spend_path.exists() else ""
        )


# ---------------------------------------------------------------------------
# upstream_error_kind enum.
#
# Contract specified by these tests: ``keysmith.upstream.upstream_error_kind``
# (body: bytes) -> str maps the parsed upstream error body's ``error.code``
# through an allowlist to a CLOSED four-value vocabulary
# {'invalid_api_key', 'quota', 'rate_limited', 'other'} — preserving
# why-it-failed UX without re-serializing upstream data.
# ---------------------------------------------------------------------------

ERROR_KIND_VOCAB = ("invalid_api_key", "quota", "rate_limited", "other")


def _upstream_error_body(code: Any) -> bytes:
    return json.dumps(
        {"error": {"message": "Incorrect API key provided: sk-fake.", "type": "invalid_request_error", "code": code}}
    ).encode("utf-8")


class UpstreamErrorKindTests(unittest.TestCase):
    def _kind(self, body: bytes) -> str:
        from keysmith.upstream import upstream_error_kind

        return upstream_error_kind(body)

    def test_allowlisted_codes_map_to_their_kinds(self):
        cases = (
            ("invalid_api_key", "invalid_api_key"),
            ("insufficient_quota", "quota"),
            ("rate_limit_exceeded", "rate_limited"),
            ("rate_limited", "rate_limited"),
        )
        for code, expected in cases:
            with self.subTest(code=code):
                self.assertEqual(self._kind(_upstream_error_body(code)), expected)

    def test_unmapped_inputs_map_to_other(self):
        cases: list[bytes] = [
            _upstream_error_body("brand_new_code_9000"),
            _upstream_error_body(""),
            _upstream_error_body(None),
            _upstream_error_body(3),
            _upstream_error_body({"nested": "dict"}),
            json.dumps({"error": {"message": "no code field"}}).encode("utf-8"),
            json.dumps({"error": "not-an-object"}).encode("utf-8"),
            json.dumps(["not", "a", "dict"]).encode("utf-8"),
            b"not json at all",
            b"\xff\xfe not utf8",
            b"",
        ]
        for body in cases:
            with self.subTest(body=body[:60]):
                self.assertEqual(self._kind(body), "other")

    def test_vocabulary_is_closed_and_carries_no_upstream_data(self):
        adversarial = (
            "sk-kéy-üñï-444",
            "sk-日本語-key-777",
            'qu"ote',
            "back\\slash",
            "x" * 10_000,
            "invalid_api_key<script>",
        )
        for code in adversarial:
            with self.subTest(code=code[:30]):
                kind = self._kind(_upstream_error_body(code))
                self.assertIn(kind, ERROR_KIND_VOCAB)
                self.assertLess(len(kind), 20, "the kind must be fixed vocabulary, not upstream text")
                self.assertNotIn(code[:8], kind)


class QuotaKindEnvelopeTests(ServerTestCase):
    """All keys fail auth with upstream error code 'insufficient_quota' ->
    the all-keys-fail 502 envelope must carry error_kind 'quota' and stay
    free of upstream data."""

    aliases = (KEY_A_ALIAS,)
    fake_kwargs = {
        "fail_auth_values": frozenset({"Bearer " + KEY_A_VALUE}),
        "fail_auth_code": "insufficient_quota",
    }

    def test_envelope_carries_quota_kind_and_no_upstream_data(self):
        status, _headers, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 502)
        parsed = walk_decoded_body(
            self, body, (KEY_A_VALUE,), context="quota 502 envelope",
            forbid_error_keys=("upstream_error",),
        )
        err = parsed["error"]
        self.assertEqual(err["upstream_status"], 401)
        self.assertEqual(err["error_kind"], "quota")
        # The upstream code string itself must not surface verbatim.
        for value in (KEY_A_VALUE, "Bearer " + KEY_A_VALUE, "insufficient_quota", "Incorrect API key"):
            self.assertNotIn(value, body.decode("utf-8"))


class UnknownKindEnvelopeTests(ServerTestCase):
    """All keys fail auth with an UNMAPPED upstream code -> error_kind
    'other'; the raw upstream code must not leak through the enum."""

    aliases = (KEY_A_ALIAS,)
    fake_kwargs = {
        "fail_auth_values": frozenset({"Bearer " + KEY_A_VALUE}),
        "fail_auth_code": "brand_new_code_9000",
    }

    def test_envelope_carries_other_kind_and_not_the_raw_code(self):
        status, _headers, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 502)
        parsed = walk_decoded_body(
            self, body, (KEY_A_VALUE,), context="unknown-code 502 envelope",
            forbid_error_keys=("upstream_error",),
        )
        err = parsed["error"]
        self.assertEqual(err["upstream_status"], 401)
        self.assertEqual(err["error_kind"], "other")
        self.assertNotIn("brand_new_code_9000", body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
