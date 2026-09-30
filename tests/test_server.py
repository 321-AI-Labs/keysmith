"""End-to-end loopback tests for the keysmith HTTP server.

Every server (product and fake upstream) binds 127.0.0.1:0; no os.getcwd(),
no fixed ports, no network beyond loopback, no real keys (fake values are
planted via unittest.mock.patch.dict on os.environ).
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import shutil
import socket
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr
from typing import Any
from unittest import mock

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith import server as server_module  # noqa: E402
from keysmith.config import Config, ProviderConfig  # noqa: E402
from keysmith.redact import REDACTED, SecretVault  # noqa: E402
from keysmith.server import KeysmithServer, error_json, resolve_route, split_model  # noqa: E402
from keysmith.spendlog import SpendLog  # noqa: E402
from tests.decoded_walk import walk_decoded_body  # noqa: E402
from tests.fake_upstream import FakeUpstream  # noqa: E402

TOKEN = "tok-local-test-123"
KEY_A_ALIAS = "FAKE_KEY_A"
KEY_B_ALIAS = "FAKE_KEY_B"
KEY_A_VALUE = "sk-fake-AAA-111"
KEY_B_VALUE = "sk-fake-BBB-222"
TEST_ENV = {KEY_A_ALIAS: KEY_A_VALUE, KEY_B_ALIAS: KEY_B_VALUE}

# ---------------------------------------------------------------------------
# Adversarial key shapes for the envelope-level leak test.
#
# http.client.putheader encodes outgoing header values as latin-1, so a key
# value containing a character beyond U+00FF cannot even be sent upstream
# (verified before this test was written: U+2026 raises UnicodeEncodeError at
# putheader, and keysmith then fails the request as a transport error, never
# reaching the all-keys-fail path). The non-ASCII plant therefore uses
# latin-1-range characters (é U+00E9, ü U+00FC, ñ U+00F1, ï U+00EF): they DO
# reach the fake upstream and come back inside its JSON-escaped 401 echo —
# the exact serialization-escape leak class this test pins out.
# ---------------------------------------------------------------------------

KEY_NONASCII_ALIAS = "FAKE_KEY_NONASCII"
KEY_QUOTE_ALIAS = "FAKE_KEY_QUOTE"
KEY_BACKSLASH_ALIAS = "FAKE_KEY_BACKSLASH"
KEY_NONASCII_VALUE = "sk-kéy-üñï-444"  # non-ASCII, latin-1 encodable
KEY_QUOTE_VALUE = 'sk-qu"ote-key-555'  # embedded double quote
KEY_BACKSLASH_VALUE = "sk-back\\slash-key-666"  # embedded backslash
ADVERSARIAL_KEYS = (KEY_NONASCII_VALUE, KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE)
ADVERSARIAL_ENV = {
    KEY_NONASCII_ALIAS: KEY_NONASCII_VALUE,
    KEY_QUOTE_ALIAS: KEY_QUOTE_VALUE,
    KEY_BACKSLASH_ALIAS: KEY_BACKSLASH_VALUE,
}


def escaped_key_forms(key: str) -> list[bytes]:
    """Byte serializations of ``key`` that could plausibly reach a client.

    Covers: raw UTF-8, latin-1, and the JSON string escaping produced by
    ``json.dumps(..., ensure_ascii=True)`` (non-ASCII -> ``\\uXXXX`` with
    lowercase hex, ``"`` -> ``\\"``, ``\\`` -> ``\\\\``) plus an
    uppercase-hex variant of the same — each bare and 'Bearer '-prefixed.
    The JSON-escaped form is exactly the serialization that would survive
    raw-value redaction: re-serializing the parsed upstream 401 body
    escapes the key so the raw value no longer matches.
    """
    bare = [
        key.encode("utf-8"),
        key.encode("latin-1"),
        json.dumps(key)[1:-1].encode("utf-8"),
        re.sub(
            r"\\u([0-9a-f]{4})",
            lambda match: "\\u" + match.group(1).upper(),
            json.dumps(key)[1:-1],
        ).encode("utf-8"),
    ]
    return bare + [b"Bearer " + form for form in bare]


# ---------------------------------------------------------------------------
# Redact-then-truncate ordering fixtures.
#
# Both diagnostic paths truncate the formatted traceback at
# ``_TRACEBACK_CHAR_LIMIT`` (4000) before redacting. A secret straddling the
# cut point therefore survives as a partial fragment that redact() can no
# longer match (the full value is no longer present in the truncated text).
# 'Z7' is a two-character alphabet that appears nowhere else in a traceback,
# so any visible fragment of >= 8 chars is unambiguous key material. The
# paddings below place the 4000-char cut deep inside the secret for any
# traceback overhead between ~0 and ~2700 chars (measured overheads: ~220
# for a direct raise, ~800 through the mocked-resolver path).
# ---------------------------------------------------------------------------

_TRUNCATION_LIMIT = server_module._TRACEBACK_CHAR_LIMIT
TRUNCATION_SECRET = "Z7" * 1700  # 3400 chars
TRUNCATION_MESSAGE = (
    "P" * max(0, _TRUNCATION_LIMIT - 2800) + TRUNCATION_SECRET + "Q" * 500
)


def make_provider(base_url: str, aliases: tuple[str, ...] = ("FAKE_KEY_A", "FAKE_KEY_B"),
                  cooldown: float = 60.0, models: dict[str, str] | None = None,
                  name: str = "fake") -> ProviderConfig:
    return ProviderConfig(
        name=name,
        base_url=base_url,
        key_env_vars=aliases,
        models=dict(models or {"fake-model": "upstream-model-x"}),
        cooldown_seconds=cooldown,
        timeout_seconds=30.0,
        allow_insecure=True,
    )


def dead_loopback_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class ServerTestCase(unittest.TestCase):
    """One keysmith server + one fake upstream per test class."""

    token: str = TOKEN
    fake_kwargs: dict[str, Any] = {}
    aliases: tuple[str, ...] = (KEY_A_ALIAS, KEY_B_ALIAS)
    env: dict[str, str] = TEST_ENV  # env vars planted for this class's aliases
    cooldown: float = 60.0
    base_url_override: str | None = None  # set to skip the fake upstream
    extra_providers: dict[str, ProviderConfig] = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-test-"))
        cls.fake: FakeUpstream | None = None
        if cls.base_url_override is None:
            cls.fake = FakeUpstream(**cls.fake_kwargs)
            cls.fake.start()
            base_url = cls.fake.url
        else:
            base_url = cls.base_url_override
        providers: dict[str, ProviderConfig] = {"fake": make_provider(base_url, aliases=cls.aliases, cooldown=cls.cooldown)}
        providers.update(cls.extra_providers)
        cls.config = Config(providers=providers)
        cls.spend_path = cls.tmp / "spend.jsonl"
        cls.vault = SecretVault()
        cls.spend_log = SpendLog(cls.spend_path)
        cls.server = KeysmithServer(cls.config, cls.token, cls.spend_log, cls.vault, host="127.0.0.1", port=0)
        cls.server.start()
        patcher = mock.patch.dict(os.environ, cls.env)
        patcher.start()
        cls._env_patcher = patcher

    @classmethod
    def tearDownClass(cls) -> None:
        cls._env_patcher.stop()
        cls.server.stop()
        if cls.fake is not None:
            cls.fake.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- helpers ------------------------------------------------------

    def request(self, method: str, path: str, body: bytes | None = None,
                token: str | None = None, headers: dict[str, str] | None = None):
        req_headers: dict[str, str] = {"Content-Type": "application/json"}
        if token is not None:
            req_headers["Authorization"] = f"Bearer {token}"
        if headers:
            req_headers.update(headers)
        request = urllib.request.Request(
            self.server.url + path, data=body, method=method, headers=req_headers
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, dict(exc.headers), exc.read()

    def post_chat(self, body: bytes, token: str | None = None):
        return self.request("POST", "/v1/chat/completions", body=body, token=token)

    def chat_body(self, model: str = "fake/fake-model", content: str = "hello",
                  stream: Any = None) -> bytes:
        payload: dict[str, Any] = {"model": model, "messages": [{"role": "user", "content": content}]}
        if stream is not None:
            payload["stream"] = stream
        return json.dumps(payload).encode("utf-8")

    def spend_text(self) -> str:
        return self.spend_path.read_text(encoding="utf-8") if self.spend_path.exists() else ""

    def reset_spend(self) -> None:
        if self.spend_path.exists():
            self.spend_path.unlink()

    def sweep_for(self, secrets: list[str], *surfaces: str) -> None:
        for secret in secrets:
            for index, surface in enumerate(surfaces):
                self.assertNotIn(secret, surface, f"secret leaked to surface #{index}")


class ModelHelperTests(unittest.TestCase):
    def test_split_model(self):
        self.assertEqual(split_model("glm/glm-4.8"), ("glm", "glm-4.8"))

    def test_split_model_rejects_bad_strings(self):
        for bad in ("", "glm", "/glm", "glm/", "a/b/c", "glm/"):
            with self.subTest(model=bad):
                with self.assertRaises(ValueError):
                    split_model(bad)

    def test_resolve_route_happy(self):
        provider = make_provider("https://api.example.com/v1")
        route = resolve_route(Config(providers={"fake": provider}), "fake/fake-model")
        self.assertEqual(route.provider_id, "fake")
        self.assertEqual(route.public_model, "fake/fake-model")
        self.assertEqual(route.upstream_model, "upstream-model-x")

    def test_resolve_route_deny_by_default(self):
        cfg = Config(providers={"fake": make_provider("https://api.example.com/v1")})
        for model in ("other/thing", "fake/nope", "nope", "fake/fake-model/x"):
            with self.subTest(model=model):
                with self.assertRaises(ValueError) as ctx:
                    resolve_route(cfg, model)
                self.assertNotIn("upstream-model-x", str(ctx.exception))

    def test_error_json_envelope(self):
        payload = json.loads(
            error_json(404, "nope", "invalid_request_error", code="model_not_found",
                       upstream_status=401, error_kind="timeout")
        )
        err = payload["error"]
        self.assertEqual(err["message"], "nope")
        self.assertEqual(err["type"], "invalid_request_error")
        self.assertEqual(err["code"], "model_not_found")
        self.assertEqual(err["upstream_status"], 401)
        self.assertEqual(err["error_kind"], "timeout")


class RoutingTests(ServerTestCase):
    def test_wrong_token_gets_401(self):
        self.reset_spend()
        status, headers, body = self.post_chat(self.chat_body(), token="wrong-token")
        self.assertEqual(status, 401)
        err = json.loads(body)["error"]
        self.assertEqual(err["type"], "keysmith_auth")
        self.assertIn("token", err["message"])
        # Auth before logging — an unauthenticated 401
        # writes NO spend record.
        self.assertEqual(self.spend_log.line_count(), 0)

    def test_missing_token_gets_401(self):
        status, _, body = self.post_chat(self.chat_body(), token=None)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["type"], "keysmith_auth")

    def test_unknown_path_is_404_without_spend(self):
        self.reset_spend()
        status, _, body = self.request("POST", "/v1/nope", body=self.chat_body(), token=self.token)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"]["code"], "path_not_found")
        self.assertEqual(self.spend_log.line_count(), 0)

    def test_anthropic_v1_messages_is_404(self):
        # README 'What it is NOT': Anthropic-native /v1/messages is not
        # implemented — it is just another unknown path.
        status, _, body = self.request("POST", "/v1/messages", body=self.chat_body(), token=self.token)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"]["code"], "path_not_found")

    def test_unknown_model_is_404_upstream_untouched(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        status, _, body = self.post_chat(self.chat_body(model="fake/nope"), token=self.token)
        self.assertEqual(status, 404)
        self.assertIn("nope", json.loads(body)["error"]["message"])
        self.assertEqual(self.fake.requests(), ())  # deny-by-default: never guessed
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, 404)
        self.assertEqual(records[0].model, "fake/nope")
        self.assertEqual(records[0].provider, "")
        self.assertEqual(records[0].upstream_model, "")

    def test_unknown_provider_is_404(self):
        status, _, body = self.post_chat(self.chat_body(model="other/thing"), token=self.token)
        self.assertEqual(status, 404)
        message = json.loads(body)["error"]["message"]
        self.assertIn("other", message)

    def test_models_listing_sorted(self):
        status, _, body = self.request("GET", "/v1/models", token=self.token)
        self.assertEqual(status, 200)
        listing = json.loads(body)
        self.assertEqual(listing["object"], "list")
        ids = [entry["id"] for entry in listing["data"]]
        self.assertEqual(ids, sorted(ids))
        # README: 'lists every configured pair' — the EXACT set of
        # provider/model ids, not merely a subset.
        self.assertEqual(ids, ["fake/fake-model"])
        for entry in listing["data"]:
            self.assertEqual(entry["object"], "model")
            self.assertEqual(entry["owned_by"], "keysmith")

    def test_models_requires_token(self):
        status, _, _ = self.request("GET", "/v1/models", token=None)
        self.assertEqual(status, 401)

    def test_happy_path_routes_rewrites_and_forwards_key(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        status, headers, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 200)
        completion = json.loads(body)
        self.assertEqual(completion["model"], "upstream-model-x")  # rewritten
        self.assertIn("echo: hello", completion["choices"][0]["message"]["content"])
        recorded = self.fake.requests()
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0].path, "/v1/chat/completions")
        self.assertEqual(recorded[0].authorization, "Bearer " + KEY_A_VALUE)
        self.assertEqual(json.loads(recorded[0].body)["model"], "upstream-model-x")
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.provider, "fake")
        self.assertEqual(record.model, "fake/fake-model")
        self.assertEqual(record.upstream_model, "upstream-model-x")
        self.assertEqual(record.key_alias, KEY_A_ALIAS)
        self.assertEqual(record.status, 200)
        self.assertIsNone(record.error_kind)
        self.assertEqual(
            (record.prompt_tokens, record.completion_tokens, record.total_tokens),
            (11, 7, 18),
        )
        self.assertGreaterEqual(record.latency_ms, 0.0)

    def test_stream_true_rejected(self):
        status, _, body = self.post_chat(self.chat_body(stream=True), token=self.token)
        self.assertEqual(status, 400)
        err = json.loads(body)["error"]
        self.assertIn("streaming", err["message"])
        self.assertEqual(err["code"], "streaming_not_supported")
        # The message must say that streaming is roadmap,
        # not v0.1 — an explicit, honest rejection.
        self.assertIn("roadmap", err["message"].lower())

    def test_stream_false_allowed(self):
        status, _, _ = self.post_chat(self.chat_body(stream=False), token=self.token)
        self.assertEqual(status, 200)

    def test_malformed_json_rejected(self):
        status, _, body = self.post_chat(b"{not json", token=self.token)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"]["type"], "invalid_request_error")

    def test_non_object_json_rejected(self):
        status, _, _ = self.post_chat(b"[]", token=self.token)
        self.assertEqual(status, 400)

    def test_missing_or_nonstring_model_rejected(self):
        for payload in (b'{"messages": []}', b'{"model": 3, "messages": []}', b'{"model": "", "messages": []}'):
            with self.subTest(payload=payload):
                status, _, _ = self.post_chat(payload, token=self.token)
                self.assertEqual(status, 400)


class MultiProviderModelsTests(ServerTestCase):
    extra_providers = {
        "zeta": ProviderConfig(
            name="zeta", base_url="https://api.example.com/v1",
            key_env_vars=("ZETA_KEY",), models={"z-1": "z-1-up"},
            cooldown_seconds=60.0, timeout_seconds=30.0, allow_insecure=False,
        ),
    }

    def test_models_sorted_across_providers(self):
        status, _, body = self.request("GET", "/v1/models", token=self.token)
        ids = [entry["id"] for entry in json.loads(body)["data"]]
        self.assertEqual(ids, sorted(ids))
        # The EXACT set across every configured provider/model pair.
        self.assertEqual(ids, ["fake/fake-model", "zeta/z-1"])


class SpendScopeTests(ServerTestCase):
    def test_exactly_one_record_per_authenticated_post(self):
        """Spend records exist only for client-token-
        authenticated requests. Unauthenticated 401s (wrong or missing
        token) write nothing; every authenticated POST outcome (400/404/200)
        writes exactly one record."""
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        self.post_chat(self.chat_body(), token="wrong")       # 401 -> NO record
        self.post_chat(self.chat_body(), token=None)          # 401 -> NO record
        self.post_chat(b"{bad json", token=self.token)        # 400 -> record
        self.post_chat(self.chat_body(model="fake/nope"), token=self.token)  # 404 -> record
        self.post_chat(self.chat_body(), token=self.token)    # 200 -> record
        records = self.spend_log.read_all()
        self.assertEqual([r.status for r in records], [400, 404, 200])
        self.assertTrue(all(r.provider == "" for r in records[:2]))
        self.assertEqual(records[2].provider, "fake")
        # GET /v1/models, unknown-path 404 and 405 requests write none.
        self.request("GET", "/v1/models", token=self.token)
        self.request("POST", "/v1/other", body=self.chat_body(), token=self.token)
        self.request("PUT", "/v1/chat/completions", body=b"{}", token=self.token)
        self.assertEqual(self.spend_log.line_count(), 3)


class AuthSpendOrderTests(ServerTestCase):
    """Auth-ordering semantics of spend logging.

    Unauthenticated requests never write a spend record (the token check
    happens before anything that logs); GET 401 and unknown-path 404 keep
    writing none; authenticated failures still write exactly one record
    each."""

    def test_wrong_token_post_401_writes_no_record(self):
        self.reset_spend()
        status, _, body = self.post_chat(self.chat_body(), token="wrong-token")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["type"], "keysmith_auth")
        self.assertEqual(self.spend_log.line_count(), 0)

    def test_missing_token_post_401_writes_no_record(self):
        self.reset_spend()
        status, _, _ = self.post_chat(self.chat_body(), token=None)
        self.assertEqual(status, 401)
        self.assertEqual(self.spend_log.line_count(), 0)

    def test_missing_or_wrong_token_get_401_writes_no_record(self):
        self.reset_spend()
        for token in (None, "wrong-token"):
            with self.subTest(token=token):
                status, _, _ = self.request("GET", "/v1/models", token=token)
                self.assertEqual(status, 401)
                self.assertEqual(self.spend_log.line_count(), 0)

    def test_unauthenticated_unknown_path_writes_no_record(self):
        # The token check comes first: an unauthenticated POST to an
        # unknown path is a 401 (not a 404) and writes no spend record.
        self.reset_spend()
        status, _, _ = self.request("POST", "/v1/nope", body=self.chat_body(), token=None)
        self.assertEqual(status, 401)
        self.assertEqual(self.spend_log.line_count(), 0)

    def test_authenticated_unknown_path_404_writes_no_record(self):
        # Keep: unknown-path 404s never write a spend record.
        self.reset_spend()
        status, _, _ = self.request("POST", "/v1/nope", body=self.chat_body(), token=self.token)
        self.assertEqual(status, 404)
        self.assertEqual(self.spend_log.line_count(), 0)

    def test_unauthenticated_method_not_allowed_writes_no_record(self):
        self.reset_spend()
        status, _, _ = self.request("PUT", "/v1/chat/completions", body=b"{}", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(self.spend_log.line_count(), 0)

    def test_authenticated_post_outcomes_each_write_one_record(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        self.post_chat(b"{bad json", token=self.token)                       # 400
        self.post_chat(self.chat_body(model="fake/nope"), token=self.token)  # 404
        self.post_chat(self.chat_body(), token=self.token)                   # 200
        records = self.spend_log.read_all()
        self.assertEqual([r.status for r in records], [400, 404, 200])
        self.assertEqual([r.provider for r in records], ["", "", "fake"])


class HandlerSafetyTests(ServerTestCase):
    def test_put_gets_405_json_not_stdlib_501_html(self):
        status, headers, body = self.request("PUT", "/v1/chat/completions", body=b"{}", token=self.token)
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET, POST")
        payload = json.loads(body)
        self.assertEqual(payload["error"]["type"], "keysmith_request_error")
        self.assertNotIn(b"<!DOCTYPE", body)
        self.assertNotIn("text/html", headers.get("Content-Type", ""))

    def test_delete_and_options_get_405_json(self):
        for method in ("DELETE", "OPTIONS", "PATCH", "TRACE"):
            with self.subTest(method=method):
                status, headers, body = self.request(method, "/v1/chat/completions", body=b"{}", token=self.token)
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "GET, POST")
                json.loads(body)  # must be the JSON envelope, not HTML

    def test_unknown_method_without_token_gets_401(self):
        status, _, body = self.request("PUT", "/v1/chat/completions", body=b"{}", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["type"], "keysmith_auth")

    def _raw_exchange(self, raw: bytes):
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            sock.sendall(raw)
            stream = sock.makefile("rb")
            status_line = stream.readline().decode("iso-8859-1")
            headers: dict[str, str] = {}
            while True:
                line = stream.readline().decode("iso-8859-1")
                if line in ("\r\n", "\n", ""):
                    break
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
            length = int(headers.get("content-length", "0"))
            payload = stream.read(length) if length else b""
            return status_line, headers, payload

    def test_malformed_request_line_gets_400_json(self):
        status_line, headers, payload = self._raw_exchange(b"GARBAGE\r\n\r\n")
        self.assertIn("400", status_line)
        self.assertIn("application/json", headers.get("content-type", ""))
        json.loads(payload)  # JSON envelope, not the stdlib HTML page
        self.assertNotIn(b"<!DOCTYPE", payload)

    def test_handle_error_redacts_and_writes_no_stderr(self):
        httpd = self.server._httpd
        assert httpd is not None
        self.vault.register(KEY_A_VALUE)
        capture = io.StringIO()
        with redirect_stderr(capture):
            try:
                raise RuntimeError(f"boom while handling key {KEY_A_VALUE}")
            except RuntimeError:
                httpd.handle_error(None, ("127.0.0.1", 1))
        self.assertEqual(capture.getvalue(), "")
        self.assertTrue(self.server.diagnostics)
        last = self.server.diagnostics[-1]
        self.assertNotIn(KEY_A_VALUE, last)
        self.assertIn(REDACTED, last)

    def test_request_catch_all_returns_500_with_redacted_diagnostic(self):
        self.reset_spend()
        # The route resolver fails before any key attempt, so register the
        # planted value explicitly (as a real attempt would).
        self.vault.register(KEY_A_VALUE)
        with mock.patch.object(
            server_module, "resolve_route",
            side_effect=RuntimeError(f"kaboom key {KEY_A_VALUE}"),
        ):
            status, _, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 500)
        err = json.loads(body)["error"]
        self.assertEqual(err["type"], "keysmith_internal")
        self.assertEqual(err["message"], "internal error")
        joined = "\n".join(self.server.diagnostics)
        self.assertNotIn(KEY_A_VALUE, joined)
        self.assertIn(REDACTED, joined)


class DiagnosticOrderTests(ServerTestCase):
    """Both diagnostic paths must REDACT first and truncate AFTER.

    Truncating first would let a secret that straddles the
    ``_TRACEBACK_CHAR_LIMIT`` cut in the formatted traceback survive as a
    partial fragment that redact() can no longer match — key material in the
    diagnostics ring. ``TRUNCATION_MESSAGE`` places a 3400-char unique
    secret across the cut for any realistic traceback overhead (see the
    fixtures block at the top of this file)."""

    def _assert_no_secret_fragments(self, line: str) -> None:
        # Any prefix fragment of the secret >= 8 chars contains its first
        # 8 characters; any suffix fragment contains its last 8; and a full
        # occurrence contains the whole value.
        self.assertNotIn(TRUNCATION_SECRET[:8], line)
        self.assertNotIn(TRUNCATION_SECRET[-8:], line)
        self.assertNotIn(TRUNCATION_SECRET, line)
        # Redaction must actually have run on the FULL text before the cut:
        # otherwise an implementation that simply drops diagnostics would
        # pass.
        self.assertIn(REDACTED, line)

    def test_handle_error_redacts_before_truncation(self):
        httpd = self.server._httpd
        assert httpd is not None
        self.vault.register(TRUNCATION_SECRET)
        before = len(self.server.diagnostics)
        capture = io.StringIO()
        with redirect_stderr(capture):
            try:
                raise RuntimeError(TRUNCATION_MESSAGE)
            except RuntimeError:
                httpd.handle_error(None, ("127.0.0.1", 1))
        self.assertEqual(capture.getvalue(), "")
        new_lines = self.server.diagnostics[before:]
        self.assertEqual(len(new_lines), 1)
        self._assert_no_secret_fragments(new_lines[0])

    def test_internal_error_redacts_before_truncation(self):
        self.vault.register(TRUNCATION_SECRET)
        before = len(self.server.diagnostics)

        def _raise_giant(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError(TRUNCATION_MESSAGE)

        with mock.patch.object(server_module, "resolve_route", side_effect=_raise_giant):
            status, _, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(body)["error"]["type"], "keysmith_internal")
        # The client-visible 500 envelope must be clean too.
        self.assertNotIn(TRUNCATION_SECRET[:8], body.decode("utf-8", "replace"))
        tb_lines = [
            line for line in self.server.diagnostics[before:]
            if "RuntimeError" in line
        ]
        self.assertEqual(len(tb_lines), 1)
        self._assert_no_secret_fragments(tb_lines[0])


class KeepAliveTests(ServerTestCase):
    """Raw sockets: stdlib urllib uses a fresh connection per request and
    cannot catch keep-alive desync."""

    @staticmethod
    def _read_response(stream) -> tuple[str, dict[str, str], bytes]:
        status_line = stream.readline().decode("iso-8859-1")
        headers: dict[str, str] = {}
        while True:
            line = stream.readline().decode("iso-8859-1")
            if line in ("\r\n", "\n", ""):
                break
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        payload = stream.read(length) if length else b""
        return status_line, headers, payload

    def _valid_post(self, content: str = "hello") -> bytes:
        body = json.dumps(
            {"model": "fake/fake-model", "messages": [{"role": "user", "content": content}]}
        ).encode("utf-8")
        return (
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
        )

    def test_early_401_with_unread_body_closes_connection(self):
        body = b'{"model": "fake/fake-model", "messages": []}'
        request = (
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer wrong-token\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
        )
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            sock.sendall(request)  # body bytes will sit unread on the server
            stream = sock.makefile("rb")
            status_line, headers, payload = self._read_response(stream)
            self.assertIn("401", status_line)
            self.assertEqual(headers.get("connection"), "close")
            self.assertTrue(payload)
            # Clean EOF: the server must close rather than let the unread
            # body corrupt a following request.
            self.assertEqual(sock.recv(1), b"")

    def test_early_404_with_unread_body_closes_connection(self):
        body = b'{"model": "fake/fake-model", "messages": []}'
        request = (
            b"POST /v1/nope HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
        )
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            sock.sendall(request)  # body bytes will sit unread on the server
            stream = sock.makefile("rb")
            status_line, headers, payload = self._read_response(stream)
            self.assertIn("404", status_line)
            self.assertEqual(headers.get("connection"), "close")
            self.assertEqual(json.loads(payload)["error"]["code"], "path_not_found")
            # Clean EOF: the unread body must not corrupt a following request.
            self.assertEqual(sock.recv(1), b"")

    def test_early_405_with_unread_body_closes_connection(self):
        body = b'{"model": "fake/fake-model", "messages": []}'
        request = (
            b"PUT /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
        )
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            sock.sendall(request)  # body bytes will sit unread on the server
            stream = sock.makefile("rb")
            status_line, headers, payload = self._read_response(stream)
            self.assertIn("405", status_line)
            self.assertEqual(headers.get("connection"), "close")
            self.assertEqual(headers.get("allow"), "GET, POST")
            # Clean EOF: the unread body must not corrupt a following request.
            self.assertEqual(sock.recv(1), b"")

    def test_two_valid_posts_on_one_connection_both_200(self):
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            stream = sock.makefile("rb")
            for index in range(2):
                sock.sendall(self._valid_post(content=f"msg-{index}"))
                status_line, headers, payload = self._read_response(stream)
                self.assertIn("200", status_line, f"request {index}: {status_line}")
                self.assertNotEqual(headers.get("connection"), "close")
                completion = json.loads(payload)
                self.assertIn(f"echo: msg-{index}", completion["choices"][0]["message"]["content"])

    def test_post_without_content_length_gets_411(self):
        request = (
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"\r\n"
        )
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            sock.sendall(request)
            stream = sock.makefile("rb")
            status_line, headers, payload = self._read_response(stream)
            self.assertIn("411", status_line)
            self.assertEqual(headers.get("connection"), "close")
            json.loads(payload)

    def test_body_over_limit_gets_413_without_reading_body(self):
        from keysmith.server import MAX_BODY_BYTES

        huge = MAX_BODY_BYTES + 1
        request = (
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {huge}\r\n".encode("ascii")
            + b"\r\n"
            # Deliberately no body follows.
        )
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            sock.sendall(request)
            stream = sock.makefile("rb")
            status_line, headers, payload = self._read_response(stream)
            self.assertIn("413", status_line)
            self.assertEqual(headers.get("connection"), "close")
            self.assertIn("exceeds", json.loads(payload)["error"]["message"])


class ErrorLeakTests(ServerTestCase):
    """(a) the bad key's 401 body echoes the bearer value — error position.

    The all-keys-fail 502 envelope must carry
    ``upstream_status`` and a fixed, key-free message. The parsed upstream
    error body (whose message echoes the bearer value) must NOT be embedded:
    ``upstream_error`` is removed from client-facing envelopes entirely."""

    aliases = (KEY_A_ALIAS,)
    fake_kwargs = {"fail_auth_values": frozenset({"Bearer " + KEY_A_VALUE})}

    def test_single_bad_key_502_envelope_has_status_not_upstream_body(self):
        self.reset_spend()
        status, _, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 502)
        text = body.decode("utf-8")
        self.assertNotIn(KEY_A_VALUE, text)
        self.assertNotIn("Bearer " + KEY_A_VALUE, text)
        err = json.loads(text)["error"]
        self.assertEqual(err["upstream_status"], 401)
        self.assertNotIn("upstream_error", err)
        # Absence of the embedded upstream error BODY, not just the key:
        # the fake's 401 message text must not surface in any form.
        self.assertNotIn("Incorrect API key", text)
        # The envelope deliberately carries
        # the closed-vocabulary error_kind, and 'invalid_api_key' is one of
        # its four enum values — so the value must appear ONLY as the enum
        # field, and no other upstream text rides along.
        self.assertEqual(err["error_kind"], "invalid_api_key")
        self.assertEqual(text.count("invalid_api_key"), 1)
        self.assertIn("failed authentication", err["message"])
        # Decoded walk — json.loads the client-visible
        # body, walk every decoded string, assert raw and json-escaped
        # forms of the planted key are absent, upstream_error key absent.
        walk_decoded_body(
            self, body, (KEY_A_VALUE,),
            context="single-bad-key 502 envelope",
            forbid_error_keys=("upstream_error",),
        )

        spend = self.spend_text()
        diagnostics = "\n".join(self.server.diagnostics)
        self.sweep_for([KEY_A_VALUE, "Bearer " + KEY_A_VALUE], text, spend, diagnostics)
        self.assertIn(KEY_A_ALIAS, spend)


class AdversarialKeyShapeTests(ServerTestCase):
    """The envelope-level adversarial test.

    Three configured keys — non-ASCII (latin-1 range, see the fixtures
    block at the top of this file), double-quote, and backslash — ALL fail
    upstream auth, so the response is the all-keys-fail 502. The envelope
    must never embed the parsed upstream 401 body (which echoes the bearer
    value JSON-escaped). The raw key values are vault-registered before each
    attempt, yet an ESCAPED serialization would survive raw-value redaction —
    the exact serialization-escape leak class.

    Asserts: no key material, in any escaped form, reaches ANY
    client-visible byte — the full raw HTTP response (status line + headers
    + body, captured on the socket) — nor the spend log or diagnostics."""

    aliases = (KEY_NONASCII_ALIAS, KEY_QUOTE_ALIAS, KEY_BACKSLASH_ALIAS)
    env = ADVERSARIAL_ENV
    fake_kwargs = {
        "fail_auth_values": frozenset("Bearer " + value for value in ADVERSARIAL_KEYS),
    }

    def _raw_post_chat_response(self) -> bytes:
        """Every byte of the server's response, status line through body,
        over a raw socket closed via 'Connection: close'."""
        body = self.chat_body()
        request = (
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
        )
        chunks: list[bytes] = []
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=15) as sock:
            sock.sendall(request)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks)

    def test_all_keys_fail_envelope_leaks_no_key_material_in_any_form(self):
        self.reset_spend()
        raw = self._raw_post_chat_response()
        self.assertTrue(raw.startswith(b"HTTP/1.1 502"), raw[:64])
        _header_block, _, body = raw.partition(b"\r\n\r\n")
        err = json.loads(body)["error"]
        # Structural fix: upstream_status present, no embedded upstream body.
        self.assertEqual(err["upstream_status"], 401)
        self.assertNotIn("upstream_error", err)
        self.assertIn("failed authentication", err["message"])
        # Decoded walk of the client-visible body on top of
        # the raw-byte sweep below — raw-byte assertions alone are
        # structurally blind to JSON escaping.
        walk_decoded_body(
            self, body, ADVERSARIAL_KEYS,
            context="adversarial-shapes 502 envelope",
            forbid_error_keys=("upstream_error",),
        )
        # The authenticated request still wrote exactly one routed record.
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, 401)
        self.assertIn(records[0].key_alias, self.aliases)
        # THE sweep: no key material in any escaped serialization in any
        # client-visible byte (status line + headers + body), spend, or
        # diagnostics.
        spend = self.spend_text()
        diagnostics = "\n".join(self.server.diagnostics)
        for key in ADVERSARIAL_KEYS:
            for form in escaped_key_forms(key):
                context = f"key {key!r} in form {form!r}"
                self.assertNotIn(form, raw, context)
                self.assertNotIn(form, spend.encode("utf-8"), context)
                self.assertNotIn(form, diagnostics.encode("utf-8"), context)


class BodyLeakTests(ServerTestCase):
    """(b) the good key's value planted inside a 200 body — body position."""

    aliases = (KEY_B_ALIAS,)
    fake_kwargs = {"echo_auth_in_success_body": True}

    def test_success_body_plant_is_redacted_client_side(self):
        assert self.fake is not None
        self.reset_spend()
        status, _, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertNotIn(KEY_B_VALUE, text)
        self.assertIn(REDACTED, text)
        # Decoded walk (KEY_B_VALUE is pure ASCII so its
        # json-escaped twin equals the raw value; the walk additionally
        # proves the body parses and every decoded string is clean).
        walk_decoded_body(self, body, (KEY_B_VALUE,), context="success body plant (200)")
        # The real header WAS forwarded upstream (header position plant).
        recorded = self.fake.requests()
        self.assertEqual(recorded[-1].authorization, "Bearer " + KEY_B_VALUE)
        # ...while every keysmith output surface stays clean.
        spend = self.spend_text()
        diagnostics = "\n".join(self.server.diagnostics)
        self.sweep_for([KEY_B_VALUE, "Bearer " + KEY_B_VALUE], text, spend, diagnostics)
        self.assertIn(KEY_B_ALIAS, spend)


class MessageAndHeaderLeakTests(ServerTestCase):
    """(c)+(d): the real Authorization header is forwarded upstream yet
    absent from every keysmith output; a client message containing the
    other key's value comes back masked."""

    fake_kwargs = {"fail_auth_values": frozenset({"Bearer " + KEY_A_VALUE})}

    def test_planted_values_never_reach_outputs(self):
        assert self.fake is not None
        self.reset_spend()
        planted = f"my other key is {KEY_B_VALUE} and the first is {KEY_A_VALUE}"
        status, _, body = self.post_chat(self.chat_body(content=planted), token=self.token)
        # A fails auth -> rotation registers BOTH key values in the vault,
        # then B serves: the echoed content must come back masked.
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn(REDACTED, text)
        # Decoded walk of the echoed content.
        walk_decoded_body(
            self, body, (KEY_A_VALUE, KEY_B_VALUE),
            context="message/header leak 200 echo",
        )
        recorded = self.fake.requests()
        self.assertGreaterEqual(len(recorded), 2)
        self.assertEqual(recorded[-1].authorization, "Bearer " + KEY_B_VALUE)
        self.assertIn(KEY_A_VALUE, recorded[0].body.decode("utf-8"))  # forwarded as-is
        spend = self.spend_text()
        diagnostics = "\n".join(self.server.diagnostics)
        self.sweep_for(
            [KEY_A_VALUE, KEY_B_VALUE, "Bearer " + KEY_A_VALUE, "Bearer " + KEY_B_VALUE],
            text, spend, diagnostics,
        )
        self.assertIn(KEY_B_ALIAS, spend)  # alias present, value absent


class NoKeysTests(ServerTestCase):
    """All configured keys cooling down -> 503, upstream untouched."""

    def test_all_keys_cooling_gives_503_no_keys(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        pool = self.server.pools["fake"]
        now = time.monotonic()
        for alias in (KEY_A_ALIAS, KEY_B_ALIAS):
            for _ in range(3):
                pool.report_auth_failure(alias, now)
        status, _, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 503)
        err = json.loads(body)["error"]
        self.assertIn("no keys available", err["message"])
        self.assertEqual(err["error_kind"], "no_keys")
        self.assertEqual(self.fake.requests(), ())  # no upstream attempt at all
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, 0)
        self.assertEqual(records[0].error_kind, "no_keys")
        self.assertEqual(records[0].key_alias, "")
        self.assertEqual(records[0].provider, "fake")


class TransportFailureTests(ServerTestCase):
    """Provider points at a dead loopback port -> 502 upstream unreachable."""

    base_url_override = None  # replaced per-class in setUpClass via property

    @classmethod
    def setUpClass(cls) -> None:
        cls.base_url_override = f"http://127.0.0.1:{dead_loopback_port()}/v1"
        super().setUpClass()

    def test_connection_refused_gives_502_with_error_kind(self):
        self.reset_spend()
        status, _, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 502)
        err = json.loads(body)["error"]
        self.assertEqual(err["type"], "keysmith_upstream")
        self.assertEqual(err["message"], "upstream unreachable")
        self.assertIn(err["error_kind"], ("connection", "timeout", "unknown"))
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, 0)
        self.assertEqual(records[0].error_kind, err["error_kind"])
        self.assertEqual(records[0].key_alias, KEY_A_ALIAS)


if __name__ == "__main__":
    unittest.main()
