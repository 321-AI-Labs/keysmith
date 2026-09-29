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
import shutil
import socket
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr
from typing import Any
from unittest import mock

from keysmith import server as server_module
from keysmith.config import Config, ProviderConfig
from keysmith.redact import REDACTED, SecretVault
from keysmith.server import KeysmithServer, error_json, resolve_route, split_model
from keysmith.spendlog import SpendLog

from .fake_upstream import FakeUpstream

TOKEN = "tok-local-test-123"
KEY_A_ALIAS = "FAKE_KEY_A"
KEY_B_ALIAS = "FAKE_KEY_B"
KEY_A_VALUE = "sk-fake-AAA-111"
KEY_B_VALUE = "sk-fake-BBB-222"
TEST_ENV = {KEY_A_ALIAS: KEY_A_VALUE, KEY_B_ALIAS: KEY_B_VALUE}


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
        patcher = mock.patch.dict(os.environ, TEST_ENV)
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
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, 401)
        self.assertEqual(records[0].provider, "")
        self.assertEqual(records[0].key_alias, "")

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
        self.assertIn("fake/fake-model", ids)
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
        self.assertIn("fake/fake-model", ids)
        self.assertIn("zeta/z-1", ids)


class SpendScopeTests(ServerTestCase):
    def test_exactly_one_record_per_post_including_pre_routing(self):
        assert self.fake is not None
        self.fake.clear()
        self.reset_spend()
        self.post_chat(self.chat_body(), token="wrong")       # 401
        self.post_chat(b"{bad json", token=self.token)        # 400
        self.post_chat(self.chat_body(model="fake/nope"), token=self.token)  # 404
        self.post_chat(self.chat_body(), token=self.token)    # 200
        records = self.spend_log.read_all()
        self.assertEqual([r.status for r in records], [401, 400, 404, 200])
        self.assertTrue(all(r.provider == "" for r in records[:3]))
        self.assertEqual(records[3].provider, "fake")
        # GET /v1/models, unknown-path 404 and 405 requests write none.
        self.request("GET", "/v1/models", token=self.token)
        self.request("POST", "/v1/other", body=self.chat_body(), token=self.token)
        self.request("PUT", "/v1/chat/completions", body=b"{}", token=self.token)
        self.assertEqual(self.spend_log.line_count(), 4)


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
    """(a) the bad key's 401 body echoes the bearer value — error position."""

    aliases = (KEY_A_ALIAS,)
    fake_kwargs = {"fail_auth_values": frozenset({"Bearer " + KEY_A_VALUE})}

    def test_single_bad_key_502_with_redacted_upstream_error(self):
        self.reset_spend()
        status, _, body = self.post_chat(self.chat_body(), token=self.token)
        self.assertEqual(status, 502)
        text = body.decode("utf-8")
        self.assertNotIn(KEY_A_VALUE, text)
        self.assertNotIn("Bearer " + KEY_A_VALUE, text)
        self.assertIn(REDACTED, text)
        err = json.loads(text)["error"]
        self.assertEqual(err["upstream_status"], 401)
        self.assertEqual(err["upstream_error"]["error"]["code"], "invalid_api_key")

        spend = self.spend_text()
        diagnostics = "\n".join(self.server.diagnostics)
        self.sweep_for([KEY_A_VALUE, "Bearer " + KEY_A_VALUE], text, spend, diagnostics)
        self.assertIn(KEY_A_ALIAS, spend)


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
