"""Dashboard v0.2 end-to-end tests: shell byte-identity, the auth
matrix, JSON payload correctness against the live config and pool state,
the wizard over HTTP, POST body laws, and the shipped-template coverage
(charter DoD item 1).

Every server binds 127.0.0.1:0; no real keys (values are planted via
mock.patch.dict on os.environ), no network beyond loopback.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from typing import Any
from unittest import mock

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith import ui_page  # noqa: E402
from keysmith.config import load_config  # noqa: E402
from keysmith.redact import SecretVault  # noqa: E402
from keysmith.server import KeysmithServer  # noqa: E402
from keysmith.spendlog import SpendLog, SpendRecord  # noqa: E402
from tests.fake_upstream import FakeUpstream  # noqa: E402

TOKEN = "tok-ui-test-123"
KEY_A_ALIAS = "UI_FAKE_KEY_A"
KEY_B_ALIAS = "UI_FAKE_KEY_B"
KEY_A_VALUE = "sk-ui-fake-AAA-111"
KEY_B_VALUE = "sk-ui-fake-BBB-222"
UI_ENV = {KEY_A_ALIAS: KEY_A_VALUE, KEY_B_ALIAS: KEY_B_VALUE}

VALID_WIZARD_DOCUMENT = {
    "providers": {
        "wizz": {
            "base_url": "https://api.wizz.example/v1",
            "keys": ["WIZZ_KEY"],
            "models": {"wizz-model": "wizz-upstream"},
        }
    }
}

API_GET_PATHS = (
    "/api/status",
    "/api/spend",
    "/api/connections",
    "/api/wizard/current",
)
API_POST_PATHS = (
    "/api/wizard/preview",
    "/api/wizard/write",
)


class UITestCase(unittest.TestCase):
    """One keysmith server (with a fake upstream) + temp config path."""

    token: str = TOKEN
    with_config_path: bool = True

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-ui-"))
        cls.fake = FakeUpstream()
        cls.fake.start()
        cls.config_path = cls.tmp / "providers.json"
        cls.config_path.write_text(
            json.dumps(
                {
                    "_comment": "ui test config",
                    "providers": {
                        "fake": {
                            "base_url": cls.fake.url,
                            "keys": [KEY_A_ALIAS, KEY_B_ALIAS],
                            "models": {"fake-model": "upstream-model-x"},
                            "cooldown_seconds": 60.0,
                            "timeout_seconds": 30.0,
                            "allow_insecure": True,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        cls.config = load_config(cls.config_path)
        cls.spend_path = cls.tmp / "spend.jsonl"
        cls.vault = SecretVault()
        cls.spend_log = SpendLog(cls.spend_path)
        cls.server = KeysmithServer(
            cls.config,
            cls.token,
            cls.spend_log,
            cls.vault,
            host="127.0.0.1",
            port=0,
            config_path=str(cls.config_path) if cls.with_config_path else None,
        )
        cls.server.start()
        patcher = mock.patch.dict(os.environ, UI_ENV)
        patcher.start()
        cls._env_patcher = patcher

    @classmethod
    def tearDownClass(cls) -> None:
        cls._env_patcher.stop()
        cls.server.stop()
        cls.fake.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- helpers ------------------------------------------------------

    def request(self, method: str, path: str, body: bytes | None = None,
                token: str | None = None):
        headers: dict[str, str] = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.server.url + path, data=body, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, dict(exc.headers), exc.read()

    def chat_body(self, model: str = "fake/fake-model") -> bytes:
        return json.dumps(
            {"model": model, "messages": [{"role": "user", "content": "hi"}]}
        ).encode("utf-8")

    def post_json(self, path: str, document: object, token: str | None = None):
        return self.request(
            "POST", path, body=json.dumps(document).encode("utf-8"), token=token
        )


class ShellBytesTests(UITestCase):
    """The static shell at / is the single documented pre-auth route: a
    login page with zero data, byte-identical for every client."""

    def test_shell_served_without_token(self):
        status, headers, body = self.request("GET", "/", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), ui_page.CONTENT_TYPE)
        self.assertEqual(body, ui_page.DOCUMENT_BYTES)

    def test_shell_identical_with_wrong_and_right_token(self):
        _, _, no_token = self.request("GET", "/", token=None)
        _, _, wrong = self.request("GET", "/", token="wrong-token")
        _, _, right = self.request("GET", "/", token=self.token)
        self.assertEqual(no_token, wrong)
        self.assertEqual(no_token, right)
        self.assertEqual(no_token, ui_page.DOCUMENT_BYTES)

    def test_shell_identical_across_different_servers(self):
        # A second server with a different token, config and port must
        # serve the very same bytes: the shell embeds no server data.
        other_config_path = self.tmp / "other.providers.json"
        other_config_path.write_text(
            json.dumps(
                {
                    "providers": {
                        "zeta": {
                            "base_url": "https://api.zeta.example/v1",
                            "keys": ["ZETA_KEY"],
                            "models": {"z-1": "z-1-up"},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        other = KeysmithServer(
            load_config(other_config_path),
            "a-completely-different-token",
            SpendLog(self.tmp / "other-spend.jsonl"),
            SecretVault(),
            host="127.0.0.1",
            port=0,
            config_path=str(other_config_path),
        )
        other.start()
        try:
            _, _, body = self.request("GET", "/", token=None)
            request = urllib.request.Request(other.url + "/")
            with urllib.request.urlopen(request, timeout=15) as response:
                other_body = response.read()
            self.assertEqual(body, other_body)
        finally:
            other.stop()

    def test_shell_is_html_with_no_dynamic_data(self):
        document = ui_page.DOCUMENT
        self.assertIn("<!DOCTYPE html>", document)
        # Zero data: no config, spend, token or URL values are baked in.
        self.assertNotIn(self.token, document)
        self.assertNotIn(KEY_A_ALIAS, document)
        self.assertNotIn(self.server.url, document)
        self.assertNotIn("fake-model", document)


class AuthMatrixTests(UITestCase):
    """Charter security law: every new endpoint without a token gets a
    401 JSON envelope, never an HTML page. The ONLY carve-out is the
    static shell at / (the login page; pinned by ShellBytesTests)."""

    def test_every_api_get_without_token_is_401_json(self):
        for path in API_GET_PATHS:
            for token in (None, "wrong-token"):
                with self.subTest(path=path, token=token):
                    status, headers, body = self.request("GET", path, token=token)
                    self.assertEqual(status, 401)
                    self.assertIn("application/json", headers.get("Content-Type", ""))
                    payload = json.loads(body)
                    self.assertEqual(payload["error"]["type"], "keysmith_auth")
                    self.assertNotIn(b"<!DOCTYPE", body)

    def test_every_api_post_without_token_is_401_json(self):
        for path in API_POST_PATHS:
            for token in (None, "wrong-token"):
                with self.subTest(path=path, token=token):
                    status, headers, body = self.request(
                        "POST", path, body=b'{"providers": {}}', token=token
                    )
                    self.assertEqual(status, 401)
                    self.assertIn("application/json", headers.get("Content-Type", ""))
                    payload = json.loads(body)
                    self.assertEqual(payload["error"]["type"], "keysmith_auth")
                    self.assertNotIn(b"<!DOCTYPE", body)

    def test_unknown_api_path_is_404_json(self):
        status, _, body = self.request("GET", "/api/nope", token=self.token)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"]["code"], "path_not_found")

    def test_method_not_allowed_on_api_routes(self):
        status, headers, body = self.request(
            "DELETE", "/api/status", token=self.token
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET, POST")
        json.loads(body)

    def test_wizard_write_without_token_writes_nothing(self):
        """Token-gated writes fail closed: an unauthenticated wizard
        write must not touch the config file."""
        before = self.config_path.read_text(encoding="utf-8")
        document = {
            "providers": {
                "intruder": {
                    "base_url": "https://api.evil.example/v1",
                    "keys": ["EVIL_KEY"],
                    "models": {"evil": "evil-up"},
                }
            }
        }
        status, _, _ = self.post_json("/api/wizard/write", document, token="wrong-token")
        self.assertEqual(status, 401)
        self.assertEqual(self.config_path.read_text(encoding="utf-8"), before)


class StatusEndpointTests(UITestCase):
    def test_status_matches_live_config(self):
        status, _, body = self.request("GET", "/api/status", token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["provider_count"], 1)
        self.assertEqual(payload["model_count"], 1)
        provider = payload["providers"][0]
        self.assertEqual(provider["id"], "fake")
        self.assertEqual(provider["base_url"], self.fake.url)
        self.assertEqual(
            provider["models"], [{"public": "fake-model", "upstream": "upstream-model-x"}]
        )
        self.assertEqual([k["alias"] for k in provider["keys"]], [KEY_A_ALIAS, KEY_B_ALIAS])
        for key in provider["keys"]:
            self.assertIn("auth_failures", key)
            self.assertIn("cooling", key)
            self.assertIn("cooldown_remaining_seconds", key)

    def test_status_reports_cooldown_remaining(self):
        pool = self.server.pools["fake"]
        now = time.monotonic()
        # Drive key A into cooldown (3 consecutive auth failures).
        for _ in range(3):
            pool.report_auth_failure(KEY_A_ALIAS, now)
        status, _, body = self.request("GET", "/api/status", token=self.token)
        self.assertEqual(status, 200)
        keys = {k["alias"]: k for k in json.loads(body)["providers"][0]["keys"]}
        self.assertTrue(keys[KEY_A_ALIAS]["cooling"])
        remaining = keys[KEY_A_ALIAS]["cooldown_remaining_seconds"]
        self.assertIsNotNone(remaining)
        self.assertGreater(remaining, 0.0)
        self.assertLessEqual(remaining, 60.0)
        # Key B untouched: not cooling, null remaining.
        self.assertFalse(keys[KEY_B_ALIAS]["cooling"])
        self.assertIsNone(keys[KEY_B_ALIAS]["cooldown_remaining_seconds"])

    def test_status_never_contains_key_values(self):
        # Names only: key VALUES must never ride along on any status
        # response (they are not read anywhere on this path).
        _, _, body = self.request("GET", "/api/status", token=self.token)
        text = body.decode("utf-8")
        self.assertNotIn(KEY_A_VALUE, text)
        self.assertNotIn(KEY_B_VALUE, text)

    def test_status_with_empty_providers(self):
        # The Anthropic-stub shape: zero providers, honest empty state.
        empty_path = self.tmp / "empty.providers.json"
        empty_path.write_text(json.dumps({"providers": {}}), encoding="utf-8")
        server = KeysmithServer(
            load_config(empty_path), "tok-empty",
            SpendLog(self.tmp / "empty-spend.jsonl"), SecretVault(),
            host="127.0.0.1", port=0,
        )
        server.start()
        try:
            request = urllib.request.Request(
                server.url + "/api/status",
                headers={"Authorization": "Bearer tok-empty"},
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload, {"provider_count": 0, "model_count": 0, "providers": []})
        finally:
            server.stop()


class SpendEndpointTests(UITestCase):
    def test_spend_endpoint_reflects_log(self):
        # Generate real records through the chat path: one 200, one 404.
        self.request("POST", "/v1/chat/completions", body=self.chat_body(), token=self.token)
        self.request(
            "POST", "/v1/chat/completions", body=self.chat_body(model="fake/nope"),
            token=self.token,
        )
        status, _, body = self.request("GET", "/api/spend", token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["row_count"], 2)
        self.assertEqual(payload["totals"]["requests"], 2)
        self.assertEqual(payload["totals"]["failed"], 1)
        # Newest first: the 404 leads.
        self.assertEqual(payload["rows"][0]["status"], 404)
        self.assertEqual(payload["rows"][0]["provider"], "")
        self.assertEqual(payload["rows"][1]["status"], 200)
        self.assertEqual(payload["rows"][1]["provider"], "fake")
        # The alias appears; the value never does.
        text = body.decode("utf-8")
        self.assertIn(KEY_A_ALIAS, text)
        self.assertNotIn(KEY_A_VALUE, text)

    def test_spend_endpoint_empty_log(self):
        server = KeysmithServer(
            self.config, "tok-spend-empty",
            SpendLog(self.tmp / "spend-empty.jsonl"), SecretVault(),
            host="127.0.0.1", port=0,
        )
        server.start()
        try:
            request = urllib.request.Request(
                server.url + "/api/spend",
                headers={"Authorization": "Bearer tok-spend-empty"},
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload["row_count"], 0)
            self.assertEqual(payload["rows"], [])
            self.assertEqual(payload["totals"]["requests"], 0)
        finally:
            server.stop()

    def test_spend_endpoint_malformed_log_is_json_500(self):
        bad_path = self.tmp / "spend-bad.jsonl"
        bad_path.write_text("{not json at all\n", encoding="utf-8")
        server = KeysmithServer(
            self.config, "tok-spend-bad", SpendLog(bad_path), SecretVault(),
            host="127.0.0.1", port=0,
        )
        server.start()
        try:
            request = urllib.request.Request(
                server.url + "/api/spend",
                headers={"Authorization": "Bearer tok-spend-bad"},
            )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    self.fail("expected HTTP 500")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 500)
                payload = json.loads(exc.read())
                self.assertEqual(payload["error"]["type"], "keysmith_internal")
                self.assertIn("spend log", payload["error"]["message"])
        finally:
            server.stop()


class ConnectionsEndpointTests(UITestCase):
    def test_one_card_per_provider_model_pair(self):
        status, _, body = self.request("GET", "/api/connections", token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(len(payload["cards"]), 1)
        card = payload["cards"][0]
        self.assertEqual(card["provider"], "fake")
        self.assertEqual(card["model"], "fake/fake-model")
        self.assertEqual(card["base_url"], self.fake.url)
        self.assertEqual(card["endpoint"], self.server.url + "/v1/chat/completions")
        self.assertEqual(card["token_env_var"], "KEYSMITH_TOKEN")
        self.assertEqual(card["token_placeholder"], "$KEYSMITH_TOKEN")

    def test_curl_example_uses_placeholder_and_public_model(self):
        _, _, body = self.request("GET", "/api/connections", token=self.token)
        curl = json.loads(body)["cards"][0]["curl"]
        self.assertIn(self.server.url + "/v1/chat/completions", curl)
        self.assertIn("$KEYSMITH_TOKEN", curl)
        # The model is shell-quoted inside the -d argument.
        self.assertIn('\\"fake/fake-model\\"', curl)
        # The REAL token value must never be baked into the example.
        self.assertNotIn(self.token, curl)


class WizardEndpointTests(UITestCase):
    def test_current_returns_seed_document_and_path(self):
        status, _, body = self.request("GET", "/api/wizard/current", token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["config_path"], str(self.config_path))
        self.assertTrue(payload["writable"])
        self.assertEqual(payload["document"]["providers"]["fake"]["keys"], [KEY_A_ALIAS, KEY_B_ALIAS])

    def test_preview_valid_document(self):
        status, _, body = self.post_json("/api/wizard/preview", VALID_WIZARD_DOCUMENT, token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["summary"]["provider_count"], 1)
        self.assertEqual(payload["summary"]["providers"][0]["key_count"], 1)

    def test_preview_invalid_document_names_the_path(self):
        bad = {"providers": {"wizz": {"base_url": "https://x.example/v1", "keys": ["K"], "models": {"m": "u"}, "oops": 1}}}
        status, _, body = self.post_json("/api/wizard/preview", bad, token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertIn("providers.wizz.oops", payload["errors"][0])
        self.assertIn("unknown field", payload["errors"][0])

    def test_write_replaces_config_and_reloads(self):
        status, _, body = self.post_json("/api/wizard/write", VALID_WIZARD_DOCUMENT, token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertIn("Restart", payload["message"])
        # The file on disk is the new document and loads through the
        # real startup loader.
        config = load_config(self.config_path)
        self.assertEqual(set(config.providers), {"wizz"})
        # Restore the fake-upstream config for other tests in this class.
        self._restore_config()

    def test_write_invalid_document_leaves_file_untouched(self):
        before = self.config_path.read_text(encoding="utf-8")
        bad = {"nope": True}
        status, _, body = self.post_json("/api/wizard/write", bad, token=self.token)
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])
        self.assertEqual(self.config_path.read_text(encoding="utf-8"), before)

    @classmethod
    def _restore_config(cls) -> None:
        cls.config_path.write_text(
            json.dumps(
                {
                    "_comment": "ui test config",
                    "providers": {
                        "fake": {
                            "base_url": cls.fake.url,
                            "keys": [KEY_A_ALIAS, KEY_B_ALIAS],
                            "models": {"fake-model": "upstream-model-x"},
                            "cooldown_seconds": 60.0,
                            "timeout_seconds": 30.0,
                            "allow_insecure": True,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )


class WizardNoPathTests(UITestCase):
    """A server constructed without config_path (every pre-v0.2 shape):
    the wizard write fails closed, everything else works."""

    with_config_path = False

    def test_current_reports_not_writable(self):
        status, _, body = self.request("GET", "/api/wizard/current", token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIsNone(payload["config_path"])
        self.assertFalse(payload["writable"])
        self.assertIsNone(payload["document"])

    def test_write_fails_closed(self):
        status, _, body = self.post_json("/api/wizard/write", VALID_WIZARD_DOCUMENT, token=self.token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertEqual(len(payload["errors"]), 1)
        self.assertIn("cannot write", payload["errors"][0])
        # Nothing was created anywhere on disk by the wizard.
        leftovers = [p.name for p in self.tmp.iterdir() if "wizard-tmp" in p.name]
        self.assertEqual(leftovers, [])


class WizardPostBodyLawTests(UITestCase):
    """The wizard POST routes reuse the chat body laws and the
    drain-or-close keep-alive discipline, and never write spend
    records (spend scope stays chat-only)."""

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

    def test_preview_without_content_length_gets_411_close(self):
        request = (
            b"POST /api/wizard/preview HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"\r\n"
        )
        status_line, headers, payload = self._raw_exchange(request)
        self.assertIn("411", status_line)
        self.assertEqual(headers.get("connection"), "close")
        json.loads(payload)

    def test_two_wizard_posts_on_one_connection_both_200(self):
        body = json.dumps(VALID_WIZARD_DOCUMENT).encode("utf-8")
        head = (
            b"POST /api/wizard/preview HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Authorization: Bearer " + self.token.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
        )
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
            stream = sock.makefile("rb")
            for index in range(2):
                sock.sendall(head + body)
                status_line = stream.readline().decode("iso-8859-1")
                # headers
                while stream.readline() not in (b"\r\n", b"\n", b""):
                    pass
                self.assertIn("200", status_line, f"post {index}: {status_line}")
                # connection stays open: no Connection: close was sent.
        # If we got here both round-trips parsed on one socket.

    def test_wizard_posts_write_no_spend_records(self):
        spend_before = self.spend_log.line_count()
        self.post_json("/api/wizard/preview", VALID_WIZARD_DOCUMENT, token=self.token)
        bad = {"providers": {"wizz": {"oops": 1}}}
        self.post_json("/api/wizard/write", bad, token=self.token)
        self.request("GET", "/api/status", token=self.token)
        self.request("GET", "/api/spend", token=self.token)
        self.request("GET", "/api/connections", token=self.token)
        self.request("GET", "/api/wizard/current", token=self.token)
        self.request("GET", "/", token=None)
        self.assertEqual(self.spend_log.line_count(), spend_before)

    def test_wizard_post_invalid_json_is_400(self):
        status, _, body = self.request(
            "POST", "/api/wizard/preview", body=b"{not json", token=self.token
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"]["code"], "invalid_json")


class TemplatePayloadTests(unittest.TestCase):
    """Charter DoD 1: the panels work against real config files from the
    repo's templates/examples. Every shipped template flows through all
    three payload builders."""

    def test_every_template_builds_all_payloads(self):
        from keysmith import ui_api
        from keysmith import keys as keys_module

        repo = pathlib.Path(_REPO_ROOT)
        templates = sorted((repo / "templates").glob("providers.*.json"))
        templates.append(repo / "example.providers.json")
        self.assertGreaterEqual(len(templates), 7)
        for path in templates:
            with self.subTest(template=path.name):
                config = load_config(path)
                pools = {
                    name: keys_module.KeyPool(p.key_env_vars, p.cooldown_seconds)
                    for name, p in config.providers.items()
                }
                status = ui_api.status_payload(config, pools, now=123.0)
                self.assertEqual(status["provider_count"], len(config.providers))
                self.assertEqual(
                    status["model_count"],
                    sum(len(p.models) for p in config.providers.values()),
                )
                connections = ui_api.connections_payload(
                    config, "http://127.0.0.1:8317"
                )
                self.assertEqual(len(connections["cards"]), status["model_count"])
                for card in connections["cards"]:
                    self.assertIn("$KEYSMITH_TOKEN", card["curl"])
                    self.assertIn(card["model"], card["curl"])
                spend = ui_api.spend_payload([])
                self.assertEqual(spend["row_count"], 0)


class SpendRecordFieldPassthroughTests(unittest.TestCase):
    """ui_api.spend_payload rows carry exactly the SpendRecord fields of
    the JSONL schema (the page renders them verbatim)."""

    def test_row_fields_match_record_schema(self):
        from keysmith import ui_api

        record = SpendRecord(
            ts="2026-09-30T00:00:00+00:00",
            provider="p",
            model="p/m",
            upstream_model="m-up",
            key_alias="K",
            status=200,
            error_kind=None,
            latency_ms=1.0,
            prompt_tokens=1,
            completion_tokens=2,
            total_tokens=3,
        )
        rows = ui_api.spend_payload([record])["rows"]
        self.assertEqual(
            set(rows[0]),
            {
                "ts", "provider", "model", "upstream_model", "key_alias",
                "status", "error_kind", "latency_ms", "prompt_tokens",
                "completion_tokens", "total_tokens",
            },
        )


if __name__ == "__main__":
    unittest.main()
