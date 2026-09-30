"""Charter security law, test-demonstrated: EVERY byte the dashboard
emits passes the redact() choke point.

Adversarial setup (same shapes as the v0.1 envelope sweep in
tests/test_server.py, latin-1 range so the values can actually travel):
non-ASCII, double-quote and backslash key values, ALL failing upstream
auth so the vault registers them mid-rotation; a planted secret inside a
CONFIG model name (status surface), one inside a chat model string
(spend surface), one inside a wizard base_url (validator-error surface),
and the client token itself (every surface).

Then every dashboard surface is walked: the HTML shell, all four GET
JSON endpoints, wizard preview/write responses, the 401/404/405 error
envelopes, and the diagnostics ring. For every planted secret, every
registered escape form (raw, canonical JSON-escaped, uppercase-hex
escaped, double-escaped) must be absent from the raw bytes AND from
every decoded JSON string (tests.decoded_walk standard).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest import mock

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith import ui_page  # noqa: E402
from keysmith.config import load_config  # noqa: E402
from keysmith.redact import REDACTED, SecretVault  # noqa: E402
from keysmith.server import KeysmithServer  # noqa: E402
from keysmith.spendlog import SpendLog  # noqa: E402
from tests.decoded_walk import iter_decoded_strings, variant_forms  # noqa: E402
from tests.fake_upstream import FakeUpstream  # noqa: E402

TOKEN = "tok-redact-sweep-42"

KEY_NONASCII_ALIAS = "SWEEP_KEY_NONASCII"
KEY_QUOTE_ALIAS = "SWEEP_KEY_QUOTE"
KEY_BACKSLASH_ALIAS = "SWEEP_KEY_BACKSLASH"
KEY_NONASCII_VALUE = "sk-sw\u00e9ep-\u00fc\u00f1-111"
KEY_QUOTE_VALUE = 'sk-sw"eep-222'
KEY_BACKSLASH_VALUE = "sk-sw\\eep-333"
ADVERSARIAL_ENV = {
    KEY_NONASCII_ALIAS: KEY_NONASCII_VALUE,
    KEY_QUOTE_ALIAS: KEY_QUOTE_VALUE,
    KEY_BACKSLASH_ALIAS: KEY_BACKSLASH_VALUE,
}

# A secret planted in a CONFIG public model name: rides the status
# surface. Must not contain '/' (validator rule).
MODEL_PLANT_SECRET = "sk-mod\u00e9l-plant-444"
PLANTED_PUBLIC_MODEL = f"leaky-{MODEL_PLANT_SECRET}-model"

# A secret planted in a client chat model string: rides the spend
# surface via the pre-route 404 record.
CHAT_MODEL_PLANT_SECRET = "sk-chat-plant-555"

# A secret planted in a wizard base_url: rides the validator-error
# surface of preview responses (the ConfigError message embeds the
# value with repr()).
WIZARD_URL_PLANT_SECRET = "sk-wizz-plant-666"

ALL_PLANTS = (
    KEY_NONASCII_VALUE,
    KEY_QUOTE_VALUE,
    KEY_BACKSLASH_VALUE,
    MODEL_PLANT_SECRET,
    CHAT_MODEL_PLANT_SECRET,
    WIZARD_URL_PLANT_SECRET,
    TOKEN,
)


class DashboardRedactSweepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-uisweep-"))
        cls.fake = FakeUpstream(
            fail_auth_values=frozenset(
                "Bearer " + value
                for value in (KEY_NONASCII_VALUE, KEY_QUOTE_VALUE, KEY_BACKSLASH_VALUE)
            )
        )
        cls.fake.start()
        cls.config_path = cls.tmp / "providers.json"
        cls.config_path.write_text(
            json.dumps(
                {
                    "providers": {
                        "fake": {
                            "base_url": cls.fake.url,
                            "keys": [
                                KEY_NONASCII_ALIAS,
                                KEY_QUOTE_ALIAS,
                                KEY_BACKSLASH_ALIAS,
                            ],
                            "models": {
                                "fake-model": "upstream-model-x",
                                PLANTED_PUBLIC_MODEL: "upstream-leaky",
                            },
                            "allow_insecure": True,
                        }
                    }
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        cls.config = load_config(cls.config_path)
        cls.vault = SecretVault()
        cls.spend_log = SpendLog(cls.tmp / "spend.jsonl")
        cls.server = KeysmithServer(
            cls.config,
            TOKEN,
            cls.spend_log,
            cls.vault,
            host="127.0.0.1",
            port=0,
            config_path=str(cls.config_path),
        )
        cls.server.start()
        # Register the non-rotation plants explicitly (rotation only
        # registers the three adversarial KEY values; the model/url
        # plants reach the vault the same way a real read would).
        cls.vault.register(MODEL_PLANT_SECRET)
        cls.vault.register(CHAT_MODEL_PLANT_SECRET)
        cls.vault.register(WIZARD_URL_PLANT_SECRET)
        patcher = mock.patch.dict(os.environ, ADVERSARIAL_ENV)
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
                token: str | None = TOKEN):
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
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read()

    def sweep_bytes(self, surface: bytes, context: str) -> None:
        for secret in ALL_PLANTS:
            for label, form in variant_forms(secret):
                encoded = form.encode("utf-8")
                self.assertNotIn(
                    encoded, surface, f"{context}: {label} form of planted secret survived"
                )

    def sweep_json(self, body: bytes, context: str) -> dict:
        parsed = json.loads(body.decode("utf-8"))
        strings = list(iter_decoded_strings(parsed))
        for secret in ALL_PLANTS:
            for label, form in variant_forms(secret):
                for index, value in enumerate(strings):
                    self.assertNotIn(
                        form,
                        value,
                        f"{context}: {label} form survived decoding in string #{index}",
                    )
        self.sweep_bytes(body, context)
        return parsed

    # ---- the sweep ------------------------------------------------------

    def test_every_dashboard_surface_is_clean(self):
        # 1a. Drive key-value registration through a real chat request
        #     with a VALID model (all three adversarial keys fail
        #     upstream auth -> 502; rotation registers each value).
        chat = json.dumps(
            {"model": "fake/fake-model", "messages": []}
        ).encode("utf-8")
        status, body = self.request("POST", "/v1/chat/completions", body=chat)
        self.assertEqual(status, 502)
        self.sweep_json(body, "all-keys-fail 502 envelope")

        # 1b. A chat with the planted model string -> pre-route 404 that
        #     writes a spend record carrying the plant.
        chat = json.dumps(
            {"model": f"fake/x-{CHAT_MODEL_PLANT_SECRET}", "messages": []}
        ).encode("utf-8")
        status, body = self.request("POST", "/v1/chat/completions", body=chat)
        self.assertEqual(status, 404)
        self.sweep_json(body, "planted-model 404 envelope")

        # 2. The static shell.
        status, shell = self.request("GET", "/", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(shell, ui_page.DOCUMENT_BYTES)
        self.sweep_bytes(shell, "dashboard shell HTML")

        # 3. Status JSON (carries the planted model name -> must be
        #    masked, proving redaction runs on dashboard payloads).
        status, body = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        payload = self.sweep_json(body, "GET /api/status")
        models = [m["public"] for m in payload["providers"][0]["models"]]
        joined_models = " ".join(models)
        self.assertIn(REDACTED, joined_models)
        self.assertNotIn(MODEL_PLANT_SECRET, joined_models)

        # 4. Spend JSON (carries the planted chat model string in the
        #    pre-route 404 record -> must be masked).
        status, body = self.request("GET", "/api/spend")
        self.assertEqual(status, 200)
        payload = self.sweep_json(body, "GET /api/spend")
        rows_text = " ".join(str(row.get("model", "")) for row in payload["rows"])
        self.assertIn(REDACTED, rows_text)
        self.assertNotIn(CHAT_MODEL_PLANT_SECRET, rows_text)

        # 5. Connections JSON.
        status, body = self.request("GET", "/api/connections")
        self.assertEqual(status, 200)
        self.sweep_json(body, "GET /api/connections")

        # 6. Wizard current JSON.
        status, body = self.request("GET", "/api/wizard/current")
        self.assertEqual(status, 200)
        self.sweep_json(body, "GET /api/wizard/current")

        # 7. Wizard preview with the URL plant inside an INVALID base_url
        #    (ftp scheme): the validator error embeds the value with
        #    repr(), redaction must mask it before the bytes leave.
        planted_doc = {
            "providers": {
                "wizz": {
                    "base_url": f"ftp://{WIZARD_URL_PLANT_SECRET}.example/v1",
                    "keys": ["WIZZ_KEY"],
                    "models": {"m": "u"},
                }
            }
        }
        status, body = self.request(
            "POST", "/api/wizard/preview",
            body=json.dumps(planted_doc).encode("utf-8"),
        )
        self.assertEqual(status, 200)
        payload = self.sweep_json(body, "POST /api/wizard/preview (url plant)")
        self.assertFalse(payload["ok"])
        errors_text = " ".join(payload["errors"])
        self.assertIn(REDACTED, errors_text)

        # 8. Wizard write with a clean document: response stays clean.
        clean_doc = {
            "providers": {
                "wizz": {
                    "base_url": "https://api.wizz.example/v1",
                    "keys": ["WIZZ_KEY"],
                    "models": {"m": "u"},
                }
            }
        }
        status, body = self.request(
            "POST", "/api/wizard/write",
            body=json.dumps(clean_doc).encode("utf-8"),
        )
        self.assertEqual(status, 200)
        self.sweep_json(body, "POST /api/wizard/write (clean doc)")

        # 9. Error envelopes: 401 (no token), 404 (unknown api path),
        #    405 (bad method), 400 (invalid wizard JSON).
        for method, path, kw_token, body_bytes, context in (
            ("GET", "/api/status", None, None, "401 envelope"),
            ("GET", "/api/nope", TOKEN, None, "404 envelope"),
            ("DELETE", "/api/status", TOKEN, None, "405 envelope"),
            ("POST", "/api/wizard/preview", TOKEN, b"{not json", "400 envelope"),
        ):
            status, body = self.request(method, path, body=body_bytes, token=kw_token)
            self.assertIn(context[:3], str(status))
            self.sweep_json(body, context)

        # 10. Diagnostics ring.
        diagnostics = "\n".join(self.server.diagnostics)
        self.sweep_bytes(diagnostics.encode("utf-8"), "diagnostics ring")

        # 11. The spend log file itself (already covered by v0.1 sweep
        #     tests; re-checked here because this class wrote new lines).
        self.sweep_bytes(
            self.spend_log.path.read_text(encoding="utf-8").encode("utf-8"),
            "spend log file",
        )


if __name__ == "__main__":
    unittest.main()
