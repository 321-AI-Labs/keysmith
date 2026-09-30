"""The rotation tests: cooldown failover, then recovery.

Two keys, first fails auth 3x -> cooldown -> second key serves; recovery
after cooldown elapses. Asserts via fake-upstream hit counts, not timing
(one bounded 0.3 s recovery sleep). Companion: single-key exhaustion ->
502s with redacted error -> 503 while cooling."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith.config import Config, ProviderConfig  # noqa: E402
from keysmith.redact import SecretVault  # noqa: E402
from keysmith.server import KeysmithServer  # noqa: E402
from keysmith.spendlog import SpendLog  # noqa: E402
from tests.decoded_walk import walk_decoded_body, walk_decoded_jsonl  # noqa: E402
from tests.fake_upstream import FakeUpstream  # noqa: E402

KEY_A_ALIAS = "FAKE_KEY_A"
KEY_B_ALIAS = "FAKE_KEY_B"
A_VALUE = "sk-fake-AAA-111"
B_VALUE = "sk-fake-BBB-222"
ENV = {KEY_A_ALIAS: A_VALUE, KEY_B_ALIAS: B_VALUE}
TOKEN = "tok-rotation"


class _RotationBase(unittest.TestCase):
    aliases: tuple[str, ...] = (KEY_A_ALIAS, KEY_B_ALIAS)
    cooldown_seconds: float = 0.25
    fail_auth: frozenset[str] = frozenset()

    def setUp(self) -> None:
        tmp = tempfile.mkdtemp(prefix="keysmith-rotation-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.fake = FakeUpstream(fail_auth_values=self.fail_auth)
        self.fake.start()
        self.addCleanup(self.fake.stop)
        provider = ProviderConfig(
            name="fake",
            base_url=self.fake.url,
            key_env_vars=self.aliases,
            models={"fake-model": "upstream-model-x"},
            cooldown_seconds=self.cooldown_seconds,
            timeout_seconds=30.0,
            allow_insecure=True,
        )
        self.spend_path = pathlib.Path(tmp) / "spend.jsonl"
        self.spend_log = SpendLog(self.spend_path)
        self.server = KeysmithServer(
            Config(providers={"fake": provider}),
            TOKEN,
            self.spend_log,
            SecretVault(),
            host="127.0.0.1",
            port=0,
        )
        self.server.start()
        self.addCleanup(self.server.stop)
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def chat(self) -> tuple[int, bytes]:
        payload = json.dumps(
            {"model": "fake/fake-model", "messages": [{"role": "user", "content": "hi"}]}
        ).encode("utf-8")
        request = urllib.request.Request(
            self.server.url + "/v1/chat/completions",
            data=payload,
            method="POST",
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read()


class RotationTests(_RotationBase):
    cooldown_seconds = 0.25
    fail_auth = frozenset({"Bearer " + A_VALUE})

    def test_first_key_fails_three_times_then_cooldown_second_key_succeeds(self):
        # Three chat requests each transparently fail over A -> 401 -> B.
        for _ in range(3):
            status, _body = self.chat()
            self.assertEqual(status, 200)
        self.assertEqual(self.fake.auth_hits("Bearer " + A_VALUE), 3)
        self.assertGreaterEqual(self.fake.auth_hits("Bearer " + B_VALUE), 3)
        state = self.server.pools["fake"].state(KEY_A_ALIAS)
        self.assertIsNotNone(state.cooldown_until)
        self.assertEqual(state.auth_failures, 0)  # reset on cooldown entry

        # Request 4: A is cooling, so the pool hands out B directly.
        status, _body = self.chat()
        self.assertEqual(status, 200)
        self.assertEqual(self.fake.auth_hits("Bearer " + A_VALUE), 3)
        self.assertGreaterEqual(self.fake.auth_hits("Bearer " + B_VALUE), 4)

        # Recovery without restart: one bounded sleep past the cooldown.
        time.sleep(0.3)
        status, _body = self.chat()
        self.assertEqual(status, 200)
        self.assertEqual(self.fake.auth_hits("Bearer " + A_VALUE), 4)  # A back in play

    def test_every_request_wrote_exactly_one_spend_record(self):
        for _ in range(3):
            self.chat()
        records = self.spend_log.read_all()
        self.assertEqual(len(records), 3)
        self.assertEqual([r.status for r in records], [200, 200, 200])
        self.assertEqual([r.key_alias for r in records], [KEY_B_ALIAS] * 3)


class SingleKeyExhaustionTests(_RotationBase):
    aliases = (KEY_A_ALIAS,)
    cooldown_seconds = 60.0  # long: stays cooling for the rest of the test
    fail_auth = frozenset({"Bearer " + A_VALUE})

    def test_single_key_exhaustion_and_503(self):
        for attempt in range(3):
            status, body = self.chat()
            self.assertEqual(status, 502)
            text = body.decode("utf-8")
            # Decoded-walk standard: the body must parse, and every decoded
            # string (and byte form) must be free of the key in raw and
            # every escaped variant form (A_VALUE is pure ASCII, so its
            # variant forms coincide with the raw value; the walk also
            # proves every decoded string is clean, not just the envelope
            # text).
            walk_decoded_body(
                self, body, (A_VALUE,),
                context=f"rotation single-key 502 envelope (attempt {attempt + 1})",
            )
            err = json.loads(text)["error"]
            self.assertEqual(err["upstream_status"], 401)
            # Client-facing envelopes carry upstream_status
            # and a fixed, key-free message — no embedded upstream error
            # body, even though the fake's 401 body echoes the bearer value.
            self.assertNotIn("upstream_error", err)
            self.assertIn("failed authentication", err["message"])

        # Third failure triggered cooldown: no keys available.
        status, body = self.chat()
        self.assertEqual(status, 503)
        err = json.loads(body.decode("utf-8"))["error"]
        self.assertIn("no keys available", err["message"])
        self.assertEqual(err["error_kind"], "no_keys")

        records = self.spend_log.read_all()
        self.assertEqual(len(records), 4)  # each 502/503 wrote its record
        self.assertEqual([r.status for r in records], [401, 401, 401, 0])
        self.assertEqual([r.error_kind for r in records], [None, None, None, "no_keys"])
        self.assertEqual([r.key_alias for r in records], [KEY_A_ALIAS] * 3 + [""])
        spend_text = self.spend_path.read_text(encoding="utf-8")
        # Decoded-walk standard for the spend log — every
        # line must parse, and every decoded string (and byte form) must be
        # free of the key in raw and every escaped variant form.
        walk_decoded_jsonl(self, spend_text, (A_VALUE,), context="rotation spend log")
        self.assertIn(KEY_A_ALIAS, spend_text)


if __name__ == "__main__":
    unittest.main()
