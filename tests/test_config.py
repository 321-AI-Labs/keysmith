"""Config validation tests, including test_shipped_templates_and_example_load
so a template typo fails the suite, not the quickstart."""

import json
import pathlib
import shutil
import tempfile
import unittest

from keysmith.config import ConfigError, ProviderConfig, load_config

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class ConfigTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-config-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, data: object, name: str = "providers.json") -> pathlib.Path:
        path = self.tmp / name
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def good_provider(self, **overrides: object) -> dict:
        provider: dict = {
            "base_url": "https://api.example.com/v1",
            "keys": ["EXAMPLE_KEY"],
            "models": {"example-model": "example-model-v1"},
        }
        provider.update(overrides)
        return {"example": provider}

    def assert_config_error(self, data: object, fragment: str) -> None:
        with self.assertRaises(ConfigError) as ctx:
            load_config(self.write(data))
        self.assertIn(fragment, str(ctx.exception))


class HappyPathTests(ConfigTestCase):
    def test_full_provider(self):
        cfg = load_config(self.write({
            "_comment": "hello",
            "providers": self.good_provider(
                cooldown_seconds=5,
                timeout_seconds=10,
                allow_insecure=False,
            ),
        }))
        self.assertEqual(set(cfg.providers), {"example"})
        provider = cfg.providers["example"]
        self.assertIsInstance(provider, ProviderConfig)
        self.assertEqual(provider.name, "example")
        self.assertEqual(provider.base_url, "https://api.example.com/v1")
        self.assertEqual(provider.key_env_vars, ("EXAMPLE_KEY",))
        self.assertEqual(provider.models, {"example-model": "example-model-v1"})
        self.assertEqual(provider.cooldown_seconds, 5.0)
        self.assertEqual(provider.timeout_seconds, 10.0)
        self.assertFalse(provider.allow_insecure)

    def test_defaults(self):
        provider = load_config(self.write({"providers": self.good_provider()})).providers["example"]
        self.assertEqual(provider.cooldown_seconds, 60.0)
        self.assertEqual(provider.timeout_seconds, 120.0)
        self.assertFalse(provider.allow_insecure)

    def test_empty_providers_allowed(self):
        cfg = load_config(self.write({"providers": {}}))
        self.assertEqual(cfg.providers, {})

    def test_keys_deduplicated_order_preserved(self):
        provider = load_config(self.write({
            "providers": self.good_provider(keys=["K1", "K2", "K1", "K3", "K2"]),
        })).providers["example"]
        self.assertEqual(provider.key_env_vars, ("K1", "K2", "K3"))


class SchemeRuleTests(ConfigTestCase):
    def test_https_is_fine(self):
        cfg = load_config(self.write({"providers": self.good_provider()}))
        self.assertTrue(cfg.providers["example"].base_url.startswith("https://"))

    def test_http_loopback_with_allow_insecure(self):
        cfg = load_config(self.write({
            "providers": self.good_provider(base_url="http://127.0.0.1:8000/v1", allow_insecure=True),
        }))
        self.assertTrue(cfg.providers["example"].allow_insecure)

    def test_http_localhost_and_ipv6_loopback_with_allow_insecure(self):
        base = self.good_provider()["example"]
        cfg = load_config(self.write({"providers": {
            "a": base | {"base_url": "http://localhost:8000/v1", "allow_insecure": True},
            "b": base | {"base_url": "http://[::1]:8000/v1", "allow_insecure": True},
        }}))
        self.assertEqual(set(cfg.providers), {"a", "b"})

    def test_http_loopback_requires_allow_insecure(self):
        self.assert_config_error(
            {"providers": self.good_provider(base_url="http://127.0.0.1:8000/v1")},
            "cleartext",
        )

    def test_http_non_loopback_rejected_even_with_allow_insecure(self):
        self.assert_config_error(
            {"providers": self.good_provider(base_url="http://example.com/v1", allow_insecure=True)},
            "cleartext",
        )

    def test_http_private_address_is_not_loopback(self):
        self.assert_config_error(
            {"providers": self.good_provider(base_url="http://192.168.1.5/v1", allow_insecure=True)},
            "cleartext",
        )

    def test_non_http_scheme_rejected(self):
        self.assert_config_error(
            {"providers": self.good_provider(base_url="ftp://example.com/v1")},
            "scheme",
        )


class SchemaTests(ConfigTestCase):
    def test_unknown_provider_field_names_path(self):
        self.assert_config_error(
            {"providers": self.good_provider(typo=True)},
            "providers.example.typo: unknown field",
        )

    def test_unknown_top_level_field(self):
        self.assert_config_error({"providers": {}, "bogus": 1}, "unknown top-level field")

    def test_malformed_provider_ids_rejected(self):
        for bad in ("Bad_ID", "-leading", "_leading", "with space", "é", "UPPER"):
            with self.subTest(provider_id=bad):
                data = {"providers": self.good_provider()}
                data["providers"][bad] = data["providers"].pop("example")
                self.assert_config_error(data, "provider id")

    def test_provider_id_charset(self):
        cfg = load_config(self.write({
            "providers": self.good_provider(
                keys=["EXAMPLE_KEY"], models={"example-model": "example-model-v1"}
            ),
        }))
        self.assertIn("example", cfg.providers)
        cfg2 = load_config(self.write({
            "providers": {
                "a-b_2": self.good_provider()["example"],
            },
        }))
        self.assertIn("a-b_2", cfg2.providers)

    def test_missing_required_fields(self):
        for field in ("base_url", "keys", "models"):
            with self.subTest(missing=field):
                data = {"providers": self.good_provider()}
                data["providers"]["example"].pop(field)
                self.assert_config_error(data, "required")

    def test_keys_must_be_nonempty_list_of_nonempty_strings(self):
        self.assert_config_error({"providers": self.good_provider(keys=[])}, "keys")
        self.assert_config_error({"providers": self.good_provider(keys=[""])}, "keys")
        self.assert_config_error({"providers": self.good_provider(keys="K1")}, "keys")
        self.assert_config_error({"providers": self.good_provider(keys=[1])}, "keys")

    def test_models_rules(self):
        self.assert_config_error({"providers": self.good_provider(models={})}, "models")
        self.assert_config_error(
            {"providers": self.good_provider(models={"a/b": "x"})}, "must not contain '/'"
        )
        self.assert_config_error(
            {"providers": self.good_provider(models={"ok": ""})}, "nonempty string"
        )
        self.assert_config_error(
            {"providers": self.good_provider(models={"ok": 3})}, "nonempty string"
        )

    def test_cooldown_and_timeout_rules(self):
        for field in ("cooldown_seconds", "timeout_seconds"):
            for bad in (0, -5, "60", True, None):
                with self.subTest(field=field, bad=bad):
                    self.assert_config_error(
                        {"providers": self.good_provider(**{field: bad})}, field
                    )

    def test_allow_insecure_must_be_bool(self):
        self.assert_config_error(
            {"providers": self.good_provider(allow_insecure="yes")}, "allow_insecure"
        )

    def test_invalid_json(self):
        path = self.write("{not json")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_top_level_not_object(self):
        path = self.write("[1, 2]")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_providers_missing_or_wrong_type(self):
        with self.assertRaises(ConfigError):
            load_config(self.write({}))
        with self.assertRaises(ConfigError):
            load_config(self.write({"providers": [1]}))

    def test_provider_not_object(self):
        self.assert_config_error({"providers": {"example": 5}}, "must be a JSON object")

    def test_unreadable_file(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(self.tmp / "nope.json")
        self.assertIn("cannot read", str(ctx.exception))


class ShippedTemplatesTest(ConfigTestCase):
    def test_shipped_templates_and_example_load(self):
        paths = sorted((REPO_ROOT / "templates").glob("*.json"))
        paths.append(REPO_ROOT / "example.providers.json")
        self.assertEqual(len(paths), 7)  # six templates + the merged example
        for path in paths:
            with self.subTest(path=path.name):
                cfg = load_config(path)
                self.assertIsInstance(cfg.providers, dict)
        stub = load_config(REPO_ROOT / "templates" / "providers.anthropic-stub.json")
        self.assertEqual(stub.providers, {})


if __name__ == "__main__":
    unittest.main()
