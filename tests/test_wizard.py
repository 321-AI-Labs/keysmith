"""Setup wizard: preview/write/fail-closed behavior, path-naming
validator errors, the env-NAMES-only law as a source scan, and atomic
write guarantees (temp cleanup, no partial file) on Windows paths.
"""

from __future__ import annotations

import ast
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from keysmith import ui_strings, wizard  # noqa: E402
from keysmith.config import ConfigError, load_config, validate_config_data  # noqa: E402

VALID_DOCUMENT = {
    "_comment": "wizard test document",
    "providers": {
        "demo": {
            "base_url": "https://api.example.com/v1",
            "keys": ["DEMO_KEY_ONE", "DEMO_KEY_TWO"],
            "models": {"demo-model": "demo-upstream"},
            "cooldown_seconds": 90,
            "timeout_seconds": 30,
            "allow_insecure": False,
        }
    },
}

ALTERNATIVE_DOCUMENT = {
    "providers": {
        "other": {
            "base_url": "https://api.other.example/v1",
            "keys": ["OTHER_KEY"],
            "models": {"other-model": "other-upstream"},
        }
    },
}


class ValidateConfigDataTests(unittest.TestCase):
    """The public wrapper around the existing validator."""

    def test_valid_document_returns_config(self):
        config = validate_config_data(VALID_DOCUMENT)
        self.assertEqual(set(config.providers), {"demo"})
        self.assertEqual(config.providers["demo"].key_env_vars, ("DEMO_KEY_ONE", "DEMO_KEY_TWO"))

    def test_invalid_document_raises_config_error_with_path(self):
        bad = json.loads(json.dumps(VALID_DOCUMENT))
        bad["providers"]["demo"]["oops"] = 1
        with self.assertRaises(ConfigError) as ctx:
            validate_config_data(bad)
        # Path-naming message, existing v0.1 behavior (reused, not
        # reinvented).
        self.assertIn("providers.demo.oops", str(ctx.exception))
        self.assertIn("unknown field", str(ctx.exception))


class ReadCurrentDocumentTests(unittest.TestCase):
    def test_reads_file_including_comment(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-wiz-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = tmp / "providers.json"
        path.write_text(json.dumps(VALID_DOCUMENT), encoding="utf-8")
        self.assertEqual(wizard.read_current_document(path), VALID_DOCUMENT)

    def test_missing_file_is_none(self):
        self.assertIsNone(wizard.read_current_document(pathlib.Path("Z:/definitely/not/here.json")))

    def test_none_path_is_none(self):
        self.assertIsNone(wizard.read_current_document(None))

    def test_invalid_json_is_none(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-wiz-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = tmp / "providers.json"
        path.write_text("{not json", encoding="utf-8")
        self.assertIsNone(wizard.read_current_document(path))


class PreviewTests(unittest.TestCase):
    def test_valid_document_previews_with_summary(self):
        result = wizard.preview_document(VALID_DOCUMENT)
        self.assertTrue(result.ok)
        summary = result.payload["summary"]
        self.assertEqual(summary["provider_count"], 1)
        self.assertEqual(summary["model_count"], 1)
        self.assertEqual(summary["providers"][0]["key_count"], 2)
        self.assertEqual(summary["providers"][0]["models"][0]["upstream"], "demo-upstream")

    def test_unknown_field_rejected_with_path_naming(self):
        bad = json.loads(json.dumps(VALID_DOCUMENT))
        bad["providers"]["demo"]["nope"] = 1
        result = wizard.preview_document(bad)
        self.assertFalse(result.ok)
        errors = result.payload["errors"]
        self.assertEqual(len(errors), 1)
        self.assertIn("providers.demo.nope", errors[0])
        self.assertIn("unknown field", errors[0])

    def test_non_object_rejected_by_existing_validator(self):
        result = wizard.preview_document(["not", "an", "object"])
        self.assertFalse(result.ok)
        self.assertIn("top level", result.payload["errors"][0])

    def test_empty_providers_is_valid(self):
        # The Anthropic stub template configures zero providers; the
        # wizard must treat that as valid, like startup does.
        result = wizard.preview_document({"providers": {}})
        self.assertTrue(result.ok)
        self.assertEqual(result.payload["summary"]["provider_count"], 0)


class WriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-wiz-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "providers.json"

    def test_write_then_load_config_round_trip(self):
        result = wizard.write_document(self.path, VALID_DOCUMENT)
        self.assertTrue(result.ok)
        self.assertEqual(result.payload["message"], ui_strings.WIZARD_RESTART_HINT)
        self.assertEqual(result.payload["config_path"], str(self.path))
        # The file validates through the real startup loader.
        config = load_config(self.path)
        self.assertEqual(set(config.providers), {"demo"})
        # Written with indent + trailing newline, like the shipped
        # templates.
        text = self.path.read_text(encoding="utf-8")
        self.assertTrue(text.endswith("\n"))
        self.assertIn("\n  ", text)

    def test_write_replaces_existing_file_atomically(self):
        self.path.write_text(json.dumps(ALTERNATIVE_DOCUMENT), encoding="utf-8")
        before = self.path.read_text(encoding="utf-8")
        result = wizard.write_document(self.path, VALID_DOCUMENT)
        self.assertTrue(result.ok)
        after = self.path.read_text(encoding="utf-8")
        self.assertNotEqual(before, after)
        # No temp leftovers next to the destination.
        leftovers = [p.name for p in self.tmp.iterdir() if "wizard-tmp" in p.name]
        self.assertEqual(leftovers, [])

    def test_invalid_document_writes_nothing(self):
        self.path.write_text(json.dumps(ALTERNATIVE_DOCUMENT), encoding="utf-8")
        before = self.path.read_text(encoding="utf-8")
        bad = json.loads(json.dumps(VALID_DOCUMENT))
        bad["extraneous"] = 1
        result = wizard.write_document(self.path, bad)
        self.assertFalse(result.ok)
        self.assertIn("extraneous", result.payload["errors"][0])
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)
        self.assertEqual(list(self.tmp.iterdir()), [self.path])

    def test_none_config_path_fails_closed(self):
        result = wizard.write_document(None, VALID_DOCUMENT)
        self.assertFalse(result.ok)
        self.assertEqual(result.payload["errors"], [ui_strings.WIZARD_NO_CONFIG_PATH])
        # Fail closed means nothing anywhere was written.
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_unwritable_target_fails_closed_without_partial_file(self):
        # os.replace onto an existing directory raises on Windows and
        # POSIX alike; the temp file must be cleaned up and no partial
        # providers.json left behind.
        target = self.tmp / "occupied"
        target.mkdir()
        result = wizard.write_document(target, VALID_DOCUMENT)
        self.assertFalse(result.ok)
        errors = result.payload["errors"]
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith(ui_strings.WIZARD_WRITE_FAILED))
        self.assertTrue(target.is_dir())  # the directory is untouched
        leftovers = [p.name for p in self.tmp.iterdir() if "wizard-tmp" in p.name]
        self.assertEqual(leftovers, [])

    def test_wizard_result_payload_is_json_serializable(self):
        for result in (
            wizard.preview_document(VALID_DOCUMENT),
            wizard.write_document(self.path, VALID_DOCUMENT),
            wizard.write_document(None, VALID_DOCUMENT),
        ):
            json.dumps(result.payload)  # must not raise


class CurrentStatePayloadTests(unittest.TestCase):
    def test_with_path(self):
        payload = wizard.current_state_payload("providers.json", VALID_DOCUMENT)
        self.assertEqual(payload["config_path"], "providers.json")
        self.assertEqual(payload["document"], VALID_DOCUMENT)
        self.assertTrue(payload["writable"])

    def test_without_path(self):
        payload = wizard.current_state_payload(None, None)
        self.assertIsNone(payload["config_path"])
        self.assertIsNone(payload["document"])
        self.assertFalse(payload["writable"])


class EnvNamesOnlyLawTests(unittest.TestCase):
    """The wizard/UI modules must never touch the environment or key
    values: the only reader of key values in the codebase stays
    keys.read_key_value (v0.1 law, kept intact). The scan walks the AST,
    so docstrings that merely MENTION the law cannot satisfy or trip it."""

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-wizlaw-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "providers.json"

    @staticmethod
    def _environment_accesses(module_name: str) -> list[str]:
        tree = ast.parse(
            (_REPO_ROOT / "keysmith" / module_name).read_text(encoding="utf-8"),
            filename=module_name,
        )
        hits: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv"):
                hits.append(f"{module_name}: os.{node.attr}")
            if isinstance(node, ast.Name) and node.id == "read_key_value":
                hits.append(f"{module_name}: read_key_value")
        return hits

    def test_wizard_never_reads_environment_or_key_values(self):
        self.assertEqual(self._environment_accesses("wizard.py"), [])

    def test_ui_api_never_reads_environment_or_key_values(self):
        self.assertEqual(self._environment_accesses("ui_api.py"), [])

    def test_ui_page_never_reads_environment_or_key_values(self):
        self.assertEqual(self._environment_accesses("ui_page.py"), [])

    def test_document_shape_has_no_value_field(self):
        # The only key-related field the wizard can produce is 'keys'
        # (env var NAMES). There is structurally nowhere for a value.
        result = wizard.write_document(self.path, VALID_DOCUMENT)
        self.assertTrue(result.ok)
        written = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(
            set(written["providers"]["demo"]),
            {"base_url", "keys", "models", "cooldown_seconds", "timeout_seconds", "allow_insecure"},
        )
        for name in written["providers"]["demo"]["keys"]:
            self.assertIsInstance(name, str)


if __name__ == "__main__":
    unittest.main()
