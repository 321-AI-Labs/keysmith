"""In-process tests for the ``python -m keysmith`` command line.

Pins the README CLI claims: the four flags and their documented defaults
(providers.json, spend.jsonl, 127.0.0.1, 8317), and the two abort paths —
a missing KEYSMITH_TOKEN and an invalid config path — exiting with
status 2 and a diagnostic.

No subprocess is spawned. The exit-code tests run the package's real
``__main__`` through runpy with ``run_name="__main__"``, which fires the
module's ``if __name__ == "__main__"`` guard (``SystemExit(main())``),
with sys.argv patched. The flag tests call ``keysmith.__main__.main``
directly with ``KeysmithServer`` mocked out (no socket is bound; the
serve loop's ``time`` reference is replaced by a mock whose ``sleep``
raises KeyboardInterrupt, so main() returns) and inspect what the CLI
handed to the server and printed at startup.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import runpy
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from keysmith import __main__ as cli  # noqa: E402

TOKEN = "cli-test-token-123"

# Minimal valid providers.json (schema per keysmith/config.py).
VALID_CONFIG = {
    "providers": {
        "demo": {
            "base_url": "https://api.example.com/v1",
            "keys": ["DEMO_KEY"],
            "models": {"demo-model": "demo-upstream"},
        }
    }
}


class CliExitCodeTests(unittest.TestCase):
    """Both documented startup aborts exit with status 2 and a diagnostic."""

    def _run_module_expect_system_exit(self, argv: list[str]) -> tuple[int, str]:
        # runpy warns when the package's __main__ submodule is already
        # imported (the flag tests below import it as ``cli``): execute
        # against a clean registration, then restore the imported module.
        saved_main = sys.modules.pop("keysmith.__main__", None)
        try:
            with mock.patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()) as out:
                    with self.assertRaises(SystemExit) as ctx:
                        runpy.run_module("keysmith", run_name="__main__")
        finally:
            if saved_main is not None:
                sys.modules["keysmith.__main__"] = saved_main
        return int(ctx.exception.code), out.getvalue()

    def test_missing_token_exits_2_with_diagnostic(self):
        env = dict(os.environ)
        env.pop("KEYSMITH_TOKEN", None)
        with mock.patch.dict(os.environ, env, clear=True):
            code, out = self._run_module_expect_system_exit(["keysmith"])
        self.assertEqual(code, 2)
        self.assertIn("KEYSMITH_TOKEN", out)

    def test_invalid_config_path_exits_2_with_diagnostic(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-cli-test-"))
        missing = tmp / "definitely-missing.json"
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.assertFalse(missing.exists())
        with mock.patch.dict(os.environ, {"KEYSMITH_TOKEN": TOKEN}):
            code, out = self._run_module_expect_system_exit(
                ["keysmith", "--config", str(missing)]
            )
        self.assertEqual(code, 2)
        self.assertIn("invalid config", out)
        self.assertIn("definitely-missing.json", out)


class CliFlagTests(unittest.TestCase):
    """--config/--spend-log/--host/--port: the documented defaults and
    explicit values, observed on what main() hands to KeysmithServer
    (mocked — no socket is bound) and on the startup line it prints."""

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="keysmith-cli-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "providers.json").write_text(json.dumps(VALID_CONFIG), encoding="utf-8")

    def _run_main(self, argv: list[str]) -> tuple[int, str, mock.Mock]:
        server_factory = mock.Mock(name="KeysmithServer factory")
        fake_time = mock.Mock(name="time")
        fake_time.sleep.side_effect = KeyboardInterrupt  # one Ctrl-C ends the serve loop
        with (
            mock.patch.dict(os.environ, {"KEYSMITH_TOKEN": TOKEN}),
            mock.patch.object(cli, "KeysmithServer", server_factory),
            mock.patch.object(cli, "time", fake_time),
            redirect_stdout(io.StringIO()) as out,
        ):
            code = cli.main(argv)
        return code, out.getvalue(), server_factory

    def test_flags_default_to_documented_values(self):
        # The --config default is cwd-relative: run from the temp dir,
        # where providers.json exists.
        previous_cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            code, out, factory = self._run_main([])
        finally:
            os.chdir(previous_cwd)
        self.assertEqual(code, 0)
        self.assertIn("config: providers.json", out)
        self.assertIn("spend log: spend.jsonl", out)
        factory.assert_called_once()
        self.assertEqual(factory.call_args.kwargs, {"host": "127.0.0.1", "port": 8317})
        server = factory.return_value
        server.start.assert_called_once_with()
        server.stop.assert_called_once_with()

    def test_flags_parse_explicit_values(self):
        config = self.tmp / "custom.providers.json"
        config.write_text(json.dumps(VALID_CONFIG), encoding="utf-8")
        spend_log = self.tmp / "custom-spend.jsonl"
        code, out, factory = self._run_main(
            [
                "--config", str(config),
                "--spend-log", str(spend_log),
                "--host", "127.0.0.2",
                "--port", "9599",  # a string on the command line; must parse to int
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn(f"config: {config}", out)
        self.assertIn(f"spend log: {spend_log}", out)
        self.assertEqual(factory.call_args.kwargs, {"host": "127.0.0.2", "port": 9599})


if __name__ == "__main__":
    unittest.main()
