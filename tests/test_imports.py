"""Machine-checks the packaging law: ast-walks every .py file in the repo
and asserts every imported top-level module is stdlib (per
sys.stdlib_module_names) or local (keysmith/tests). Also enforces the
egress law as a suite item: 'sys.stderr' appears nowhere in keysmith/*.py
and 'print(' appears only in keysmith/__main__.py."""

from __future__ import annotations

import ast
import os
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCAL_MODULES = {"keysmith", "tests"}

# EXPECTED_PY_FILE_COUNT is a floor, not an exact-count pin — and a floor
# count cannot prove whole-repo coverage by itself: any scanned subset of
# >= 17 .py files would pass it. Whole-repo coverage is pinned by the
# rglob over REPO_ROOT below together with the ANCHOR_FILES assertions,
# which require files from every corner of the tree (package, scripts,
# tests) to appear inside the scanned set.
EXPECTED_PY_FILE_COUNT = 17
ANCHOR_FILES = (
    "keysmith/server.py",
    "keysmith/__main__.py",
    "scripts/smoke.py",
    "tests/fake_upstream.py",
    "tests/test_imports.py",
)


def iter_python_files() -> list[pathlib.Path]:
    return sorted(path for path in REPO_ROOT.rglob("*.py"))


class StdlibOnlyImportTests(unittest.TestCase):
    def test_only_stdlib_and_local_imports(self):
        violations: list[str] = []
        files = iter_python_files()
        # The scan must cover the whole repo, not just the tests directory.
        relative_names = {str(p.relative_to(REPO_ROOT)).replace(os.sep, "/") for p in files}
        self.assertGreaterEqual(
            len(files), EXPECTED_PY_FILE_COUNT, "expected the full repo to be scanned"
        )
        for anchor in ANCHOR_FILES:
            self.assertIn(anchor, relative_names)
        for path in files:
            relative = path.relative_to(REPO_ROOT)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        if root not in sys.stdlib_module_names and root not in LOCAL_MODULES:
                            violations.append(f"{relative}: imports {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if node.level > 0:
                        continue  # relative import: local by construction
                    if node.module is None:
                        continue
                    root = node.module.split(".")[0]
                    if root not in sys.stdlib_module_names and root not in LOCAL_MODULES:
                        violations.append(f"{relative}: imports from {node.module}")
        self.assertEqual(violations, [])


class EgressLawSourceTests(unittest.TestCase):
    def test_no_sys_stderr_anywhere_in_package(self):
        for path in sorted((REPO_ROOT / "keysmith").glob("*.py")):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn(
                "sys.stderr", source, f"{path.name} references the standard error stream"
            )

    def test_print_only_in_dunder_main(self):
        for path in sorted((REPO_ROOT / "keysmith").glob("*.py")):
            if path.name == "__main__.py":
                continue
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("print(", source, f"{path.name} contains a stray print call")


if __name__ == "__main__":
    unittest.main()
