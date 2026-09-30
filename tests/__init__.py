"""Marks tests as a package so `python -m unittest discover -s tests` works.

Bootstraps the repo root onto sys.path so `import keysmith` works no matter
which working directory discovery was launched from. Each test module
repeats the same guard, because `discover -s tests` on Python 3.12 imports
test modules under bare names (test_redact, not tests.test_redact), so this
package's __init__ does not always run first.
"""

import pathlib
import sys

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
