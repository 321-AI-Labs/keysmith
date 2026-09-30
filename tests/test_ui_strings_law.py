"""Naming-law machine guard for the dashboard shell (honesty law).

The module docstring of ``keysmith.ui_page`` claims that no prose lives
in the HTML tags or the JavaScript: every user-visible string renders
from the one JSON blob embedded from ``ui_strings.PAGE_TEXT``. This test
file makes that claim falsifiable. It FAILS on the pre-fix ui-v02 tip
(the hardcoded brand span, the literal document-title fallback, the
hardcoded tablist aria-label, and 55 dormant ``T.x || "literal"`` JS
fallbacks, seven of which had drifted from the module values) and PASSES
only when:

* no HTML text node outside the embedded JSON blob carries prose
  (every data-t hook ships empty in the skeleton),
* no aria-label / placeholder / title attribute carries a literal
  without its data-t-aria-label / data-t-placeholder / data-t-title
  hook,
* every data-t* key used in the skeleton exists in
  ``ui_strings.PAGE_TEXT``,
* the embedded JSON blob round-trips to ``ui_strings.PAGE_TEXT``
  exactly,
* the page JavaScript contains no non-empty ``T.<key> || "..."``
  fallback (drift is impossible when there is nothing to drift from).
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import unittest
from html.parser import HTMLParser

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from keysmith import ui_page, ui_strings  # noqa: E402

# Attribute -> the data-t-* hook that is allowed to fill it.
_HOOKED_ATTRIBUTES = {
    "aria-label": "data-t-aria-label",
    "placeholder": "data-t-placeholder",
    "title": "data-t-title",
}

_FALLBACK_RE = re.compile(r"""T\.\w+\s*\|\|\s*(?:"([^"]*)"|'([^']*)')""")


class _SkeletonParser(HTMLParser):
    """Walks the built DOCUMENT, separating the renderable skeleton from
    the two raw-text islands (the CSS <style> and the two <script>
    blocks, one of which is the JSON strings blob)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.text_nodes: list[tuple[str, str]] = []  # (text, where)
        self.hooked_attr_literals: list[tuple[str, str, str]] = []
        self.data_t_keys: list[tuple[str, str]] = []  # (attr name, key)
        self.script_bodies: list[tuple[str | None, str]] = []
        self._script_type: str | None = None
        self._script_id: str | None = None
        self._script_chunks: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        self.stack.append(tag)
        for attr, hook in _HOOKED_ATTRIBUTES.items():
            value = attr_map.get(attr)
            if value and value.strip() and hook not in attr_map:
                self.hooked_attr_literals.append((tag, attr, value))
        for hook in ("data-t", "data-t-placeholder", "data-t-title",
                     "data-t-aria-label"):
            if hook in attr_map:
                self.data_t_keys.append((hook, attr_map[hook]))
        if tag == "script":
            self._script_type = attr_map.get("type")
            self._script_id = attr_map.get("id")
            self._script_chunks = []

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.stack.pop()

    def handle_endtag(self, tag):
        if tag == "script" and self._script_chunks is not None:
            self.script_bodies.append(
                (self._script_id, "".join(self._script_chunks))
            )
            self._script_chunks = None
            self._script_type = None
            self._script_id = None
        while self.stack:
            if self.stack.pop() == tag:
                break

    def handle_data(self, data):
        if not self.stack:
            return
        if self._script_chunks is not None:
            self._script_chunks.append(data)
            return
        if "style" in self.stack:
            return
        if data.strip():
            where = ">".join(self.stack[-4:])
            self.text_nodes.append((data.strip(), where))


def _parse_document() -> _SkeletonParser:
    parser = _SkeletonParser()
    parser.feed(ui_page.DOCUMENT)
    parser.close()
    return parser


class SkeletonCarriesNoProseTests(unittest.TestCase):
    """The HTML skeleton ships with empty hooks; the strings module fills
    every one of them at page init."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.parsed = _parse_document()

    def test_no_text_node_outside_the_json_blob_carries_prose(self):
        failures = [f"<{where}>: {text!r}" for text, where in self.parsed.text_nodes]
        self.assertEqual(
            failures,
            [],
            "prose text nodes in the skeleton (hooks must ship empty)",
        )

    def test_no_literal_aria_placeholder_or_title_without_a_hook(self):
        failures = [
            f"<{tag} {attr}={value!r}> lacks {_HOOKED_ATTRIBUTES[attr]}"
            for tag, attr, value in self.parsed.hooked_attr_literals
        ]
        self.assertEqual(
            failures,
            [],
            "prose attributes without a data-t-* hook",
        )

    def test_every_data_t_key_exists_in_page_text(self):
        missing = sorted(
            {key for _, key in self.parsed.data_t_keys}
            - set(ui_strings.PAGE_TEXT)
        )
        self.assertEqual(missing, [], "data-t* keys missing from PAGE_TEXT")

    def test_every_hook_kind_is_used(self):
        # The skeleton exercises all four channels, so a dropped channel
        # in the init JS cannot hide behind an empty key set.
        used = {hook for hook, _ in self.parsed.data_t_keys}
        self.assertEqual(
            used,
            {"data-t", "data-t-placeholder", "data-t-title", "data-t-aria-label"},
        )


class StringsBlobTests(unittest.TestCase):
    """The page's one JSON blob is exactly ui_strings.PAGE_TEXT."""

    def test_blob_round_trips_to_page_text(self):
        parsed = _parse_document()
        blobs = [
            body for script_id, body in parsed.script_bodies
            if script_id == "ui-strings"
        ]
        self.assertEqual(len(blobs), 1)
        self.assertEqual(json.loads(blobs[0]), ui_strings.PAGE_TEXT)


class JavaScriptCarriesNoProseFallbackTests(unittest.TestCase):
    """No ``T.<key> || "literal"`` fallback may carry prose: the strings
    module is the only source, so a fallback can only drift from it."""

    def test_no_nonempty_fallback_on_any_t_lookup(self):
        parsed = _parse_document()
        scripts = [
            body for script_id, body in parsed.script_bodies
            if script_id != "ui-strings"
        ]
        self.assertEqual(len(scripts), 1)
        failures = []
        for match in _FALLBACK_RE.finditer(scripts[0]):
            literal = match.group(1) if match.group(1) is not None else match.group(2)
            if literal:
                failures.append(match.group(0))
        self.assertEqual(
            failures,
            [],
            "non-empty T.* fallbacks in the page JavaScript",
        )


if __name__ == "__main__":
    unittest.main()
