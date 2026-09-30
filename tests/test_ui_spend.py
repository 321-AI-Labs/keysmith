"""aggregate_spend and spend_payload against a fixture JSONL with
hand-computed, pinned totals (charter scope item 3: "totals must be
provably correct").

Fixture: tests/fixtures/spend_v02.jsonl, five lines, oldest first.

Hand computation (the pinned truth this test asserts):

  row 1  glm      glm/glm-4.8      status 200  p  60 c  40 t  100
  row 2  glm      glm/glm-4.8      status 200  p  20 c  10 t   30
  row 3  openai   openai/gpt-4.1   status 200  p 500 c 250 t  750
  row 4  openai   openai/gpt-4.1   status 429  p  -   c  -   t    -   (failed, no usage)
  row 5  (none)   glm/glm-4.8      status 400  pre-route failure        (failed)

  totals:        requests 5, ok 3, failed 2, prompt 580, completion 300, total 880
  by provider:   (note: the pre-route row 5 carries provider "")
                 ""       1 / 0 / 1, p 0,   c 0,   t 0
                 glm      2 / 2 / 0, p 80,  c 50,  t 130
                 openai   2 / 1 / 1, p 500, c 250, t 750
  by model:      glm/glm-4.8    3 / 2 / 1, p 80,  c 50,  t 130
                 openai/gpt-4.1 2 / 1 / 1, p 500, c 250, t 750
"""

from __future__ import annotations

import pathlib
import sys
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from keysmith import ui_api  # noqa: E402
from keysmith.spendlog import SpendLog, SpendRecord  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "spend_v02.jsonl"

TOTALS = {
    "requests": 5,
    "ok": 3,
    "failed": 2,
    "prompt_tokens": 580,
    "completion_tokens": 300,
    "total_tokens": 880,
}
NO_PROVIDER = {
    "provider": "",
    "requests": 1,
    "ok": 0,
    "failed": 1,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
}
GLM_PROVIDER = {
    "provider": "glm",
    "requests": 2,
    "ok": 2,
    "failed": 0,
    "prompt_tokens": 80,
    "completion_tokens": 50,
    "total_tokens": 130,
}
OPENAI_PROVIDER = {
    "provider": "openai",
    "requests": 2,
    "ok": 1,
    "failed": 1,
    "prompt_tokens": 500,
    "completion_tokens": 250,
    "total_tokens": 750,
}
GLM_MODEL = {
    "model": "glm/glm-4.8",
    "requests": 3,
    "ok": 2,
    "failed": 1,
    "prompt_tokens": 80,
    "completion_tokens": 50,
    "total_tokens": 130,
}
OPENAI_MODEL = {
    "model": "openai/gpt-4.1",
    "requests": 2,
    "ok": 1,
    "failed": 1,
    "prompt_tokens": 500,
    "completion_tokens": 250,
    "total_tokens": 750,
}


def fixture_records() -> list[SpendRecord]:
    return SpendLog(FIXTURE).read_all()


class AggregateSpendTests(unittest.TestCase):
    def test_totals_pinned_against_fixture(self):
        result = ui_api.aggregate_spend(fixture_records())
        self.assertEqual(result["totals"], TOTALS)

    def test_by_provider_pinned_against_fixture(self):
        result = ui_api.aggregate_spend(fixture_records())
        # glm and openai tie at 2 requests each and sort by provider id
        # ascending; the pre-route row forms its own "" group of 1.
        self.assertEqual(
            result["by_provider"],
            [GLM_PROVIDER, OPENAI_PROVIDER, NO_PROVIDER],
        )

    def test_by_model_pinned_against_fixture(self):
        result = ui_api.aggregate_spend(fixture_records())
        self.assertEqual(result["by_model"], [GLM_MODEL, OPENAI_MODEL])

    def test_tie_break_is_key_ascending(self):
        # glm (2) + one extra = 3, openai (2) + one extra = 3: the tie
        # sorts by provider id ascending.
        records = fixture_records()

        def extra(provider: str, model: str) -> SpendRecord:
            return SpendRecord(
                ts="2026-09-30T11:00:00+00:00",
                provider=provider,
                model=model,
                upstream_model=model.split("/")[-1],
                key_alias="X",
                status=200,
                error_kind=None,
                latency_ms=1.0,
                prompt_tokens=1,
                completion_tokens=1,
                total_tokens=2,
            )

        result = ui_api.aggregate_spend(
            records
            + [extra("glm", "glm/glm-4.8"), extra("openai", "openai/gpt-4.1")]
        )
        by_provider = result["by_provider"]
        self.assertEqual(
            [(row["provider"], row["requests"]) for row in by_provider],
            [("glm", 3), ("openai", 3), ("", 1)],
        )

    def test_empty_log_is_all_zeros(self):
        result = ui_api.aggregate_spend([])
        self.assertEqual(
            result,
            {
                "totals": {
                    "requests": 0,
                    "ok": 0,
                    "failed": 0,
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                },
                "by_provider": [],
                "by_model": [],
            },
        )

    def test_status_zero_counts_as_failed(self):
        # status 0 marks a request that never reached an upstream
        # (no_keys / transport failure): not ok.
        record = SpendRecord(
            ts="2026-09-30T12:00:00+00:00",
            provider="glm",
            model="glm/glm-4.8",
            upstream_model="glm-4.8",
            key_alias="",
            status=0,
            error_kind="no_keys",
            latency_ms=2.0,
            prompt_tokens=None,
            completion_tokens=None,
            total_tokens=None,
        )
        totals = ui_api.aggregate_spend([record])["totals"]
        self.assertEqual((totals["ok"], totals["failed"]), (0, 1))


class SpendPayloadTests(unittest.TestCase):
    def test_rows_newest_first_and_counts(self):
        records = fixture_records()
        payload = ui_api.spend_payload(records)
        self.assertEqual(payload["row_count"], 5)
        self.assertFalse(payload["capped"])
        self.assertEqual(len(payload["rows"]), 5)
        # Newest first: the pre-route 400 (10:04) leads, the first row
        # (10:00) is last.
        self.assertEqual(payload["rows"][0]["ts"], "2026-09-30T10:04:00+00:00")
        self.assertEqual(payload["rows"][0]["status"], 400)
        self.assertEqual(payload["rows"][4]["ts"], "2026-09-30T10:00:00+00:00")
        # Aggregate fields ride along, identical to the pure function.
        self.assertEqual(payload["totals"], ui_api.aggregate_spend(records)["totals"])

    def test_rows_capped_to_max(self):
        records = fixture_records()
        payload = ui_api.spend_payload(records, max_rows=2)
        self.assertTrue(payload["capped"])
        self.assertEqual(payload["row_count"], 5)
        self.assertEqual(
            [row["ts"] for row in payload["rows"]],
            ["2026-09-30T10:04:00+00:00", "2026-09-30T10:03:00+00:00"],
        )

    def test_row_shape_matches_spend_record_fields(self):
        rows = ui_api.spend_payload(fixture_records())["rows"]
        expected_fields = {
            "ts", "provider", "model", "upstream_model", "key_alias",
            "status", "error_kind", "latency_ms", "prompt_tokens",
            "completion_tokens", "total_tokens",
        }
        for row in rows:
            self.assertEqual(set(row), expected_fields)
            # Token counts survive as ints/nulls, never strings.
            self.assertIsInstance(row["status"], int)
            self.assertIsInstance(row["latency_ms"], float)


if __name__ == "__main__":
    unittest.main()
