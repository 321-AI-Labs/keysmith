"""KeyPool unit tests with injected monotonic `now` and patched os.environ:
round-robin order, CURSOR LAW (pinned on a 3-key pool), missing-env
skipping, 3-consecutive-failure cooldown, skip-while-cooling, recovery
after cooldown, reset-on-success. Zero timing dependence."""

import os
import unittest
from unittest import mock

from keysmith.keys import AUTH_FAILURE_LIMIT, KeyPool, read_key_value

ENV = {"KEY_A": "sk-a", "KEY_B": "sk-b", "KEY_C": "sk-c"}


class ReadKeyValueTests(unittest.TestCase):
    def test_reads_env_at_call_time(self):
        with mock.patch.dict(os.environ, {"KEY_X": "sk-x"}):
            self.assertEqual(read_key_value("KEY_X"), "sk-x")
        self.assertIsNone(read_key_value("KEY_X"))

    def test_unset_and_empty_return_none(self):
        with mock.patch.dict(os.environ, {"KEY_EMPTY": ""}):
            self.assertIsNone(read_key_value("KEY_EMPTY"))
        self.assertIsNone(read_key_value("KEY_UNSET_XYZ_NOT_SET"))


@mock.patch.dict(os.environ, ENV)
class KeyPoolTests(unittest.TestCase):
    def test_round_robin_order(self):
        pool = KeyPool(["KEY_A", "KEY_B", "KEY_C"])
        order = [pool.next_available(0.0) for _ in range(6)]
        self.assertEqual(order, ["KEY_A", "KEY_B", "KEY_C", "KEY_A", "KEY_B", "KEY_C"])

    def test_empty_pool_returns_none(self):
        pool = KeyPool([])
        self.assertIsNone(pool.next_available(0.0))

    def test_missing_env_keys_are_skipped(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("KEY_B", None)
            pool = KeyPool(["KEY_A", "KEY_B", "KEY_C"])
            order = [pool.next_available(0.0) for _ in range(4)]
            self.assertEqual(order, ["KEY_A", "KEY_C", "KEY_A", "KEY_C"])

    def test_cursor_law_skipped_keys_do_not_advance_cursor_on_their_own(self):
        # 3-key pool, B unset. Handouts go A, C, A, C: the cursor advances
        # only past the alias actually returned (A -> position of B; C ->
        # wrap to A), never past a skipped key.
        with mock.patch.dict(os.environ):
            os.environ.pop("KEY_B", None)
            pool = KeyPool(["KEY_A", "KEY_B", "KEY_C"])
            self.assertEqual(pool.next_available(0.0), "KEY_A")
            self.assertEqual(pool.next_available(0.0), "KEY_C")
            self.assertEqual(pool.next_available(0.0), "KEY_A")
            self.assertEqual(pool.next_available(0.0), "KEY_C")

    def test_cursor_law_empty_scan_leaves_cursor_unchanged(self):
        pool = KeyPool(["KEY_A", "KEY_B", "KEY_C"])
        self.assertEqual(pool.next_available(0.0), "KEY_A")  # cursor now at B
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(pool.next_available(0.0))  # empty scan
        # The empty scan must not have moved the cursor: B is next.
        self.assertEqual(pool.next_available(0.0), "KEY_B")

    def test_cooling_key_is_skipped(self):
        pool = KeyPool(["KEY_A", "KEY_B"], cooldown_seconds=60.0)
        for _ in range(3):
            pool.report_auth_failure("KEY_A", 0.0)  # cooldown until t=60
        self.assertEqual(pool.next_available(10.0), "KEY_B")
        # cursor wrapped back to A, which is still cooling: B again.
        self.assertEqual(pool.next_available(59.9), "KEY_B")

    def test_three_consecutive_failures_trigger_cooldown_and_reset_counter(self):
        pool = KeyPool(["KEY_A", "KEY_B"], cooldown_seconds=60.0)
        self.assertFalse(pool.report_auth_failure("KEY_A", 10.0))
        self.assertFalse(pool.report_auth_failure("KEY_A", 11.0))
        self.assertTrue(pool.report_auth_failure("KEY_A", 12.0))  # third in a row
        state = pool.state("KEY_A")
        self.assertEqual(state.cooldown_until, 12.0 + 60.0)
        self.assertEqual(state.auth_failures, 0)  # reset on cooldown entry

    def test_recovery_after_cooldown_without_restart(self):
        pool = KeyPool(["KEY_A", "KEY_B"], cooldown_seconds=60.0)
        for _ in range(3):
            pool.report_auth_failure("KEY_A", 0.0)  # cooldown until t=60
        self.assertEqual(pool.next_available(10.0), "KEY_B")
        # At exactly the cooldown deadline the key is available again.
        self.assertEqual(pool.next_available(60.0), "KEY_A")

    def test_success_resets_failure_streak(self):
        pool = KeyPool(["KEY_A"], cooldown_seconds=60.0)
        pool.report_auth_failure("KEY_A", 1.0)
        pool.report_auth_failure("KEY_A", 2.0)
        pool.report_success("KEY_A")
        self.assertEqual(pool.state("KEY_A").auth_failures, 0)
        # '3 times' means 3 in a row: this is failure #1 of a new streak.
        self.assertFalse(pool.report_auth_failure("KEY_A", 3.0))

    def test_success_does_not_clear_active_cooldown(self):
        pool = KeyPool(["KEY_A"], cooldown_seconds=60.0)
        for _ in range(3):
            pool.report_auth_failure("KEY_A", 0.0)
        pool.report_success("KEY_A")
        self.assertIsNotNone(pool.state("KEY_A").cooldown_until)
        self.assertIsNone(pool.next_available(10.0))

    def test_states_lists_every_alias_in_order(self):
        pool = KeyPool(["KEY_B", "KEY_A"])
        self.assertEqual([s.alias for s in pool.states()], ["KEY_B", "KEY_A"])
        self.assertEqual(pool.state("KEY_A").alias, "KEY_A")
        self.assertEqual(pool.state("KEY_A").auth_failures, 0)
        self.assertIsNone(pool.state("KEY_A").cooldown_until)

    def test_auth_failure_limit_is_three(self):
        self.assertEqual(AUTH_FAILURE_LIMIT, 3)


if __name__ == "__main__":
    unittest.main()
