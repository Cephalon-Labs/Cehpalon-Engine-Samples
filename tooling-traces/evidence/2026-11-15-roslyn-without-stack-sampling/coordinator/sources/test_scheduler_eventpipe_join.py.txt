from copy import deepcopy
from fractions import Fraction
import unittest

from scheduler_eventpipe_join import join_eventpipe_point


def generation(number=1, *, begin=1_000_000, exit_at=8_000_000, free_at=9_000_000,
               initial=False, tid=77):
    return {"execution_id": "run-1", "generation": number, "local_tid": tid,
            "born_ns": begin, "exit_ns": exit_at, "free_ns": free_at,
            "initial_state_unknown": initial}


def join(time_ms, records=None, *, offsets=(0, 0), pid=100, tid=77):
    return join_eventpipe_point({"processId": pid, "threadId": tid, "timeMsec": time_ms},
                               [generation()] if records is None else records,
                               execution_id="run-1", target_pid=100, offset_ms=offsets)


class EventPipeJoinTests(unittest.TestCase):
    def test_exact_fraction_mapping_and_active_identity(self):
        result = join(2, offsets=("-1/1000000", "1/1000000"))
        self.assertEqual(result["mapped_mono_ns"], ["1999999", "2000001"])
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["generation"], 1)
        self.assertIsNone(result["scheduler_state"])

    def test_retired_identity_stays_separate_from_active_work(self):
        result = join(Fraction(17, 2))
        self.assertEqual((result["status"], result["generation"]), ("retired", 1))

    def test_exact_lifecycle_boundaries_remain_unassigned(self):
        for point in (1, 8, 9):
            with self.subTest(point=point):
                result = join(point)
                self.assertEqual(result["status"], "boundary")
                self.assertIsNone(result["generation"])

    def test_numeric_tid_reuse_selects_its_lifetime(self):
        records = [generation(), generation(2, begin=9_100_000, exit_at=19_000_000, free_at=20_000_000)]
        self.assertEqual(join(2, records)["generation"], 1)
        self.assertEqual(join(10, records)["generation"], 2)

    def test_uncertain_clock_across_reuse_keeps_both_candidates(self):
        records = [generation(), generation(2, begin=9_100_000, exit_at=19_000_000, free_at=20_000_000)]
        result = join(9, records, offsets=("-1/5", "1/5"))
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["candidate_generations"], [1, 2])
        self.assertIsNone(result["generation"])

    def test_inconsistent_overlapping_lifetimes_are_ambiguous(self):
        records = [generation(), generation(2, begin=1_500_000)]
        self.assertEqual(join(2, records)["status"], "ambiguous")

    def test_prearm_enrollment_does_not_assert_a_birth_or_scheduler_state(self):
        record = generation(initial=True)
        result = join(2, [record])
        self.assertEqual(result["status"], "active")
        self.assertTrue(result["lifetime_left_censored"])
        self.assertIsNone(result["scheduler_state"])
        self.assertEqual(join(1, [record])["status"], "boundary")
        self.assertEqual(join(Fraction(1, 2), [record])["status"], "missing")

    def test_missing_lifetime_and_foreign_headers_stay_explicit(self):
        self.assertEqual(join(2, [])["status"], "missing")
        self.assertEqual(join(2, tid=78)["status"], "missing")
        self.assertEqual(join(2, pid=101)["status"], "foreign_process")
        self.assertEqual(join(2, [generation(exit_at=None, free_at=None)])["status"],
                         "incomplete_lifetime")

    def test_observed_exit_can_bound_active_identity_before_unknown_free(self):
        self.assertEqual(join(2, [generation(free_at=None)])["status"], "active")
        self.assertEqual(join(Fraction(17, 2), [generation(free_at=None)])["status"],
                         "incomplete_lifetime")

    def test_cross_execution_duplicate_and_reversed_records_are_rejected(self):
        foreign = generation()
        foreign["execution_id"] = "run-2"
        for records in ([foreign], [generation(), generation()],
                        [generation(exit_at=900_000)], [generation(free_at=7_000_000)]):
            with self.subTest(records=records):
                with self.assertRaises(ValueError):
                    join(2, records)

    def test_invalid_clock_or_native_headers_are_rejected(self):
        for time_ms, offsets, pid, tid in (
            (float("nan"), (0, 0), 100, 77), (True, (0, 0), 100, 77),
            (2, (1, 0), 100, 77), (2, (3, 3), 100, 77),
            (2, (0, 0), True, 77), (2, (0, 0), 100, 0),
        ):
            with self.subTest(time=time_ms, offsets=offsets, pid=pid, tid=tid):
                with self.assertRaises(ValueError):
                    join(time_ms, offsets=offsets, pid=pid, tid=tid)

    def test_fixed_generation_bound_and_input_preservation(self):
        records = [generation(i, tid=i) for i in range(1, 65)]
        before = deepcopy(records)
        self.assertEqual(join(2, records, tid=64)["generation"], 64)
        self.assertEqual(records, before)
        with self.assertRaises(ValueError):
            join(2, records + [generation(65, tid=65)])


if __name__ == "__main__":
    unittest.main()
