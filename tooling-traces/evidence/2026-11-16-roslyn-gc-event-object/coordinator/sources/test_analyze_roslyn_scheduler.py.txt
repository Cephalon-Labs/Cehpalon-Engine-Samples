from fractions import Fraction
import unittest

from analyze_roslyn_scheduler import partition, target_gc_boundary, union


class SchedulerQueryTests(unittest.TestCase):
    def test_union_does_not_double_count_nested_waits(self):
        self.assertEqual(union([(10, 20), (12, 18), (19, 25)]), [[10, 25]])

    def test_partition_keeps_unobserved_edges_unknown(self):
        intervals = [{"begin_ns": 10, "end_ns": 20, "state": "running_observed"}]
        self.assertEqual(partition([(Fraction(5), Fraction(25))], intervals),
                         {"running_observed": "10", "unknown": "10"})

    def test_exact_fraction_boundaries_are_preserved(self):
        intervals = [{"begin_ns": 10, "end_ns": 20, "state": "off_cpu_sleep_state"}]
        self.assertEqual(partition([(Fraction(21, 2), Fraction(39, 2))], intervals),
                         {"off_cpu_sleep_state": "9", "unknown": "0"})

    def test_foreign_gc_boundary_cannot_enter_the_target_wait(self):
        event = {"provider": "Microsoft-Windows-DotNETRuntime", "name": "GC/SuspendEEStart", "processId": 11}
        self.assertTrue(target_gc_boundary(event, 11))
        self.assertFalse(target_gc_boundary(event, 12))


if __name__ == "__main__":
    unittest.main()
