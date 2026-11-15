from fractions import Fraction
import unittest

from analyze_roslyn_gc_wake_order import PHASES, event_to_point, recorded_gaps, touches


class WakeOrderTests(unittest.TestCase):
    def setUp(self):
        self.row = {"generation": 1, "entry_bracket_ns": [101, 102], "return_bracket_ns": [160, 161],
                    "intervening_lifecycle_rows": [
                        {"kind": kind, "slot": i, "generation": 1, "mono_ns": 110 + i * 10,
                         "raw_state": 8193 if i == 0 else 0} for i, kind in enumerate(PHASES)]}

    def test_comparison_excludes_touching_outer_edge(self):
        self.assertTrue(touches((1, 2), (2, 3)))
        self.assertFalse(touches((1, 2), (Fraction(201, 100), 3)))

    def test_signed_restart_bounds_preserve_uncertainty(self):
        self.assertEqual(event_to_point((10, 12), 11), ("-1", "1"))
        self.assertEqual(event_to_point((10, 12), 8), ("-4", "-2"))

    def test_native_gaps_and_mask_use_both_clocks_and_slots(self):
        gaps, reason = recorded_gaps(self.row, [])
        self.assertIsNone(reason)
        self.assertEqual(list(gaps.values()), [10, 10, 10])
        self.assertEqual(recorded_gaps(self.row, [{"begin_ns": 90, "end_ns": 101}]), (None, "visible_order_mask"))
        self.row["intervening_lifecycle_rows"][2]["slot"] = 1
        self.assertEqual(recorded_gaps(self.row, []), (None, "nonincreasing_lifecycle_order"))


if __name__ == "__main__":
    unittest.main()
