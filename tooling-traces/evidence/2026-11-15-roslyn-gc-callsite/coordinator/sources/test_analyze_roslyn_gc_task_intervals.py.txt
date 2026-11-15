import unittest

from analyze_roslyn_gc_task_intervals import overlaps, phase_position, receipt_scope, strict_contains


class IntervalTests(unittest.TestCase):
    def test_positive_overlap_excludes_equal_edge_and_empty_core(self):
        self.assertTrue(overlaps((1, 4), (3, 5)))
        self.assertFalse(overlaps((1, 4), (4, 5)))
        self.assertFalse(overlaps((3, 3), (1, 5)))
        self.assertFalse(overlaps((5, 3), (1, 6)))

    def test_strict_containment_preserves_callback_edge(self):
        self.assertTrue(strict_contains((1, 4), (2, 2)))
        self.assertFalse(strict_contains((1, 4), (1, 3)))
        self.assertFalse(strict_contains((1, 4), (2, 4)))

    def test_receipt_scopes_distinguish_inner_and_outer(self):
        inner, outer = (3, 7), (1, 9)
        self.assertEqual(receipt_scope((4, 6), inner, outer), "strictly_inside_gc_inner")
        self.assertEqual(receipt_scope((2, 4), inner, outer), "partly_overlaps_gc_inner")
        self.assertEqual(receipt_scope((1, 3), inner, outer), "possible_gc_outer")
        self.assertEqual(receipt_scope((9, 10), inner, outer), "possible_gc_outer")
        self.assertEqual(receipt_scope((10, 11), inner, outer), "outside_gc_outer")

    def test_gc_phase_bracket_order_requires_separation(self):
        entry, ret = (10, 11), (20, 21)
        self.assertEqual(phase_position((5, 9), entry, ret), "before_entry")
        self.assertEqual(phase_position((12, 19), entry, ret), "between_receipts")
        self.assertEqual(phase_position((22, 23), entry, ret), "after_return")
        self.assertEqual(phase_position((9, 10), entry, ret), "receipt_edge")
        self.assertEqual(phase_position((11, 18), entry, ret), "receipt_edge")
        self.assertEqual(phase_position((12, 20), entry, ret), "receipt_edge")


if __name__ == "__main__":
    unittest.main()
