import unittest

from scheduler_recorded_order import ordering_masks
from scheduler_trace_model import mask_intervals


def row(slot, stamp, kind="in", state=0):
    return {"slot": slot, "mono_ns": stamp, "kind": kind, "raw_state": state}


class RecordedOrderTests(unittest.TestCase):
    def test_reversal_stays_unknown_until_a_later_definite_reset(self):
        rows = [row(0, 200), row(1, 100, "out", 1), row(2, 250), row(3, 300, "exit")]
        masks = ordering_masks(rows)
        self.assertEqual([(m["begin_ns"], m["end_ns"], m["reset_slot"]) for m in masks], [(100, 250, 2)])
        result = mask_intervals([{"begin_ns": 100, "end_ns": 300, "state": "running_observed"}], masks)
        self.assertEqual(result, [{"begin_ns": 100, "end_ns": 250, "state": "unknown"},
                                  {"begin_ns": 250, "end_ns": 300, "state": "running_observed"}])

    def test_tie_does_not_assign_a_state_until_reset(self):
        masks = ordering_masks([row(0, 100), row(1, 100, "out", 1), row(2, 200), row(3, 300, "exit")])
        self.assertEqual((masks[0]["begin_ns"], masks[0]["end_ns"], masks[0]["reasons"]), (100, 200, ["tie"]))

    def test_no_reset_extends_to_exit(self):
        masks = ordering_masks([row(0, 200), row(1, 100, "out", 1), row(2, 300, "exit")])
        self.assertEqual((masks[0]["begin_ns"], masks[0]["end_ns"], masks[0]["reset_slot"]), (100, 300, None))

    def test_ordered_records_need_no_mask(self):
        self.assertEqual(ordering_masks([row(0, 100), row(1, 200), row(2, 300, "exit")]), [])


if __name__ == "__main__":
    unittest.main()
