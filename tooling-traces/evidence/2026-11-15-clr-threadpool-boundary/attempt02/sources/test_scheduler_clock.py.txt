import struct
import unittest

from scheduler_clock_analysis import ROW, SLOTS, analyze
from scheduler_clock_program import clock_program


def fixture(points=(110, 120), cpu=0, ordinal=1):
    raw = ROW.pack(ordinal, cpu, cpu, 0, *points) + bytes((SLOTS-1)*ROW.size)
    batch = [{"cpu": cpu, "syscall": 186, "affinity": [cpu],
              "rows": [{"before_ns": 100, "after_ns": 130, "result": 1}]}]
    return raw, batch


class ClockFixtureTests(unittest.TestCase):
    def test_observed_point_intervals_keep_both_reference_edges(self):
        raw, batches = fixture()
        result = analyze(raw, (1, 0, 0, 0), 128, batches)
        self.assertEqual(result["observations"][0]["conditional_discrepancy_intervals_ns"], [[-20, 10], [-10, 20]])
        self.assertIsNone(result["transferable_clock_error_bound"])
        self.assertFalse(result["historical_roslyn_qualified"])

    def test_outside_and_backward_fast_points_are_retained_outcomes(self):
        raw, batches = fixture((140, 90))
        result = analyze(raw, (1, 0, 0, 0), 128, batches)
        self.assertEqual(result["outside_reference_brackets"], 1)
        self.assertEqual(result["recorded_callback_backwards"], 1)

    def test_exact_negative_capacity_loss_is_required(self):
        raw, batches = fixture()
        batches[0]["rows"] *= 2
        self.assertEqual(analyze(raw, (2, 1, 0, 0), 1, batches)["retained"], 1)
        with self.assertRaises(ValueError):
            analyze(raw, (2, 0, 0, 0), 1, batches)

    def test_malformed_shape_padding_ordinal_cpu_and_counts_rejected(self):
        raw, batches = fixture()
        invalid = [raw[:-1], raw[:-1]+b'\1', ROW.pack(2, 0, 0, 0, 110, 120)+raw[32:],
                   ROW.pack(1, 0, 1, 0, 110, 120)+raw[32:],
                   ROW.pack(1, 0, 0, 1, 110, 120)+raw[32:]]
        for value in invalid:
            with self.assertRaises(ValueError):
                analyze(value, (1, 0, 0, 0), 128, batches)
        with self.assertRaises(ValueError):
            analyze(raw, (1, 0, 1, 0), 128, batches)

    def test_bad_reference_and_wrong_syscall_rejected(self):
        raw, batches = fixture()
        batches[0]["rows"][0]["before_ns"] = 140
        with self.assertRaises(ValueError):
            analyze(raw, (1, 0, 0, 0), 128, batches)
        raw, batches = fixture()
        batches[0]["syscall"] = 39
        with self.assertRaises(ValueError):
            analyze(raw, (1, 0, 0, 0), 128, batches)

    def test_program_is_owned_gettid_only_and_contains_two_clock_cpu_pairs(self):
        code = clock_program(11, 12, 13, 128)
        rows = list(struct.iter_unpack('<BBhi', code))
        helpers = [(i, row[3]) for i, row in enumerate(rows) if row[0] == 0x85]
        self.assertEqual([h for _, h in helpers], [158, 156, 8, 5, 1, 1, 5, 8])
        self.assertIn((0x55, 1, next(row[2] for row in rows if row[0] == 0x55 and row[3] == 186), 186), rows)
        reservation = next(i for i,row in enumerate(rows) if row[0] == 0xC3 and row[2] == 0)
        clocks = [i for i,h in helpers if h == 5]
        self.assertLess(clocks[0], reservation)
        self.assertLess(reservation, clocks[1])
        for capacity in (0, 129, True):
            with self.assertRaises(ValueError):
                clock_program(11, 12, 13, capacity)


if __name__ == '__main__':
    unittest.main()
