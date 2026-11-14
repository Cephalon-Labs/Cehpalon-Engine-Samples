import unittest

from scheduler_trace_model import ROW, decode_scheduler, state_intervals


class SchedulerModelTests(unittest.TestCase):
    def test_initial_enrollment_has_no_invented_birth_or_first_wake(self):
        rows = [(10, 0, 0xFFFFFFFF, 0, 10), (3, 0, 0xFFFFFFFF, 0, 11),
                (7, 0, 0xFFFFFFFF, 0, 20), (4, 0, 0xFFFFFFFF, 128, 21),
                (8, 0, 0xFFFFFFFF, 0, 22)]
        raw = b"".join(ROW.pack(*row, 100, 1000, 1, 0) for row in rows) + bytes(40)
        report = {"terminal_counts": [5, 0, 0, 1, 1, 1]}
        identities, intervals, _ = decode_scheduler(raw, report, "owned", slots=6)
        self.assertTrue(identities[0]["initial_state_unknown"])
        self.assertEqual(intervals[1][0]["state"], "unknown")

    def test_waking_is_unknown_until_actual_wakeup(self):
        rows = [
            {"mono_ns": 10, "kind": "out", "raw_state": 1},
            {"mono_ns": 20, "kind": "waking", "raw_state": 0},
            {"mono_ns": 25, "kind": "wakeup", "raw_state": 0},
            {"mono_ns": 30, "kind": "in", "raw_state": 0},
            {"mono_ns": 40, "kind": "exit", "raw_state": 0},
        ]
        states = state_intervals(rows, 10, 40)
        self.assertEqual([s["state"] for s in states],
                         ["off_cpu_sleep_state", "unknown", "runnable_observed", "running_observed"])


if __name__ == "__main__":
    unittest.main()
