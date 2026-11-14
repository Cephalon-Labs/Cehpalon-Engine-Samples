import unittest

from collect_scheduler_clr_fixture import ROW, SLOTS, validate_trace


def fixture():
    report = {
        "controller": {"run_send_ns": 10},
        "reaped_ns": 90,
        "parked": {"worker_tid": 102, "mono_ns": 20},
        "park_oracle": {"mono_ns": 24},
        "completed": {"ping_begin_ns": 25, "ping_end_ns": 35, "work_end_ns": 39},
        "prearm_cohort": [{"tid": 101}],
        "held_after_work": [{"tid": 101}, {"tid": 102}],
    }
    no_cpu = 0xFFFFFFFF
    events = [
        (1, 0, no_cpu, 0, 12), (2, 0, 0, 0, 13), (3, 0, no_cpu, 0, 14),
        (4, 1, no_cpu, 1, 21), (5, 0, 1, 0, 26), (6, 1, 1, 0, 27),
        (3, 1, no_cpu, 0, 28), (7, 1, no_cpu, 0, 60),
        (4, 1, no_cpu, 128, 61), (8, 1, no_cpu, 0, 95),
    ]
    rows = [ROW.pack(*event, 102, 1002, 1, 0) for event in events]
    return report, b"".join(rows) + bytes((SLOTS - len(rows)) * ROW.size)


class ClrFixtureTests(unittest.TestCase):
    def test_callback_binds_the_observed_generation(self):
        report, raw = fixture()
        validate_trace(report, raw, (10, 0, 0, 1, 1))
        self.assertEqual(report["callback_binding"]["global_tid"], 1002)
        self.assertEqual(report["callback_binding"]["resumed_slot"], 6)

    def test_reject_an_unbound_runtime_thread_in_the_held_snapshot(self):
        report, raw = fixture()
        report["held_after_work"].append({"tid": 103})
        with self.assertRaisesRegex(ValueError, "lacks pre-arm or birth identity"):
            validate_trace(report, raw, (10, 0, 0, 1, 1))

    def test_callback_completion_cannot_stand_in_for_exit(self):
        report, raw = fixture()
        report["completed"]["work_end_ns"] = 62
        with self.assertRaisesRegex(ValueError, "lifetime do not align"):
            validate_trace(report, raw, (10, 0, 0, 1, 1))


if __name__ == "__main__":
    unittest.main()
