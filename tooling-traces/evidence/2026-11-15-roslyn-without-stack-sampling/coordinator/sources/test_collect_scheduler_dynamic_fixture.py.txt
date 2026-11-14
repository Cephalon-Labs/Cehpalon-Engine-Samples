import struct
import unittest

from collect_scheduler_dynamic_fixture import U32_MAX, validate_ledger


def fixture():
    report = {"run_before_ns": 10, "parked": {"worker_tid": 101}, "park_oracle": {"mono_ns": 15},
              "joined": {"joined_ns": 30, "write_before_ns": 16, "write_after_ns": 20,
                         "worker_read_return_ns": 21}}
    events = [(1, 0, U32_MAX, 0), (2, 0, 0, 0), (3, 0, U32_MAX, 0),
              (4, 1, U32_MAX, 1), (5, 0, 1, 0), (6, 1, 1, 0),
              (3, 1, U32_MAX, 0), (7, 1, U32_MAX, 0), (4, 1, U32_MAX, 128),
              (8, 1, U32_MAX, 0)]
    stamps = [11, 12, 13, 14, 16, 17, 18, 25, 26, 31]
    return report, [struct.pack("<IIIIQII", *event, stamp, 101, 901)
                    for event, stamp in zip(events, stamps)]


class LedgerTests(unittest.TestCase):
    def test_remote_wakeup_may_emit_on_target_cpu(self):
        report, rows = fixture()
        validate_ledger(report, rows + [bytes(32)], (10, 0, 0, 1), 512, 0, 1)
        self.assertEqual(report["chain_slots"]["waking"], 4)
        self.assertEqual(report["chain_slots"]["free"], 9)

    def test_fixed_loss_reconciliation(self):
        report, rows = fixture()
        validate_ledger(report, [rows[0], bytes(32)], (10, 9, 0, 1), 1, 0, 1)
        with self.assertRaisesRegex(ValueError, "accounting"):
            validate_ledger(report, [rows[0], bytes(32)], (10, 8, 0, 1), 1, 0, 1)

    def test_reject_extra_waking_before_resume(self):
        report, rows = fixture()
        extra = struct.pack("<IIIIQII", 5, 1, 1, 0, 17, 101, 901)
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            validate_ledger(report, [*rows[:6], extra, *rows[6:]], (11, 0, 0, 1), 512, 0, 1)

    def test_reject_preempted_park(self):
        report, rows = fixture()
        rows[3] = struct.pack("<IIIIQII", 4, 1, U32_MAX, 0x80000001, 14, 101, 901)
        with self.assertRaisesRegex(ValueError, "interruptible switch-out"):
            validate_ledger(report, rows, (10, 0, 0, 1), 512, 0, 1)


if __name__ == "__main__":
    unittest.main()
