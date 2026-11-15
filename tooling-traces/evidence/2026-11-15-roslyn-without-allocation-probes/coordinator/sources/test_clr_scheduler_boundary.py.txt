import unittest

from collect_clr_scheduler_boundary import classify
from collect_scheduler_clr_fixture import ROW as LIFE
from scheduler_boundary_analysis import ROW, SLOTS


def fixture(rows):
    raw = b"".join(ROW.pack(i, *row) for i, row in enumerate(rows, 1))
    return raw.ljust(ROW.size * SLOTS, b"\0")


class ClrBoundaryTests(unittest.TestCase):
    def test_interleaved_generations_preserve_newborn_migration_and_retired_tail(self):
        life = b"".join(LIFE.pack(kind, 0, 0, 0, 100, tid, tid, gen, 0)
                        for gen, tid in ((1, 48), (2, 49)) for kind in (1, 8))
        raw = fixture([(1, 2, 1, 0, 0, 0, 48, 10, 11),
                       (1, 1, 0, 0, 0, 0, 48, 12, 13),
                       (2, 2, 1, 1, 1, 0, 49, 14, 15),
                       (1, 2, 1, 1, 1, 0, 48, 16, 17),
                       (1, 1, 0, 1, 1, 1, 48, 19, 18)])
        out = classify(raw, (5, 0, 0, 0), life, {"generation": 1, "local_tid": 48})
        self.assertEqual(out["pairs"], [{"generation": 1, "entry": 2, "exit": 4,
                                         "preempt_mode": False, "is_switch": True, "cpu_changed": True}])
        self.assertEqual(out["backwards_body_ordinals"], [5])
        self.assertEqual(out["tails"][0]["ordinal"], 5)
        with self.assertRaisesRegex(ValueError, "ledger did not reconcile"):
            classify(raw, (5, 1, 0, 0), life, {"generation": 1, "local_tid": 48})
        with self.assertRaisesRegex(ValueError, "outside completed lifecycle identities"):
            classify(raw, (5, 0, 0, 0), life, {"generation": 1, "local_tid": 49})
