import unittest

from scheduler_dynamic_multi_validation import (
    RECORD, SLOTS, U32_MAX, validate_multi_ledger,
)


def worker(tid, fd, run, park, oracle, wake, joined):
    return {
        "run_before_ns": run,
        "parked": {"worker_tid": tid, "worker_cpu": 1, "park_read_fd": fd, "mono_ns": park},
        "park_oracle": {"syscall": 0, "fd": fd, "count": 1, "state": "S", "worker_cpu": 1,
                        "mono_ns": oracle},
        "joined": {"worker_tid": tid, "main_cpu": 0, "worker_cpu": 1, "write_before_ns": wake - 1,
                   "write_after_ns": wake + 1, "worker_read_return_ns": wake + 3, "joined_ns": joined},
    }


def events(generation, parent, tid, global_tid, stamps):
    kinds = [(1, 0, U32_MAX, 0), (2, 0, 0, 0), (3, 0, U32_MAX, 0),
             (4, 1, U32_MAX, 1), (5, 0, 1, 0), (6, 1, 1, 0), (3, 1, U32_MAX, 0),
             (7, 1, U32_MAX, 0), (4, 1, U32_MAX, 128), (8, 1, U32_MAX, 0)]
    return [(*kind, stamp, tid, global_tid, generation, parent) for kind, stamp in zip(kinds, stamps)]


def fixture(*, reuse_c=False):
    c_tid, c_global = (101, 901) if reuse_c else (103, 903)
    report = {"workers": {
        "A": worker(101, 10, 10, 17, 19, 22, 28),
        "B": worker(102, 11, 10, 16, 20, 32, 38),
        "C": worker(c_tid, 12, 41, 44, 46, 48, 54),
    }}
    a = events(1, 0, 101, 901, (11, 12, 13, 18, 22, 23, 24, 26, 27, 30))
    b = events(2, 1, 102, 902, (14, 15, 16, 17, 32, 33, 34, 36, 37, 40))
    c = events(3, 0, c_tid, c_global, (42, 43, 44, 45, 48, 49, 50, 52, 53, 55))
    return report, sorted(a + b + c, key=lambda row: row[4])


def validate(report, rows, *, capacity=SLOTS, counts=None):
    if counts is None:
        counts = (len(rows), 0, 0, 3, 3)
    encoded = [RECORD.pack(*row) for row in rows]
    encoded += [bytes(RECORD.size)] * (SLOTS - len(encoded))
    validate_multi_ledger(report, encoded, counts, capacity, 0, 1)


class MultiLedgerTests(unittest.TestCase):
    def test_overlapping_nested_generations_keep_physical_slots(self):
        report, rows = fixture()
        validate(report, rows)
        chains = report["chain_slots"]
        self.assertLess(chains["B"]["birth"], chains["A"]["free"])
        self.assertLess(chains["A"]["free"], chains["B"]["waking"])
        self.assertEqual(chains["C"]["birth"], 20)
        self.assertEqual(report["decoded"][chains["B"]["birth"]]["parent_generation"], 1)

    def test_numeric_tids_can_be_reused_after_the_old_generation_frees(self):
        report, rows = fixture(reuse_c=True)
        validate(report, rows)
        old, new = (report["decoded"][report["chain_slots"][label]["birth"]] for label in ("A", "C"))
        self.assertEqual((old["local_tid"], old["global_tid"]), (new["local_tid"], new["global_tid"]))
        self.assertNotEqual(old["generation"], new["generation"])

    def test_rejects_same_global_tid_for_overlapping_workers(self):
        report, rows = fixture()
        rows = [(*row[:6], 901, *row[7:]) if row[7] == 2 else row for row in rows]
        with self.assertRaisesRegex(ValueError, "overlapping generations"):
            validate(report, rows)

    def test_rejects_stale_rows_even_after_numeric_tid_is_reused(self):
        report, rows = fixture(reuse_c=True)
        stale = (3, 1, U32_MAX, 0, 47, 101, 901, 1, 0)
        rows.insert(24, stale)
        with self.assertRaisesRegex(ValueError, "stale or has an unbound identity"):
            validate(report, rows)

    def test_rejects_wrong_parent(self):
        report, rows = fixture()
        slot = next(i for i, row in enumerate(rows) if row[0] == 1 and row[7] == 2)
        rows[slot] = (*rows[slot][:-1], 0)
        with self.assertRaisesRegex(ValueError, "unexpected parent for B"):
            validate(report, rows)

    def test_rejects_borrowing_another_generations_remote_wake(self):
        report, rows = fixture()
        rows = [row for row in rows if not (row[0] == 5 and row[7] == 2)]
        with self.assertRaisesRegex(ValueError, "cross-CPU waking"):
            validate(report, rows)

    def test_rejects_starting_c_before_free_even_if_birth_itself_follows_free(self):
        report, rows = fixture()
        report["workers"]["C"]["run_before_ns"] = 39
        with self.assertRaisesRegex(ValueError, "C launch did not follow B free"):
            validate(report, rows)

    def test_overflow_keeps_only_a_birth_but_requires_three_completions(self):
        report, rows = fixture()
        validate(report, rows[:1], capacity=1, counts=(30, 29, 0, 3, 3))
        self.assertEqual([row["kind"] for row in report["decoded"]], ["birth"])
        with self.assertRaisesRegex(ValueError, "terminal counters"):
            validate(report, rows[:1], capacity=1, counts=(30, 29, 0, 2, 3))
        with self.assertRaisesRegex(ValueError, "publication accounting"):
            validate(report, rows[:1], capacity=1, counts=(30, 28, 0, 3, 3))


if __name__ == "__main__":
    unittest.main()
