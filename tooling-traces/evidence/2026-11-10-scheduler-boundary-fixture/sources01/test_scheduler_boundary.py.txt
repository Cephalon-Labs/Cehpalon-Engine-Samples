import unittest

from scheduler_boundary_analysis import LEGACY_ROW, LEGACY_SLOTS, ROW, SLOTS, U32_MAX, analyze


LEADER = 100
WORKER = 101


def legacy():
    values = [(1, 0, U32_MAX, 0, 10), (2, 0, 1, 0, 11),
              (3, 1, U32_MAX, 0, 12), (4, 1, U32_MAX, 1, 13),
              (5, 0, 1, 0, 14), (6, 0, 1, 0, 15),
              (3, 1, U32_MAX, 0, 16), (7, 1, U32_MAX, 0, 17),
              (4, 1, U32_MAX, 128, 18), (8, 2, U32_MAX, 0, 19)]
    raw = b''.join(LEGACY_ROW.pack(*v, WORKER, 1001, 1, 0) for v in values)
    return raw + bytes((LEGACY_SLOTS-len(values))*LEGACY_ROW.size), (len(values), 0, 0, 1, 1)


def row(generation, kind, flag=0, cpu=0, retired=0, begin=100, end=101):
    return [generation, kind, flag, cpu, cpu, retired, LEADER if generation == 0 else WORKER, begin, end]


def fixture(rows=None):
    if rows is None:
        rows = [row(0, 2, 1), row(0, 1), row(1, 2, 1), row(0, 2, 0),
                row(1, 1, cpu=1), row(1, 2, 1, cpu=1), row(1, 1, retired=1), row(0, 1)]
    raw = b''.join(ROW.pack(i+1, *value) for i, value in enumerate(rows))
    return raw + bytes((SLOTS-len(rows))*ROW.size), (len(rows), 0, 0, 0)


def check(rows=None):
    raw, counts = fixture(rows)
    old, old_counts = legacy()
    return analyze(raw, counts, SLOTS, old, old_counts, LEADER)


class BoundaryAnalysisTests(unittest.TestCase):
    def test_complete_true_false_prefixes_and_terminal_open(self):
        result = check()
        self.assertEqual(result['coverage']['complete_switch_pairs'], 1)
        self.assertEqual(result['coverage']['complete_no_switch_pairs'], 1)
        self.assertEqual(result['coverage']['leader_left_censored_exits'], 1)
        self.assertEqual(result['coverage']['owned_newborn_exit_prefixes'], 1)
        self.assertEqual(result['coverage']['unreturned_retired_lifetime_entries'], 1)
        self.assertEqual(result['coverage']['leader_open_at_detach'], 1)
        self.assertEqual(result['accounted_rows'], 8)
        self.assertFalse(result['physical_scheduler_duration_certified'])

    def test_pairs_across_cpu_migration_not_by_cpu(self):
        result = check([row(0, 1, cpu=0), row(1, 2, 1, cpu=0),
                        row(0, 2, 1, cpu=1), row(1, 1, retired=1, cpu=1)])
        self.assertEqual(result['complete_pairs'][0]['generation'], 0)
        self.assertTrue(result['complete_pairs'][0]['entry_exit_cpu_changed'])

    def test_time_reversals_do_not_reorder_pairing(self):
        result = check([row(0, 1, begin=200, end=190), row(1, 2, 1),
                        row(0, 2, 1, begin=100, end=101), row(1, 1, retired=1)])
        self.assertEqual(result['complete_pairs'][0]['invocation_entry_ordinal'], 1)
        self.assertEqual(result['coverage']['recorded_body_backwards'], 1)
        self.assertEqual(result['coverage']['per_generation_adjacent_fast_reversals'], 1)

    def test_returned_retired_cleanup_invocation_is_allowed(self):
        result = check([row(0, 2, 1), row(1, 2, 1), row(1, 1, retired=1),
                        row(1, 2, 0, retired=1), row(1, 1, retired=1)])
        self.assertEqual(result['coverage']['complete_no_switch_pairs'], 1)
        self.assertEqual(result['complete_pairs'][0]['entry_retired'], 1)

    def test_unknown_initial_worker_false_exit_is_preserved(self):
        result = check([row(0, 2), row(1, 2, 0), row(1, 1, retired=1)])
        self.assertEqual(result['coverage']['unknown_worker_exit_prefixes'], 1)
        self.assertEqual(result['coverage']['owned_newborn_exit_prefixes'], 0)

    def test_noninitial_orphan_exit_rejected(self):
        with self.assertRaises(ValueError):
            check([row(0, 2), row(1, 2, 1), row(0, 2), row(1, 1, retired=1)])

    def test_nested_entries_rejected(self):
        with self.assertRaises(ValueError):
            check([row(0, 1), row(1, 2, 1), row(0, 1), row(1, 1, retired=1)])

    def test_closed_worker_live_tail_rejected(self):
        with self.assertRaises(ValueError):
            check([row(0, 2), row(1, 2, 1), row(1, 1)])

    def test_generation_local_identity_is_required(self):
        rows = [row(0, 2), row(1, 2, 1), row(1, 1, retired=1)]
        rows[1][6] = LEADER
        with self.assertRaises(ValueError):
            check(rows)

    def test_retirement_must_latch_per_worker(self):
        with self.assertRaises(ValueError):
            check([row(0, 2), row(1, 2, 1), row(1, 1, retired=1), row(1, 2, 1), row(1, 1, retired=1)])

    def test_bool_generation_kind_and_cpu_fields_are_bounded(self):
        for index, value in [(0, 2), (1, 3), (2, 2), (3, 32), (4, 32), (5, 2)]:
            rows = [row(0, 2), row(1, 2, 1), row(1, 1, retired=1)]
            rows[1][index] = value
            with self.assertRaises(ValueError):
                check(rows)

    def test_duplicate_or_missing_ordinals_and_padding_rejected(self):
        raw, counts = fixture(); old, old_counts = legacy()
        variants = [ROW.pack(2, *ROW.unpack_from(raw)[1:])+raw[ROW.size:], raw[:-1]+b'\1', raw[:-1]]
        for value in variants:
            with self.assertRaises(ValueError):
                analyze(value, counts, SLOTS, old, old_counts, LEADER)

    def test_negative_loss_is_reconciled_without_pairing(self):
        raw, _ = fixture([row(0, 2, 1)]); old, old_counts = legacy()
        result = analyze(raw, (20, 19, 0, 0), 1, old, old_counts, LEADER)
        self.assertFalse(result['classification_complete'])
        self.assertEqual(result['complete_pairs'], [])
        for counts in [(20, 18, 0, 0), (1, 0, 0, 0), (20, 19, 1, 0)]:
            with self.assertRaises(ValueError):
                analyze(raw, counts, 1, old, old_counts, LEADER)

    def test_legacy_lifetime_and_counts_must_be_complete(self):
        raw, counts = fixture(); old, old_counts = legacy()
        for bad_counts in [(10, 1, 0, 1, 1), (10, 0, 0, 0, 1), (10, 0, 0, 1, 2)]:
            with self.assertRaises(ValueError):
                analyze(raw, counts, SLOTS, old, bad_counts, LEADER)
        with self.assertRaises(ValueError):
            analyze(raw, counts, SLOTS, old[:-1]+b'\1', old_counts, LEADER)

    def test_no_cross_generation_invocation_pairing(self):
        with self.assertRaises(ValueError):
            check([row(0, 1), row(1, 2, 1), row(1, 2, 1), row(0, 2)])

    def test_counter_bool_and_leader_retirement_are_rejected(self):
        raw, counts = fixture(); old, old_counts = legacy()
        with self.assertRaises(ValueError):
            analyze(raw, (True, 0, 0, 0), SLOTS, old, old_counts, LEADER)
        with self.assertRaises(ValueError):
            check([row(0, 2, retired=1), row(1, 2, 1), row(1, 1, retired=1)])


if __name__ == '__main__':
    unittest.main()
