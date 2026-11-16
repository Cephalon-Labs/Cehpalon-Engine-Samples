from types import SimpleNamespace
import unittest

from analyze_roslyn_gc_callsites import pair_endpoints, worker_links


class CallsiteJoinTests(unittest.TestCase):
    def test_reused_tid_never_bridges_generations(self):
        lives = [{"local_tid": 5, "generation": 1, "born_ns": 1, "exit_ns": 10},
                 {"local_tid": 5, "generation": 2, "born_ns": 12, "exit_ns": 20}]
        rows = [(1, 4, 5, 1, 4, 0), (2, 4, 5, 2, 15, 0), (3, 4, 5, 1, 16, 0), (4, 4, 5, 2, 17, 0)]
        pairs, excluded = pair_endpoints(rows, lives)
        self.assertEqual(excluded, {1: "open_call_tail", 2: "return_without_observed_call"})
        self.assertEqual([row["call_ordinal"] for row in pairs[2]], [3])

    def test_nested_and_unbound_receipts_are_preserved(self):
        ages = [{"local_tid": 5, "generation": 1, "born_ns": 1, "exit_ns": 20}]
        rows = [(i, 4, tid, site, i + 1, 0)
                for i, (tid, site) in enumerate(((5, 1), (5, 1), (5, 2), (5, 2), (6, 2)), 1)]
        pairs, excluded = pair_endpoints(rows, ages)
        self.assertFalse(pairs)
        self.assertEqual([excluded[x] for x in range(1, 5)], ["ambiguous_nested_endpoints"] * 4)
        self.assertEqual(excluded[5], "outside_observed_lifetime")

    def test_nonincreasing_clocks_leave_generation_unpaired(self):
        ages = [{"local_tid": 5, "generation": 1, "born_ns": 1, "exit_ns": 20}]
        pairs, excluded = pair_endpoints([(1, 4, 5, 1, 9, 0), (2, 4, 5, 2, 8, 0)], ages)
        self.assertFalse(pairs)
        self.assertEqual(set(excluded.values()), {"nonincreasing_generation_clock"})

    def test_nested_switch_needs_strict_endpoints_and_gc_inner_order(self):
        site = {"call_ns": 1, "return_ns": 16}
        receipt = {"generation": 5, "switch": True, "entry_ordinal": 3, "entry_bracket_ns": [2, 3],
                   "return_bracket_ns": [12, 15], "intervening_lifecycle_rows": []}
        episode = SimpleNamespace(inner=(4, 8), generation=9)
        gc = {3: [{"gc_inner_between_receipts": True, "gc_episode": 1}]}
        nested, strong = worker_links(site, [receipt], gc, {1: episode}, 5)
        self.assertEqual(nested, [3])
        self.assertEqual(len(strong), 1)
        self.assertEqual(worker_links({**site, "return_ns": 15}, [receipt], gc, {1: episode}, 5), ([], []))
        self.assertEqual(worker_links(site, [receipt], {3: [{"gc_inner_between_receipts": False}]}, {}, 5), ([3], []))


if __name__ == "__main__":
    unittest.main()
