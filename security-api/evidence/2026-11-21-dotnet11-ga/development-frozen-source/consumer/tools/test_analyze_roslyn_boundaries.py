import unittest

from analyze_roslyn_boundaries import contained, pair_rows


def row(n, gen, kind, start, finish, *, retired=0, flag=1):
    return (n, gen, kind, flag, 0, 0, retired, gen + 100, start, finish)


def identity(gen, initial=False):
    return {"generation": gen, "local_tid": gen + 100, "initial_state_unknown": initial,
            "born_ns": 1, "exit_ns": 90}


class RoslynBoundaryTests(unittest.TestCase):
    def test_generation_pairing_strict_containment_and_censoring(self):
        rows = [row(1, 1, 2, 5, 6), row(2, 2, 2, 7, 8),
                row(3, 1, 1, 20, 22), row(4, 2, 1, 23, 24),
                row(5, 1, 2, 30, 31), row(6, 2, 2, 32, 33),
                row(7, 1, 1, 91, 92, retired=1)]
        pairs, prefixes, tails, usable, excluded, ambiguous = pair_rows(rows, [identity(1, True), identity(2)])
        self.assertEqual([p["class"] for p in prefixes], ["initial_or_unknown", "born_prefix"])
        self.assertEqual(tails, [{"generation": 1, "ordinal": 7}])
        self.assertEqual((len(pairs), excluded, ambiguous), (2, {}, []))
        self.assertEqual(contained([20], usable[1], (19, 32)), [3])
        self.assertEqual(contained([20], usable[1], (20, 32)), [])
        self.assertEqual(contained([20], usable[1], (19, 31)), [])

    def test_reversed_or_overlapping_clock_receipts_are_excluded(self):
        pairs, _, _, usable, excluded, ambiguous = pair_rows(
            [row(1, 1, 1, 20, 25), row(2, 1, 2, 24, 26)], [identity(1)])
        self.assertEqual(len(pairs), 1)
        self.assertEqual(ambiguous, [1, 2])
        self.assertEqual(usable, {})
        self.assertEqual(excluded["visible_clock_or_cpu_ambiguity"], 1)

    def test_rejects_live_tail_and_wrong_identity(self):
        with self.assertRaisesRegex(ValueError, "live tail"):
            pair_rows([row(1, 1, 1, 20, 21)], [identity(1)])
        with self.assertRaisesRegex(ValueError, "invalid boundary record"):
            pair_rows([row(1, 2, 2, 20, 21)], [identity(1)])
