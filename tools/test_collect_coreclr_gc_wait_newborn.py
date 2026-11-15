from types import SimpleNamespace
import sys
import unittest

if sys.platform.startswith("linux"):
    from collect_coreclr_gc_wait_newborn import ordered_pairs, program


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux BPF ABI")
class NewbornCallsiteTests(unittest.TestCase):
    def test_ordered_pairs_require_both_sites_and_monotonic_order(self):
        call = (1, 50, 60, 1, 70, 0)
        ret = (2, 50, 60, 2, 71, 0)
        self.assertEqual(ordered_pairs([call, ret]), 1)
        for rows in ([], [call], [ret, call], [call, ret[:4] + (70, 0)]):
            with self.assertRaisesRegex(ValueError, "Unpaired"):
                ordered_pairs(rows)

    def test_program_checks_namespace_before_allocation(self):
        code = program(500, SimpleNamespace(st_dev=4, st_ino=123), 11, 12)
        # The PID namespace helper and target gate precede cookie and map access.
        self.assertLess(code.index(bytes.fromhex("8500000078000000")),
                        code.index(bytes.fromhex("85000000ae000000")))
        self.assertLess(code.index(bytes.fromhex("85000000ae000000")),
                        code.index(bytes.fromhex("8500000001000000")))


if __name__ == "__main__":
    unittest.main()
