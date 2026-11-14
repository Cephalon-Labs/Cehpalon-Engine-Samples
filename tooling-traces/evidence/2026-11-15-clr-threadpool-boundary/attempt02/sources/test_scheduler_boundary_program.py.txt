import struct
import unittest

from collect_scheduler_boundary import boundary_attach
from scheduler_boundary_program import HOOKS, boundary_program


class BoundaryProgramTests(unittest.TestCase):
    def test_only_two_declared_hooks_and_raw_boolean_load(self):
        self.assertEqual(set(HOOKS.values()), {'sched_entry_tp', 'sched_exit_tp'})
        for name in HOOKS:
            rows = list(struct.iter_unpack('<BBhi', boundary_program(name, 11, 12, 13, 14, 1024, 101)))
            self.assertEqual(rows[0], (0xBF, 0x16, 0, 0))
            self.assertIn((0x79, 0x61, 0, 0), rows)
            self.assertNotIn((0x79, 0x76, 0, 0), rows)  # raw argument is not a task pointer

    def test_member_lookup_precedes_birth_read_and_two_clocks_surround_publication(self):
        rows = list(struct.iter_unpack('<BBhi', boundary_program('entry', 11, 12, 13, 14, 1024, 101)))
        calls = [(i, row[3]) for i,row in enumerate(rows) if row[0] == 0x85]
        def first(helper):
            return next(i for i,h in calls if h == helper)
        self.assertLess(first(158), first(156))
        self.assertLess(first(156), first(35))
        self.assertLess(first(35), first(1))
        self.assertLess(first(1), first(113))
        clocks = [i for i,h in calls if h == 5]
        self.assertEqual(len(clocks), 2)
        reserve = next(i for i,row in enumerate(rows) if row[0] == 0xC3 and row[2] == 0)
        self.assertLess(clocks[0], reserve)
        self.assertLess(reserve, clocks[1])

    def test_unscoped_hook_rejected_before_native_operation(self):
        with self.assertRaises(ValueError):
            boundary_attach(None, {}, 'sched_switch', 10)

    def test_unfrozen_capacity_kind_and_identity_rejected(self):
        for name,capacity,tid in [('other',1024,1), ('entry',512,1), ('entry',True,1),
                                  ('entry',1,True), ('entry',1,0)]:
            with self.assertRaises(ValueError):
                boundary_program(name, 11, 12, 13, 14, capacity, tid)


if __name__ == '__main__':
    unittest.main()
