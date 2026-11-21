import unittest

from scheduler_dynamic_multi_program import multi_program
from scheduler_roslyn_program import (
    COUNTS_BYTES, INITIAL_KIND, MEMBERS, PROBES, SLOTS, roslyn_program,
)
from test_scheduler_dynamic_program import instructions, reachable


def program(name, initial_limit=7):
    return roslyn_program(name, 3, 4, 5, 6, 4026532213, initial_limit)


class RoslynProgramTests(unittest.TestCase):
    def test_all_fixed_instructions_have_a_control_path(self):
        for name in PROBES:
            for initial_limit in (1, MEMBERS):
                with self.subTest(name=name, initial_limit=initial_limit):
                    seen, length = reachable(program(name, initial_limit))
                    self.assertEqual(seen, set(range(length)))

    def test_prearm_uses_typed_ownership_before_pointer_lookup_and_read(self):
        rows = instructions(program("prearm"))
        calls = [(i, immediate) for i, (opcode, _, _, immediate) in enumerate(rows) if opcode == 0x85]
        self.assertEqual([helper for _, helper in calls[:4]], [158, 156, 35, 1])
        probe = next(i for i, helper in calls if helper == 113)
        self.assertGreater(probe, calls[3][0])
        # A raw sys_enter hook supplies a context, but no syscall, argument,
        # register, or other context content is retained or read here.
        self.assertFalse(any(opcode in (0x61, 0x79) and registers >> 4 == 6
                             for opcode, registers, _, _ in rows))
        storage_call = calls[1][0]
        scalar_call = calls[2][0]
        guards = rows[storage_call + 1:scalar_call]
        self.assertTrue(any(opcode == 0x15 and registers == 0 and immediate == 0
                            for opcode, registers, _, immediate in guards))
        self.assertTrue(any(opcode == 0x55 and registers == 1
                            for opcode, registers, _, _ in guards))

    def test_initial_is_a_distinct_enrollment_record(self):
        initial = instructions(program("prearm"))
        born = instructions(program("birth"))
        self.assertEqual(PROBES["prearm"], ("sys_enter", INITIAL_KIND))
        self.assertEqual(INITIAL_KIND, 10)
        self.assertIn((0x62, 10, -20, 10), initial)
        self.assertIn((0x62, 10, -20, 1), born)
        self.assertNotIn((0x62, 10, -20, 1), initial)

    def test_initial_count_and_total_count_are_bounded_separately(self):
        initial = instructions(program("prearm", 7))
        initial_reservation = next(i for i, row in enumerate(initial)
                                   if row == (0xC3, 0x19, 20, 1))
        total_reservation = next(i for i, row in enumerate(initial)
                                 if row == (0xC3, 0x19, 16, 1))
        self.assertEqual(initial[initial_reservation + 1][0], 0x35)
        self.assertEqual(initial[initial_reservation + 1][3], 7)
        self.assertEqual(initial[total_reservation + 1][0], 0x35)
        self.assertEqual(initial[total_reservation + 1][3], MEMBERS)
        self.assertEqual(COUNTS_BYTES, 24)
        for name in PROBES.keys() - {"prearm"}:
            self.assertFalse(any(opcode == 0xC3 and offset == 20
                                 for opcode, _, offset, _ in instructions(program(name))))

    def test_publication_capacity_is_fixed_and_overflow_is_counted(self):
        self.assertEqual(SLOTS, 262144)
        for name in PROBES.keys() - {"exec"}:
            rows = instructions(program(name))
            self.assertTrue(any(opcode == 0x35 and immediate == SLOTS
                                for opcode, _, _, immediate in rows))
            self.assertIn((0xC3, 0x19, 4, 0), rows)

    def test_exec_guard_only_writes_a_fault(self):
        rows = instructions(program("exec"))
        self.assertEqual([offset for opcode, _, offset, _ in rows if opcode == 0xC3], [8])
        self.assertNotIn((0x62, 10, -20, 10), rows)

    def test_input_profile_rejects_unbounded_or_malformed_values(self):
        for value in (0, -1, 65, True, 1.5):
            with self.subTest(initial_limit=value):
                with self.assertRaises(ValueError):
                    program("prearm", value)
        for namespace in (-1, 1 << 32, True):
            with self.subTest(namespace=namespace):
                with self.assertRaises(ValueError):
                    roslyn_program("prearm", 3, 4, 5, 6, namespace, 7)
        with self.assertRaises(ValueError):
            program("unknown")

    def test_existing_multiworker_profiles_still_generate(self):
        for name in PROBES.keys() - {"prearm"}:
            for capacity in (1, 512):
                self.assertTrue(multi_program(name, 3, 4, 5, 6, capacity, 1))


if __name__ == "__main__":
    unittest.main()
