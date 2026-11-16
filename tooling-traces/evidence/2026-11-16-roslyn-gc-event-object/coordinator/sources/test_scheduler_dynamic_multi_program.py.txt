import unittest

from scheduler_dynamic_multi_program import PROBES, multi_program
from test_scheduler_dynamic_program import instructions, reachable


def program(name, capacity=512):
    return multi_program(name, 3, 4, 5, 6, capacity, 4026532213)


def helper_rows(code, helper):
    return [i for i, (opcode, _, _, imm) in enumerate(instructions(code))
            if opcode == 0x85 and imm == helper]


class MultiProgramTests(unittest.TestCase):
    def test_all_program_instructions_have_a_control_path(self):
        for name in PROBES:
            for capacity in (1, 512):
                with self.subTest(name=name, capacity=capacity):
                    seen, count = reachable(program(name, capacity))
                    self.assertEqual(seen, set(range(count)))

    def test_membership_lookup_precedes_target_read(self):
        for name in PROBES.keys() - {"birth"}:
            with self.subTest(name=name):
                code = program(name)
                self.assertLess(helper_rows(code, 1)[0], helper_rows(code, 113)[0])

    def test_only_birth_inserts_and_only_free_deletes(self):
        self.assertEqual([name for name in PROBES if helper_rows(program(name), 2)], ["birth"])
        self.assertEqual([name for name in PROBES if helper_rows(program(name), 3)], ["free"])

    def test_both_switch_sides_use_different_raw_context_slots(self):
        self.assertEqual(PROBES["switch_in"][0], PROBES["switch_out"][0])
        load_in = (0x79, 0x67, 16, 0)
        load_out = (0x79, 0x67, 8, 0)
        self.assertIn(load_in, instructions(program("switch_in")))
        self.assertIn(load_out, instructions(program("switch_out")))
        self.assertNotIn(load_out, instructions(program("switch_in")))
        self.assertNotIn(load_in, instructions(program("switch_out")))


if __name__ == "__main__":
    unittest.main()
