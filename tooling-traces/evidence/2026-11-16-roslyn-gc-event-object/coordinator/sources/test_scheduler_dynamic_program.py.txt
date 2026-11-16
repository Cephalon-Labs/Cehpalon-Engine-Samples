import struct
import unittest

from scheduler_dynamic_program import EVENTS, lifecycle_program, seed_program


def instructions(code):
    return list(struct.iter_unpack("<BBhi", code))


def reachable(code):
    rows = instructions(code)
    seen = set()
    pending = [0]
    while pending:
        index = pending.pop()
        if index in seen:
            continue
        opcode, _, offset, _ = rows[index]
        seen.add(index)
        if opcode == 0x18:
            seen.add(index + 1)
            pending.append(index + 2)
        elif opcode != 0x95:
            if opcode not in (0x05,):
                pending.append(index + 1)
            if opcode & 7 in (5, 6) and opcode != 0x85:
                pending.append(index + 1 + offset)
    return seen, len(rows)


class DynamicProgramTests(unittest.TestCase):
    def test_all_fixed_program_instructions_have_a_control_path(self):
        cases = [seed_program(3)]
        cases += [lifecycle_program(hook, 3, 4, 5, 6, capacity, 4026532213)
                  for hook in EVENTS for capacity in (1, 512)]
        for program in cases:
            with self.subTest(instructions=len(program) // 8):
                seen, length = reachable(program)
                self.assertEqual(seen, set(range(length)))

    def test_exec_guard_has_only_fault_counter_write(self):
        rows = instructions(lifecycle_program("sched_prepare_exec", 3, 4, 5, 6, 512, 1))
        self.assertEqual([offset for opcode, _, offset, _ in rows if opcode == 0xC3], [8])
        self.assertEqual({imm for opcode, reg, _, imm in rows
                          if opcode == 0x18 and reg >> 4 == 1}, {3, 4, 5})


if __name__ == "__main__":
    unittest.main()
