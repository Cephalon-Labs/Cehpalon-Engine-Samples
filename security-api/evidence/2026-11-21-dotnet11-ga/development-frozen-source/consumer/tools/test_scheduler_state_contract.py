import unittest

from scheduler_state_contract import LEGACY, WSL618, classify_switch_out, profile_details
from scheduler_trace_model import mask_intervals, state_intervals


class StateContractTests(unittest.TestCase):
    def test_exact_observed_combinations_require_explicit_profile(self):
        for state in (258, 8193):
            self.assertEqual(classify_switch_out(state), "unknown")
            self.assertEqual(classify_switch_out(state, WSL618), "off_cpu_sleep_state")

    def test_exhaustive_16_bit_and_preempt_contract(self):
        changed = []
        for state in range(1 << 16):
            expected = "runnable_observed" if state == 0 else (
                "off_cpu_sleep_state" if state in (1, 2) else "unknown")
            self.assertEqual(classify_switch_out(state, LEGACY), expected)
            new = classify_switch_out(state, WSL618)
            if new != expected:
                changed.append(state)
                self.assertEqual(new, "off_cpu_sleep_state")
            for profile in (LEGACY, WSL618):
                self.assertEqual(classify_switch_out(state | 0x80000000, profile), "runnable_observed")
        self.assertEqual(changed, [258, 8193])

    def test_no_unobserved_qualifier_or_high_bit_expansion(self):
        for state in (3, 256, 257, 259, 8192, 8194, 8195, 8449, 0x40000001, 0x7FFFFFFF):
            self.assertEqual(classify_switch_out(state, WSL618), "unknown")

    def test_invalid_profile_and_unsigned_state_are_rejected(self):
        for profile in ("auto", None, "wsl"):
            with self.assertRaises(ValueError):
                classify_switch_out(258, profile)
        for state in (-1, 1 << 32, True, "258", 258.0):
            with self.assertRaises(ValueError):
                classify_switch_out(state, WSL618)

    def test_initial_waking_ties_and_order_masks_stay_unknown(self):
        rows = [{"mono_ns": 10, "kind": "initial_enrollment", "raw_state": 0},
                {"mono_ns": 12, "kind": "out", "raw_state": 8193},
                {"mono_ns": 20, "kind": "waking", "raw_state": 0},
                {"mono_ns": 25, "kind": "wakeup", "raw_state": 0},
                {"mono_ns": 30, "kind": "out", "raw_state": 258},
                {"mono_ns": 30, "kind": "in", "raw_state": 0},
                {"mono_ns": 40, "kind": "exit", "raw_state": 0}]
        intervals = state_intervals(rows, 10, 40, state_profile=WSL618)
        self.assertEqual([row["state"] for row in intervals],
                         ["unknown", "off_cpu_sleep_state", "unknown", "runnable_observed", "unknown"])
        masked = mask_intervals(intervals, [{"begin_ns": 12, "end_ns": 20}])
        self.assertFalse(any(row["state"] == "off_cpu_sleep_state" for row in masked))

    def test_profile_provenance_does_not_promote_duration(self):
        self.assertEqual(profile_details(LEGACY)["added_raw_values"], [])
        proof = profile_details(WSL618)
        self.assertEqual(proof["added_raw_values"], [258, 8193])
        self.assertFalse(proof["certifies_physical_scheduler_duration"])


if __name__ == "__main__":
    unittest.main()
