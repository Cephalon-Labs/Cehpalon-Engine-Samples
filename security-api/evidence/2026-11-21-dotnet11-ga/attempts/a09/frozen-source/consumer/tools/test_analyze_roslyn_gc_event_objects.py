from types import SimpleNamespace
import unittest

from analyze_roslyn_gc_event_objects import emitter_proof, object_context, ordered_switch, transitions


class EventObjectJoinTests(unittest.TestCase):
    def setUp(self):
        self.reset = {"site": "reset", "slot": 1, "ns": 11, "tid": 11, "object_token": 1}
        self.wait = {"site": "wait", "slot": 3, "ns": 16, "tid": 12, "object_token": 1}
        self.setter = {"site": "set", "slot": 4, "ns": 22, "tid": 11, "object_token": 1}
        self.call, self.ret = {"ns": 12, "slot": 2}, {"ns": 30, "slot": 5}

    def test_single_same_object_set_required(self):
        group = transitions([self.reset, self.setter])
        self.assertEqual(object_context(self.call, self.ret, [self.wait], group),
                         ((self.reset, self.wait, self.setter), None))
        self.assertEqual(object_context(self.call, self.ret, [self.wait], transitions(
            [self.reset, {**self.setter, "object_token": 2}]))[1], "missing_or_ambiguous_reset_set")
        self.assertEqual(object_context(self.call, self.ret, [self.wait], transitions(
            [self.reset, self.setter, {**self.setter, "ns": 25}]))[1], "missing_or_ambiguous_reset_set")

    def test_gc_emitter_and_phase_edges_are_separate_checks(self):
        episode = SimpleNamespace(generation=4, phase_brackets=((7, 8), (14, 15), (18, 19), (25, 26)))
        lives = {4: {"local_tid": 11, "born_ns": 3, "exit_ns": 40}}
        self.assertTrue(all(emitter_proof((self.reset, self.wait, self.setter), episode, lives).values()))
        shifted = {**self.setter, "ns": 19}
        self.assertFalse(emitter_proof((self.reset, self.wait, shifted), episode, lives)["set_in_restart"])
        lives[4]["local_tid"] = 55
        self.assertFalse(emitter_proof((self.reset, self.wait, self.setter), episode, lives)["same_gc_emitter"])

    def test_switch_requires_set_before_waking_and_clear_mask(self):
        row = {"generation": 3, "entry_bracket_ns": [15, 16], "return_bracket_ns": [29, 30],
               "intervening_lifecycle_rows": [
                   {"local_tid": 12, "generation": 3, "kind": kind, "mono_ns": stamp, "slot": index}
                   for index, (kind, stamp) in enumerate((("out", 18), ("waking", 23), ("wakeup", 24), ("in", 26)))]}
        context = self.reset, self.wait, self.setter
        self.assertTrue(ordered_switch(context, row, []))
        self.assertFalse(ordered_switch(context, row, [{"begin_ns": 15, "end_ns": 16}]))
        self.assertFalse(ordered_switch((self.reset, self.wait, {**self.setter, "ns": 23}), row, []))


if __name__ == "__main__":
    unittest.main()
