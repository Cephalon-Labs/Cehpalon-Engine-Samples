import struct
import sys
import unittest

if sys.platform.startswith("linux"):
    from collect_coreclr_gc_event_object import decode, worker_chains


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux BPF ABI")
class GcObjectTests(unittest.TestCase):
    def test_equal_values_receive_the_same_local_token(self):
        raw = b"".join(struct.pack("<IIIIQQ", index, 77, 78, role, index, operand)
                       for index, (role, operand) in enumerate(((1, 0), (3, 65600), (4, 65600), (5, 69632)), 1))
        rows = decode(raw.ljust(512 * 32, b"\0"), 4, 77)
        self.assertEqual([row["object_token"] for row in rows], [None, 1, 1, 2])
        self.assertNotIn(65600, rows[1].values())

    def chain(self, setter_token, extra=()):
        reset, call, wait, setter, ret = (
            {"site": site, "ns": ns, "slot": i, "object_token": token, "tid": tid}
            for i, (site, ns, token, tid) in enumerate(
                (("reset", 1, 1, 4), ("call", 2, None, 5), ("wait", 3, 1, 5),
                 ("set", 5, setter_token, 4), ("return", 9, None, 5)), 1))
        points = [{"kind": kind, "mono_ns": ns, "slot": ns}
                  for kind, ns in (("out", 4), ("waking", 6), ("wakeup", 7), ("in", 8))]
        return worker_chains([call, wait, ret], [reset, call, wait, setter, ret, *extra], points)

    def test_same_object_set_by_another_thread_matches(self):
        pairs, exact = self.chain(1)
        self.assertEqual(pairs, 1)
        self.assertEqual(len(exact), 1)
        self.assertEqual(exact[0]["setter_tid"], 4)

    def test_mismatched_object_or_additional_change_prevents_exact_chain(self):
        self.assertEqual(self.chain(2), (1, []))
        self.assertEqual(self.chain(1, [{"site": "reset", "ns": 7, "tid": 4, "object_token": 1}]), (1, []))


if __name__ == "__main__":
    unittest.main()
