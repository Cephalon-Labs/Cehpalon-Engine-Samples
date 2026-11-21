import struct
import sys
import unittest

if sys.platform.startswith("linux"):
    from collect_coreclr_gc_wait_fixture import decode_ring


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux perf ring ABI")
class PerfRingTests(unittest.TestCase):
    def ring(self, tail, record):
        page, size = 4096, 4096
        ring = bytearray(page + size)
        struct.pack_into("<QQQQ", ring, 1024, tail + len(record), tail, page, size)
        for i, byte in enumerate(record):
            ring[page + (tail + i) % size] = byte
        return ring

    def test_sample_on_both_sides_of_ring_wrap(self):
        sample = struct.pack("<IHHQIIQ", 9, 0, 32, 45, 7, 8, 100)
        for tail in (0, 4090):
            ring = self.ring(tail, sample)
            self.assertEqual(decode_ring(ring, 4096, "call", 7, 8, 45),
                             [{"site": "call", "pid": 7, "tid": 8, "monotonic_ns": 100}])
            self.assertEqual(struct.unpack_from("<Q", ring, 1032)[0], tail + 32)

    def test_reject_lost_record(self):
        lost = struct.pack("<IHHQQ", 2, 0, 24, 9, 1)
        with self.assertRaisesRegex(ValueError, "lost perf record"):
            decode_ring(self.ring(0, lost), 4096, "call", 7, 8, 45)

    def test_reject_foreign_thread_and_mismatched_site(self):
        for address, tid in ((46, 8), (45, 9)):
            sample = struct.pack("<IHHQIIQ", 9, 0, 32, address, 7, tid, 100)
            with self.assertRaisesRegex(ValueError, "owner or site mismatch"):
                decode_ring(self.ring(0, sample), 4096, "call", 7, 8, 45)

    def test_empty_ring_at_nonzero_tail(self):
        self.assertEqual(decode_ring(self.ring(6130, b""), 4096, "return", 7, 8, 45), [])


if __name__ == "__main__":
    unittest.main()
