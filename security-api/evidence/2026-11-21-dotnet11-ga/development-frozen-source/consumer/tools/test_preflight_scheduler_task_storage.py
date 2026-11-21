import ctypes
import errno
import struct
import unittest
from unittest.mock import call, patch

import preflight_scheduler_task_storage as probe


class TaskStoragePreflightTests(unittest.TestCase):
    def test_btf_declares_only_signed_i32_key_and_unsigned_u64_value(self):
        btf = probe.storage_btf_bytes()
        self.assertEqual(struct.unpack_from("<HBB5I", btf), (0xEB9F, 1, 0, 24, 0, 32, 32, 9))
        self.assertEqual(struct.unpack_from("<4I", btf, 24), (1, 0x01000000, 4, 0x01000020))
        self.assertEqual(struct.unpack_from("<4I", btf, 40), (5, 0x01000000, 8, 64))
        self.assertEqual(btf[56:], b"\0int\0u64\0")

    def test_map_create_has_no_preallocation_and_exact_btf_ids(self):
        attr = probe.map_create_attr(13)
        self.assertEqual(len(attr), 64)
        self.assertEqual(struct.unpack_from("<7I", attr), (29, 4, 8, 0, 1, 0, 0))
        self.assertEqual(struct.unpack_from("<5I", attr, 44), (0, 13, 1, 2, 0))

    def test_program_uses_typed_current_lookup_and_checks_null_before_read(self):
        instructions = list(struct.iter_unpack("<BBhi", probe.program_bytes(17)))
        self.assertEqual(instructions, [
            (0x85, 0, 0, 158),
            (0xBF, 2, 0, 0),
            (0x18, 17, 0, 17),
            (0, 0, 0, 0),
            (0xB7, 3, 0, 0),
            (0xB7, 4, 0, 0),
            (0x85, 0, 0, 156),
            (0x15, 0, 1, 0),
            (0x79, 1, 0, 0),
            (0xB7, 0, 0, 0),
            (0x95, 0, 0, 0),
        ])

    def test_only_three_load_commands_and_reverse_cleanup(self):
        seen = []

        def inspect_call(command, attr):
            seen.append(command)
            if command == 18:
                blob, log, size, log_size, level, trailing = struct.unpack("<QQIIII", attr)
                self.assertEqual(ctypes.string_at(blob, size), probe.storage_btf_bytes())
                self.assertEqual((log_size, level, trailing), (65536, 2, 0))
                ctypes.memmove(log, b"btf log\0", 8)
                return 11
            if command == 0:
                self.assertEqual(attr, probe.map_create_attr(11))
                return 12
            self.assertEqual(command, 5)
            prog_type, count, code, license_text, level, log_size, log = struct.unpack_from(
                "<IIQQIIQ", attr
            )
            self.assertEqual((prog_type, count, level, log_size), (17, 11, 2, 65536))
            self.assertEqual(ctypes.string_at(license_text), b"GPL")
            self.assertEqual(ctypes.string_at(code, count * 8), probe.program_bytes(12))
            ctypes.memmove(log, b"verifier log\0", 13)
            return 13

        with patch.object(probe, "bpf_call", side_effect=inspect_call), patch.object(probe.os, "close") as close:
            result = probe.run_probe()
        self.assertEqual(seen, [18, 0, 5])
        self.assertEqual(close.call_args_list, [call(13), call(12), call(11)])
        self.assertEqual(result["closed"], ["program", "map", "btf"])
        self.assertTrue(result["program_loaded"])
        self.assertFalse(result["capture_ready"])
        self.assertEqual(bytes.fromhex(result["btf_log_hex"]), b"btf log")
        self.assertEqual(bytes.fromhex(result["verifier_log_hex"]), b"verifier log")

    def test_failure_stops_later_calls_and_closes_earlier_fds(self):
        for stage, opened in (("btf_load", []), ("map_create", [11]), ("program_load", [11, 12])):
            with self.subTest(stage=stage), patch.object(
                probe, "bpf_call", side_effect=[*opened, OSError(errno.EINVAL, "fixture")]
            ) as bpf, patch.object(probe.os, "close") as close:
                result = probe.run_probe()
                self.assertEqual(bpf.call_count, len(opened) + 1)
                self.assertEqual(close.call_args_list, [call(fd) for fd in reversed(opened)])
                self.assertEqual(result["failed_stage"], stage)
                self.assertEqual(result["load_errno"], errno.EINVAL)
                self.assertFalse(result["program_loaded"])

    def test_close_error_is_retained_and_cleanup_continues(self):
        with patch.object(probe, "bpf_call", side_effect=[11, 12, 13]), patch.object(
            probe.os, "close", side_effect=[OSError(errno.EIO, "fixture"), None, None]
        ) as close:
            result = probe.run_probe()
        self.assertEqual(close.call_args_list, [call(13), call(12), call(11)])
        self.assertEqual(result["closed"], ["map", "btf"])
        self.assertEqual(result["close_errors"], [{"object": "program", "errno": errno.EIO}])


if __name__ == "__main__":
    unittest.main()
