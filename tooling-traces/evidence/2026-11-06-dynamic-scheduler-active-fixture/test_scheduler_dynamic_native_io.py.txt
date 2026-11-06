import ctypes
import errno
import struct
import unittest
from unittest.mock import patch

import scheduler_dynamic_native_io as io


class NativeIoTests(unittest.TestCase):
    def test_fixed_arrays_have_reviewed_sizes_and_user_access_modes(self):
        with patch.object(io, "bpf_call", side_effect=(30, 31, 32)) as call:
            self.assertEqual(io.create_private_state(), 30)
            self.assertEqual(io.create_counts(), 31)
            self.assertEqual(io.create_records(), 32)
        expected = [
            (24, 1, 16, b"ceph_dyn_state"),
            (16, 1, 8, b"ceph_dyn_counts"),
            (32, 512, 8, b"ceph_dyn_rows"),
        ]
        for invocation, (size, capacity, flags, name) in zip(call.call_args_list, expected):
            command, attr = invocation.args
            self.assertEqual(command, 0)
            self.assertEqual(attr, struct.pack("<7I16s", 2, 4, size, capacity, flags, 0, 0, name))

    def test_counts_and_record_syscalls_copy_only_published_maps(self):
        counts = struct.pack("<IIII", 21, 3, 2, 1)
        row = bytes(range(32))
        fixtures = {31: (0, counts), 32: (511, row)}

        def lookup(command, attr):
            self.assertEqual(command, 1)
            fd, key, value, flags = struct.unpack("<I4xQQQ", attr)
            index, data = fixtures[fd]
            self.assertEqual(ctypes.string_at(key, 4), struct.pack("<I", index))
            self.assertEqual(flags, 0)
            ctypes.memmove(value, data, len(data))

        with patch.object(io, "bpf_call", side_effect=lookup):
            self.assertEqual(io.read_counts(31), (21, 3, 2, 1))
            self.assertEqual(io.read_record(32, 511), row)

    def test_record_read_rejects_invalid_index_before_syscall(self):
        with patch.object(io, "bpf_call") as call:
            for index in (-1, 512, True, 1.5):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    io.read_record(32, index)
        call.assert_not_called()

    def test_syscall_errors_are_not_replaced_with_zero_counts(self):
        with patch.object(io, "bpf_call", side_effect=OSError(errno.EPERM, "denied")):
            with self.assertRaises(OSError) as failure:
                io.read_counts(31)
        self.assertEqual(failure.exception.errno, errno.EPERM)

    def test_raw_attach_uses_exact_hook_set_and_zero_cookie(self):
        expected = {
            "sys_enter", "task_newtask", "sched_wakeup_new", "sched_switch", "sched_waking",
            "sched_wakeup", "sched_process_exit", "sched_process_free", "sched_prepare_exec",
        }
        self.assertEqual(io.RAW_HOOKS, expected)
        seen = set()

        def open_link(command, attr):
            self.assertEqual(command, 17)
            self.assertEqual(attr[12:16], b"\0" * 4)
            pointer, prog_fd, cookie = struct.unpack("<QI4xQ", attr)
            self.assertEqual((prog_fd, cookie), (41, 0))
            seen.add(ctypes.string_at(pointer).decode("ascii"))
            return 42

        with patch.object(io, "bpf_call", side_effect=open_link) as call:
            for hook in sorted(expected):
                self.assertEqual(io.attach_raw_tracepoint(hook, 41), 42)
            for hook in ("sched:sched_switch", "sched_waking\0", "sys_exit", None, []):
                with self.subTest(hook=hook), self.assertRaises(ValueError):
                    io.attach_raw_tracepoint(hook, 41)
            self.assertEqual(call.call_count, len(expected))
        self.assertEqual(seen, expected)

    def test_link_receipt_matches_exact_name_and_cookie(self):
        prefix = "pos:\t0\nflags:\t02000002\n"
        fields = "tp_name:\tsched_waking\ncookie:\t0\n"
        self.assertEqual(io.validate_link_fdinfo(prefix + fields, "sched_waking"),
                         {"tp_name": "sched_waking", "cookie": 0})
        for altered in (prefix, fields + "cookie:\t0\n", fields.replace("0", "1"),
                        fields.replace("sched_waking", "sched_wakeup")):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                io.validate_link_fdinfo(altered, "sched_waking")

    def test_read_recursion_misses_uses_program_info_not_runtime_counter(self):
        def info_by_fd(command, attr):
            self.assertEqual(command, 15)
            fd, info_len, pointer = struct.unpack("<IIQ", attr)
            self.assertEqual((fd, info_len), (41, 216))
            self.assertEqual(ctypes.string_at(pointer, 208), b"\0" * 208)
            ctypes.memmove(pointer, struct.pack("<II", 17, 28), 8)
            ctypes.memmove(pointer + 192, struct.pack("<QQQ", 0, 99, 7), 24)

        with patch.object(io, "bpf_call", side_effect=info_by_fd):
            self.assertEqual(io.recursion_misses(41), 7)

    def test_missing_or_wrong_object_info_fails_closed(self):
        for obj_type, obj_id, write_misses in ((17, 1, False), (2, 1, True), (17, 0, True)):
            def info_by_fd(command, attr):
                _, _, pointer = struct.unpack("<IIQ", attr)
                ctypes.memmove(pointer, struct.pack("<II", obj_type, obj_id), 8)
                if write_misses:
                    ctypes.memmove(pointer + 208, b"\0" * 8, 8)

            with patch.object(io, "bpf_call", side_effect=info_by_fd), self.assertRaises(ValueError):
                io.recursion_misses(41)


if __name__ == "__main__":
    unittest.main()
