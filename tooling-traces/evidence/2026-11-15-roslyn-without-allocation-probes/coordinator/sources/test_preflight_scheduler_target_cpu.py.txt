"""Offline tests for the fixed target-CPU verifier input and result handling."""

import ctypes
import errno
import gzip
import hashlib
from pathlib import Path
import struct
import unittest
from unittest.mock import Mock, patch

import preflight_scheduler_target_cpu as tool


RETAINED_BTF = (Path(__file__).resolve().parents[1] / "tooling-traces" / "evidence"
                / "2026-11-05-dynamic-scheduler" / "readiness" / "vmlinux.btf.gz")


class ProbeTests(unittest.TestCase):
    def test_pinned_retained_layout(self):
        with gzip.open(RETAINED_BTF, "rb") as stream:
            layout = tool.describe_layout(stream.read(tool.BTF_LENGTH + 1))
        self.assertEqual(layout["type_ids"], {"task_struct": 184, "thread_info": 342})
        self.assertEqual(layout["task_struct_size"], 3328)
        self.assertEqual(layout["thread_info_member"], {
            "offset": 0, "size": 24, "kind": "struct", "target": "thread_info",
        })
        self.assertEqual(layout["cpu_member"], {
            "offset": 20, "size": 4, "kind": "integer", "signed": False,
        })
        self.assertEqual(layout["task_cpu_offset"], 20)

    def test_changed_btf_is_rejected(self):
        with gzip.open(RETAINED_BTF, "rb") as stream:
            data = stream.read(tool.BTF_LENGTH + 1)
        with self.assertRaisesRegex(tool.BtfError, "pinned"):
            tool.describe_layout(data[:-1] + bytes([data[-1] ^ 1]))

    def test_exact_instructions(self):
        self.assertEqual(list(struct.iter_unpack("<BBhi", tool.program_bytes())), [
            (0x79, 0x13, 0, 0),
            (0x07, 0x03, 0, 20),
            (0xBF, 0xA1, 0, 0),
            (0x07, 0x01, 0, -8),
            (0xB7, 0x02, 0, 4),
            (0x85, 0x00, 0, 113),
            (0xB7, 0x00, 0, 0),
            (0x95, 0x00, 0, 0),
        ])

    def test_fake_verifier_loads_once_and_closes(self):
        def fake_syscall(number, command, attr, size):
            self.assertEqual((number.value, command.value, size.value), (321, 5, 72))
            values = struct.unpack("<IIQQIIQII16sII", ctypes.string_at(attr, size.value))
            (prog_type, count, code, license_ptr, log_level, log_size, log_ptr,
             kernel_version, flags, name, ifindex, expected_attach_type) = values
            self.assertEqual((prog_type, count, log_level, log_size), (17, 8, 2, 65536))
            self.assertEqual((kernel_version, flags, ifindex, expected_attach_type), (0, 0, 0, 0))
            self.assertEqual(name.rstrip(b"\0"), b"ceph_target_cpu")
            self.assertEqual(ctypes.string_at(code, count * 8), tool.program_bytes())
            self.assertEqual(ctypes.string_at(license_ptr), b"GPL")
            ctypes.memmove(log_ptr, b"accepted", 8)
            return 14

        syscall = Mock(side_effect=fake_syscall)
        with patch.object(tool.ctypes, "CDLL", return_value=Mock(syscall=syscall)), \
                patch.object(tool.os, "close") as close:
            result = tool.load_once()
        syscall.assert_called_once()
        close.assert_called_once_with(14)
        self.assertTrue(result["load_accepted"])
        self.assertTrue(result["fd_closed"])
        self.assertFalse(result["capture_ready"])
        self.assertEqual(bytes.fromhex(result["verifier_log_hex"]), b"accepted")

    def test_fake_rejection_never_closes_an_invalid_fd(self):
        syscall = Mock(return_value=-1)
        with patch.object(tool.ctypes, "CDLL", return_value=Mock(syscall=syscall)), \
                patch.object(tool.ctypes, "get_errno", return_value=errno.EINVAL), \
                patch.object(tool.os, "close") as close:
            result = tool.load_once()
        syscall.assert_called_once()
        close.assert_not_called()
        self.assertEqual(result["load_errno"], errno.EINVAL)
        self.assertFalse(result["load_accepted"])
        self.assertFalse(result["fd_closed"])
        self.assertFalse(result["capture_ready"])

    def test_fake_close_error_is_retained(self):
        syscall = Mock(return_value=14)
        with patch.object(tool.ctypes, "CDLL", return_value=Mock(syscall=syscall)), \
                patch.object(tool.os, "close", side_effect=OSError(errno.EINTR, "interrupted")):
            result = tool.load_once()
        self.assertTrue(result["load_accepted"])
        self.assertFalse(result["fd_closed"])
        self.assertEqual(result["close_errno"], errno.EINTR)


if __name__ == "__main__":
    unittest.main()
