import ctypes
import errno
import struct
import unittest
from unittest.mock import Mock, patch

import preflight_scheduler_pidfd_seed as seed


class PidfdSeedTests(unittest.TestCase):
    def test_exact_element_abi_and_cookie(self):
        def syscall(command, attr):
            map_fd, key, value, flags = struct.unpack("<I4xQQQ", attr)
            self.assertEqual((map_fd, ctypes.c_int32.from_address(key).value), (11, 17))
            if command == seed.UPDATE:
                self.assertEqual((flags, ctypes.c_uint64.from_address(value).value),
                                 (seed.BPF_NOEXIST, seed.COOKIE))
            elif command == seed.LOOKUP:
                self.assertEqual(flags, 0)
                ctypes.c_uint64.from_address(value).value = seed.COOKIE
            else:
                self.assertEqual((flags, value), (0, 0))

        report = []
        with patch.object(seed, "bpf_call", side_effect=syscall):
            seed.check_element(report, "seed", seed.UPDATE, 11, 17, value=seed.COOKIE)
            seed.check_element(report, "read", seed.LOOKUP, 11, 17, expected=seed.COOKIE)
            seed.check_element(report, "delete", seed.DELETE, 11, 17)
        self.assertEqual([row["value"] for row in report], [None, seed.COOKIE, None])

    def test_errno_mismatch_keeps_failed_receipt(self):
        report = []
        with patch.object(seed, "bpf_call", side_effect=OSError(errno.EINVAL, "invalid")):
            with self.assertRaises(OSError):
                seed.check_element(report, "absent", seed.LOOKUP, 11, 17,
                                   expected_errno=errno.ENOENT)
        self.assertEqual(report, [{"stage": "absent", "errno": errno.EINVAL}])

    def test_close_error_still_reaps_actor(self):
        actor = Mock(returncode=2)
        actor.stdin.close.side_effect = BrokenPipeError(errno.EPIPE, "broken pipe")
        report = {"cleanup_errors": []}
        seed.finish_actor(actor, report)
        actor.wait.assert_called_once_with(timeout=1)
        actor.stdout.close.assert_called_once_with()
        self.assertEqual(report, {"cleanup_errors": [{"stream": "stdin", "errno": errno.EPIPE}],
                                  "actor_exit_code": 2})


if __name__ == "__main__":
    unittest.main()
