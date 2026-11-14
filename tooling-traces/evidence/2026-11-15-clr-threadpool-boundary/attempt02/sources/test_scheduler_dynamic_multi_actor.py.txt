import ctypes
import unittest
from unittest.mock import Mock, patch

import scheduler_dynamic_multi_actor as actor


class MultiActorTests(unittest.TestCase):
    def test_multi_commands_do_not_change_historical_actor(self):
        import scheduler_dynamic_actor as original

        self.assertEqual(actor.core.parse_command(b'{"command":"wake_b"}\n'), "wake_b")
        with self.assertRaises(ValueError):
            original.parse_command(b'{"command":"wake_b"}\n')
        with self.assertRaises(ValueError):
            actor.core.parse_command(b'{"command":"wake"}\n')

    def test_a_creates_b_with_live_native_tid_before_parking(self):
        libc = Mock()
        nested = Mock()
        events = Mock()
        events.attach_mock(nested.start, "start")

        def read(number, fd, target, count):
            self.assertEqual((number.value, fd.value, count.value), (0, 5, 1))
            ctypes.memmove(target, b"W", 1)
            return 1

        libc.syscall.side_effect = read
        with (
            patch.object(actor.os, "pipe2", create=True, return_value=(5, 6)),
            patch.object(actor.os, "O_CLOEXEC", create=True, new=1),
            patch.object(actor.os, "sched_setaffinity", create=True),
            patch.object(actor.core, "require_cpu"),
            patch.object(actor.core, "native_tid", return_value=102),
            patch.object(actor.core, "send", events.send),
        ):
            worker = actor.Worker("A", libc, 4, nested)
            worker.creator_tid = 101
            worker.read()
        self.assertEqual([call[0] for call in events.mock_calls], ["start", "send"])
        nested.start.assert_called_once_with(102)
        self.assertEqual(events.send.call_args.args, ("park",))
        self.assertEqual(events.send.call_args.kwargs["creator_tid"], 101)
        self.assertEqual(events.send.call_args.kwargs["worker_tid"], 102)
        self.assertEqual(events.send.call_args.kwargs["park_read_fd"], 5)
        self.assertIsNotNone(worker.read_return_ns)

    def test_protocol_allows_only_a_b_then_c_lifecycle(self):
        created = {}
        tids = {"A": 102, "B": 103, "C": 104}

        def make(label, libc, cpu, nested=None):
            worker = Mock(tid=tids[label], nested=nested)
            created[label] = worker
            return worker

        for overlap_order in (("a", "b"), ("b", "a")):
            with self.subTest(overlap_order=overlap_order):
                commands = ["run", *("wake_" + label for label in overlap_order),
                            "run_c", "wake_c", "finish"]
                with (
                    patch.object(actor.core, "prepare"),
                    patch.object(actor.os, "getpid", return_value=101),
                    patch.object(actor.os, "sched_getaffinity", create=True, return_value={3, 4}),
                    patch.object(actor.os, "sched_setaffinity", create=True),
                    patch.object(actor.core, "require_cpu"),
                    patch.object(actor, "local_tids", return_value=[101]),
                    patch.object(actor, "Worker", side_effect=make),
                    patch.object(actor.core, "receive", side_effect=commands),
                    patch.object(actor.core, "send") as send,
                    patch.object(actor, "close_workers") as close,
                ):
                    actor.run(3, 4)
                first, second = (label.upper() for label in overlap_order)
                self.assertEqual(created[first].wake.call_args.args[2], [101, tids[second]])
                self.assertEqual(created[second].wake.call_args.args[2], [101])
                self.assertEqual(created["C"].wake.call_args.args[2], [101])
                created["A"].start.assert_called_once_with(101)
                created["B"].start.assert_not_called()
                created["C"].start.assert_called_once_with(101)
                self.assertIs(created["A"].nested, created["B"])
                self.assertEqual(send.call_args.kwargs["joined_labels"], ["A", "B", "C"])
                close.assert_called_once()

    def test_rejects_c_while_workers_are_still_live(self):
        with (
            patch.object(actor.core, "prepare"),
            patch.object(actor.os, "getpid", return_value=101),
            patch.object(actor.os, "sched_getaffinity", create=True, return_value={3, 4}),
            patch.object(actor.os, "sched_setaffinity", create=True),
            patch.object(actor.core, "require_cpu"),
            patch.object(actor, "local_tids", return_value=[101]),
            patch.object(actor, "Worker") as make,
            patch.object(actor.core, "receive", side_effect=["run", "run_c"]),
            patch.object(actor.core, "send"),
            patch.object(actor, "close_workers") as close,
        ):
            with self.assertRaisesRegex(ValueError, "outside the actor lifecycle"):
                actor.run(3, 4)
        self.assertEqual(make.call_count, 2)
        close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
