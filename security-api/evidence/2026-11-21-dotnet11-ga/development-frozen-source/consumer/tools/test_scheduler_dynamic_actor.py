from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import scheduler_dynamic_actor as actor


class DynamicActorTests(unittest.TestCase):
    def test_exact_declared_commands(self):
        for command in actor.COMMANDS:
            with self.subTest(command=command):
                line = f'{{"command": "{command}"}}\n'.encode("ascii")
                self.assertEqual(actor.parse_command(line), command)

    def test_rejects_ambiguous_or_undeclared_commands(self):
        for line in (
            b'{"command":"start"}\n',
            b'{"command":"run","command":"run"}\n',
            b'{"command":"run","cpu":0}\n',
            b'{"command":true}\n',
            b'[["command","run"]]\n',
            b'{"command":"run"}',
            b'{"command":"run"}\n{"command":"wake"}\n',
            b' ' * actor.COMMAND_BYTES + b'\n',
        ):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    actor.parse_command(line)

    def test_control_deadline_and_eof(self):
        with patch.object(actor.time, "monotonic", return_value=8):
            with self.assertRaises(TimeoutError):
                actor.receive(7)
            with patch.object(actor.select, "select", return_value=([0], [], [])):
                with patch.object(actor.os, "read", return_value=b""):
                    with self.assertRaises(EOFError):
                        actor.receive(9)

    def test_ack_only_finish_has_no_worker(self):
        tasks = Mock()
        tasks.iterdir.return_value = [Path("101")]
        libc = Mock()
        libc.sched_getcpu.return_value = 3
        with (
            patch.object(actor, "prepare", return_value=libc),
            patch.object(actor, "TASKS", tasks),
            patch.object(actor.os, "getpid", return_value=101),
            patch.object(actor.os, "sched_getaffinity", create=True, side_effect=[{3, 4}, {3}]),
            patch.object(actor.os, "sched_setaffinity", create=True),
            patch.object(actor, "receive", return_value="finish"),
            patch.object(actor, "run_worker") as run_worker,
            patch.object(actor, "send") as send,
        ):
            actor.run(3, 4)
        run_worker.assert_not_called()
        self.assertEqual([call.args[0] for call in send.call_args_list], ["ready", "finished"])
        self.assertFalse(send.call_args.kwargs["worker_joined"])

    def test_cannot_launch_second_worker(self):
        tasks = Mock()
        tasks.iterdir.return_value = [Path("101")]
        libc = Mock()
        libc.sched_getcpu.return_value = 3
        with (
            patch.object(actor, "prepare", return_value=libc),
            patch.object(actor, "TASKS", tasks),
            patch.object(actor.os, "getpid", return_value=101),
            patch.object(actor.os, "sched_getaffinity", create=True, side_effect=[{3, 4}, {3}]),
            patch.object(actor.os, "sched_setaffinity", create=True),
            patch.object(actor, "receive", side_effect=["run", "run"]),
            patch.object(actor, "run_worker") as run_worker,
            patch.object(actor, "send"),
        ):
            with self.assertRaisesRegex(ValueError, "outside the actor lifecycle"):
                actor.run(3, 4)
        run_worker.assert_called_once()

    def test_nonmember_fork_reaps_owned_child(self):
        with (
            patch.object(actor.os, "fork", create=True, return_value=102),
            patch.object(actor.os, "getpid", return_value=101),
            patch.object(actor, "reap_child", return_value=0) as reap,
            patch.object(actor, "send") as send,
        ):
            actor.run_nonmember_fork(float("inf"))
        self.assertEqual(reap.call_args.args[0], 102)
        self.assertEqual(send.call_args.args, ("fork",))
        self.assertEqual(send.call_args.kwargs["child_local_pid"], 102)
        self.assertEqual(send.call_args.kwargs["parent_local_pid"], 101)
        self.assertEqual(send.call_args.kwargs["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
