"""Three fixed worker lifetimes, with one nested birth and two overlapping parks."""

import argparse
from contextlib import ExitStack
import ctypes
import importlib.util
import os
from pathlib import Path
import signal
import sys
import threading
import time


# The controller launches with -I, which omits the script directory from sys.path.
# Load one fixed sibling privately so the historical actor keeps its own commands.
core_spec = importlib.util.spec_from_file_location(
    "_scheduler_dynamic_actor_core", Path(__file__).with_name("scheduler_dynamic_actor.py"),
)
core = importlib.util.module_from_spec(core_spec)
core_spec.loader.exec_module(core)
core.COMMANDS = {"marker", "fork", "run", "wake_a", "wake_b", "run_c", "wake_c", "finish"}


class Worker:
    def __init__(self, label, libc, cpu, nested=None):
        self.label = label
        self.libc = libc
        self.cpu = cpu
        self.nested = nested
        self.creator_tid = None
        self.tid = None
        self.read_return_ns = None
        self.error = None
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.read_fd, self.write_fd = os.pipe2(os.O_CLOEXEC)

    def start(self, creator_tid):
        self.creator_tid = creator_tid
        self.thread.start()

    def read(self):
        try:
            os.sched_setaffinity(0, {self.cpu})
            core.require_cpu(self.libc, self.cpu)
            self.tid = core.native_tid(self.libc)
            if self.nested is not None:
                self.nested.start(self.tid)
            byte = ctypes.create_string_buffer(1)
            core.send("park", label=self.label, creator_tid=self.creator_tid, worker_tid=self.tid,
                      worker_cpu=self.cpu, park_read_fd=self.read_fd, mono_ns=time.monotonic_ns())
            count = self.libc.syscall(ctypes.c_long(core.SYS_READ), ctypes.c_int(self.read_fd),
                                      ctypes.byref(byte), ctypes.c_size_t(1))
            returned_ns = time.monotonic_ns()
            if count != 1 or byte.raw != b"W":
                raise RuntimeError("worker did not read the one wake byte")
            core.require_cpu(self.libc, self.cpu)
            self.read_return_ns = returned_ns
        except Exception as error:
            self.error = str(error)
            core.send("worker_error", label=self.label, message=self.error)

    def wake(self, main_cpu, deadline, remaining_tids):
        if self.tid is None or self.error is not None:
            raise RuntimeError("worker is not ready to wake")
        core.require_cpu(self.libc, main_cpu)
        before = time.monotonic_ns()
        written = os.write(self.write_fd, b"W")
        after = time.monotonic_ns()
        if written != 1:
            raise RuntimeError("actor wake byte was not written")
        self.thread.join(max(0, min(deadline - time.monotonic(), core.JOIN_SECONDS)))
        if self.thread.is_alive() or self.error is not None or self.read_return_ns is None:
            raise RuntimeError("actor worker did not join successfully")
        joined = time.monotonic_ns()
        retire_deadline = min(deadline, time.monotonic() + core.JOIN_SECONDS)
        while (core.TASKS / str(self.tid)).exists():
            if time.monotonic() >= retire_deadline:
                raise TimeoutError("joined worker still appears in proc task directory")
            time.sleep(0.001)
        remaining = local_tids()
        if remaining != sorted(remaining_tids):
            raise RuntimeError("unexpected task population after worker join")
        self.close_writer()
        self.close_reader()
        core.send("joined", label=self.label, worker_tid=self.tid, worker_cpu=self.cpu,
                  main_cpu=main_cpu, write_before_ns=before, write_after_ns=after,
                  worker_read_return_ns=self.read_return_ns, joined_ns=joined,
                  remaining_local_tids=remaining)

    def close_writer(self):
        if self.write_fd is not None:
            fd, self.write_fd = self.write_fd, None
            os.close(fd)

    def close_reader(self):
        if self.read_fd is not None:
            fd, self.read_fd = self.read_fd, None
            os.close(fd)


def local_tids():
    return sorted(int(task.name) for task in core.TASKS.iterdir())


def close_workers(workers):
    with ExitStack() as readers:
        for worker in workers:
            readers.callback(worker.close_reader)
        # Closing every writer releases each private read on EOF on failure.
        with ExitStack() as writers:
            for worker in workers:
                writers.callback(worker.close_writer)
        deadline = time.monotonic() + core.JOIN_SECONDS
        for worker in workers:
            if worker.thread.is_alive():
                worker.thread.join(max(0, deadline - time.monotonic()))


def marker(libc, cpu, pid):
    core.require_cpu(libc, cpu)
    before = time.monotonic_ns()
    tid = core.native_tid(libc)
    after = time.monotonic_ns()
    if tid != pid:
        raise RuntimeError("marker caller is not the actor leader")
    core.send("marker", local_tid=tid, cpu=cpu, mono_before_ns=before, mono_after_ns=after)


def run(main_cpu, worker_cpu):
    libc = core.prepare()
    pid = os.getpid()
    allowed = sorted(os.sched_getaffinity(0))
    if main_cpu == worker_cpu or main_cpu not in allowed or worker_cpu not in allowed:
        raise ValueError("two distinct allowed CPUs are required")
    if local_tids() != [pid]:
        raise RuntimeError("actor must be single-threaded before release")
    os.sched_setaffinity(0, {main_cpu})
    core.require_cpu(libc, main_cpu)
    deadline = time.monotonic() + core.ACTOR_SECONDS
    core.send("ready", pid=pid, main_tid=pid, main_cpu=main_cpu, worker_cpu=worker_cpu,
              allowed_cpus=allowed, mono_ns=time.monotonic_ns())
    workers = {}
    joined = set()
    fork_done = False
    try:
        for _ in range(10):
            active = workers.keys() - joined
            timeout = core.PARK_SECONDS if active else core.READY_SECONDS
            command = core.receive(min(deadline, time.monotonic() + timeout))
            if command == "marker" and not workers:
                marker(libc, main_cpu, pid)
            elif command == "fork" and not fork_done and not workers:
                core.run_nonmember_fork(deadline)
                fork_done = True
            elif command == "run" and not workers:
                workers["B"] = Worker("B", libc, worker_cpu)
                workers["A"] = Worker("A", libc, worker_cpu, nested=workers["B"])
                workers["A"].start(pid)
            elif command == "run_c" and workers.keys() == joined == {"A", "B"}:
                workers["C"] = Worker("C", libc, worker_cpu)
                workers["C"].start(pid)
            elif command in {"wake_a", "wake_b", "wake_c"} and command[-1].upper() in active:
                label = command[-1].upper()
                if any(workers[name].tid is None for name in active):
                    raise RuntimeError("active workers have not all reached their park receipts")
                remaining = [pid, *(workers[name].tid for name in active - {label})]
                workers[label].wake(main_cpu, deadline, remaining)
                joined.add(label)
            elif command == "finish" and (not workers or joined == {"A", "B", "C"}):
                core.send("finished", pid=pid, worker_joined=bool(joined),
                          joined_labels=sorted(joined), mono_ns=time.monotonic_ns())
                return
            else:
                raise ValueError("command is outside the actor lifecycle")
        raise ValueError("actor command limit reached")
    finally:
        close_workers(list(reversed(workers.values())))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("main_cpu", type=int)
    parser.add_argument("worker_cpu", type=int)
    options = parser.parse_args()
    try:
        if sys.platform == "linux":
            signal.alarm(core.ACTOR_SECONDS + core.JOIN_SECONDS)
        run(options.main_cpu, options.worker_cpu)
    except Exception as error:
        try:
            core.send("actor_error", message=str(error))
        except OSError:
            pass
        os._exit(1)
    os._exit(0)
