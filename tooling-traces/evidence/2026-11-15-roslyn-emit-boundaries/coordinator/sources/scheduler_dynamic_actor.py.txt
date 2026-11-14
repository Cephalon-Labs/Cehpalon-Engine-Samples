"""One ordinary WSL actor and one dynamically created, remotely woken worker."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import sys
import threading
import time


COMMANDS = {"marker", "fork", "run", "wake", "finish"}
COMMAND_BYTES = 128
READY_SECONDS = 10
PARK_SECONDS = 5
JOIN_SECONDS = 2
ACTOR_SECONDS = 30
SYS_READ = 0
SYS_GETTID = 186
TASKS = Path("/proc/self/task")


def parse_command(line):
    if len(line) > COMMAND_BYTES or line.count(b"\n") != 1 or not line.endswith(b"\n"):
        raise ValueError("one bounded command line is required")
    pairs = json.loads(line.decode("ascii"), object_pairs_hook=list)
    if (type(pairs) is not list or len(pairs) != 1 or type(pairs[0]) is not tuple
            or pairs[0][0] != "command" or type(pairs[0][1]) is not str
            or pairs[0][1] not in COMMANDS):
        raise ValueError("one declared command is required")
    return pairs[0][1]


def receive(deadline):
    frame = bytearray()
    while b"\n" not in frame:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
            raise TimeoutError("actor control deadline expired")
        data = os.read(0, COMMAND_BYTES + 1 - len(frame))
        if not data:
            raise EOFError("actor control pipe closed")
        frame.extend(data)
        if len(frame) > COMMAND_BYTES:
            raise ValueError("actor command exceeds byte limit")
    return parse_command(frame)


def send(kind, **fields):
    frame = json.dumps({"kind": kind, **fields}, separators=(",", ":")).encode("ascii") + b"\n"
    if len(frame) > 4096 or os.write(1, frame) != len(frame):
        raise RuntimeError("actor receipt was not written atomically")


def prepare():
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RuntimeError("actor requires Linux x86-64")
    if os.getresuid() != (1000,) * 3 or os.getresgid() != (1000,) * 3 or os.getgroups():
        raise RuntimeError("actor must start with ordinary UID/GID 1000 and no extra groups")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.sched_getcpu.argtypes = []
    libc.sched_getcpu.restype = ctypes.c_int
    return libc


def native_tid(libc):
    tid = libc.syscall(ctypes.c_long(SYS_GETTID))
    if tid <= 0:
        raise OSError(ctypes.get_errno(), "actor gettid failed")
    return tid


def require_cpu(libc, cpu):
    if os.sched_getaffinity(0) != {cpu} or libc.sched_getcpu() != cpu:
        raise RuntimeError("actor affinity and current CPU do not match")


def reap_child(child, deadline):
    while time.monotonic() < deadline:
        pid, status = os.waitpid(child, os.WNOHANG)
        if pid == child:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.001)
    return None


def run_nonmember_fork(deadline):
    before = time.monotonic_ns()
    child = os.fork()
    if child == 0:
        os._exit(0)
    exit_code = reap_child(child, min(deadline, time.monotonic() + JOIN_SECONDS))
    if exit_code is None:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if reap_child(child, time.monotonic() + JOIN_SECONDS) is None:
            raise TimeoutError("owned process child did not reap after cleanup")
        raise TimeoutError("owned process child did not reap on time")
    if exit_code != 0:
        raise RuntimeError("owned process child did not exit successfully")
    send("fork", child_local_pid=child, parent_local_pid=os.getpid(), exit_code=exit_code,
         mono_before_ns=before, mono_after_ns=time.monotonic_ns())


def worker_read(libc, cpu, read_fd, result):
    try:
        os.sched_setaffinity(0, {cpu})
        require_cpu(libc, cpu)
        tid = native_tid(libc)
        byte = ctypes.create_string_buffer(1)
        send("park", worker_tid=tid, worker_cpu=cpu, park_read_fd=read_fd,
             mono_ns=time.monotonic_ns())
        count = libc.syscall(ctypes.c_long(SYS_READ), ctypes.c_int(read_fd),
                             ctypes.byref(byte), ctypes.c_size_t(1))
        returned_ns = time.monotonic_ns()
        if count != 1 or byte.raw != b"W":
            raise RuntimeError("actor worker did not read the one wake byte")
        require_cpu(libc, cpu)
        result.update(worker_tid=tid, worker_read_return_ns=returned_ns)
    except Exception as error:
        result["error"] = str(error)
        send("worker_error", message=str(error))


def run_worker(libc, main_cpu, worker_cpu, deadline):
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    result = {}
    worker = threading.Thread(
        target=worker_read, args=(libc, worker_cpu, read_fd, result), daemon=True,
    )
    try:
        worker.start()
        command = receive(min(deadline, time.monotonic() + PARK_SECONDS))
        if command != "wake":
            raise ValueError("only wake is allowed while the worker is parked")
        require_cpu(libc, main_cpu)
        write_before_ns = time.monotonic_ns()
        written = os.write(write_fd, b"W")
        write_after_ns = time.monotonic_ns()
        if written != 1:
            raise RuntimeError("actor wake byte was not written")
        worker.join(max(0, min(deadline - time.monotonic(), JOIN_SECONDS)))
        if worker.is_alive() or "error" in result or "worker_tid" not in result:
            raise RuntimeError("actor worker did not join successfully")
        joined_ns = time.monotonic_ns()

        retire_deadline = min(deadline, time.monotonic() + JOIN_SECONDS)
        while (TASKS / str(result["worker_tid"])).exists():
            if time.monotonic() >= retire_deadline:
                raise TimeoutError("joined worker still appears in proc task directory")
            time.sleep(0.001)
        remaining = sorted(int(task.name) for task in TASKS.iterdir())
        if remaining != [os.getpid()]:
            raise RuntimeError("unexpected task population after worker join")
    finally:
        # Closing the writer releases the private read on EOF after failure.
        try:
            os.close(write_fd)
        finally:
            try:
                if worker.is_alive():
                    worker.join(JOIN_SECONDS)
            finally:
                os.close(read_fd)
    send("joined", main_cpu=main_cpu, worker_cpu=worker_cpu,
         write_before_ns=write_before_ns, write_after_ns=write_after_ns,
         joined_ns=joined_ns, remaining_local_tids=remaining, **result)


def run(main_cpu, worker_cpu):
    libc = prepare()
    allowed = sorted(os.sched_getaffinity(0))
    if main_cpu == worker_cpu or main_cpu not in allowed or worker_cpu not in allowed:
        raise ValueError("two distinct allowed CPUs are required")
    if sorted(int(task.name) for task in TASKS.iterdir()) != [os.getpid()]:
        raise RuntimeError("actor must be single-threaded before release")
    os.sched_setaffinity(0, {main_cpu})
    require_cpu(libc, main_cpu)
    deadline = time.monotonic() + ACTOR_SECONDS
    send("ready", pid=os.getpid(), main_tid=os.getpid(), main_cpu=main_cpu,
         worker_cpu=worker_cpu, allowed_cpus=allowed, mono_ns=time.monotonic_ns())
    worker_joined = False
    fork_done = False
    for _ in range(8):
        command = receive(min(deadline, time.monotonic() + READY_SECONDS))
        if command == "marker":
            require_cpu(libc, main_cpu)
            before = time.monotonic_ns()
            tid = native_tid(libc)
            after = time.monotonic_ns()
            if tid != os.getpid():
                raise RuntimeError("marker caller is not the actor leader")
            send("marker", local_tid=tid, cpu=main_cpu, mono_before_ns=before, mono_after_ns=after)
        elif command == "fork" and not fork_done and not worker_joined:
            run_nonmember_fork(deadline)
            fork_done = True
        elif command == "run" and not worker_joined:
            run_worker(libc, main_cpu, worker_cpu, deadline)
            worker_joined = True
        elif command == "finish":
            send("finished", pid=os.getpid(), worker_joined=worker_joined, mono_ns=time.monotonic_ns())
            return
        else:
            raise ValueError("command is outside the actor lifecycle")
    raise ValueError("actor command limit reached")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("main_cpu", type=int)
    parser.add_argument("worker_cpu", type=int)
    options = parser.parse_args()
    try:
        if sys.platform == "linux":
            signal.alarm(ACTOR_SECONDS + JOIN_SECONDS)
        run(options.main_cpu, options.worker_cpu)
    except Exception as error:
        try:
            send("actor_error", message=str(error))
        except OSError:
            pass
        os._exit(1)
    os._exit(0)
