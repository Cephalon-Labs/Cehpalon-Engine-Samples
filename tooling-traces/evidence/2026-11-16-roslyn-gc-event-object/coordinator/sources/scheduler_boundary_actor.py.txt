"""One ordinary leader, fixed yields and one private pipe worker."""

import ctypes
import json
import os
from pathlib import Path
import signal
import sys
import threading


class Timespec(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("nsec", ctypes.c_long)]


def main():
    signal.alarm(30)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def clock():
        t = Timespec()
        if libc.syscall(ctypes.c_long(228), ctypes.c_long(1), ctypes.byref(t)) != 0:
            raise OSError(ctypes.get_errno(), "raw monotonic reference failed")
        if t.sec < 0 or not 0 <= t.nsec < 1_000_000_000:
            raise ValueError("invalid reference timespec")
        return t.sec*1_000_000_000+t.nsec

    def send(kind, **fields):
        print(json.dumps({"kind": kind, **fields}), flush=True)

    def tid():
        value = libc.syscall(ctypes.c_long(186))
        if value <= 0:
            raise OSError("gettid failed")
        return value

    os.sched_setaffinity(0, {0})
    send("held", pid=os.getpid())
    for line in sys.stdin:
        cmd = json.loads(line)
        if cmd["command"] == "finish":
            send("done")
            return
        if cmd["command"] == "yield":
            if cmd["cpu"] not in (0, 1) or cmd["count"] != 8:
                raise ValueError("fixed yield batch required")
            os.sched_setaffinity(0, {cmd["cpu"]})
            references = []
            for _ in range(8):
                low = clock()
                result = libc.syscall(ctypes.c_long(24))
                high = clock()
                if result != 0 or low > high:
                    raise ValueError("yield/reference failure")
                references.append([low, high])
            send("yield", cpu=cmd["cpu"], affinity=sorted(os.sched_getaffinity(0)), references=references)
            continue
        if cmd["command"] != "run":
            raise ValueError("unsupported controlled command")
        os.sched_setaffinity(0, {0})
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        result = {}
        def worker():
            try:
                os.sched_setaffinity(0, {1})
                worker_tid = tid()
                send("park", worker_tid=worker_tid, worker_cpu=1, park_read_fd=read_fd,
                     reference_ns=clock())
                byte = ctypes.create_string_buffer(1)
                got = libc.syscall(ctypes.c_long(0), ctypes.c_int(read_fd), ctypes.byref(byte), ctypes.c_size_t(1))
                after = clock()
                if got != 1 or byte.raw != b"W":
                    raise ValueError("private read failed")
                result.update(worker_tid=worker_tid, worker_read_return_ns=after)
            except Exception as error:
                result["error"] = str(error)
        born_before = clock()
        thread = threading.Thread(target=worker, daemon=True)
        try:
            thread.start()
            command = json.loads(next(sys.stdin))
            if command["command"] != "wake":
                raise ValueError("wake required while worker held")
            before = clock()
            if os.write(write_fd, b"W") != 1:
                raise ValueError("wake write failed")
            after = clock()
            thread.join(2)
            if thread.is_alive() or "error" in result or "worker_tid" not in result:
                raise ValueError("worker failed to join: " + str(result))
            joined = clock()
            # The collector retains the separate kernel-free/lifetime tail.
            send("joined", born_before_ns=born_before, write_before_ns=before,
                 write_after_ns=after, joined_ns=joined, main_cpu=0, worker_cpu=1,
                 remaining_local_tids=sorted(int(p.name) for p in Path('/proc/self/task').iterdir()), **result)
        finally:
            os.close(write_fd)
            if thread.is_alive():
                thread.join(2)
            os.close(read_fd)


if __name__ == "__main__":
    main()
