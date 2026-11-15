"""Ordinary single-thread actor using explicit x86-64 raw clock syscalls."""

import ctypes
import json
import os
import sys


class Timespec(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("nanoseconds", ctypes.c_long)]


def main():
    syscall = ctypes.CDLL(None, use_errno=True).syscall
    syscall.restype = ctypes.c_long

    def reference():
        value = Timespec()
        if syscall(ctypes.c_long(228), ctypes.c_long(1), ctypes.byref(value)) != 0:
            raise OSError(ctypes.get_errno(), "raw clock_gettime failed")
        if value.seconds < 0 or not 0 <= value.nanoseconds < 1_000_000_000:
            raise ValueError("invalid raw monotonic timespec")
        return value.seconds * 1_000_000_000 + value.nanoseconds

    def send(value):
        print(json.dumps(value), flush=True)

    send({"kind": "held", "pid": os.getpid()})
    for line in sys.stdin:
        command = json.loads(line)
        if command["command"] == "finish":
            send({"kind": "done"})
            return
        if command["command"] != "probe" or command["cpu"] not in (0, 1):
            raise ValueError("unsupported actor command")
        count = command["count"]
        call = command.get("syscall", 186)
        if type(count) is not int or not 1 <= count <= 8 or call not in (39, 186):
            raise ValueError("unsupported bounded syscall batch")
        os.sched_setaffinity(0, {command["cpu"]})
        rows = []
        for _ in range(count):
            before = reference()
            result = syscall(ctypes.c_long(call))
            after = reference()
            if result != os.getpid() or before > after:
                raise ValueError("actor syscall identity or reference order differs")
            rows.append({"before_ns": before, "after_ns": after, "result": result})
        send({"kind": "probe", "cpu": command["cpu"], "syscall": call,
              "affinity": sorted(os.sched_getaffinity(0)), "rows": rows})


if __name__ == "__main__":
    main()
