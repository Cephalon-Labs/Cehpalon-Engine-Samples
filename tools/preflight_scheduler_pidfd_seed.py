"""Prove userspace task-storage identity with one held ordinary WSL actor."""

import argparse
from contextlib import ExitStack
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys

from preflight_scheduler_dynamic_verifier import verify_host
from preflight_scheduler_task_storage import bpf_call, create_task_storage, load_btf


UID = GID = 1000
COOKIE = 0x43455048414C4F4E
LOOKUP, UPDATE, DELETE = 1, 2, 3
BPF_NOEXIST = 1
ACTOR = """
import os
import select
os.write(1, b"H")
ready, _, _ = select.select([0], [], [], 10)
raise SystemExit(0 if ready and os.read(0, 1) == b"R" else 2)
"""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_element(report, stage, command, map_fd, pidfd, *, value=0, expected=None,
                  expected_errno=None):
    key = ctypes.c_int32(pidfd)
    cell = ctypes.c_uint64(value)
    attr = struct.pack("<I4xQQQ", map_fd, ctypes.addressof(key),
                       0 if command == DELETE else ctypes.addressof(cell),
                       BPF_NOEXIST if command == UPDATE else 0)
    try:
        bpf_call(command, attr)
    except OSError as error:
        report.append({"stage": stage, "errno": error.errno})
        if error.errno != expected_errno:
            raise
    else:
        observed = cell.value if command == LOOKUP else None
        report.append({"stage": stage, "errno": None, "value": observed})
        require(expected_errno is None and observed == expected, f"unexpected result at {stage}")


def fields(path):
    return dict(line.split(":", 1) for line in path.read_text().splitlines() if ":" in line)


def lease(pid, pidfds):
    proc = Path("/proc") / str(pid)
    status = fields(proc / "status")
    ids = {"uid": list(map(int, status["Uid"].split())),
           "gid": list(map(int, status["Gid"].split()))}
    require(ids == {"uid": [UID] * 4, "gid": [GID] * 4}, "actor credentials changed")
    caps = {name: int(status[name], 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")}
    require(not any(caps.values()) and not status["Groups"].strip(), "actor retained privileges")
    require([entry.name for entry in (proc / "task").iterdir()] == [str(pid)],
            "actor must be a single-threaded leader")
    require(int(status["PPid"]) == os.getpid(), "actor is outside the controlled parent")
    namespace = (proc / "ns/pid").stat()
    require(os.path.samestat(namespace, Path("/proc/self/ns/pid").stat()), "different PID namespace")
    require(os.path.samestat((proc / "exe").stat(), Path("/proc/self/exe").stat()),
            "actor executable differs from the controlled Python")
    tail = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
    start_ticks = int(tail[19])
    require(start_ticks > 0 and tail[0] not in {"Z", "X"}, "actor is not held live")

    mappings = []
    for fd in pidfds:
        require(not select.select([fd], [], [], 0)[0], "pidfd already readable")
        info = fields(Path("/proc/self/fdinfo") / str(fd))
        mapping = {"pid": int(info["Pid"]), "nspid": list(map(int, info["NSpid"].split()))}
        require(mapping == {"pid": pid, "nspid": [pid]}, "pidfd does not bind the held actor")
        mappings.append(mapping)
    require(os.path.samestat(os.fstat(pidfds[0]), os.fstat(pidfds[1])), "pidfd aliases differ")
    return {"local_pid": pid, "start_ticks": start_ticks, "pid_namespace_inode": namespace.st_ino,
            "credentials": ids, "capabilities": caps, "pidfd_mappings": mappings}


def exercise(actor, map_fd, report, resources):
    require(select.select([actor.stdout], [], [], 3)[0] and os.read(actor.stdout.fileno(), 1) == b"H",
            "ordinary actor did not acknowledge hold")
    opened = []
    for pid in (actor.pid, actor.pid, os.getpid()):
        fd = os.pidfd_open(pid)
        resources.callback(close_owned, fd, report)
        opened.append(fd)
    owner, alias, nonmember = opened
    report["lease_before"] = lease(actor.pid, (owner, alias))
    receipts = report["map_operations"]
    check_element(receipts, "initial_owner_absent", LOOKUP, map_fd, owner,
                  expected_errno=errno.ENOENT)
    check_element(receipts, "seed_owner", UPDATE, map_fd, owner, value=COOKIE)
    check_element(receipts, "owner_alias_read", LOOKUP, map_fd, alias, expected=COOKIE)
    check_element(receipts, "reject_duplicate_seed", UPDATE, map_fd, alias,
                  value=COOKIE + 1, expected_errno=errno.EEXIST)
    check_element(receipts, "original_seed_retained", LOOKUP, map_fd, owner, expected=COOKIE)
    check_element(receipts, "collector_nonmember_absent", LOOKUP, map_fd, nonmember,
                  expected_errno=errno.ENOENT)
    check_element(receipts, "delete_via_alias", DELETE, map_fd, alias)
    check_element(receipts, "owner_absent_after_delete", LOOKUP, map_fd, owner,
                  expected_errno=errno.ENOENT)
    report["lease_after"] = lease(actor.pid, (owner, alias))
    require(report["lease_after"] == report["lease_before"], "actor lease changed")
    actor.stdin.write(b"R")
    actor.stdin.flush()
    require(actor.wait(timeout=3) == 0, "ordinary actor did not exit cleanly")
    check_element(receipts, "reaped_owner_absent", LOOKUP, map_fd, owner,
                  expected_errno=errno.ENOENT)


def close_owned(fd, report):
    try:
        os.close(fd)
    except OSError as error:
        report["cleanup_errors"].append({"errno": error.errno})
    else:
        report["closed_fds"] += 1


def finish_actor(actor, report):
    try:
        actor.stdin.close()
    except OSError as error:
        report["cleanup_errors"].append({"stream": "stdin", "errno": error.errno})
    finally:
        try:
            actor.wait(timeout=1)
        except subprocess.TimeoutExpired:
            report["forced_cleanup"] = True
            actor.kill()
            actor.wait(timeout=2)
        finally:
            report["actor_exit_code"] = actor.returncode
            actor.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prove-held-owner", action="store_true", required=True)
    parser.parse_args()
    report = {"capture_ready": False, "passed": False, "map_operations": [],
              "closed_fds": 0, "cleanup_errors": [], "forced_cleanup": False}
    stage = "host"
    try:
        verify_host()
        with ExitStack() as resources:
            stage = "btf"
            btf = load_btf()
            resources.callback(close_owned, btf, report)
            stage = "map"
            map_fd = create_task_storage(btf)
            resources.callback(close_owned, map_fd, report)
            stage = "held_owner"
            actor = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", "-c", ACTOR],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
                user=UID, group=GID, extra_groups=[], cwd="/", env={},
            )
            resources.callback(finish_actor, actor, report)
            exercise(actor, map_fd, report, resources)
        report["passed"] = (report["closed_fds"] == 5 and report["actor_exit_code"] == 0
                            and not report["cleanup_errors"] and not report["forced_cleanup"])
    except (OSError, ValueError, KeyError, IndexError, subprocess.TimeoutExpired) as error:
        report["failure"] = {"stage": stage, "error": str(error), "errno": getattr(error, "errno", None)}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
