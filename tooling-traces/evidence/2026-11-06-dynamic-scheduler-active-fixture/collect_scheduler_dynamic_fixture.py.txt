"""Collect the fixed one-child scheduler fixture on the pinned WSL host."""

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
import time

from preflight_scheduler_dynamic_verifier import LOG_SIZE, verify_host
from preflight_scheduler_pidfd_seed import (
    COOKIE, DELETE, GID, LOOKUP, UID, UPDATE, check_element, close_owned, fields,
    finish_actor, lease, require,
)
from preflight_scheduler_task_storage import create_task_storage, load_btf, load_program
from scheduler_dynamic_native_io import (
    attach_raw_tracepoint, create_counts, create_private_state, create_records,
    read_counts, read_record, recursion_misses, validate_link_fdinfo,
)
from scheduler_dynamic_program import ACK, EVENTS, lifecycle_program, seed_program


ACTOR = Path(__file__).with_name("scheduler_dynamic_actor.py").resolve()
HOOKS = ("sched_prepare_exec", *(hook for hook in EVENTS
                                 if hook not in {"sched_prepare_exec", "task_newtask"}), "task_newtask")
EVENT_NAMES = ("", "birth", "wake_new", "switch_in", "switch_out", "waking",
               "wakeup", "exit", "free")
U32_MAX = (1 << 32) - 1
TAIL_NS = 2_000_000_000


def mono():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def receive(actor, expected):
    result = bytearray()
    deadline = time.monotonic() + 5
    while len(result) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([actor.stdout], [], [], remaining)[0]:
            break
        byte = os.read(actor.stdout.fileno(), 1)
        if byte == b"\n":
            row = json.loads(result)
            if row["kind"] == "actor_error":
                raise ValueError(f"actor failed before {expected}: {row['message']}")
            require(row["kind"] == expected, f"unexpected actor receipt for {expected}")
            return row
        require(byte, f"actor ended before {expected}")
        result.extend(byte)
    raise ValueError(f"missing or oversized actor receipt for {expected}")


def command(actor, name, expected):
    actor.stdin.write((json.dumps({"command": name}) + "\n").encode("ascii"))
    return receive(actor, expected)


def own(resources, report, fd):
    resources.callback(close_owned, fd, report)
    return fd


def load(resources, report, hook, program):
    log = ctypes.create_string_buffer(LOG_SIZE)
    stage = {"hook": hook, "program_hex": program.hex()}
    report["programs"].append(stage)
    try:
        fd = own(resources, report, load_program(program, log))
    finally:
        stage["verifier_log_hex"] = log.value.hex()
    stage["recursion_before"] = recursion_misses(fd)
    return fd, stage


def attach(resources, report, hook, program):
    link = own(resources, report, attach_raw_tracepoint(hook, program))
    info = (Path("/proc/self/fdinfo") / str(link)).read_text()
    report["attached_hooks"].append(validate_link_fdinfo(info, hook))


def check_misses(fd, stage):
    stage["recursion_after"] = recursion_misses(fd)
    require(stage["recursion_after"] == stage["recursion_before"] == 0,
            f"raw hook recursion misses for {stage['hook']}")


def seed_actor(actor, storage, owner, alias, nonmember, report):
    receipts = report["seed_map_receipts"]
    with ExitStack() as program_resources:
        fd, stage = load(program_resources, report, "sys_enter", seed_program(storage))
        with ExitStack() as link_resources:
            attach(link_resources, report, "sys_enter", fd)
            report["owner_unseeded_marker"] = command(actor, "marker", "marker")
            check_element(receipts, "unseeded_owner", LOOKUP, storage, owner,
                          expected_errno=errno.ENOENT)
            check_element(receipts, "seed_owner", UPDATE, storage, owner, value=COOKIE)
            syscall = ctypes.CDLL(None).syscall
            syscall.restype = ctypes.c_long
            require(syscall(ctypes.c_long(186)) == os.getpid(), "nonmember marker did not run")
            check_element(receipts, "unseeded_collector", LOOKUP, storage, nonmember,
                          expected_errno=errno.ENOENT)
            check_element(receipts, "seed_unchanged_after_nonmember", LOOKUP, storage, alias,
                          expected=COOKIE)
            report["owner_seeded_marker"] = command(actor, "marker", "marker")
            check_element(receipts, "kernel_ack", LOOKUP, storage, alias, expected=ACK)
        check_misses(fd, stage)
    for label in ("owner_unseeded_marker", "owner_seeded_marker"):
        require(report[label]["local_tid"] == actor.pid and report[label]["cpu"] == 0,
                "owner marker local TID or pinned CPU differs")


def await_park(pid, parked, worker_cpu):
    tid = parked["worker_tid"]
    require(type(tid) is int and tid > 0 and tid != pid, "invalid new local TID")
    task = Path("/proc") / str(pid) / "task" / str(tid)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            call = (task / "syscall").read_text().split()
        except OSError as error:
            if error.errno != errno.EAGAIN:
                raise
        else:
            status = fields(task / "status")
            if (len(call) == 9 and call[0] == "0"
                    and int(call[1], 0) == parked["park_read_fd"] and int(call[3], 0) == 1
                    and status["State"].split()[0] == "S"
                    and status["Cpus_allowed_list"].strip() == str(worker_cpu)):
                return {"syscall": 0, "fd": int(call[1], 0), "count": int(call[3], 0),
                        "state": "S", "worker_cpu": worker_cpu, "mono_ns": mono()}
        time.sleep(0.005)
    raise ValueError("worker did not park in the declared pipe read")


def terminal_counts(pid, tid, joined, counts):
    deadline = joined["joined_ns"] + TAIL_NS
    task = Path("/proc") / str(pid) / "task" / str(tid)
    while mono() <= deadline:
        row = read_counts(counts)
        if row[3] == 1 and not task.exists():
            return row
        require(row[2] == 0, "kernel fault during lifecycle")
        time.sleep(0.005)
    raise ValueError("missing terminal free completion within 2 seconds of join")


def read_ledger(records):
    return [read_record(records, slot) for slot in range(512)]


def validate_ledger(report, rows, counts, capacity, main_cpu, worker_cpu):
    attempted, lost, faults, frees = counts
    require(faults == 0 and frees == 1 and 8 <= attempted <= 4096, "invalid terminal counters")
    used = min(attempted, capacity)
    require(lost == attempted - used and not any(any(row) for row in rows[used:]),
            "publication accounting differs from fixed capacity")
    decoded = []
    for row in rows[:used]:
        kind, emitter, target, aux, stamp, local_tid, global_tid = struct.unpack("<IIIIQII", row)
        require(1 <= kind < len(EVENT_NAMES), "unknown or incomplete ledger row")
        require(local_tid == report["parked"]["worker_tid"] and global_tid > 0,
                "ledger task identity differs from the owned worker")
        require(report["run_before_ns"] <= stamp <= report["joined"]["joined_ns"] + TAIL_NS,
                "ledger timestamp outside the owned monotonic interval")
        require(target != U32_MAX if kind in {2, 5, 6} else target == U32_MAX,
                "unexpected presence or absence of a target CPU")
        require(kind == 4 or aux == 0, "unexpected scheduler state field")
        decoded.append({"kind": EVENT_NAMES[kind], "emitter_cpu": emitter,
                        "target_cpu": None if target == U32_MAX else target,
                        "raw_state": aux, "mono_ns": stamp,
                        "local_tid": local_tid, "global_tid": global_tid})
    report["decoded"] = decoded
    require(len({row["global_tid"] for row in decoded}) == 1 and decoded[0]["kind"] == "birth",
            "first record does not establish exactly one generation")
    if capacity == 1:
        require(lost > 0, "overflow negative did not lose a publication")
        return
    require(lost == 0 and decoded[-1]["kind"] == "free", "positive lost data or lacks terminal free")
    kinds = [row["kind"] for row in decoded]
    for kind in ("birth", "wake_new", "exit", "free"):
        require(kinds.count(kind) == 1, f"expected one {kind}")
    first_switch = kinds.index("switch_in")
    require(0 < kinds.index("wake_new") < first_switch, "first wake and first switch are unordered")
    oracle = report["park_oracle"]["mono_ns"]
    joined = report["joined"]
    waking = [i for i, row in enumerate(decoded)
              if row["kind"] == "waking" and row["emitter_cpu"] == main_cpu
              and row["target_cpu"] == worker_cpu
              and joined["write_before_ns"] <= row["mono_ns"] <= joined["write_after_ns"]]
    require(len(waking) == 1, "controlled cross-CPU waking was missing or ambiguous")
    wake_index = waking[0]
    sleep = [i for i, row in enumerate(decoded[:wake_index])
             if i > first_switch and row["kind"] == "switch_out" and row["raw_state"] == 1
             and row["emitter_cpu"] == worker_cpu and row["mono_ns"] <= oracle]
    require(sleep, "owned interruptible switch-out did not precede the blocked-read oracle")
    require(not any(kind in {"switch_in", "switch_out"} for kind in kinds[sleep[-1] + 1:wake_index]),
            "another switch intervened between the observed sleep and controlled waking")
    resumed = next((i for i in range(wake_index + 1, len(kinds))
                    if kinds[i] in {"switch_in", "switch_out"}), None)
    require(resumed is not None and kinds[resumed] == "switch_in" and resumed < kinds.index("exit")
            and decoded[resumed]["emitter_cpu"] == worker_cpu
            and decoded[resumed]["mono_ns"] <= joined["worker_read_return_ns"],
            "first target switch did not resume on the worker CPU before read return and exit")
    between = range(wake_index + 1, resumed)
    wakeups = [i for i in between if kinds[i] == "wakeup"]
    require(len(wakeups) == 1 and not any(kinds[i] == "waking" for i in between)
            and decoded[wakeups[0]]["target_cpu"] == worker_cpu
            and decoded[wakeups[0]]["emitter_cpu"] in {main_cpu, worker_cpu},
            "target wakeup was missing or ambiguous before the first resumed switch")
    terminal = [i for i, row in enumerate(decoded)
                if row["kind"] == "switch_out" and row["raw_state"] == 0x80]
    require(len(terminal) == 1 and kinds.index("exit") < terminal[0] < kinds.index("free"),
            "terminal exit/switch/free is missing or out of order")
    report["chain_slots"] = {"birth": 0, "wake_new": kinds.index("wake_new"),
                             "first_switch": first_switch, "park_switch": sleep[-1],
                             "waking": wake_index, "wakeup": wakeups[0], "resumed": resumed,
                             "exit": kinds.index("exit"), "terminal_switch": terminal[0],
                             "free": kinds.index("free")}
    timestamps = [decoded[index]["mono_ns"] for index in report["chain_slots"].values()]
    require(all(left < right for left, right in zip(timestamps, timestamps[1:])),
            "selected lifecycle timestamps are not strictly increasing")


def lifecycle(actor, storage, report, capacity, main_cpu, worker_cpu):
    with ExitStack() as resources:
        state = own(resources, report, create_private_state())
        counts = own(resources, report, create_counts())
        records = own(resources, report, create_records())
        namespace = report["lease"]["pid_namespace_inode"]
        programs = {}
        for hook in HOOKS:
            code = lifecycle_program(hook, storage, state, counts, records, capacity, namespace)
            programs[hook] = load(resources, report, hook, code)
        with ExitStack() as links:
            for hook, (fd, _) in programs.items():
                attach(links, report, hook, fd)
            report["nonmember_fork"] = command(actor, "fork", "fork")
            require(report["nonmember_fork"]["exit_code"] == 0, "nonmember fork failed")
            report["after_fork_counts"] = read_counts(counts)
            require(tuple(report["after_fork_counts"]) == (0, 0, 0, 0),
                    "nonmember process fork affected the ledger")
            report["run_before_ns"] = mono()
            report["parked"] = command(actor, "run", "park")
            report["park_oracle"] = await_park(actor.pid, report["parked"], worker_cpu)
            report["joined"] = command(actor, "wake", "joined")
            joined = report["joined"]
            tid = report["parked"]["worker_tid"]
            require(joined["worker_tid"] == tid and joined["remaining_local_tids"] == [actor.pid],
                    "owned worker join did not match its start")
            require((joined["main_cpu"], joined["worker_cpu"]) == (main_cpu, worker_cpu),
                    "actor CPU receipts differ from pinned CPUs")
            require(report["park_oracle"]["mono_ns"] <= joined["write_before_ns"]
                    <= min(joined["worker_read_return_ns"], joined["write_after_ns"])
                    <= max(joined["worker_read_return_ns"], joined["write_after_ns"]) <= joined["joined_ns"],
                    "actor monotonic intervals differ from the controlled park/wake order")
            report["terminal_before_detach"] = terminal_counts(actor.pid, tid, joined, counts)
        for fd, stage in programs.values():
            check_misses(fd, stage)
        report["terminal_counts"] = read_counts(counts)
        rows = read_ledger(records)
        report["ledger_hex"] = b"".join(rows).hex()
        time.sleep(0.01)
        require(report["terminal_counts"] == report["terminal_before_detach"] == read_counts(counts)
                and rows == read_ledger(records), "terminal ledger changed across detached reads")
        validate_ledger(report, rows, report["terminal_counts"], capacity, main_cpu, worker_cpu)


def run(case, main_cpu, worker_cpu, namespace, report):
    verify_host()
    require((main_cpu, worker_cpu) == (0, 1) and {0, 1} <= os.sched_getaffinity(0),
            "expected the fixed CPU 0 to CPU 1 fixture")
    require(Path("/proc/self/ns/pid").stat().st_ino == namespace, "PID namespace changed")
    require(["monotonic", "0", "0"] in [line.split() for line in
            Path("/proc/self/timens_offsets").read_text().splitlines()], "nonzero monotonic offset")
    with ExitStack() as resources:
        btf = own(resources, report, load_btf())
        storage = own(resources, report, create_task_storage(btf))
        actor = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", str(ACTOR), str(main_cpu), str(worker_cpu)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
            user=UID, group=GID, extra_groups=[], cwd="/", env={},
        )
        resources.callback(finish_actor, actor, report)
        report["ready"] = receive(actor, "ready")
        require(report["ready"]["pid"] == report["ready"]["main_tid"] == actor.pid,
                "actor ready identity mismatch")
        require(os.path.samestat((Path("/proc") / str(actor.pid) / "ns/time").stat(),
                                 Path("/proc/self/ns/time").stat()), "actor time namespace differs")
        owner = own(resources, report, os.pidfd_open(actor.pid))
        alias = own(resources, report, os.pidfd_open(actor.pid))
        nonmember = own(resources, report, os.pidfd_open(os.getpid()))
        report["lease"] = lease(actor.pid, (owner, alias))
        require(report["lease"]["pid_namespace_inode"] == namespace, "actor PID namespace changed")
        seed_actor(actor, storage, owner, alias, nonmember, report)
        if case != "seed":
            lifecycle(actor, storage, report, 1 if case == "negative" else 512, main_cpu, worker_cpu)
        require(lease(actor.pid, (owner, alias)) == report["lease"], "owner lease changed")
        receipts = report["seed_map_receipts"]
        check_element(receipts, "delete_owner", DELETE, storage, alias)
        check_element(receipts, "owner_absent_after_delete", LOOKUP, storage, owner,
                      expected_errno=errno.ENOENT)
        report["finished"] = command(actor, "finish", "finished")
        require(actor.wait(timeout=2) == 0, "actor failed to exit cleanly")
    require(not report["cleanup_errors"] and not report["forced_cleanup"]
            and report["actor_exit_code"] == 0
            and report["closed_fds"] == (7 if case == "seed" else 26),
            "owned resource cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=("seed", "negative", "positive"))
    parser.add_argument("--namespace-inode", required=True, type=int)
    args = parser.parse_args()
    report = {"case": args.case, "passed": False, "capture_ready": False, "programs": [],
              "attached_hooks": [], "seed_map_receipts": [], "closed_fds": 0,
              "cleanup_errors": [], "forced_cleanup": False}
    try:
        run(args.case, 0, 1, args.namespace_inode, report)
        report["passed"] = True
    except (OSError, ValueError, KeyError, IndexError, subprocess.TimeoutExpired) as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error),
                             "errno": getattr(error, "errno", None)}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
