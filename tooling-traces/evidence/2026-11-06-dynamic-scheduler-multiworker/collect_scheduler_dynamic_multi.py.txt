"""Collect the pinned, three-generation synthetic WSL scheduler fixture."""

import argparse
from contextlib import ExitStack
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

from collect_scheduler_dynamic_fixture import (
    TAIL_NS, attach, await_park, check_misses, command, load, mono, own, receive, run,
)
from preflight_scheduler_pidfd_seed import require
from preflight_scheduler_task_storage import BPF_MAP_CREATE, bpf_call
from scheduler_dynamic_multi_program import PROBES, multi_program
from scheduler_dynamic_multi_validation import validate_multi_ledger
from scheduler_dynamic_native_io import (
    BPF_F_RDONLY, BPF_F_WRONLY, BPF_MAP_LOOKUP_ELEM, BPF_MAP_TYPE_ARRAY, RECORD_CAPACITY,
)


ACTOR = Path(__file__).with_name("scheduler_dynamic_multi_actor.py").resolve()
COUNTS = struct.Struct("<IIIII")
ROW_SIZE = 40


def create_map(map_type, key_size, value_size, capacity, flags, name):
    return bpf_call(BPF_MAP_CREATE, struct.pack("<7I16s", map_type, key_size, value_size,
                                               capacity, flags, 0, 0, name))


def read_array(fd, slot):
    key = ctypes.c_uint32(slot)
    value = ctypes.create_string_buffer(ROW_SIZE)
    bpf_call(BPF_MAP_LOOKUP_ELEM, struct.pack("<I4xQQQ", fd, ctypes.addressof(key),
                                            ctypes.addressof(value), 0))
    return value.raw


def read_counts(fd):
    return COUNTS.unpack_from(read_array(fd, 0))


def wait_free(actor, worker, counts, total):
    joined = worker["joined"]
    deadline = joined["joined_ns"] + TAIL_NS
    path = Path("/proc") / str(actor.pid) / "task" / str(joined["worker_tid"])
    while mono() <= deadline:
        row = read_counts(counts)
        require(row[2] == 0 and row[3] <= total, "unexpected fault or free during worker retirement")
        if row[3] == total and not path.exists():
            worker["free_ack"] = {"mono_ns": mono(), "counts": row}
            require(worker["free_ack"]["mono_ns"] <= deadline, "free acknowledgement exceeded deadline")
            return
        time.sleep(0.005)
    raise ValueError(f"worker {total} free missing within the two-second deadline")


def park(actor, label, receipt, start, worker_cpu):
    require(receipt["label"] == label and receipt["worker_cpu"] == worker_cpu,
            "wrong worker park label or CPU")
    return {"run_before_ns": start, "parked": receipt,
            "park_oracle": await_park(actor.pid, receipt, worker_cpu)}


def wake(actor, label, workers, counts, total, main_cpu, worker_cpu):
    worker = workers[label]
    joined = command(actor, f"wake_{label.lower()}", "joined")
    worker["joined"] = joined
    require(joined["label"] == label and joined["worker_tid"] == worker["parked"]["worker_tid"],
            "joined receipt differs from the held worker")
    require((joined["main_cpu"], joined["worker_cpu"]) == (main_cpu, worker_cpu),
            "pinned CPUs differ at wake")
    require(worker["park_oracle"]["mono_ns"] <= joined["write_before_ns"]
            <= min(joined["worker_read_return_ns"], joined["write_after_ns"])
            <= max(joined["worker_read_return_ns"], joined["write_after_ns"]) <= joined["joined_ns"],
            "worker park, write and join timestamps are unordered")
    surviving = [actor.pid]
    if label == "A":
        surviving.append(workers["B"]["parked"]["worker_tid"])
    require(sorted(joined["remaining_local_tids"]) == sorted(surviving), "unexpected live cohort after join")
    wait_free(actor, worker, counts, total)


def execute_workers(actor, counts, report, main_cpu, worker_cpu):
    report["nonmember_fork"] = command(actor, "fork", "fork")
    require(report["nonmember_fork"]["exit_code"] == 0, "nonmember fork failed")
    report["after_fork_counts"] = read_counts(counts)
    require(report["after_fork_counts"] == (0,) * 5, "nonmember fork affected the ledger")
    start = mono()
    first = command(actor, "run", "park")
    second = receive(actor, "park")
    receipts = {first["label"]: first, second["label"]: second}
    require(set(receipts) == {"A", "B"}, "expected two distinct park receipts")
    workers = report["workers"] = {}
    for label in ("A", "B"):
        workers[label] = park(actor, label, receipts[label], start, worker_cpu)
    require(receipts["A"]["creator_tid"] == actor.pid
            and receipts["B"]["creator_tid"] == receipts["A"]["worker_tid"]
            and receipts["A"]["worker_tid"] != receipts["B"]["worker_tid"], "worker lineage differed")
    wake(actor, "A", workers, counts, 1, main_cpu, worker_cpu)
    report["b_still_parked_after_a_free"] = await_park(actor.pid, receipts["B"], worker_cpu)
    wake(actor, "B", workers, counts, 2, main_cpu, worker_cpu)
    start = mono()
    third = command(actor, "run_c", "park")
    workers["C"] = park(actor, "C", third, start, worker_cpu)
    require(third["creator_tid"] == actor.pid, "replacement worker creator differed")
    wake(actor, "C", workers, counts, 3, main_cpu, worker_cpu)


def lifecycle(actor, storage, report, capacity, main_cpu, worker_cpu):
    with ExitStack() as resources:
        members = own(resources, report, create_map(1, 8, 32, 4, BPF_F_WRONLY, b"ceph_dyn_member"))
        counts = own(resources, report, create_map(BPF_MAP_TYPE_ARRAY, 4, COUNTS.size, 1,
                                                  BPF_F_RDONLY, b"ceph_dyn_mcount"))
        records = own(resources, report, create_map(BPF_MAP_TYPE_ARRAY, 4, ROW_SIZE, RECORD_CAPACITY,
                                                   BPF_F_RDONLY, b"ceph_dyn_mrows"))
        namespace = report["lease"]["pid_namespace_inode"]
        programs = {}
        for name, (hook, _) in PROBES.items():
            code = multi_program(name, storage, members, counts, records, capacity, namespace)
            try:
                fd, stage = load(resources, report, hook, code)
            finally:
                report["programs"][-1]["probe"] = name
            programs[name] = (fd, stage)
        with ExitStack() as links:
            for name, (fd, _) in programs.items():
                attach(links, report, PROBES[name][0], fd)
            execute_workers(actor, counts, report, main_cpu, worker_cpu)
        for fd, stage in programs.values():
            check_misses(fd, stage)
        terminal = report["terminal_counts"] = read_counts(counts)
        rows = [read_array(records, i) for i in range(RECORD_CAPACITY)]
        raw = b"".join(rows)
        report["ledger_hex"] = raw.hex()
        time.sleep(0.01)
        second = b"".join(read_array(records, i) for i in range(RECORD_CAPACITY))
        report["second_read"] = {"counts": read_counts(counts),
                                 "ledger_sha256": hashlib.sha256(second).hexdigest()}
        require(terminal == report["workers"]["C"]["free_ack"]["counts"]
                == report["second_read"]["counts"] and raw == second, "detached ledger changed")
        validate_multi_ledger(report, rows, terminal, capacity, main_cpu, worker_cpu)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=("negative", "positive"))
    parser.add_argument("--namespace-inode", required=True, type=int)
    args = parser.parse_args()
    report = {"case": args.case, "passed": False, "capture_ready": False, "programs": [],
              "attached_hooks": [], "seed_map_receipts": [], "closed_fds": 0,
              "cleanup_errors": [], "forced_cleanup": False}
    try:
        run(args.case, 0, 1, args.namespace_inode, report, actor_path=ACTOR,
            lifecycle_run=lifecycle, lifecycle_fds=28)
        report["passed"] = True
    except (OSError, ValueError, KeyError, IndexError, subprocess.TimeoutExpired) as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error),
                             "errno": getattr(error, "errno", None)}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
