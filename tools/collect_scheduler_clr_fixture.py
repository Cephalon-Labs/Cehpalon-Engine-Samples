"""Collect a bounded CLR ThreadPool fixture on the pinned WSL host."""

import argparse
from contextlib import ExitStack
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import time

from collect_scheduler_dynamic_fixture import (
    TAIL_NS, attach, await_park, check_misses, command, load, mono, own, receive, seed_actor,
)
from collect_scheduler_dynamic_multi import create_map
from preflight_scheduler_dynamic_verifier import verify_host
from preflight_scheduler_pidfd_seed import (
    GID, LOOKUP, UID, UPDATE, check_element, fields, finish_actor, require,
)
from preflight_scheduler_task_storage import bpf_call, create_task_storage, load_btf
from scheduler_dynamic_multi_program import PROBES, multi_program
from scheduler_dynamic_native_io import (
    BPF_F_RDONLY, BPF_F_WRONLY, BPF_MAP_LOOKUP_ELEM, BPF_MAP_TYPE_ARRAY,
)
from scheduler_dynamic_program import ACK

SLOTS = 2048
MEMBERS = 16
ROW = struct.Struct("<IIIIQIIII")
COUNTS = struct.Struct("<IIIII")
PIDFD_THREAD = os.O_EXCL
HOST = Path("/home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet")
RUNTIME = HOST.parent / "shared/Microsoft.NETCore.App/11.0.0-rc.3.26522.148"
APP = Path("/home/tom/.local/share/cehpalon-clr-fixtures/20261106-02/out/ThreadPoolConformance.dll")


def read_array(fd, slot):
    key = ctypes.c_uint32(slot)
    value = ctypes.create_string_buffer(ROW.size)
    bpf_call(BPF_MAP_LOOKUP_ELEM, struct.pack("<I4xQQQ", fd, ctypes.addressof(key),
                                            ctypes.addressof(value), 0))
    return value.raw


def read_counts(fd):
    return COUNTS.unpack_from(read_array(fd, 0))


def held_task(pid, tid):
    base = Path("/proc") / str(pid) / "task" / str(tid)
    data = fields(base / "status")
    require(int(data["Tgid"]) == pid and int(data["Pid"]) == tid and int(data["PPid"]) == os.getpid(),
            "held task does not belong to the owned actor")
    require(all(data[name].split() == ["1000"] * 4 for name in ("Uid", "Gid"))
            and not data["Groups"].strip()
            and all(int(data[name], 16) == 0 for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")),
            "held task has unexpected credentials")
    tail = (base / "stat").read_text().rsplit(") ", 1)[1].split()
    require(tail[0] not in {"X", "Z"} and int(tail[19]) > 0, "held task is not live")
    return {"tid": tid, "start_ticks": int(tail[19]), "uid": UID, "gid": GID}


def cohort(actor):
    proc = Path("/proc") / str(actor.pid)
    tids = sorted(int(item.name) for item in (proc / "task").iterdir())
    require(actor.pid in tids and 1 <= len(tids) <= MEMBERS, "pre-arm cohort exceeded bounds")
    return [held_task(actor.pid, tid) for tid in tids]


def verify_pidfd(pidfd, tid):
    require(not select.select([pidfd], [], [], 0)[0], "held pidfd is readable")
    info = fields(Path("/proc/self/fdinfo") / str(pidfd))
    require(int(info["Pid"]) == tid and list(map(int, info["NSpid"].split())) == [tid],
            "pidfd does not match the held local TID")


def verify_process(actor, namespace):
    proc = Path("/proc") / str(actor.pid)
    require((proc / "exe").samefile(HOST), "owned executable differs from the pinned CLR host")
    require((proc / "ns/pid").stat().st_ino == namespace
            and (proc / "ns/time").samefile("/proc/self/ns/time"), "owned namespace differs")
    loaded = {parts[5] for line in (proc / "maps").read_text().splitlines()
              if len(parts := line.split(maxsplit=5)) == 6 and parts[5].startswith("/")}
    coreclr = str((RUNTIME / "libcoreclr.so").resolve())
    require(coreclr in loaded, "pinned CoreCLR library was not loaded")


def bind_cohort(actor, resources, report):
    snapshots = report["prearm_cohort"] = cohort(actor)
    owner = own(resources, report, os.pidfd_open(actor.pid))
    alias = own(resources, report, os.pidfd_open(actor.pid))
    nonmember = own(resources, report, os.pidfd_open(os.getpid()))
    verify_pidfd(owner, actor.pid)
    verify_pidfd(alias, actor.pid)
    require(os.path.samestat(os.fstat(owner), os.fstat(alias)), "owner aliases differ")
    siblings = {}
    for task in snapshots:
        tid = task["tid"]
        if tid != actor.pid:
            fd = own(resources, report, os.pidfd_open(tid, PIDFD_THREAD))
            verify_pidfd(fd, tid)
            siblings[tid] = fd
    require(cohort(actor) == snapshots, "pre-arm cohort changed while binding")
    return owner, alias, nonmember, siblings


def arm(resources, links, report, storage, namespace, *, extension=None):
    members = own(resources, report, create_map(1, 8, 32, MEMBERS, BPF_F_WRONLY, b"ceph_clr_member"))
    counts = own(resources, report, create_map(BPF_MAP_TYPE_ARRAY, 4, COUNTS.size, 1,
                                              BPF_F_RDONLY, b"ceph_clr_count"))
    records = own(resources, report, create_map(BPF_MAP_TYPE_ARRAY, 4, ROW.size, SLOTS,
                                               BPF_F_RDONLY, b"ceph_clr_rows"))
    programs = {}
    for name, (hook, _) in PROBES.items():
        code = multi_program(name, storage, members, counts, records, SLOTS, namespace, MEMBERS)
        try:
            fd, stage = load(resources, report, hook, code)
        finally:
            report["programs"][-1]["probe"] = name
        programs[name] = (fd, stage)
    for name, (fd, _) in programs.items():
        attach(links, report, PROBES[name][0], fd)
    if extension is not None:
        extension.arm(resources, links, report, members)
    return counts, records, programs


def execute(actor, report):
    clocks = report["controller"]
    clocks["run_send_ns"] = mono()
    parked = report["parked"] = command(actor, "run", "park")
    require(parked["is_thread_pool_thread"] is True, "callback was not a CLR ThreadPool worker")
    require(parked["worker_tid"] not in {task["tid"] for task in report["prearm_cohort"]},
            "callback TID already existed at arm")
    report["park_oracle"] = await_park(actor.pid, parked, 1)
    report["parked_task_identity"] = held_task(actor.pid, parked["worker_tid"])
    complete = report["completed"] = command(actor, "wake", "completed")
    clocks["done_receive_ns"] = mono()
    require(complete["worker_tid"] == parked["worker_tid"] and
            (complete["main_cpu"], complete["worker_cpu"]) == (0, 1),
            "completed CLR worker identity or CPUs differ")
    require(complete["rounds"] == 64 and complete["checksum"] == "4fcd3a1dd438d325",
            "CLR fixture workload result differs")
    require(clocks["run_send_ns"] <= complete["work_begin_ns"] <= parked["mono_ns"]
            <= report["park_oracle"]["mono_ns"] <= complete["ping_begin_ns"]
            < complete["ping_end_ns"] <= clocks["done_receive_ns"]
            and complete["work_begin_ns"] < complete["work_end_ns"] <= clocks["done_receive_ns"],
            "CLR or controller timing brackets differ")
    report["held_after_work"] = cohort(actor)
    require(report["parked_task_identity"] in report["held_after_work"],
            "worker identity changed between park and completion")
    report["finished"] = command(actor, "finish", "finished")
    require(report["finished"]["worker_completed"] is True, "CLR worker completion receipt missing")
    require(actor.wait(timeout=3) == 0, "CLR actor did not terminate cleanly")
    report["reaped_ns"] = mono()


def await_retirement(report, counts):
    deadline = report["reaped_ns"] + TAIL_NS
    while mono() <= deadline:
        row = read_counts(counts)
        require(row[2] == 0 and row[3] <= row[4] <= MEMBERS, "fault in CLR lifecycle")
        if row[3] == row[4] and row[3] > 0:
            report["terminal_before_detach"] = row
            return
        time.sleep(0.005)
    raise ValueError("CLR generations did not retire inside the two-second tail")


def validate_trace(report, raw, counts):
    attempted, lost, faults, frees, admitted = counts
    require(0 < attempted <= SLOTS and lost == faults == 0 and 1 <= frees == admitted <= MEMBERS,
            "CLR ledger is incomplete or exceeded its bounds")
    require(len(raw) == SLOTS * ROW.size and not any(raw[attempted * ROW.size:]),
            "CLR ledger has nonempty unused slots")
    generations = {}
    active = {}
    for slot, row in enumerate(ROW.iter_unpack(raw[:attempted * ROW.size])):
        kind, emitter, target, state, stamp, local, global_tid, generation, parent = row
        require(1 <= kind <= 8 and local > 0 and global_tid > 0
                and (target != 0xFFFFFFFF) == (kind in {2, 5, 6}) and (kind == 4 or state == 0),
                "unknown or incomplete CLR record")
        require(report["controller"]["run_send_ns"] <= stamp <= report["reaped_ns"] + TAIL_NS,
                "CLR record outside declared interval")
        identity = (local, global_tid, parent)
        if kind == 1:
            require(1 <= generation <= admitted and generation not in generations
                    and (parent == 0 or parent in active)
                    and all(local != other[0] and global_tid != other[1] for other in active.values()),
                    "duplicate generation, missing parent or overlapping numeric identity")
            generations[generation] = []
            active[generation] = identity
        require(active.get(generation) == identity, "record lacks an active generation")
        generations[generation].append((slot, kind, emitter, target, state, stamp, local, global_tid, parent))
        if kind == 8:
            del active[generation]
    require(set(generations) == set(range(1, admitted + 1)) and not active,
            "CLR generations did not all free")
    for rows in generations.values():
        kinds = [row[1] for row in rows]
        require(all(kinds.count(kind) == 1 for kind in (1, 2, 7, 8))
                and 0 < kinds.index(2) < kinds.index(3) < kinds.index(7) < len(rows) - 1
                and kinds[-1] == 8
                and any(row[1] == 4 and row[4] == 128 for row in rows[kinds.index(7) + 1:])
                and all(left[5] < right[5] for left, right in zip(rows, rows[1:])),
                "incomplete or unordered CLR birth/exit/free chain")

    parked, completed = report["parked"], report["completed"]
    known = {task["tid"] for task in report["prearm_cohort"]}
    known.update(rows[0][6] for rows in generations.values())
    require(all(task["tid"] in known for task in report["held_after_work"]),
            "live CLR task after work lacks pre-arm or birth identity")
    matches = [(generation, rows) for generation, rows in generations.items()
               if rows[0][6] == parked["worker_tid"] and rows[0][5] < parked["mono_ns"] < rows[-1][5]]
    require(len(matches) == 1, "CLR callback does not bind exactly one generation")
    generation, rows = matches[0]
    kinds = [row[1] for row in rows]
    require(rows[kinds.index(3)][5] < parked["mono_ns"]
            and completed["work_end_ns"] < rows[kinds.index(7)][5]
            and parked["worker_tid"] in {task["tid"] for task in report["held_after_work"]},
            "callback and native worker lifetime do not align")
    prove_remote_wake(report, rows, generation)


def prove_remote_wake(report, rows, generation):
    complete = report["completed"]
    wake = next((i for i, row in enumerate(rows) if row[1] == 5
                 and report["park_oracle"]["mono_ns"] <= row[5]), None)
    require(wake is not None and rows[wake][1:4] == (5, 0, 1)
            and complete["ping_begin_ns"] <= rows[wake][5] <= complete["ping_end_ns"],
            "first CLR waking after park was outside the controlled CPU or timing bounds")
    before = [i for i in range(wake) if rows[i][1] in {3, 4}]
    require(before and rows[before[-1]][1:5] == (4, 1, 0xFFFFFFFF, 1)
            and rows[before[-1]][5] <= report["park_oracle"]["mono_ns"],
            "controlled CLR wake lacked a prior parked switch")
    resumed = next((i for i in range(wake + 1, len(rows)) if rows[i][1] in {3, 4}), None)
    require(resumed is not None and rows[resumed][1:3] == (3, 1)
            and rows[resumed][5] <= complete["ping_end_ns"], "CLR worker did not resume on CPU 1")
    between = rows[wake + 1:resumed]
    wakes = [row for row in between if row[1] == 6]
    require(len(wakes) == 1 and wakes[0][3] == 1 and not any(row[1] == 5 for row in between),
            "CLR wakeup and resumed switch are ambiguous")
    report["callback_binding"] = {"generation": generation, "local_tid": rows[0][6],
                                  "global_tid": rows[0][7], "parent_generation": rows[0][8],
                                  "birth_slot": rows[0][0], "waking_slot": rows[wake][0],
                                  "wakeup_slot": wakes[0][0], "resumed_slot": rows[resumed][0],
                                  "exit_slot": next(row[0] for row in rows if row[1] == 7),
                                  "free_slot": rows[-1][0]}


def detached(report, counts, records, programs):
    for fd, stage in programs.values():
        check_misses(fd, stage)
    terminal = report["terminal_counts"] = read_counts(counts)
    raw = b"".join(read_array(records, i) for i in range(SLOTS))
    report["ledger_hex"] = raw.hex()
    time.sleep(0.01)
    second = b"".join(read_array(records, i) for i in range(SLOTS))
    report["second_read"] = {"counts": read_counts(counts), "ledger_sha256": hashlib.sha256(second).hexdigest()}
    require(terminal == report["terminal_before_detach"] == report["second_read"]["counts"]
            and raw == second, "detached CLR ledger changed")
    validate_trace(report, raw, terminal)


def run(mode, namespace, report, *, extension=None, host_check=verify_host):
    host_check()
    require({0, 1} <= os.sched_getaffinity(0) and Path("/proc/self/ns/pid").stat().st_ino == namespace,
            "pinned CPU or PID namespace unavailable")
    offsets = [line.split() for line in Path("/proc/self/timens_offsets").read_text().splitlines()]
    require(["monotonic", "0", "0"] in offsets, "nonzero monotonic offset")
    report["fixture_sha256"] = hashlib.sha256(APP.read_bytes()).hexdigest()
    report["runtime_sha256"] = hashlib.sha256((RUNTIME / "libcoreclr.so").read_bytes()).hexdigest()
    with ExitStack() as resources:
        actor = subprocess.Popen(
            [str(HOST), str(APP)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
            user=UID, group=GID, extra_groups=[], cwd=APP.parent, env={},
        )
        resources.callback(finish_actor, actor, report)
        ready = report["ready"] = receive(actor, "ready")
        require(ready["pid"] == ready["main_tid"] == actor.pid and ready["stopwatch_frequency"] == 1_000_000_000
                and ready["threadpool_count"] == 0 and ready["fixture_version"] == 1,
                "unexpected CLR ready identity or stopwatch clock")
        verify_process(actor, namespace)
        owner, alias, nonmember, siblings = bind_cohort(actor, resources, report)
        if mode == "off":
            report["owner_unseeded_marker"] = command(actor, "marker", "marker")
            report["owner_seeded_marker"] = command(actor, "marker", "marker")
            for label in ("owner_unseeded_marker", "owner_seeded_marker"):
                require(report[label]["local_tid"] == actor.pid and report[label]["cpu"] == 0,
                        "untraced owner marker differs")
            require(cohort(actor) == report["prearm_cohort"], "untraced pre-arm cohort changed")
            execute(actor, report)
        else:
            btf = own(resources, report, load_btf())
            storage = own(resources, report, create_task_storage(btf))
            seed_actor(actor, storage, owner, alias, nonmember, report)
            for tid, fd in siblings.items():
                verify_pidfd(fd, tid)
                check_element(report["seed_map_receipts"], f"seed_prearm_{tid}", UPDATE,
                              storage, fd, value=ACK)
                check_element(report["seed_map_receipts"], f"read_prearm_{tid}", LOOKUP,
                              storage, fd, expected=ACK)
            with ExitStack() as links:
                counts, records, programs = arm(resources, links, report, storage, namespace, extension=extension)
                require(cohort(actor) == report["prearm_cohort"], "traced pre-arm cohort changed")
                require(read_counts(counts) == (0,) * 5, "pre-work CLR ledger not empty")
                execute(actor, report)
                await_retirement(report, counts)
                if extension is not None:
                    extension.snapshot()
            detached(report, counts, records, programs)
            if extension is not None:
                extension.finish(report)
            check_element(report["seed_map_receipts"], "reaped_leader_absent", LOOKUP,
                          storage, owner, expected_errno=errno.ENOENT)
    report["controller"]["cleanup_end_ns"] = mono()
    expected_fds = (28 if mode == "on" else 3) + len(siblings)
    if extension is not None:
        expected_fds += 6
    require(not report["cleanup_errors"] and not report["forced_cleanup"]
            and report["actor_exit_code"] == 0 and report["closed_fds"] == expected_fds,
            "CLR resources did not close cleanly")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("off", "on"))
    parser.add_argument("--namespace-inode", required=True, type=int)
    args = parser.parse_args()
    report = {"mode": args.mode, "passed": False, "capture_ready": False, "programs": [],
              "controller": {"prepare_start_ns": mono()}, "attached_hooks": [], "seed_map_receipts": [],
              "closed_fds": 0, "cleanup_errors": [], "forced_cleanup": False}
    try:
        run(args.mode, args.namespace_inode, report)
        report["passed"] = True
    except (OSError, ValueError, KeyError, IndexError, subprocess.TimeoutExpired) as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error),
                             "errno": getattr(error, "errno", None)}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
