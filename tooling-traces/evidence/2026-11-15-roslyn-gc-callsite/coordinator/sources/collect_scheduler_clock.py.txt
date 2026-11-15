"""Fixed loss-negative then fresh positive owned clock-bracket fixtures."""

import argparse
from contextlib import ExitStack
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from collect_scheduler_dynamic_fixture import attach, check_misses, load, own, receive
from collect_scheduler_dynamic_multi import create_map
from preflight_scheduler_dynamic_verifier import verify_host
from preflight_scheduler_pidfd_seed import LOOKUP, UID, GID, UPDATE, check_element, finish_actor, lease, require
from preflight_scheduler_task_storage import create_task_storage, load_btf
from scheduler_clock_analysis import SLOTS, analyze
from scheduler_clock_program import clock_program
from scheduler_dynamic_native_io import BPF_F_RDONLY, create_counts, read_counts, read_record
from scheduler_dynamic_program import ACK


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def probe(actor, cpu, count, syscall=186):
    actor.stdin.write((json.dumps({"command": "probe", "cpu": cpu, "count": count,
                                 "syscall": syscall}) + "\n").encode())
    actor.stdin.flush()
    result = receive(actor, "probe")
    require(result["cpu"] == cpu and result["affinity"] == [cpu] and result["syscall"] == syscall
            and len(result["rows"]) == count
            and all(row["result"] == actor.pid for row in result["rows"]), "actor probe receipt differs")
    return result


def case(folder, capacity):
    folder.mkdir(parents=True, exist_ok=False)
    report = {"status": "preparing", "capacity": capacity, "programs": [], "attached_hooks": [],
              "closed_fds": 0, "cleanup_errors": [], "forced_cleanup": False, "seed_map_receipts": []}
    actor = None
    try:
        with ExitStack() as resources:
            errors = resources.enter_context((folder / "actor.stderr.txt").open("xb"))
            report["actor_command"] = [sys.executable, "-I", "-S", "-B",
                                       str(Path(__file__).with_name("scheduler_clock_actor.py"))]
            actor = subprocess.Popen(report["actor_command"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=errors,
                                     bufsize=0, user=UID, group=GID, extra_groups=[])
            resources.callback(finish_actor, actor, report)
            require(receive(actor, "held")["pid"] == actor.pid, "actor hold identity differs")
            report["actor_pid"] = actor.pid
            owner, alias, nonmember = [own(resources, report, os.pidfd_open(pid))
                                       for pid in (actor.pid, actor.pid, os.getpid())]
            report["lease_before"] = lease(actor.pid, (owner, alias))
            require(os.path.samestat(Path(f"/proc/{actor.pid}/ns/time").stat(), Path("/proc/self/ns/time").stat()),
                    "actor time namespace differs")
            report["timens_offsets"] = Path("/proc/self/timens_offsets").read_text()
            require(all(line.split()[1:] == ["0", "0"] for line in report["timens_offsets"].splitlines()),
                    "nonzero reference time namespace offset")
            btf = own(resources, report, load_btf())
            storage = own(resources, report, create_task_storage(btf))
            counts = own(resources, report, create_counts())
            records = own(resources, report, create_map(2, 4, 32, SLOTS, BPF_F_RDONLY, b"ceph_clk_rows"))
            fd, stage = load(resources, report, "sys_enter", clock_program(storage, counts, records, capacity))
            with ExitStack() as links:
                attach(links, report, "sys_enter", fd)
                report["unseeded"] = probe(actor, 0, 2)
                require(read_counts(counts) == (0, 0, 0, 0), "unseeded actor emitted records")
                check_element(report["seed_map_receipts"], "seed", UPDATE, storage, owner, value=ACK)
                check_element(report["seed_map_receipts"], "alias_ack", LOOKUP, storage, alias, expected=ACK)
                check_element(report["seed_map_receipts"], "nonmember_absent", LOOKUP, storage, nonmember,
                              expected_errno=errno.ENOENT)
                syscall = ctypes.CDLL(None).syscall
                syscall.restype = ctypes.c_long
                syscall(ctypes.c_long(186))
                report["wrong_syscall"] = probe(actor, 0, 1, 39)
                report["control_counts"] = read_counts(counts)
                require(report["control_counts"] == (0, 0, 0, 0), "nonmember or wrong syscall emitted records")
                batches = report["batches"] = ([probe(actor, 0, 2)] if capacity == 1 else
                                               [probe(actor, i % 2, 8) for i in range(8)])
                report["lease_after"] = lease(actor.pid, (owner, alias))
                require(report["lease_after"] == report["lease_before"], "held lease changed")
                report["before_detach_counts"] = read_counts(counts)
            check_misses(fd, stage)
            raw = b"".join(read_record(records, index) for index in range(SLOTS))
            report["terminal_counts"] = read_counts(counts)
            second = b"".join(read_record(records, index) for index in range(SLOTS))
            require(raw == second and report["terminal_counts"] == report["before_detach_counts"] == read_counts(counts),
                    "detached ledger or counters changed")
            report["second_read_sha256"] = hashlib.sha256(second).hexdigest()
            (folder / "ledger.bin").write_bytes(raw)
            analysis = analyze(raw, report["terminal_counts"], capacity, batches)
            save(folder / "analysis.json", analysis)
            actor.stdin.write(b'{"command":"finish"}\n')
            actor.stdin.flush()
            receive(actor, "done")
            require(actor.wait(timeout=3) == 0, "actor exit differs")
            check_element(report["seed_map_receipts"], "reaped_absent", LOOKUP, storage, alias,
                          expected_errno=errno.ENOENT)
            report["status"] = "completed"
    except Exception as error:
        report.update(status="failed", failure=type(error).__name__ + ": " + str(error))
        raise
    finally:
        if report["status"] == "completed" and (report["closed_fds"] != 9 or report["cleanup_errors"]
                                                or report["forced_cleanup"]):
            report.update(status="failed", cleanup_failure=True)
        save(folder / "report.json", report)
    require(report["status"] == "completed", "clock fixture cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    allowed = Path(__file__).resolve().parents[1].parent / "Cehpalon-Engine-Docs/.local/scheduler-clock01"
    args.output = args.output.resolve()
    require(args.output.is_relative_to(allowed) and args.output != allowed,
            "fresh isolated clock-fixture evidence directory required")
    verify_host()
    args.output.mkdir(parents=True, exist_ok=False)
    case(args.output / "negative01", 1)
    case(args.output / "positive01", 128)
    print(json.dumps({"status": "completed", "output": str(args.output)}))


if __name__ == "__main__":
    main()
