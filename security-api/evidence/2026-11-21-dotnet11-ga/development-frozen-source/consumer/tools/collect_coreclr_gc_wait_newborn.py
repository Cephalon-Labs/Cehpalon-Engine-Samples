"""Join TGID-scoped CoreCLR callsite receipts to real newborn fixture lifetimes."""
import argparse
from contextlib import ExitStack
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import select
import struct
import subprocess
import time

import collect_coreclr_gc_wait_fixture as single
from collect_clr_scheduler_boundary import verify_boundary_host
from collect_scheduler_clr_fixture import RUNTIME
from preflight_scheduler_task_storage import bpf_call
from roslyn_scheduler_session import SchedulerSession
from scheduler_dynamic_native_io import create_counts, create_records, read_counts, read_record, RECORD_CAPACITY
from scheduler_dynamic_program import Program
from scheduler_trace_model import decode_scheduler


ATTACH_TYPE = 48  # BPF_TRACE_UPROBE_MULTI
ROW = struct.Struct("<IIIIQQ")
check = single.check


def program(pid, namespace, counts, records, capacity=RECORD_CAPACITY, *, object_sites=False):
    check(capacity in (RECORD_CAPACITY, 16384), "Unsupported callsite ledger capacity")
    p = Program()
    p.mov(6, 1)
    p.lddw(1, namespace.st_dev)
    p.lddw(2, namespace.st_ino)
    p.mov(3, 10)
    p.emit(0x07, 3, imm=-16)
    p.number(4, 8)
    p.call(120)  # bpf_get_ns_current_pid_tgid
    p.jump(0x55, "fault", 0)
    p.emit(0x61, 1, 10, -12)  # namespace TGID
    p.jump(0x55, "fault", 1, imm=pid)
    p.mov(1, 6)
    p.call(174)  # bpf_get_attach_cookie
    p.jump(0x15, "fault", 0)
    p.jump(0x25, "fault", 0, imm=5 if object_sites else 2)
    p.mov(7, 0)
    if object_sites:
        p.emit(0x7A, 10, off=-24)
        p.jump(0xA5, "site_ready", 7, imm=3)
        p.emit(0x79, 1, 6, 112)  # Verified x86-64 pt_regs.di
        p.jump(0x15, "fault", 1)
        p.emit(0x7B, 10, 1, -24)
        p.label("site_ready")
    p.array(counts, 0)
    p.jump(0x15, "return", 0)
    p.mov(8, 0)
    p.number(1, 1)
    p.emit(0xC3, 8, 1, imm=1)  # fetch-and-add reservation
    p.jump(0x35, "overflow", 1, imm=capacity)
    p.mov(9, 1)
    p.emit(0x63, 10, 1, -4)
    p.array(records)
    p.jump(0x15, "overflow", 0)
    p.mov(6, 0)
    p.emit(0x62, 6, off=4, imm=pid)
    p.emit(0x61, 1, 10, -16)
    p.emit(0x63, 6, 1, 8)
    p.emit(0x63, 6, 7, 12)
    if object_sites:
        p.emit(0x79, 1, 10, -24)
        p.emit(0x7B, 6, 1, 24)
    p.call(5)  # bpf_ktime_get_ns
    p.emit(0x7B, 6, 0, 16)
    p.emit(0x07, 9, imm=1)
    p.emit(0x63, 6, 9)
    p.jump(0x05, "return")
    p.label("overflow")
    p.number(1, 1)
    p.emit(0xC3, 8, 1, off=4)
    p.jump(0x05, "return")
    p.label("fault")
    p.array(counts, 0)
    p.jump(0x15, "return", 0)
    p.number(1, 1)
    p.emit(0xC3, 0, 1, off=8)
    p.exit()
    return p.encode()


def load_callsite(out, pid, ns, counts, records, capacity, *, object_sites=False):
    code = program(pid, ns, counts, records, capacity, object_sites=object_sites)
    (out / "program.bin").write_bytes(code)
    insns = ctypes.create_string_buffer(code)
    license_text = ctypes.create_string_buffer(b"GPL")
    log = ctypes.create_string_buffer(65536)
    attr = struct.pack("<IIQQIIQII16sII", 2, len(code) // 8, ctypes.addressof(insns),
                       ctypes.addressof(license_text), 1, len(log), ctypes.addressof(log), 0, 0,
                       b"ceph_gc_site", 0, ATTACH_TYPE)
    try:
        prog = bpf_call(5, attr)
    finally:
        (out / "verifier.txt").write_bytes(log.value)
    return prog


def attach_callsite(image, pid, prog, sites=single.SITES):
    path = ctypes.create_string_buffer(os.fsencode(image))
    count = len(sites)
    offsets = (ctypes.c_uint64 * count)(*(x[0] for x in sites.values()))
    cookies = (ctypes.c_uint64 * count)(*range(1, count + 1))
    attr = struct.pack("<IIIIQQQQIII4x", prog, 0, ATTACH_TYPE, 0, ctypes.addressof(path),
                       ctypes.addressof(offsets), 0, ctypes.addressof(cookies), count, 0, pid)
    return bpf_call(28, attr)


def load_and_attach(stack, out, image, pid, ns, counts, records):
    prog = load_callsite(out, pid, ns, counts, records, RECORD_CAPACITY)
    stack.callback(os.close, prog)
    link = attach_callsite(image, pid, prog)
    stack.callback(os.close, link)
    return prog, link


def recursion_misses(prog):
    info = ctypes.create_string_buffer(216)
    struct.pack_into("<Q", info, 208, (1 << 64) - 1)
    bpf_call(15, struct.pack("<IIQ", prog, len(info), ctypes.addressof(info)))
    check(struct.unpack_from("<I", info)[0] == 2, "Wrong BPF program info type")
    return struct.unpack_from("<Q", info, 208)[0]


def receive(child, expected):
    check(select.select([child.stdout], [], [], 12)[0], f"Missing {expected} receipt")
    fields = child.stdout.readline().split()
    check(fields and fields[0] == expected, f"Unexpected {expected} receipt: {fields}")
    return fields[1:]


def send(child, command):
    child.stdin.write(command + "\n")
    child.stdin.flush()


def start(stack, out, app, mode):
    stderr = stack.enter_context((out / f"{mode}.stderr.txt").open("w", encoding="utf-8"))
    args = [single.HOST, app, "dynamic"] if mode == "dynamic" else [single.HOST, app]
    child = stack.enter_context(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                                                 text=True, user=1000, group=1000, extra_groups=[]))
    stack.callback(reap, child)
    return child


def reap(child):
    if child.poll() is None:
        child.kill()
        child.wait(timeout=5)


def outside_control(child, image):
    pid, tid = map(int, receive(child, "worker"))
    check(pid == child.pid, "Peer worker is outside the declared child")
    _, addresses = single.live_addresses(pid, tid, image)
    page = os.sysconf("SC_PAGE_SIZE")
    event_type = int(Path("/sys/bus/event_source/devices/uprobe/type").read_text())
    arms = {}
    with ExitStack() as probes_stack:
        probes = {}
        for site, (offset, _) in single.SITES.items():
            fd = single.open_probe(tid, image, offset, event_type)
            probes_stack.callback(os.close, fd)
            probes[site] = fd, probes_stack.enter_context(mmap.mmap(fd, 33 * page, flags=mmap.MAP_SHARED))
        for name in ("negative", "positive"):
            arms[name] = single.run_arm(child, name, probes, page, pid, tid, addresses)
    send(child, "close")
    check(child.wait(timeout=5) == 0, "Peer child did not exit")
    positive = arms["positive"]
    size = len(positive["samples"])
    check(arms["negative"]["gc_collection_deltas"] == [0] * 3 and not arms["negative"]["samples"]
          and positive["gc_collection_deltas"] == [12] * 3 and size > 0 and
          [x["site"] for x in positive["samples"]] == ["call", "return"] * (size // 2) and
          all(total == size // 2 and lost == 0 for total, _, lost in positive["counters"].values()),
          "Peer control failed to exercise exact callsite")
    return arms


def target_worker(target, image, counts):
    before = {int(path.name) for path in Path(f"/proc/{target.pid}/task").iterdir()}
    send(target, "birth")
    pid, tid = map(int, receive(target, "worker"))
    check(pid == target.pid and tid not in before, "Worker was not born after the gate")
    owner = single.live_addresses(pid, tid, image)
    worker = {"tid": tid, "start_ticks": owner[0], "arms": {}}
    for name, expected in (("negative", 0), ("positive", 20)):
        terminal_before = read_counts(counts)
        begin = time.monotonic_ns()
        send(target, name)
        delta = list(map(int, receive(target, name)))
        end = time.monotonic_ns()
        terminal_after = read_counts(counts)
        check(delta == [expected] * 3 and terminal_after[1:] == (0, 0, 0), "Worker arm failed GC or loss gate")
        check(single.live_addresses(pid, tid, image) == owner, "Worker lifetime changed while collecting")
        worker["arms"][name] = {"gc_deltas": delta, "clock": [begin, end],
                                "slots": [terminal_before[0], terminal_after[0]]}
    send(target, "retire")
    check(not receive(target, "retired"), "Invalid retirement receipt")
    return worker


def ordered_pairs(rows):
    check(len(rows) > 0 and [row[3] for row in rows] == [1, 2] * (len(rows) // 2)
          and all(left[4] < right[4] for left, right in zip(rows, rows[1:])), "Unpaired callsite receipts")
    return len(rows) // 2


def audit(raw, lifecycle, workers, target, folder, callsite_arm_ns):
    ledger = (folder / "scheduler-ledger.bin").read_bytes()
    check(lifecycle["status"] == "completed" and not lifecycle["cleanup_errors"]
          and hashlib.sha256(ledger).hexdigest() == lifecycle["ledger_sha256"] == lifecycle["second_read"]["ledger_sha256"]
          and lifecycle["terminal_counts"] == lifecycle["second_read"]["counts"], "Scheduler ledger parity failed")
    _, _, groups = decode_scheduler(ledger, lifecycle, folder.name)
    rows = [ROW.unpack_from(raw, offset) for offset in range(0, len(raw), ROW.size)]
    known = {worker["tid"] for worker in workers}
    baseline = {row["tid"] for row in lifecycle["prearm_cohort"]}
    check(len(known) == len(workers) and not known.intersection(baseline)
          and all(row[0] == index and row[1] == target and row[2] in known | baseline
         and row[3] in (1, 2) and row[4] > 0 and row[5] == 0 for index, row in enumerate(rows, 1)),
          "Unexpected callsite record or scope")
    counted = 0
    prearm = {}
    for worker in workers:
        matching = [(gen, group) for gen, group in groups.items() if group[0]["local_tid"] == worker["tid"]]
        check(len(matching) == 1, "Newborn lifecycle is missing or ambiguous")
        gen, group = matching[0]
        fields = {row["kind"]: row["mono_ns"] for row in group}
        check({"birth", "wake_new", "in", "out", "exit", "free"} <= fields.keys()
              and fields["birth"] > max(lifecycle["arm_complete_ns"], callsite_arm_ns),
              "Missing post-arm owned lifecycle")
        a, b = worker["arms"]["negative"]["slots"]
        c, d = worker["arms"]["positive"]["slots"]
        span = rows[c:d]
        selected = [row for row in span if row[2] == worker["tid"]]
        lo, hi = worker["arms"]["positive"]["clock"]
        check(a == b == c == counted and c < d <= len(rows) and all(lo < row[4] < hi for row in span)
              and all(fields["birth"] < row[4] < fields["exit"] for row in selected), "Callsite clock or arm differs")
        incidental = {row[2] for row in span if row[2] != worker["tid"]}
        check(incidental <= baseline, "Another newborn crossed the declared worker arm")
        for tid in incidental:
            prearm[tid] = prearm.get(tid, 0) + ordered_pairs([row for row in span if row[2] == tid])
        counted += len(span)
        worker.update(generation=gen, pairs=ordered_pairs(selected), lifecycle={
            name: fields[name] for name in ("birth", "wake_new", "exit", "free")})
    check(counted == len(rows), "Callsite records outside the declared arms")
    return {"rows": rows, "prearm_pairs": prearm}


def run(app, debug, out):
    verify_boundary_host()
    check(app.name == "GCWaitCallsiteFixture.dll", "Only the declared fixture is supported")
    image = RUNTIME / "libcoreclr.so"
    single.validate_image(image, debug)
    out.mkdir()
    report = {"status": "started", "workers": [], "fixture_sha256": single.sha(app.read_bytes()),
              "image_sha256": single.RUNTIME_SHA, "debug_sha256": single.DEBUG_SHA}
    lifecycle = SchedulerSession(out / "scheduler", host_check=verify_boundary_host)
    try:
        with ExitStack() as resources:
            target = start(resources, out, app, "dynamic")
            check(list(map(int, receive(target, "ready"))) == [target.pid], "Unexpected process leader")
            lifecycle.arm(target, out)
            ns = Path(f"/proc/{target.pid}/ns/pid").stat()
            counts = create_counts()
            resources.callback(os.close, counts)
            records = create_records()
            resources.callback(os.close, records)
            with ExitStack() as session:
                prog, link = load_and_attach(session, out, image, target.pid, ns, counts, records)
                fdinfo = Path(f"/proc/self/fdinfo/{link}").read_text()
                check(f"pid:\t{target.pid}\n" in fdinfo and f"path:\t{image}\n" in fdinfo
                      and "uprobe_cnt:\t2\n" in fdinfo, "Kernel link scope differs")
                (out / "attached-link.txt").write_text(fdinfo)
                report["arm_complete_ns"] = time.monotonic_ns()
                check(read_counts(counts) == (0, 0, 0, 0), "Activity before declared target arms")
                peer = start(session, out, app, "peer")
                report["peer"] = outside_control(peer, image)
                check(read_counts(counts) == (0, 0, 0, 0), "Peer activity leaked into target link")
                for _ in range(2):
                    report["workers"].append(target_worker(target, image, counts))
                terminal = read_counts(counts)
                report["terminal"] = terminal
                report["recursion_misses"] = recursion_misses(prog)
                check(report["recursion_misses"] == 0, "Callsite program missed recursive invocation")
            detached = read_counts(counts)
            raw = b"".join(read_record(records, index) for index in range(RECORD_CAPACITY))
            (out / "callsite-ledger.bin").write_bytes(raw)
            second = b"".join(read_record(records, index) for index in range(RECORD_CAPACITY))
            check(detached == terminal == read_counts(counts) and terminal[1:] == (0, 0, 0) and raw == second
                  and not any(raw[terminal[0] * ROW.size:]), "Callsite loss, trailing rows, or unstable drain")
            send(target, "close")
            check(target.wait(timeout=8) == 0, "Target child did not retire")
            lifecycle.finish(target, time.monotonic_ns())
            lifecycle.close()
            check(lifecycle.report["status"] == "completed", "Scheduler channel failed or did not clean up")
            report["audit"] = audit(raw[:terminal[0] * ROW.size], lifecycle.report, report["workers"],
                                    target.pid, lifecycle.folder, report["arm_complete_ns"])
            report.update(status="completed", ledger_sha256=hashlib.sha256(raw).hexdigest())
    except Exception as exc:
        report["failure"] = f"{type(exc).__name__}: {exc}"
        report["status"] = "failed"
        lifecycle.close()
        raise
    finally:
        single.save(out / "report.json", report)
    return report


def replay(attempt):
    report = json.loads((attempt / "report.json").read_bytes())
    check(report["recursion_misses"] == 0 and report["terminal"][1:] == [0, 0, 0], "Capture counters failed")
    raw = (attempt / "callsite-ledger.bin").read_bytes()
    used = report["terminal"][0]
    check(0 < used <= RECORD_CAPACITY and len(raw) == ROW.size * RECORD_CAPACITY
          and not any(raw[used * ROW.size:]), "Invalid saved callsite ledger")
    folder = attempt / "scheduler"
    scheduler = json.loads((folder / "scheduler.json").read_bytes())
    pid = scheduler["target_pid"]
    link = (attempt / "attached-link.txt").read_text()
    check(f"pid:\t{pid}\n" in link and "uprobe_cnt:\t2\n" in link and "link_type:\tuprobe_multi\n" in link,
          "Saved link scope differs")
    peer = report["peer"]["positive"]
    check(peer["samples"] and all(row["pid"] != pid for row in peer["samples"])
          and all(x[2] == 0 for x in peer["counters"].values()), "Saved peer control differs")
    result = audit(raw[:used * ROW.size], scheduler, report["workers"], pid, folder, report["arm_complete_ns"])
    return {"workers": report["workers"], "ledger_sha256": hashlib.sha256(raw).hexdigest(), **result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("app", "debug", "output"):
        parser.add_argument("--" + field, type=Path)
    parser.add_argument("--replay", type=Path)
    args = parser.parse_args()
    if args.replay and not args.app and not args.debug and args.output:
        check(not args.output.exists(), "Replay output must be a fresh path")
        single.save(args.output, replay(args.replay))
    elif not args.replay and args.app and args.debug and args.output:
        report = run(args.app.resolve(), args.debug.resolve(), args.output.resolve())
        print(json.dumps({"status": report["status"], "worker_pairs": [worker["pairs"] for worker in report["workers"]]}))
    else:
        parser.error("Specify --app and --debug for capture, or --replay, and an --output path")
