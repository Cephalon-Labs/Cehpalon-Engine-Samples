"""Observe the same WKS GCEvent operand at the exact reset, wait and set sites."""
import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import time

import collect_coreclr_gc_wait_fixture as single
import collect_coreclr_gc_wait_newborn as newborn
from collect_clr_scheduler_boundary import verify_boundary_host
from collect_scheduler_clr_fixture import RUNTIME
from roslyn_scheduler_session import SchedulerSession
from scheduler_dynamic_btf import Btf
from scheduler_dynamic_native_io import create_counts, create_records, read_counts, read_record, RECORD_CAPACITY
from scheduler_trace_model import decode_scheduler


SITES = {**single.SITES, "wait": (0x1F3F2B, "e990c0f4ff"),
         "set": (0x1C3CDC, "e90fbdf7ff"), "reset": (0x1C3CFC, "e91fbcf7ff")}
LABELS = ("", *SITES)
check = single.check


def verify_sites(image, debug):
    verify_boundary_host()
    single.validate_image(image, debug)
    raw = image.read_bytes()
    for offset, expected in SITES.values():
        check(raw[offset:offset + len(expected) // 2].hex() == expected, "Exact event site bytes differ")
    btf = Btf(Path("/sys/kernel/btf/vmlinux").read_bytes())
    reg = btf.structure("pt_regs")
    index, ref, offset = btf.member(reg, "di")
    btf.integer(ref, 8, False)
    check(index == 14 and offset == 112 and btf.types[reg].size_or_reference == 168, "Unexpected RDI BTF layout")


def decode(raw, total, owner, capacity=RECORD_CAPACITY):
    row = newborn.ROW
    check(0 <= total <= capacity and len(raw) == capacity * row.size
          and not any(raw[total * row.size:]), "Invalid object ledger shape")
    tokens, normalized = {}, []
    for index, (slot, pid, tid, kind, stamp, operand) in enumerate(row.iter_unpack(raw[:total * row.size]), 1):
        check(index == slot and pid == owner and tid > 0 and stamp > 0 and 1 <= kind <= 5
              and ((operand == 0) if kind < 3 else (0 < operand < 1 << 63 and operand % 8 == 0)),
              "Malformed operand or process scope")
        token = tokens.setdefault(operand, len(tokens) + 1) if operand else None
        normalized.append({"slot": slot, "tid": tid, "site": LABELS[kind], "ns": stamp, "object_token": token})
    return normalized


def worker_chains(worker_records, arm_rows, lifecycle):
    markers = [r for r in worker_records if r["site"] in ("call", "return")]
    check([row["site"] for row in markers] == ["call", "return"] * (len(markers) // 2)
          and all(a["ns"] < b["ns"] and a["slot"] < b["slot"] for a, b in zip(markers, markers[1:])),
          "Unexpected unpaired target callsite")
    chains = []
    for call, ret in zip(markers[::2], markers[1::2]):
        waits = [r for r in worker_records if r["site"] == "wait" and call["ns"] < r["ns"] < ret["ns"]]
        if len(waits) != 1:
            continue
        wait = waits[0]
        token = wait["object_token"]
        changes = sorted((r for r in arm_rows if r["site"] in ("reset", "set") and r["object_token"] == token),
                         key=lambda r: r["ns"])
        before = [r for r in changes if r["ns"] < wait["ns"]]
        after = [r for r in changes if wait["ns"] < r["ns"] < ret["ns"]]
        if not before or before[-1]["site"] != "reset" or len(after) != 1 or after[0]["site"] != "set":
            continue
        reset, setter = before[-1], after[0]
        if reset["tid"] != setter["tid"] or setter["tid"] == wait["tid"]:
            continue
        events = [r for r in lifecycle if wait["ns"] < r["mono_ns"] < ret["ns"]]
        candidates = []
        for i in range(len(events) - 3):
            points = events[i:i + 4]
            if ([r["kind"] for r in points] == ["out", "waking", "wakeup", "in"]
                    and all(a["mono_ns"] < b["mono_ns"] and a["slot"] < b["slot"]
                            for a, b in zip(points, points[1:]))
                    and points[0]["mono_ns"] < setter["ns"] < points[1]["mono_ns"]):
                candidates.append(points)
        if len(candidates) == 1:
            chains.append({"call": call["slot"], "reset": reset["slot"], "wait": wait["slot"],
                           "set": setter["slot"], "return": ret["slot"], "object_token": token,
                           "worker_tid": wait["tid"], "setter_tid": setter["tid"],
                           "worker_scheduler_rows": candidates[0]})
    return len(markers) // 2, chains


def replay(rows, session, workers, arm_ns):
    ledger = (session.folder / "scheduler-ledger.bin").read_bytes()
    _, _, groups = decode_scheduler(ledger, session.report, session.folder.name)
    cohort = {row["tid"] for row in session.report["prearm_cohort"]}
    known = {worker["tid"] for worker in workers}
    check(len(known) == len(workers) and not known & cohort and all(row["tid"] in cohort | known for row in rows),
          "Receipt from an unknown or reused fixture TID")
    consumed = 0
    summary = []
    chains = []
    for worker in workers:
        tid = worker["tid"]
        matches = [(generation, group) for generation, group in groups.items() if group[0]["local_tid"] == tid]
        check(len(matches) == 1, "Missing newborn scheduler lifetime")
        generation, lifecycle = matches[0]
        endpoints = {r["kind"]: r["mono_ns"] for r in lifecycle}
        check({"birth", "wake_new", "in", "out", "exit", "free"} <= endpoints.keys()
              and endpoints["birth"] > arm_ns, "Missing post-arm lifecycle")
        start, end = worker["arms"]["negative"]["slots"]
        a, b = worker["arms"]["positive"]["slots"]
        low, high = worker["arms"]["positive"]["clock"]
        span = rows[a:b]
        own = [row for row in span if row["tid"] == tid]
        check(start == end == a == consumed and a < b <= len(rows)
              and all(low < row["ns"] < high and row["tid"] in cohort | {tid} for row in span)
              and all(endpoints["birth"] < row["ns"] < endpoints["exit"] for row in own),
              "Invalid worker arm or outside-lifetime receipt")
        pairs, matches = worker_chains(own, span, lifecycle)
        chains.extend(matches)
        summary.append({"tid": tid, "generation": generation, "exact_call_pairs": pairs,
                        "wait_branches": sum(row["site"] == "wait" for row in own), "strict_chains": len(matches)})
        consumed = b
    check(consumed == len(rows), "Unassigned object receipts")
    return {"workers": summary, "chains": chains, "roles": dict(Counter(row["site"] for row in rows)),
            "object_tokens": sorted({r["object_token"] for r in rows if r["object_token"] is not None})}


def run(app, debug, out):
    check(app.name == "GCWaitCallsiteFixture.dll"
          and single.sha(app.read_bytes()) == "5ff25a0d0eed94fcf61f4f342f53ed9df87689f58d78bdc3b8bb7080cfb859a6",
          "Expected the existing frozen two-newborn fixture")
    image = RUNTIME / "libcoreclr.so"
    verify_sites(image, debug)
    out.mkdir()
    lifecycle = SchedulerSession(out / "scheduler", host_check=verify_boundary_host)
    report = {"status": "started", "workers": [], "sites": SITES}
    try:
        with ExitStack() as resources:
            target = newborn.start(resources, out, app, "dynamic")
            check(newborn.receive(target, "ready") == [str(target.pid)], "Expected ready owned leader")
            lifecycle.arm(target, out)
            counts = create_counts()
            resources.callback(os.close, counts)
            records = create_records()
            resources.callback(os.close, records)
            namespace = Path(f"/proc/{target.pid}/ns/pid").stat()
            prog = newborn.load_callsite(out, target.pid, namespace, counts, records, RECORD_CAPACITY, object_sites=True)
            resources.callback(os.close, prog)
            with ExitStack() as links:
                link = newborn.attach_callsite(image, target.pid, prog, SITES)
                links.callback(os.close, link)
                info = Path(f"/proc/self/fdinfo/{link}").read_text()
                (out / "attached-link.txt").write_text(info)
                check(f"pid:\t{target.pid}\n" in info and f"path:\t{image}\n" in info and "uprobe_cnt:\t5\n" in info
                      and newborn.recursion_misses(prog) == 0 and read_counts(counts) == (0, 0, 0, 0),
                      "Unexpected link owner, site count or pre-arm counter")
                arm = time.monotonic_ns()
                peer = newborn.start(links, out, app, "peer")
                report["peer"] = newborn.outside_control(peer, image)
                check(read_counts(counts) == (0, 0, 0, 0), "Peer leaked into the process-scoped ledger")
                for _ in range(2):
                    report["workers"].append(newborn.target_worker(target, image, counts))
                terminal = read_counts(counts)
            raw = b"".join(read_record(records, i) for i in range(RECORD_CAPACITY))
            (out / "object-ledger.private.bin").write_bytes(raw)
            second = b"".join(read_record(records, i) for i in range(RECORD_CAPACITY))
            report.update(terminal=terminal, detached=read_counts(counts), recursion_misses=newborn.recursion_misses(prog),
                          raw_private_sha256=hashlib.sha256(raw).hexdigest(), second_sha256=hashlib.sha256(second).hexdigest(),
                          arm_complete_ns=arm)
            check(terminal == report["detached"] and terminal[1:] == (0, 0, 0)
                  and report["recursion_misses"] == 0 and raw == second, "Loss or detached object ledger drift")
            newborn.send(target, "close")
            check(target.wait(timeout=8) == 0, "Target did not exit")
            lifecycle.finish(target, time.monotonic_ns())
            lifecycle.close()
            check(lifecycle.report["status"] == "completed", "Scheduler capture failed")
            rows = decode(raw, terminal[0], target.pid)
            single.save(out / "object-ledger.tokens.json", rows)
            report["results"] = replay(rows, lifecycle, report["workers"], arm)
            check(report["results"]["chains"], "No fully linked wait-object chain")
            report["status"] = "completed"
    except Exception as exc:
        report.update(status="failed", failure=f"{type(exc).__name__}: {exc}")
        lifecycle.close()
        raise
    finally:
        single.save(out / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("app", "debug", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    args = parser.parse_args()
    result = run(args.app.resolve(), args.debug.resolve(), args.output.resolve())
    print(result["status"], len(result["results"]["chains"]))
