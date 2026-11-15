"""Compare identical CLR lifecycle capture with and without two boundary hooks."""

import argparse
import hashlib
import json
from pathlib import Path
import os
import struct
import sys
import traceback

import collect_scheduler_clr_fixture as clr
from collect_scheduler_boundary import boundary_attach, boundary_counts, value
from collect_scheduler_dynamic_fixture import check_misses, load, mono, own
from collect_scheduler_dynamic_multi import create_map
from scheduler_boundary_analysis import ROW, SLOTS
from scheduler_boundary_program import HOOKS, boundary_program
from scheduler_dynamic_native_io import BPF_F_RDONLY
from scheduler_dynamic_btf import Btf, extract_layout, layout_member


KERNEL_58 = "6.18.58.1-microsoft-standard-WSL2"
BTF_58 = "b7699f9e49a1a780b790e54ef454e69b8e97e7e1c8950881880e90c2f5ad9a11"


def verify_boundary_host():
    """Qualify the explicitly selected later kernel for this fixture only."""
    clr.require(sys.platform == "linux" and sys.byteorder == "little" and struct.calcsize("P") == 8
                and os.uname().machine == "x86_64" and os.uname().release == KERNEL_58 and os.geteuid() == 0,
                "expected pinned WSL 6.18.58.1 x86-64 root coordinator")
    data = Path("/sys/kernel/btf/vmlinux").read_bytes()
    clr.require(len(data) == 6037569 and hashlib.sha256(data).hexdigest() == BTF_58, "WSL BTF pin differs")
    structures = extract_layout(data)["structures"]
    expected = {"task_struct": {"pid": 1360, "tgid": 1364, "start_boottime": 1656, "thread_pid": 1464},
                "pid": {"level": 4, "numbers": 144}, "upid": {"nr": 0, "ns": 8},
                "pid_namespace": {"ns": 112}, "ns_common": {"inum": 24}}
    for name, offsets in expected.items():
        clr.require({key: value["offset"] for key, value in structures[name]["members"].items()} == offsets,
                    f"unexpected raw collector offsets for {name}")
    clr.require(structures["upid"]["size"] == 16, "unexpected upid stride")
    btf = Btf(data)
    ids = {name: btf.structure(name) for name in ("task_struct", "thread_info")}
    embedded = layout_member(btf, ids, ids["task_struct"], "thread_info", "thread_info")
    cpu = layout_member(btf, ids, ids["thread_info"], "cpu", (4, False))
    clr.require(embedded["offset"] + cpu["offset"] == 20, "unexpected target CPU offset")
    for hook in HOOKS.values():
        names = [i for i, t in enumerate(btf.types) if t and t.kind == 8
                 and btf.name_is(t.name_offset, ("btf_trace_" + hook).encode())]
        clr.require(len(names) == 1, f"expected one BTF type for {hook}")
        _, pointer = btf.resolve(names[0])
        clr.require(pointer.kind == 2, "raw callback type is not a pointer")
        prototype = btf.types[pointer.size_or_reference]
        clr.require(prototype.kind == 13 and prototype.entries == 2
                    and prototype.size_or_reference == 0, "raw callback prototype differs")
        data_arg, flag_arg = (struct.unpack_from("<II", data, prototype.tail_offset + offset)[1]
                              for offset in (0, 8))
        _, flag = btf.resolve(flag_arg)
        arg = btf.types[data_arg]
        clr.require(arg.kind == 2 and arg.size_or_reference == 0 and flag.kind == 1
                    and flag.size_or_reference == 1 and btf.name_is(flag.name_offset, b"_Bool"),
                    f"raw callback {hook} no longer receives a single bool")


def classify(raw, counts, lifecycle, callback):
    """Validate complete detached rows, pairing by generation and reservation order."""
    attempted, lost, faults, reserved = counts
    clr.require(0 < attempted <= SLOTS and lost == faults == reserved == 0
                and len(raw) == SLOTS * ROW.size and not any(raw[attempted * ROW.size:]),
                "boundary ledger did not reconcile")
    births = {r[7]: r[5] for r in clr.ROW.iter_unpack(lifecycle) if r[0] == 1}
    frees = {r[7] for r in clr.ROW.iter_unpack(lifecycle) if r[0] == 8}
    clr.require(set(births) == frees and births.get(callback["generation"]) == callback["local_tid"],
                "boundary callback is outside completed lifecycle identities")
    pending, seen, retired = {}, set(), set()
    pairs, prefixes, tails, reversed_body = [], [], [], []
    for index, row in enumerate(ROW.iter_unpack(raw[:attempted * ROW.size]), start=1):
        ordinal, generation, kind, flag, cpu, cpu_end, retired_flag, tid, begin, end = row
        clr.require(ordinal == index and generation in births and births[generation] == tid
                    and kind in (1, 2) and flag in (0, 1) and retired_flag in (0, 1)
                    and cpu < 32 and cpu_end < 32 and begin > 0 and end > 0
                    and (generation not in retired or retired_flag == 1), "invalid boundary row")
        if retired_flag:
            retired.add(generation)
        if end < begin:
            reversed_body.append(ordinal)
        if kind == 1:
            clr.require(generation not in pending, "nested scheduler invocation")
            pending[generation] = row
        elif generation in pending:
            prior = pending.pop(generation)
            pairs.append({"generation": generation, "entry": prior[0], "exit": ordinal,
                          "preempt_mode": bool(prior[3]), "is_switch": bool(flag),
                          "cpu_changed": cpu != prior[4]})
        else:
            clr.require(generation not in seen, "unexpected noninitial scheduler exit")
            prefixes.append({"generation": generation, "ordinal": ordinal,
                             "kind": "owned_newborn_exit" if flag and not retired_flag else "unknown_prefix"})
        seen.add(generation)
    for generation, row in sorted(pending.items()):
        clr.require(row[6] == 1, "closed generation has an unexplained open boundary")
        tails.append({"generation": generation, "ordinal": row[0], "kind": "unreturned_retired_entry"})
    worker = callback["generation"]
    clr.require(any(p["generation"] == worker and p["is_switch"] for p in pairs)
                and any(p["generation"] == worker and p["kind"] == "owned_newborn_exit" for p in prefixes),
                "managed callback lacked its newborn exit or a returned switch invocation")
    clr.require(2 * len(pairs) + len(prefixes) + len(tails) == attempted, "boundary rows were not conserved")
    return {"rows": attempted, "pairs": pairs, "prefixes": prefixes, "tails": tails,
            "backwards_body_ordinals": reversed_body, "callback_generation": worker,
            "physical_duration_certified": False}


class BoundaryHooks:
    def arm(self, resources, links, report, members):
        self.counts = own(resources, report, create_map(2, 4, 16, 1, BPF_F_RDONLY, b"ceph_clrb_count"))
        self.records = own(resources, report, create_map(2, 4, ROW.size, SLOTS, BPF_F_RDONLY, b"ceph_clrb_rows"))
        self.programs = []
        for name, hook in HOOKS.items():
            code = boundary_program(name, None, members, self.counts, self.records, SLOTS, None, worker_limit=clr.MEMBERS)
            fd, stage = load(resources, report, hook, code)
            stage["probe"] = "boundary_" + name
            self.programs.append((fd, stage))
            boundary_attach(links, report, hook, fd)
        clr.require(boundary_counts(self.counts) == (0, 0, 0, 0), "unexpected prework boundary output")

    def snapshot(self):
        self.before_detach = boundary_counts(self.counts)

    def read(self):
        return b"".join(value(self.records, slot, ROW.size) for slot in range(SLOTS))

    def finish(self, report):
        for fd, stage in self.programs:
            check_misses(fd, stage)
        raw = self.read()
        counts = boundary_counts(self.counts)
        second = self.read()
        report["boundary_ledger_hex"] = raw.hex()
        report["boundary_counts"] = counts
        report["boundary_second_read"] = {"counts": boundary_counts(self.counts),
                                          "sha256": hashlib.sha256(second).hexdigest()}
        clr.require(raw == second and self.before_detach == counts == report["boundary_second_read"]["counts"],
                    "detached boundary snapshots differ")
        report["boundary_analysis"] = classify(raw, counts, bytes.fromhex(report["ledger_hex"]),
                                               report["callback_binding"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", required=True, choices=("lifecycle", "boundary"))
    parser.add_argument("--kernel", choices=("original", "wsl-6.18.58.1"), default="original")
    args = parser.parse_args()
    report = {"mode": "off" if args.variant == "lifecycle" else "on", "variant": args.variant,
              "passed": False, "capture_ready": False, "programs": [], "attached_hooks": [],
              "controller": {"prepare_start_ns": mono()}, "seed_map_receipts": [], "closed_fds": 0,
              "cleanup_errors": [], "forced_cleanup": False}
    try:
        namespace = Path("/proc/self/ns/pid").stat().st_ino
        profile = clr.verify_host if args.kernel == "original" else verify_boundary_host
        clr.run("on", namespace, report, extension=BoundaryHooks() if args.variant == "boundary" else None,
                host_check=profile)
        report["passed"] = True
    except Exception as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error),
                             "traceback": traceback.format_exc()}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
