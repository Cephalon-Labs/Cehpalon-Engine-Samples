"""Fixed Roslyn workload with an additional generation-scoped boundary ledger."""

import argparse
import hashlib
from pathlib import Path

import capture_roslyn_scheduler as capture
from collect_clr_scheduler_boundary import verify_boundary_host
from collect_scheduler_boundary import boundary_attach, boundary_counts, value
from collect_scheduler_dynamic_fixture import check_misses, load, own
from collect_scheduler_dynamic_multi import create_map
from scheduler_boundary_analysis import ROW
from scheduler_boundary_program import HOOKS, ROSLYN_BOUNDARY_SLOTS, boundary_program
from scheduler_dynamic_native_io import BPF_F_RDONLY


class RoslynBoundaries:
    owned_fd_count = 6

    def __init__(self, output):
        self.output = output
        self.programs = []

    def arm(self, resources, links, report, members):
        self.counts = own(resources, report, create_map(2, 4, 16, 1, BPF_F_RDONLY, b"ceph_bnd_count"))
        self.records = own(resources, report, create_map(2, 4, ROW.size, ROSLYN_BOUNDARY_SLOTS,
                                                         BPF_F_RDONLY, b"ceph_bnd_rows"))
        for name, hook in HOOKS.items():
            program = boundary_program(name, None, members, self.counts, self.records,
                                       ROSLYN_BOUNDARY_SLOTS, None, worker_limit=64)
            fd, stage = load(resources, report, hook, program)
            stage["probe"] = "boundary_" + name
            self.programs.append((fd, stage))
            boundary_attach(links, report, hook, fd)
        capture.runtime.require(boundary_counts(self.counts) == (0, 0, 0, 0),
                                "boundary callbacks preceded ownership admission")

    def snapshot(self):
        self.before_detach = boundary_counts(self.counts)

    def finish(self, report):
        for fd, stage in self.programs:
            check_misses(fd, stage)
        raw = self.read()
        (self.output / "boundaries.bin").write_bytes(raw)
        second = self.read()
        report["boundary_counts"] = boundary_counts(self.counts)
        report["boundary_sha256"] = hashlib.sha256(raw).hexdigest()
        report["boundary_second_sha256"] = hashlib.sha256(second).hexdigest()
        used, lost, faults, reserved = report["boundary_counts"]
        capture.runtime.require(self.before_detach == report["boundary_counts"] and raw == second
                                and 0 < used <= ROSLYN_BOUNDARY_SLOTS and lost == faults == reserved == 0
                                and not any(raw[used * ROW.size:]), "boundary ledger did not reconcile")

    def read(self):
        return b"".join(value(self.records, slot, ROW.size) for slot in range(ROSLYN_BOUNDARY_SLOTS))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    capture.runtime.require(out != capture.ROOT / ".local" and out.is_relative_to(capture.ROOT / ".local"),
                            "fresh output under Samples .local is required")
    capture.run(out, host_check=verify_boundary_host, engine=args.engine.resolve(),
                session_options={"slots": 524288, "extension": RoslynBoundaries(out / "scheduler")})


if __name__ == "__main__":
    main()
