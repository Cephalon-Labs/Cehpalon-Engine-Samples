"""Add the exact CoreCLR GC wait callsite ledger to the scoped Roslyn session."""
import hashlib
from pathlib import Path

from capture_roslyn_boundaries import RoslynBoundaries
from collect_coreclr_gc_wait_fixture import check
from collect_coreclr_gc_wait_newborn import ROW, attach_callsite, load_callsite, recursion_misses
from collect_scheduler_boundary import value
from collect_scheduler_clr_fixture import RUNTIME
from collect_scheduler_dynamic_fixture import own
from collect_scheduler_dynamic_multi import create_map
from scheduler_dynamic_native_io import BPF_F_RDONLY, create_counts, read_counts


CAPACITY = 16384


class RoslynGcCallsite(RoslynBoundaries):
    owned_fd_count = RoslynBoundaries.owned_fd_count + 4

    def arm(self, resources, links, report, members):
        super().arm(resources, links, report, members)
        pid = report["target_pid"]
        image = RUNTIME / "libcoreclr.so"
        ns = Path(f"/proc/{pid}/ns/pid").stat()
        check(ns.st_ino == report["namespace_inode"], "Target namespace differs")
        self.site_counts = own(resources, report, create_counts())
        self.site_records = own(resources, report, create_map(2, 4, ROW.size, CAPACITY, BPF_F_RDONLY, b"ceph_site_rows"))
        self.site_prog = own(resources, report, load_callsite(self.output, pid, ns, self.site_counts,
                                                             self.site_records, CAPACITY))
        self.initial_misses = recursion_misses(self.site_prog)
        link = own(links, report, attach_callsite(image, pid, self.site_prog))
        fdinfo = Path(f"/proc/self/fdinfo/{link}").read_text()
        (self.output / "callsite-link.txt").write_text(fdinfo)
        check(f"pid:\t{pid}\n" in fdinfo and f"path:\t{image}\n" in fdinfo and "uprobe_cnt:\t2\n" in fdinfo
              and "link_type:\tuprobe_multi\n" in fdinfo and self.initial_misses == 0,
              "Callsite link scope or initial miss counter differs")
        check(read_counts(self.site_counts) == (0, 0, 0, 0), "Callsite activity before runtime resume")
        report["callsite_capacity"] = CAPACITY

    def snapshot(self):
        super().snapshot()
        self.sites_before_detach = read_counts(self.site_counts)

    def read_sites(self):
        return b"".join(value(self.site_records, slot, ROW.size) for slot in range(CAPACITY))

    def finish(self, report):
        raw = self.read_sites()
        (self.output / "callsite-ledger.bin").write_bytes(raw)
        second = self.read_sites()
        terminal = read_counts(self.site_counts)
        misses = recursion_misses(self.site_prog)
        report.update(callsite_terminal=terminal, callsite_before_detach=self.sites_before_detach,
                      callsite_sha256=hashlib.sha256(raw).hexdigest(),
                      callsite_second_sha256=hashlib.sha256(second).hexdigest(), callsite_recursion_misses=misses)
        used, lost, faults, reserved = terminal
        check(terminal == self.sites_before_detach and raw == second and 0 <= used <= CAPACITY
              and lost == faults == reserved == misses == 0 and not any(raw[used * ROW.size:]),
              "Callsite ledger publication, detached read, or loss gate failed")
        super().finish(report)
