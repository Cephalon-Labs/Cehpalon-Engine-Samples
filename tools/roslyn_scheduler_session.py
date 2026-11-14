"""Scoped scheduler resources for a suspended ordinary Roslyn diagnostic target."""

from contextlib import ExitStack
import errno
import hashlib
import json
from pathlib import Path
import struct
import time

from collect_scheduler_clr_fixture import RUNTIME, bind_cohort, cohort, read_array, verify_process
from collect_scheduler_dynamic_fixture import attach, check_misses, load, mono, own
from collect_scheduler_dynamic_multi import create_map
from preflight_scheduler_dynamic_verifier import verify_host
from preflight_scheduler_pidfd_seed import LOOKUP, UPDATE, check_element, require
from preflight_scheduler_task_storage import create_task_storage, load_btf
from scheduler_dynamic_native_io import BPF_F_RDONLY, BPF_F_WRONLY, BPF_MAP_TYPE_ARRAY
from scheduler_dynamic_program import ACK
from scheduler_roslyn_program import PROBES, roslyn_program


SLOTS = 262144
MEMBERS = 64


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


class SchedulerSession:
    def __init__(self, folder, *, host_check=verify_host, slots=SLOTS, extension=None):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=False)
        self.resources = ExitStack()
        self.links = ExitStack()
        self.report = {"status": "preparing", "programs": [], "attached_hooks": [],
                       "seed_map_receipts": [], "closed_fds": 0, "cleanup_errors": [],
                       "capture_ready": False}
        self.programs = {}
        self.host_check = host_check
        self.slots = slots
        self.extension = extension
        if slots != SLOTS:
            self.report["lifecycle_slots"] = slots

    def counts(self):
        return struct.unpack_from("<IIIIII", read_array(self.count_fd, 0))

    def arm(self, target, folder):
        self.host_check()
        offsets = [line.split() for line in Path("/proc/self/timens_offsets").read_text().splitlines()]
        require(["monotonic", "0", "0"] in offsets
                and "CLOCK_MONOTONIC" in time.get_clock_info("perf_counter").implementation,
                "zero-offset monotonic clock is required")
        self.report["time_namespace_offsets"] = offsets
        self.target = target
        namespace = Path("/proc/self/ns/pid").stat().st_ino
        self.report.update(target_pid=target.pid, namespace_inode=namespace)
        deadline = time.monotonic() + 10
        expected = str((RUNTIME / "libcoreclr.so").resolve())
        samples = self.report["runtime_ready_samples"] = []
        previous = None
        while time.monotonic() < deadline:
            require(target.poll() is None, "owned target exited before runtime readiness")
            maps = Path("/proc", str(target.pid), "maps").read_text().splitlines()
            loaded = {parts[5] for line in maps if len(parts := line.split(maxsplit=5)) == 6
                      and parts[5].endswith("/libcoreclr.so")}
            require(not loaded or loaded == {expected}, "unexpected CoreCLR mapped before arm")
            if loaded:
                current = cohort(target)
                samples.append({"mono_ns": mono(), "cohort": current})
                if current == previous:
                    break
                previous = current
            time.sleep(0.01)
        else:
            raise ValueError("pinned CoreCLR and stable cohort were not ready within ten seconds")
        verify_process(target, namespace)
        self.report.update(target_pid=target.pid, namespace_inode=namespace,
                           arm_begin_ns=mono(), parent_group_scope="held ordinary direct child")
        owner, alias, nonmember, siblings = bind_cohort(target, self.resources, self.report)
        btf = own(self.resources, self.report, load_btf())
        storage = own(self.resources, self.report, create_task_storage(btf))
        for tid, fd in {target.pid: owner, **siblings}.items():
            check_element(self.report["seed_map_receipts"], f"seed_{tid}", UPDATE, storage, fd, value=ACK)
            check_element(self.report["seed_map_receipts"], f"read_{tid}", LOOKUP, storage, fd, expected=ACK)
        check_element(self.report["seed_map_receipts"], "collector_absent", LOOKUP, storage, nonmember,
                      expected_errno=errno.ENOENT)
        members = own(self.resources, self.report,
                      create_map(1, 8, 32, MEMBERS, BPF_F_WRONLY, b"ceph_ros_member"))
        self.count_fd = own(self.resources, self.report,
                            create_map(BPF_MAP_TYPE_ARRAY, 4, 24, 1, BPF_F_RDONLY, b"ceph_ros_count"))
        self.record_fd = own(self.resources, self.report,
                             create_map(BPF_MAP_TYPE_ARRAY, 4, 40, self.slots, BPF_F_RDONLY, b"ceph_ros_rows"))
        initial_limit = len(self.report["prearm_cohort"])
        for name, (hook, _) in PROBES.items():
            code = roslyn_program(name, storage, members, self.count_fd, self.record_fd,
                                  namespace, initial_limit, slots=self.slots)
            try:
                fd, stage = load(self.resources, self.report, hook, code)
            finally:
                self.report["programs"][-1]["probe"] = name
            self.programs[name] = fd, stage
        attach_order = [name for name in self.programs if name != "prearm"] + ["prearm"]
        for name in attach_order:
            if name == "prearm" and self.extension is not None:
                self.extension.arm(self.resources, self.links, self.report, members)
            fd, _ = self.programs[name]
            attach(self.links, self.report, PROBES[name][0], fd)
        require(cohort(target) == self.report["prearm_cohort"], "suspended pre-arm cohort changed")
        self.report["fully_armed_counts"] = self.counts()
        require(self.report["fully_armed_counts"][1:3] == (0, 0),
                "scheduler loss or fault occurred before resume")
        self.report.update(status="armed", arm_complete_ns=mono())
        save(self.folder / "scheduler.json", self.report)

    def finish(self, target, exited_ns):
        self.report["target_exit_observed_ns"] = exited_ns
        try:
            deadline = exited_ns + 2_000_000_000
            while mono() <= deadline:
                terminal = self.counts()
                attempted, lost, faults, frees, total, initial = terminal
                require(lost == faults == 0 and 0 < total <= MEMBERS
                        and frees <= total and initial <= len(self.report["prearm_cohort"]),
                        "scheduler scope, loss or fault counter failed")
                if frees == total:
                    self.report["terminal_before_detach"] = terminal
                    break
                time.sleep(0.005)
            else:
                raise ValueError("missing terminal scheduler frees inside two-second tail")
            if self.extension is not None:
                self.extension.snapshot()
            self.links.close()
            for fd, stage in self.programs.values():
                check_misses(fd, stage)
            self.report["terminal_counts"] = self.counts()
            raw = b"".join(read_array(self.record_fd, slot) for slot in range(self.slots))
            (self.folder / "scheduler-ledger.bin").write_bytes(raw)
            time.sleep(0.01)
            second = b"".join(read_array(self.record_fd, slot) for slot in range(self.slots))
            self.report["second_read"] = {"counts": self.counts(), "ledger_sha256": hashlib.sha256(second).hexdigest()}
            require(self.report["terminal_counts"] == self.report["terminal_before_detach"]
                    == self.report["second_read"]["counts"] and raw == second,
                    "scheduler terminal ledger changed")
            used = self.report["terminal_counts"][0]
            require(0 < used <= self.slots and not any(raw[used * 40:]), "scheduler array publication accounting failed")
            if self.extension is not None:
                self.extension.finish(self.report)
            self.report.update(status="completed", ledger_sha256=hashlib.sha256(raw).hexdigest(),
                               terminal_read_end_ns=mono())
        except Exception as error:
            self.report.update(status="failed", failure=type(error).__name__ + ": " + str(error))
        finally:
            self.links.close()
            save(self.folder / "scheduler.json", self.report)

    def close(self):
        self.links.close()
        self.resources.close()
        expected = len(self.report.get("prearm_cohort", [])) + 27 + (6 if self.extension is not None else 0)
        if self.report["cleanup_errors"] or (self.report["status"] == "completed"
                                            and self.report["closed_fds"] != expected):
            self.report.update(status="failed", cleanup_failure=True)
        save(self.folder / "scheduler.json", self.report)
