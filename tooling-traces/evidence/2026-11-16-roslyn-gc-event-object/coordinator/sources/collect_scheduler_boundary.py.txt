"""Fixed owned current-generation scheduler entry/exit native controls."""

import argparse
from contextlib import ExitStack
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

from collect_scheduler_dynamic_fixture import attach, await_park, check_misses, load, own, receive
from collect_scheduler_dynamic_multi import create_map, read_array, read_counts, wait_free
from preflight_scheduler_dynamic_verifier import verify_host
from preflight_scheduler_pidfd_seed import LOOKUP, UID, GID, UPDATE, check_element, finish_actor, lease, require
from preflight_scheduler_task_storage import bpf_call, create_task_storage, load_btf
from scheduler_boundary_program import HOOKS, boundary_program
from scheduler_dynamic_multi_program import PROBES, multi_program
from scheduler_dynamic_native_io import BPF_F_RDONLY, BPF_F_WRONLY
from scheduler_dynamic_program import ACK
from scheduler_clock_actor import Timespec


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8", newline="\n")


def value(fd, slot, size):
    key = ctypes.c_uint32(slot)
    buf = ctypes.create_string_buffer(size)
    bpf_call(1, struct.pack("<I4xQQQ", fd, ctypes.addressof(key), ctypes.addressof(buf), 0))
    return buf.raw


def boundary_counts(fd):
    return struct.unpack("<IIII", value(fd, 0, 16))


def reference():
    cell = Timespec()
    call = ctypes.CDLL(None, use_errno=True).syscall
    call.restype = ctypes.c_long
    require(call(ctypes.c_long(228), ctypes.c_long(1), ctypes.byref(cell)) == 0
            and cell.seconds >= 0 and 0 <= cell.nanoseconds < 1_000_000_000, 'raw reference failed')
    return cell.seconds*1_000_000_000+cell.nanoseconds


def leader_held(actor):
    deadline = time.monotonic()+1
    root = Path(f'/proc/{actor.pid}')
    while time.monotonic() < deadline:
        require(actor.poll() is None, 'leader exited before detach hold')
        try:
            call = (root/'syscall').read_text().split()
        except OSError as error:
            if error.errno != errno.EAGAIN:
                raise
            time.sleep(0.005)
            continue
        status = (root/'status').read_text().splitlines()
        state = next(line.split()[1] for line in status if line.startswith('State:'))
        if len(call) == 9 and call[0] == '0' and int(call[1], 0) == 0 and state == 'S':
            return {'syscall': 0, 'fd': 0, 'state': state, 'requested_bytes': int(call[3], 0),
                    'reference_ns': reference()}
        time.sleep(0.005)
    raise ValueError('leader did not return to its open command-pipe read')


def boundary_attach(resources, report, hook, fd):
    require(hook in HOOKS.values(), "unscoped boundary hook rejected")
    name = ctypes.create_string_buffer(hook.encode())
    link = own(resources, report, bpf_call(17, struct.pack("<QI4xQ", ctypes.addressof(name), fd, 0)))
    observed = {}
    for line in Path(f"/proc/self/fdinfo/{link}").read_text().splitlines():
        key, _, content = line.partition(':')
        if key in ('tp_name', 'cookie'):
            require(key not in observed, "duplicate boundary link field")
            observed[key] = content.strip()
    require(observed == {'tp_name': hook, 'cookie': '0'}, "boundary link name differs")
    report['attached_hooks'].append({'tp_name': hook, 'cookie': 0})


def command(actor, name, expected, **fields):
    actor.stdin.write((json.dumps({'command': name, **fields})+'\n').encode())
    actor.stdin.flush()
    return receive(actor, expected)


def execute(folder, capacity):
    folder.mkdir(parents=True, exist_ok=False)
    report = {'status': 'preparing', 'capacity': capacity, 'programs': [], 'attached_hooks': [],
              'closed_fds': 0, 'cleanup_errors': [], 'forced_cleanup': False, 'seed_map_receipts': []}
    try:
        with ExitStack() as resources:
            errors = resources.enter_context((folder/'actor.stderr.txt').open('xb'))
            argv = [sys.executable, '-I', '-S', '-B', str(Path(__file__).with_name('scheduler_boundary_actor.py'))]
            report['actor_command'] = argv
            actor = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                                     bufsize=0, user=UID, group=GID, extra_groups=[])
            resources.callback(finish_actor, actor, report)
            require(receive(actor, 'held')['pid'] == actor.pid, 'held actor identity differs')
            owner, alias, outsider = [own(resources, report, os.pidfd_open(pid))
                                      for pid in (actor.pid, actor.pid, os.getpid())]
            report['lease_before'] = lease(actor.pid, (owner, alias))
            require(os.path.samestat(Path(f'/proc/{actor.pid}/ns/time').stat(), Path('/proc/self/ns/time').stat()),
                    'time namespaces differ')
            report['timens_offsets'] = Path('/proc/self/timens_offsets').read_text()
            require(all(line.split()[1:] == ['0', '0'] for line in report['timens_offsets'].splitlines()),
                    'nonzero monotonic namespace offsets')
            btf = own(resources, report, load_btf())
            storage = own(resources, report, create_task_storage(btf))
            members = own(resources, report, create_map(1, 8, 32, 3, BPF_F_WRONLY, b'ceph_bnd_mem'))
            lifecycle_counts = own(resources, report, create_map(2, 4, 20, 1, BPF_F_RDONLY, b'ceph_bnd_lcnt'))
            lifecycle_rows = own(resources, report, create_map(2, 4, 40, 512, BPF_F_RDONLY, b'ceph_bnd_lrow'))
            counts = own(resources, report, create_map(2, 4, 16, 1, BPF_F_RDONLY, b'ceph_bnd_cnt'))
            rows = own(resources, report, create_map(2, 4, 48, 1024, BPF_F_RDONLY, b'ceph_bnd_row'))
            life = {}
            for name, (hook, _) in PROBES.items():
                fd, stage = load(resources, report, hook, multi_program(name, storage, members, lifecycle_counts,
                                  lifecycle_rows, 512, report['lease_before']['pid_namespace_inode'], 3))
                stage['probe'] = name
                life[name] = fd, stage
            boundary = {}
            for name, hook in HOOKS.items():
                fd, stage = load(resources, report, hook, boundary_program(name, storage, members, counts, rows,
                                                                          capacity, actor.pid))
                stage['probe'] = 'boundary_'+name
                boundary[name] = fd, stage
            report['reference_before_attach_ns'] = reference()
            with ExitStack() as links:
                for name, (fd, _) in life.items():
                    attach(links, report, PROBES[name][0], fd)
                for name, (fd, _) in boundary.items():
                    boundary_attach(links, report, HOOKS[name], fd)
                report['unseeded_yield'] = command(actor, 'yield', 'yield', cpu=0, count=8)
                call = ctypes.CDLL(None).syscall
                call.restype = ctypes.c_long
                report['nonmember_yield_return'] = call(ctypes.c_long(24))
                require(report['nonmember_yield_return'] == 0, 'nonmember yield failed')
                report['preadmission_boundary_counts'] = boundary_counts(counts)
                report['preadmission_lifecycle_counts'] = read_counts(lifecycle_counts)
                require(report['preadmission_boundary_counts'] == (0,)*4
                        and report['preadmission_lifecycle_counts'] == (0,)*5, 'preadmission emission')
                check_element(report['seed_map_receipts'], 'seed', UPDATE, storage, owner, value=ACK)
                check_element(report['seed_map_receipts'], 'alias_ack', LOOKUP, storage, alias, expected=ACK)
                check_element(report['seed_map_receipts'], 'outsider_absent', LOOKUP, storage, outsider,
                              expected_errno=errno.ENOENT)
                report['yield_batches'] = [command(actor, 'yield', 'yield', cpu=i%2, count=8) for i in range(8)]
                report['parked'] = command(actor, 'run', 'park')
                report['park_oracle'] = await_park(actor.pid, report['parked'], 1)
                report['joined'] = command(actor, 'wake', 'joined')
                require(report['joined']['worker_tid'] == report['parked']['worker_tid'], 'worker identity changed')
                wait_free(actor, report, lifecycle_counts, 1)
                report['lease_after'] = lease(actor.pid, (owner, alias))
                require(report['lease_after'] == report['lease_before'], 'leader lease changed')
                report['leader_detach_hold'] = leader_held(actor)
                report['before_detach_boundary_counts'] = boundary_counts(counts)
                report['before_detach_lifecycle_counts'] = read_counts(lifecycle_counts)
            report['reference_after_detach_ns'] = reference()
            for fd, stage in [*life.values(), *boundary.values()]:
                check_misses(fd, stage)
            raw = b''.join(value(rows, i, 48) for i in range(1024))
            legacy = b''.join(read_array(lifecycle_rows, i) for i in range(512))
            report['boundary_counts'] = boundary_counts(counts)
            report['lifecycle_counts'] = read_counts(lifecycle_counts)
            second = b''.join(value(rows, i, 48) for i in range(1024))
            second_legacy = b''.join(read_array(lifecycle_rows, i) for i in range(512))
            require(raw == second and legacy == second_legacy
                    and report['boundary_counts'] == report['before_detach_boundary_counts'] == boundary_counts(counts)
                    and report['lifecycle_counts'] == report['before_detach_lifecycle_counts'] == read_counts(lifecycle_counts),
                    'detached data changed')
            report['boundary_sha256'] = hashlib.sha256(raw).hexdigest()
            report['lifecycle_sha256'] = hashlib.sha256(legacy).hexdigest()
            report['second_hashes'] = [hashlib.sha256(second).hexdigest(), hashlib.sha256(second_legacy).hexdigest()]
            (folder/'boundary.bin').write_bytes(raw)
            (folder/'lifecycle.bin').write_bytes(legacy)
            from scheduler_boundary_analysis import analyze
            save(folder/'analysis.json', analyze(raw, report['boundary_counts'], capacity, legacy,
                                                 report['lifecycle_counts'], actor.pid))
            command(actor, 'finish', 'done')
            require(actor.wait(timeout=3) == 0, 'actor exit differs')
            check_element(report['seed_map_receipts'], 'reaped_absent', LOOKUP, storage, alias,
                          expected_errno=errno.ENOENT)
            report['status'] = 'completed'
    except Exception as error:
        report.update(status='failed', failure=type(error).__name__+': '+str(error))
        raise
    finally:
        if report['status'] == 'completed' and (report['closed_fds'] != 32 or report['cleanup_errors']
                                               or report['forced_cleanup']):
            report.update(status='failed', cleanup_failure=True)
        save(folder/'report.json', report)
    require(report['status'] == 'completed', 'boundary cleanup failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    allowed = Path(__file__).resolve().parents[1].parent/'Cehpalon-Engine-Docs/.local/scheduler-boundary01'
    out = args.output.resolve()
    require(out.is_relative_to(allowed) and out != allowed, 'fresh isolated boundary evidence directory required')
    verify_host()
    out.mkdir(parents=True, exist_ok=False)
    execute(out/'negative01', 1)
    execute(out/'positive01', 1024)
    print(json.dumps({'status':'completed', 'output':str(out)}))


if __name__ == '__main__':
    main()
