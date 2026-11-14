"""Fixed BPF I/O for the synthetic scheduler probe on the pinned WSL host.

The caller verifies the host before creating resources and owns every returned FD.
Read helpers take the corresponding map FD created by this module.
"""

import ctypes
import struct

from preflight_scheduler_dynamic_verifier import BPF_PROG_TYPE_RAW_TRACEPOINT
from preflight_scheduler_task_storage import BPF_MAP_CREATE, bpf_call


BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_RAW_TRACEPOINT_OPEN = 17
BPF_F_RDONLY = 1 << 3
BPF_F_WRONLY = 1 << 4
PRIVATE_STATE_BYTES = 24
COUNTS = struct.Struct("<IIII")
RECORD_BYTES = 32
RECORD_CAPACITY = 512

RAW_HOOKS = frozenset({
    "sys_enter",
    "task_newtask",
    "sched_wakeup_new",
    "sched_switch",
    "sched_waking",
    "sched_wakeup",
    "sched_process_exit",
    "sched_process_free",
    "sched_prepare_exec",
})

# Pinned x86-64 bpf_prog_info prefix through the aligned u64 recursion_misses.
RECURSION_MISSES_OFFSET = 208
PROG_INFO_BYTES = RECURSION_MISSES_OFFSET + 8
MISSING_COUNTER = (1 << 64) - 1


def _create_array(name, value_size, capacity, flags):
    attr = struct.pack("<7I16s", BPF_MAP_TYPE_ARRAY, 4, value_size, capacity, flags, 0, 0, name)
    return bpf_call(BPF_MAP_CREATE, attr)


def create_private_state():
    """Allow program access while the caller's map FD denies element reads."""
    return _create_array(b"ceph_dyn_state", PRIVATE_STATE_BYTES, 1, BPF_F_WRONLY)


def create_counts():
    return _create_array(b"ceph_dyn_counts", COUNTS.size, 1, BPF_F_RDONLY)


def create_records():
    return _create_array(b"ceph_dyn_rows", RECORD_BYTES, RECORD_CAPACITY, BPF_F_RDONLY)


def _lookup_array(map_fd, index):
    key = ctypes.c_uint32(index)
    # The largest value among this probe's fixed maps also covers either reader.
    value = ctypes.create_string_buffer(RECORD_BYTES)
    attr = struct.pack("<I4xQQQ", map_fd, ctypes.addressof(key), ctypes.addressof(value), 0)
    bpf_call(BPF_MAP_LOOKUP_ELEM, attr)
    return value.raw


def read_counts(map_fd):
    """Return attempted, failed, faults and free-completed counts."""
    return COUNTS.unpack_from(_lookup_array(map_fd, 0))


def read_record(map_fd, index):
    if type(index) is not int or not 0 <= index < RECORD_CAPACITY:
        raise ValueError("record index is outside the fixed capture array")
    return _lookup_array(map_fd, index)


def attach_raw_tracepoint(hook, prog_fd):
    if not isinstance(hook, str) or hook not in RAW_HOOKS:
        raise ValueError("raw tracepoint is outside the synthetic probe allowlist")
    name = ctypes.create_string_buffer(hook.encode("ascii"))
    attr = struct.pack("<QI4xQ", ctypes.addressof(name), prog_fd, 0)
    return bpf_call(BPF_RAW_TRACEPOINT_OPEN, attr)


def validate_link_fdinfo(fdinfo, hook):
    """Check the attached hook name and zero cookie in the link's proc fdinfo."""
    if not isinstance(hook, str) or hook not in RAW_HOOKS:
        raise ValueError("raw tracepoint is outside the synthetic probe allowlist")
    observed = {}
    for line in fdinfo.splitlines():
        key, _, value = line.partition(":")
        if key in {"tp_name", "cookie"}:
            if key in observed:
                raise ValueError("duplicate raw-tracepoint link field")
            observed[key] = value.strip()
    if observed != {"tp_name": hook, "cookie": "0"}:
        raise ValueError("raw-tracepoint link fdinfo differs from the requested hook")
    return {"tp_name": observed["tp_name"], "cookie": 0}


def recursion_misses(prog_fd):
    """Read only the miss counter from the owned raw-tracepoint program info."""
    info = ctypes.create_string_buffer(PROG_INFO_BYTES)
    struct.pack_into("<Q", info, RECURSION_MISSES_OFFSET, MISSING_COUNTER)
    attr = struct.pack("<IIQ", prog_fd, PROG_INFO_BYTES, ctypes.addressof(info))
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, attr)
    prog_type, prog_id = struct.unpack_from("<II", info)
    misses, = struct.unpack_from("<Q", info, RECURSION_MISSES_OFFSET)
    if prog_type != BPF_PROG_TYPE_RAW_TRACEPOINT or prog_id == 0 or misses == MISSING_COUNTER:
        raise ValueError("raw-tracepoint program info did not supply a valid miss counter")
    return misses
