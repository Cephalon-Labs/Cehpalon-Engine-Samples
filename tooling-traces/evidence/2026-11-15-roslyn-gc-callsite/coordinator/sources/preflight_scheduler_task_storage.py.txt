"""Verify task-storage creation and typed-current lookup on the pinned WSL kernel."""

import argparse
import ctypes
import json
import os
import struct

from preflight_scheduler_dynamic_verifier import (
    BPF_PROG_LOAD,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BTF_SHA256,
    LOG_SIZE,
    RELEASE,
    SYS_BPF,
    instruction,
    verify_host,
)


BPF_MAP_CREATE = 0
BPF_BTF_LOAD = 18
BPF_MAP_TYPE_TASK_STORAGE = 29
BPF_F_NO_PREALLOC = 1
KEY_TYPE_ID = 1
VALUE_TYPE_ID = 2
KEY_SIZE = 4
VALUE_SIZE = 8


def storage_btf_bytes():
    """Describe an int32 pidfd key and a uint64 cookie in BTF v1."""
    strings = b"\0int\0u64\0"
    types = struct.pack(
        "<8I",
        1, 1 << 24, KEY_SIZE, (1 << 24) | 32,
        5, 1 << 24, VALUE_SIZE, 64,
    )
    return struct.pack("<HBB5I", 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings


def map_create_attr(btf_fd):
    return struct.pack(
        "<7I16s5I",
        BPF_MAP_TYPE_TASK_STORAGE, KEY_SIZE, VALUE_SIZE, 0, BPF_F_NO_PREALLOC, 0, 0,
        b"ceph_task_seed", 0, btf_fd, KEY_TYPE_ID, VALUE_TYPE_ID, 0,
    )


def program_bytes(map_fd):
    return b"".join((
        instruction(0x85, imm=158),  # bpf_get_current_task_btf()
        instruction(0xBF, dst=2, src=0),
        instruction(0x18, dst=1, src=1, imm=map_fd),  # BPF_PSEUDO_MAP_FD
        instruction(0),
        instruction(0xB7, dst=3),  # No initial value.
        instruction(0xB7, dst=4),  # Lookup only. Do not create an entry.
        instruction(0x85, imm=156),  # bpf_task_storage_get(map, task, NULL, 0)
        struct.pack("<BBhi", 0x15, 0, 1, 0),  # If null, skip the cookie read.
        instruction(0x79, dst=1, src=0),  # Read the full 8-byte cookie.
        instruction(0xB7, dst=0),
        instruction(0x95),
    ))


def bpf_call(command, attr):
    buffer = ctypes.create_string_buffer(attr, len(attr))
    syscall = ctypes.CDLL(None, use_errno=True).syscall
    syscall.restype = ctypes.c_long
    result = syscall(ctypes.c_long(SYS_BPF), ctypes.c_int(command), ctypes.byref(buffer),
                     ctypes.c_uint(ctypes.sizeof(buffer)))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def load_btf(log=None):
    if log is None:
        log = ctypes.create_string_buffer(LOG_SIZE)
    btf = storage_btf_bytes()
    data = ctypes.create_string_buffer(btf)
    attr = struct.pack(
        "<QQIIII",
        ctypes.addressof(data), ctypes.addressof(log), len(btf), len(log), 2, 0,
    )
    return bpf_call(BPF_BTF_LOAD, attr)


def create_task_storage(btf_fd):
    return bpf_call(BPF_MAP_CREATE, map_create_attr(btf_fd))


def load_program(code, log):
    insns = ctypes.create_string_buffer(code)
    license_text = ctypes.create_string_buffer(b"GPL")
    attr = struct.pack(
        "<IIQQIIQII16sII",
        BPF_PROG_TYPE_RAW_TRACEPOINT, len(code) // 8,
        ctypes.addressof(insns), ctypes.addressof(license_text),
        2, len(log), ctypes.addressof(log), 0, 0, b"ceph_task_probe", 0, 0,
    )
    return bpf_call(BPF_PROG_LOAD, attr)


def run_probe():
    """Create and close only the three objects required by the unattached probe."""
    result = {
        "kernel_release": RELEASE,
        "kernel_btf_sha256": BTF_SHA256,
        "map_btf_hex": storage_btf_bytes().hex(),
        "map_attr_hex": None,
        "program_hex": None,
        "btf_loaded": False,
        "map_created": False,
        "program_loaded": False,
        "failed_stage": None,
        "load_errno": None,
        "closed": [],
        "close_errors": [],
        "capture_ready": False,
    }
    opened = []
    btf_log = ctypes.create_string_buffer(LOG_SIZE)
    verifier_log = ctypes.create_string_buffer(LOG_SIZE)
    stage = "btf_load"
    try:
        btf_fd = load_btf(btf_log)
        opened.append(("btf", btf_fd))
        result["btf_loaded"] = True
        stage = "map_create"
        result["map_attr_hex"] = map_create_attr(btf_fd).hex()
        map_fd = create_task_storage(btf_fd)
        opened.append(("map", map_fd))
        result["map_created"] = True
        stage = "program_load"
        code = program_bytes(map_fd)
        result["program_hex"] = code.hex()
        prog_fd = load_program(code, verifier_log)
        opened.append(("program", prog_fd))
        result["program_loaded"] = True
    except OSError as error:
        result["failed_stage"] = stage
        result["load_errno"] = error.errno
    finally:
        for name, fd in reversed(opened):
            try:
                os.close(fd)
            except OSError as error:
                result["close_errors"].append({"object": name, "errno": error.errno})
            else:
                result["closed"].append(name)
    result["btf_log_hex"] = btf_log.value.hex()
    result["verifier_log_hex"] = verifier_log.value.hex()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--load-unattached", action="store_true", required=True)
    parser.parse_args()
    try:
        verify_host()
    except (OSError, ValueError) as error:
        print(json.dumps({"preflight_error": str(error), "capture_ready": False}))
        return 2
    result = run_probe()
    print(json.dumps(result, indent=2))
    return 0 if result["program_loaded"] and not result["close_errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
