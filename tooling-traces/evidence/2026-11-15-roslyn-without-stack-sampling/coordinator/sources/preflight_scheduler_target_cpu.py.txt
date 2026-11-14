"""Verify a fixed raw scheduler target-CPU program without attaching or running it."""

import argparse
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct

from preflight_scheduler_dynamic_verifier import (
    BPF_PROG_LOAD,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BTF_LENGTH,
    BTF_SHA256,
    LOG_SIZE,
    RELEASE,
    SYS_BPF,
    instruction,
    verify_host,
)
from scheduler_dynamic_btf import Btf, BtfError, layout_member


TASK_CPU_OFFSET = 20
CPU_BYTES = 4
TARGET_ARG_SLOT = 0


def describe_layout(data):
    """Recover the embedded CPU member using the existing bounded BTF parser."""
    if len(data) != BTF_LENGTH or hashlib.sha256(data).hexdigest() != BTF_SHA256:
        raise BtfError("BTF bytes differ from the pinned input")
    btf = Btf(data)
    names = ("task_struct", "thread_info")
    ids = {name: btf.structure(name) for name in names}
    embedded = layout_member(btf, ids, ids["task_struct"], "thread_info", "thread_info")
    cpu = layout_member(btf, ids, ids["thread_info"], "cpu", (CPU_BYTES, False))
    offset = embedded["offset"] + cpu["offset"]
    if offset != TASK_CPU_OFFSET:
        raise BtfError("computed CPU offset differs from the fixed program")
    return {
        "btf_sha256": BTF_SHA256,
        "btf_bytes": BTF_LENGTH,
        "intended_tracepoint": "sched_waking",
        "target_arg_slot_from_source": TARGET_ARG_SLOT,
        "type_ids": ids,
        "task_struct_size": btf.types[ids["task_struct"]].size_or_reference,
        "thread_info_member": embedded,
        "cpu_member": cpu,
        "task_cpu_offset": offset,
    }


def program_bytes():
    return b"".join((
        instruction(0x79, dst=3, src=1),  # r3 = raw context args[0]
        instruction(0x07, dst=3, imm=TASK_CPU_OFFSET),
        instruction(0xBF, dst=1, src=10),
        instruction(0x07, dst=1, imm=-8),
        instruction(0xB7, dst=2, imm=CPU_BYTES),
        instruction(0x85, imm=113),  # bpf_probe_read_kernel(stack, 4, target + 20)
        instruction(0xB7, dst=0, imm=0),
        instruction(0x95),
    ))


def load_once():
    code = program_bytes()
    insns = ctypes.create_string_buffer(code)
    license_text = ctypes.create_string_buffer(b"GPL")
    log = ctypes.create_string_buffer(LOG_SIZE)
    attr = ctypes.create_string_buffer(struct.pack(
        "<IIQQIIQII16sII",
        BPF_PROG_TYPE_RAW_TRACEPOINT, len(code) // 8,
        ctypes.addressof(insns), ctypes.addressof(license_text),
        2, LOG_SIZE, ctypes.addressof(log), 0, 0, b"ceph_target_cpu", 0, 0,
    ), 72)
    syscall = ctypes.CDLL(None, use_errno=True).syscall
    syscall.restype = ctypes.c_long
    fd = syscall(ctypes.c_long(SYS_BPF), ctypes.c_int(BPF_PROG_LOAD),
                 ctypes.byref(attr), ctypes.c_uint(ctypes.sizeof(attr)))
    load_errno = ctypes.get_errno() if fd < 0 else None
    close_errno = None
    if fd >= 0:
        try:
            os.close(fd)
        except OSError as error:
            close_errno = error.errno
    return {
        "program_hex": code.hex(),
        "kernel_release": RELEASE,
        "btf_sha256": BTF_SHA256,
        "intended_tracepoint": "sched_waking",
        "raw_arg_slot": TARGET_ARG_SLOT,
        "task_cpu_offset": TASK_CPU_OFFSET,
        "load_accepted": fd >= 0,
        "load_errno": load_errno,
        "fd_closed": fd >= 0 and close_errno is None,
        "close_errno": close_errno,
        "verifier_log_hex": log.value.hex(),
        "capture_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--load-unattached", action="store_true")
    mode.add_argument("--describe-btf", type=Path, metavar="PATH")
    args = parser.parse_args()
    try:
        if args.describe_btf is not None:
            opener = gzip.open if args.describe_btf.suffix == ".gz" else open
            with opener(args.describe_btf, "rb") as stream:
                result = describe_layout(stream.read(BTF_LENGTH + 1))
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        verify_host()
    except (OSError, EOFError, ValueError) as error:
        print(json.dumps({"preflight_error": str(error), "capture_ready": False}))
        return 2
    result = load_once()
    print(json.dumps(result, indent=2))
    return 0 if result["load_accepted"] and result["fd_closed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
