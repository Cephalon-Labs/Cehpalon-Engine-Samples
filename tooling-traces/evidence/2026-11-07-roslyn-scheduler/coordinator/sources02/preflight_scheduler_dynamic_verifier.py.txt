"""One pinned x86_64 WSL verifier probe. It never attaches or runs the program."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys


RELEASE = "6.18.54.1-microsoft-standard-WSL2"
BTF_SHA256 = "1c1326be5d6ca0e60ad8790971b6765bba91cc8a3ab897a94794177484c8c9b9"
BTF_LENGTH = 6018902
TASK_PID_OFFSET = 1360
LOG_SIZE = 65536
SYS_BPF = 321
BPF_PROG_LOAD = 5
BPF_PROG_TYPE_RAW_TRACEPOINT = 17


def instruction(code, dst=0, src=0, imm=0):
    return struct.pack("<BBhi", code, dst | (src << 4), 0, imm)


def program_bytes():
    return b"".join((
        instruction(0x85, imm=158),  # get_current_task_btf()
        instruction(0xBF, dst=3, src=0),
        instruction(0x07, dst=3, imm=TASK_PID_OFFSET),
        instruction(0xBF, dst=1, src=10),
        instruction(0x07, dst=1, imm=-8),
        instruction(0xB7, dst=2, imm=4),
        instruction(0x85, imm=113),  # probe_read_kernel(stack, 4, task + offset)
        instruction(0xB7, dst=0, imm=0),
        instruction(0x95),
    ))


def verify_host():
    if sys.platform != "linux" or sys.byteorder != "little" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("expected little-endian 64-bit Linux")
    kernel = os.uname()
    if kernel.machine != "x86_64" or kernel.release != RELEASE or os.geteuid() != 0:
        raise ValueError("expected the pinned x86_64 WSL kernel and root operator")
    with Path("/sys/kernel/btf/vmlinux").open("rb") as btf:
        blob = btf.read(BTF_LENGTH + 1)
    if len(blob) != BTF_LENGTH or hashlib.sha256(blob).hexdigest() != BTF_SHA256:
        raise ValueError("live BTF differs from the pinned layout")


def load_once():
    code = program_bytes()
    insns = ctypes.create_string_buffer(code)
    license_text = ctypes.create_string_buffer(b"GPL")
    log = ctypes.create_string_buffer(LOG_SIZE)
    attr = ctypes.create_string_buffer(struct.pack(
        "<IIQQIIQII16sII",
        BPF_PROG_TYPE_RAW_TRACEPOINT, len(code) // 8,
        ctypes.addressof(insns), ctypes.addressof(license_text),
        2, LOG_SIZE, ctypes.addressof(log), 0, 0, b"ceph_dyn_probe", 0, 0,
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
        "load_accepted": fd >= 0,
        "load_errno": load_errno,
        "fd_closed": fd >= 0 and close_errno is None,
        "close_errno": close_errno,
        "verifier_log_hex": log.value.hex(),
        "capture_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--load-unattached", action="store_true", required=True)
    parser.parse_args()
    try:
        verify_host()
    except (OSError, ValueError) as error:
        print(json.dumps({"preflight_error": str(error), "capture_ready": False}))
        return 2
    result = load_once()
    print(json.dumps(result, indent=2))
    return 0 if result["load_accepted"] and result["fd_closed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
