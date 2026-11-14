"""Bounded scheduler programs with explicit, left-censored pre-arm enrollment."""

import struct

from scheduler_dynamic_multi_program import (
    KEY, PROBES as LIFECYCLE_PROBES, VALUE, birth, hash_call, publish, target,
)
from scheduler_dynamic_program import (
    ACK, Program, TASK_BIRTH, TASK_PID, TASK_THREAD_PID,
)


SLOTS = 262144
MEMBERS = 64
COUNTS_BYTES = 24  # attempted, lost, faults, frees, all admissions, initial admissions.
INITIAL_KIND = 10
PROBES = {"prearm": ("sys_enter", INITIAL_KIND), **LIFECYCLE_PROBES}


def prearm(p, storage, members, counts, namespace, initial_limit):
    # Ownership is established through typed current task storage before a raw
    # task pointer becomes a private hash key or any task field is read.
    p.current_storage(storage)
    p.jump(0x15, "return", 0)
    p.emit(0x79, 1, 0)
    p.jump(0x55, "return", 1, imm=ACK)
    p.call(35)
    p.mov(7, 0)
    p.emit(0x7B, 10, 7, KEY)
    hash_call(p, members, 1)
    p.jump(0x15, "initial_new", 0)
    p.mov(8, 0)
    p.read(7, TASK_BIRTH, 8, 0)
    p.emit(0x79, 1, 8)
    p.jump(0x5D, "fault", 0, 1)
    p.jump(0x05, "return")
    p.label("initial_new")
    p.read(7, TASK_BIRTH, 8, 0)
    p.jump(0x15, "fault", 0)
    p.emit(0x7B, 10, 0, VALUE)
    p.read(7, TASK_PID, 4, 0)
    p.jump(0x15, "fault", 0)
    p.emit(0x63, 10, 0, VALUE + 8)
    p.read(7, TASK_THREAD_PID, 8, 9)
    p.jump(0x15, "fault", 9)
    p.read(9, 144, 4, 0)
    p.emit(0x61, 1, 10, VALUE + 8)
    p.jump(0x5D, "fault", 0, 1)
    p.read(9, 4, 4, 0)
    p.jump(0x25, "fault", 0, imm=32)
    p.emit(0x67, 0, imm=4)
    p.emit(0x0F, 9, 0)
    p.read(9, 144, 4, 0)
    p.jump(0x15, "fault", 0)
    p.emit(0x63, 10, 0, VALUE + 12)
    p.read(9, 152, 8, 9)
    p.jump(0x15, "fault", 9)
    p.read(9, 136, 4, 0)
    signed_namespace = struct.unpack("<i", struct.pack("<I", namespace))[0]
    p.jump(0x56, "fault", 0, imm=signed_namespace)
    p.emit(0x62, 10, off=VALUE + 20)
    p.emit(0x7A, 10, off=VALUE + 24)
    p.array(counts, 0)
    p.jump(0x15, "fault", 0)
    p.mov(9, 0)
    p.number(1, 1)
    p.emit(0xC3, 9, 1, 20, 1)
    p.jump(0x35, "fault", 1, imm=initial_limit)
    p.number(1, 1)
    p.emit(0xC3, 9, 1, 16, 1)
    p.jump(0x35, "fault", 1, imm=MEMBERS)
    p.emit(0x07, 1, imm=1)
    p.emit(0x63, 10, 1, VALUE + 16)
    hash_call(p, members, 2)
    p.jump(0x55, "fault", 0)
    hash_call(p, members, 1)
    p.jump(0x15, "fault", 0)
    p.mov(8, 0)


def roslyn_program(name, storage, members, counts, records, namespace, initial_limit):
    """Emit one fixed profile, allowing only the frozen live FD/namespace slots."""
    if name not in PROBES or type(initial_limit) is not int or not 1 <= initial_limit <= MEMBERS:
        raise ValueError("unsupported Roslyn scheduler profile")
    if type(namespace) is not int or not 0 <= namespace < 1 << 32:
        raise ValueError("invalid PID namespace inode")
    p = Program()
    p.mov(6, 1)
    if name != "exec":
        p.emit(0x62, 10, off=-20, imm=PROBES[name][1])
        p.emit(0x62, 10, off=-24, imm=-1)
        p.emit(0x62, 10, off=-28)
    if name == "prearm":
        prearm(p, storage, members, counts, namespace, initial_limit)
    elif name == "birth":
        birth(p, storage, members, counts, namespace, MEMBERS)
    else:
        target(p, name, storage, members)
    if name != "exec":
        publish(p, name, members, counts, records, SLOTS)
    p.label("fault")
    p.array(counts, 0)
    p.jump(0x15, "return", 0)
    p.number(1, 1)
    p.emit(0xC3, 0, 1, off=8)
    p.exit()
    return p.encode()
