"""Fixed programs for three generations in the synthetic WSL scheduler fixture."""

import struct

from scheduler_dynamic_program import ACK, CLONE_THREAD, Program, TASK_BIRTH, TASK_CPU, TASK_PID, TASK_TGID, TASK_THREAD_PID


PROBES = {
    "exec": ("sched_prepare_exec", 0),
    "wake_new": ("sched_wakeup_new", 2),
    "switch_in": ("sched_switch", 3),
    "switch_out": ("sched_switch", 4),
    "waking": ("sched_waking", 5),
    "wakeup": ("sched_wakeup", 6),
    "exit": ("sched_process_exit", 7),
    "free": ("sched_process_free", 8),
    "birth": ("task_newtask", 1),
}
KEY = -40
VALUE = -80  # u64 birth, u32 global/local/generation/parent/retired, then padding.


def stack_address(p, reg, offset):
    p.mov(reg, 10)
    p.emit(0x07, reg, imm=offset)


def hash_call(p, members, helper):
    p.lddw(1, members, src=1)
    stack_address(p, 2, KEY)
    if helper == 2:
        stack_address(p, 3, VALUE)
        p.number(4, 1)  # BPF_NOEXIST.
    p.call(helper)


def get_member(p, members, pointer):
    p.emit(0x7B, 10, pointer, KEY)
    hash_call(p, members, 1)
    p.jump(0x15, "return", 0)
    p.mov(8, 0)
    p.read(pointer, TASK_BIRTH, 8, 0)
    p.emit(0x79, 1, 8)
    p.jump(0x5D, "fault", 0, 1)


def birth(p, storage, members, counts, namespace):
    p.emit(0x79, 2, 6, 8)
    p.jump(0x45, "thread", 2, imm=CLONE_THREAD)
    p.jump(0x05, "return")
    p.label("thread")
    p.emit(0x62, 10, off=VALUE + 20)  # Parent zero is the seeded leader.
    p.current_storage(storage)
    p.jump(0x15, "nested", 0)
    p.emit(0x79, 1, 0)
    p.jump(0x15, "parent", 1, imm=ACK)
    p.label("nested")
    p.call(35)  # Untyped current task, used as a private map key.
    p.mov(7, 0)
    get_member(p, members, 7)
    p.emit(0x61, 1, 8, 24)
    p.jump(0x55, "fault", 1)  # Retired workers cannot parent new generations.
    p.emit(0x61, 1, 8, 16)
    p.emit(0x63, 10, 1, VALUE + 20)
    p.label("parent")
    p.call(158)
    p.read(0, TASK_TGID, 4, 0)
    p.emit(0x63, 10, 0, -32)
    p.emit(0x79, 7, 6)
    p.emit(0x7B, 10, 7, KEY)
    p.read(7, TASK_TGID, 4, 0)
    p.emit(0x61, 1, 10, -32)
    p.jump(0x5D, "fault", 0, 1)
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
    p.jump(0x56, "fault", 0, imm=struct.unpack("<i", struct.pack("<I", namespace))[0])
    p.array(counts, 0)
    p.jump(0x15, "fault", 0)
    p.number(1, 1)
    p.emit(0xC3, 0, 1, 16, 1)  # Bounded admission ordinal before insert.
    p.jump(0x35, "fault", 1, imm=3)
    p.emit(0x07, 1, imm=1)
    p.emit(0x63, 10, 1, VALUE + 16)
    p.emit(0x7A, 10, off=VALUE + 24)
    hash_call(p, members, 2)
    p.jump(0x55, "fault", 0)
    hash_call(p, members, 1)
    p.jump(0x15, "fault", 0)
    p.mov(8, 0)


def target(p, name, storage, members):
    if name == "exec":
        p.current_storage(storage)
        p.jump(0x15, "exec_worker", 0)
        p.emit(0x79, 1, 0)
        p.jump(0x15, "fault", 1, imm=ACK)
        p.label("exec_worker")
    slot = {"switch_in": 16, "switch_out": 8}.get(name, 0)
    p.emit(0x79, 7, 6, slot)
    get_member(p, members, 7)
    if name == "exec":
        p.jump(0x05, "fault")
    elif name == "switch_out":
        p.emit(0x79, 0, 6, 24)
        p.emit(0x79, 1, 6)
        p.jump(0x15, "raw_state", 1)
        p.emit(0x44, 0, imm=-2147483648)
        p.label("raw_state")
        p.emit(0x63, 10, 0, -28)
    elif name in {"waking", "wakeup", "wake_new"}:
        p.read(7, TASK_CPU, 4, 0)
        p.emit(0x63, 10, 0, -24)
    elif name == "exit":
        p.number(1, 1)
        p.emit(0xC3, 8, 1, 24, 0xE1)  # Retire once.
        p.jump(0x55, "fault", 1)
    elif name == "free":
        p.emit(0x61, 1, 8, 24)
        p.jump(0x55, "fault", 1, imm=1)


def publish(p, name, members, counts, records, capacity):
    for offset in (8, 12, 16, 20):
        p.emit(0x61, 1, 8, offset)
        p.emit(0x63, 10, 1, VALUE + offset)
    if name == "free":
        hash_call(p, members, 3)
        p.jump(0x55, "fault", 0)
    p.array(counts, 0)
    p.jump(0x15, "fault", 0)
    p.mov(9, 0)
    p.number(1, 1)
    p.emit(0xC3, 9, 1, imm=1)  # Reserve a unique slot, or account for overflow.
    p.jump(0x35, "overflow", 1, imm=capacity)
    p.emit(0x63, 10, 1, -4)
    p.array(records)
    p.jump(0x15, "overflow", 0)
    p.mov(7, 0)
    fields = ((-20, 0), (-24, 8), (-28, 12), (VALUE + 12, 24),
              (VALUE + 8, 28), (VALUE + 16, 32), (VALUE + 20, 36))
    for offset, field in fields:
        p.emit(0x61, 1, 10, offset)
        p.emit(0x63, 7, 1, field)
    p.call(8)
    p.emit(0x63, 7, 0, 4)
    p.call(5)
    p.emit(0x7B, 7, 0, 16)
    p.jump(0x05, "complete")
    p.label("overflow")
    p.number(1, 1)
    p.emit(0xC3, 9, 1, off=4)
    p.label("complete")
    if name == "free":
        p.number(1, 1)
        p.emit(0xC3, 9, 1, off=12)
    p.jump(0x05, "return")


def multi_program(name, storage, members, counts, records, capacity, namespace):
    if name not in PROBES or capacity not in {1, 512}:
        raise ValueError("unsupported multiworker probe")
    p = Program()
    p.mov(6, 1)
    if name != "exec":
        p.emit(0x62, 10, off=-20, imm=PROBES[name][1])
        p.emit(0x62, 10, off=-24, imm=-1)
        p.emit(0x62, 10, off=-28)
    if name == "birth":
        birth(p, storage, members, counts, namespace)
    else:
        target(p, name, storage, members)
    if name != "exec":
        publish(p, name, members, counts, records, capacity)
    p.label("fault")
    p.array(counts, 0)
    p.jump(0x15, "return", 0)
    p.number(1, 1)
    p.emit(0xC3, 0, 1, off=8)
    p.exit()
    return p.encode()
