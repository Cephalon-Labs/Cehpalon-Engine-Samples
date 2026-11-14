"""Fixed BPF programs for the one-child dynamic scheduler fixture."""

import struct

from preflight_scheduler_pidfd_seed import COOKIE


ACK = 0x43455048
TASK_PID = 1360
TASK_TGID = 1364
TASK_THREAD_PID = 1464
TASK_BIRTH = 1656
TASK_CPU = 20
CLONE_THREAD = 0x10000

EVENTS = {
    "task_newtask": 1,
    "sched_wakeup_new": 2,
    "sched_switch": 3,
    "sched_waking": 5,
    "sched_wakeup": 6,
    "sched_process_exit": 7,
    "sched_process_free": 8,
    "sched_prepare_exec": 9,
}


class Program:
    def __init__(self):
        self.rows = []
        self.labels = {}

    def emit(self, code, dst=0, src=0, off=0, imm=0):
        self.rows.append((code, dst | (src << 4), off, imm))

    def label(self, name):
        if name in self.labels:
            raise ValueError(f"duplicate instruction label {name}")
        self.labels[name] = len(self.rows)

    def jump(self, code, name, dst=0, src=0, imm=0):
        self.emit(code, dst, src, name, imm)

    def mov(self, dst, src):
        self.emit(0xBF, dst, src)

    def number(self, dst, value):
        self.emit(0xB7, dst, imm=value)

    def lddw(self, dst, value, src=0):
        low, high = struct.unpack("<ii", struct.pack("<Q", value))
        self.emit(0x18, dst, src, imm=low)
        self.emit(0, imm=high)

    def call(self, helper):
        self.emit(0x85, imm=helper)

    def array(self, fd, slot=None):
        if slot is not None:
            self.emit(0x62, 10, off=-4, imm=slot)
        self.lddw(1, fd, src=1)
        self.mov(2, 10)
        self.emit(0x07, 2, imm=-4)
        self.call(1)

    def read(self, base, offset, size, result):
        self.mov(3, base)
        if offset:
            self.emit(0x07, 3, imm=offset)
        self.mov(1, 10)
        self.emit(0x07, 1, imm=-16)
        self.number(2, size)
        self.call(113)
        self.jump(0x55, "fault", 0, imm=0)
        self.emit(0x79 if size == 8 else 0x61, result, 10, -16)

    def current_storage(self, fd):
        self.call(158)
        self.mov(2, 0)
        self.lddw(1, fd, src=1)
        self.number(3, 0)
        self.number(4, 0)
        self.call(156)

    def exit(self):
        self.label("return")
        self.number(0, 0)
        self.emit(0x95)

    def encode(self):
        code = bytearray()
        for index, (opcode, registers, offset, immediate) in enumerate(self.rows):
            if isinstance(offset, str):
                offset = self.labels[offset] - index - 1
            code.extend(struct.pack("<BBhi", opcode, registers, offset, immediate))
        return bytes(code)


def seed_program(storage):
    p = Program()
    p.emit(0x79, 2, 1, 8)  # raw sys_enter(regs, id)
    p.jump(0x55, "return", 2, imm=186)
    p.current_storage(storage)
    p.jump(0x15, "return", 0)
    p.emit(0x79, 1, 0)
    p.lddw(2, COOKIE)
    p.jump(0x5D, "return", 1, 2)
    p.emit(0x7A, 0, imm=ACK)
    p.exit()
    return p.encode()


def admission(p, storage, namespace):
    p.emit(0x79, 2, 6, 8)
    p.jump(0x45, "thread", 2, imm=CLONE_THREAD)
    p.jump(0x05, "return")
    p.label("thread")
    p.current_storage(storage)
    p.jump(0x15, "return", 0)
    p.emit(0x79, 1, 0)
    p.jump(0x55, "return", 1, imm=ACK)
    p.emit(0x79, 1, 8, 8)
    p.jump(0x55, "fault", 1)
    p.call(158)
    p.read(0, TASK_TGID, 4, 0)
    p.emit(0x63, 10, 0, -32)
    p.emit(0x79, 7, 6)
    p.read(7, TASK_TGID, 4, 0)
    p.emit(0x61, 1, 10, -32)
    p.jump(0x5D, "fault", 0, 1)
    p.read(7, TASK_BIRTH, 8, 0)
    p.jump(0x15, "fault", 0)
    p.emit(0x7B, 8, 0, 8)
    p.read(7, TASK_PID, 4, 0)
    p.jump(0x15, "fault", 0)
    p.emit(0x63, 8, 0, 16)
    p.read(7, TASK_THREAD_PID, 8, 9)
    p.jump(0x15, "fault", 9)
    p.read(9, 144, 4, 0)  # pid.numbers[0].nr
    p.emit(0x61, 1, 8, 16)
    p.jump(0x5D, "fault", 0, 1)
    p.read(9, 4, 4, 0)  # pid.level
    p.jump(0x25, "fault", 0, imm=32)
    p.emit(0x67, 0, imm=4)  # sizeof(upid) == 16
    p.emit(0x0F, 9, 0)
    p.read(9, 144, 4, 0)  # pid.numbers[level].nr
    p.jump(0x15, "fault", 0)
    p.emit(0x63, 8, 0, 20)
    p.read(9, 152, 8, 9)  # pid.numbers[level].ns
    p.jump(0x15, "fault", 9)
    p.read(9, 136, 4, 0)  # pid_namespace.ns.inum
    signed_namespace = struct.unpack("<i", struct.pack("<I", namespace))[0]
    p.jump(0x56, "fault", 0, imm=signed_namespace)
    p.emit(0x7B, 8, 7)


def target_event(p, hook, storage):
    if hook == "sched_prepare_exec":
        p.current_storage(storage)
        p.jump(0x15, "other_exec", 0)
        p.emit(0x79, 1, 0)
        p.jump(0x15, "fault", 1, imm=ACK)
        p.label("other_exec")
    p.emit(0x79, 9, 8)
    p.jump(0x15, "return", 9)
    if hook == "sched_switch":
        p.emit(0x79, 7, 6, 8)
        p.jump(0x1D, "switch_out", 7, 9)
        p.emit(0x79, 7, 6, 16)
        p.jump(0x05, "target")
        p.label("switch_out")
        p.emit(0x62, 10, off=-20, imm=4)
        p.emit(0x79, 0, 6, 24)
        p.emit(0x79, 1, 6)
        p.jump(0x15, "raw_state", 1)
        p.emit(0x44, 0, imm=-2147483648)
        p.label("raw_state")
        p.emit(0x63, 10, 0, -28)
        p.label("target")
    else:
        p.emit(0x79, 7, 6)
    p.jump(0x5D, "return", 7, 9)
    p.read(7, TASK_BIRTH, 8, 0)
    p.emit(0x79, 1, 8, 8)
    p.jump(0x5D, "fault", 0, 1)
    if hook == "sched_process_free":
        p.emit(0x7A, 8)
    if hook == "sched_prepare_exec":
        p.jump(0x05, "fault")
    if hook in {"sched_waking", "sched_wakeup", "sched_wakeup_new"}:
        p.read(7, TASK_CPU, 4, 0)
        p.emit(0x63, 10, 0, -24)


def publish(p, hook, counts, records, capacity):
    p.array(counts, 0)
    p.jump(0x15, "return", 0)  # Array index 0 is in bounds.
    p.mov(9, 0)
    p.number(1, 1)
    p.emit(0xC3, 9, 1, imm=1)  # Atomic fetch-add of attempted.
    p.jump(0x35, "overflow", 1, imm=capacity)
    p.emit(0x63, 10, 1, -4)
    p.array(records)
    p.jump(0x15, "overflow", 0)
    p.mov(7, 0)
    for stack, field in ((-20, 0), (-24, 8), (-28, 12)):
        p.emit(0x61, 1, 10, stack)
        p.emit(0x63, 7, 1, field)
    p.call(8)  # Emitter CPU.
    p.emit(0x63, 7, 0, 4)
    p.call(5)  # Monotonic kernel time.
    p.emit(0x7B, 7, 0, 16)
    for offset, field in ((20, 24), (16, 28)):
        p.emit(0x61, 1, 8, offset)
        p.emit(0x63, 7, 1, field)
    p.jump(0x05, "completed")
    p.label("overflow")
    p.number(1, 1)
    p.emit(0xC3, 9, 1, off=4)  # Atomic add to failed publications.
    p.label("completed")
    if hook == "sched_process_free":
        p.number(1, 1)
        p.emit(0xC3, 9, 1, off=12)
    p.jump(0x05, "return")


def lifecycle_program(hook, storage, state, counts, records, capacity, namespace):
    if hook not in EVENTS or capacity not in {1, 512}:
        raise ValueError("unsupported lifecycle probe")
    p = Program()
    p.mov(6, 1)
    p.emit(0x62, 10, off=-20, imm=EVENTS[hook])
    p.emit(0x62, 10, off=-24, imm=-1)
    p.emit(0x62, 10, off=-28)
    p.array(state, 0)
    p.jump(0x15, "fault", 0)
    p.mov(8, 0)
    if hook == "task_newtask":
        admission(p, storage, namespace)
    else:
        target_event(p, hook, storage)
    if hook != "sched_prepare_exec":
        publish(p, hook, counts, records, capacity)
    p.label("fault")
    p.array(counts, 0)
    p.jump(0x15, "return", 0)
    p.number(1, 1)
    p.emit(0xC3, 0, 1, off=8)
    p.exit()
    return p.encode()
