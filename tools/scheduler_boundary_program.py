"""Two scoped current-task scheduler hooks with a separate boundary ABI."""

from scheduler_dynamic_multi_program import get_member
from scheduler_dynamic_program import ACK, Program

ROSLYN_BOUNDARY_SLOTS = 262144


HOOKS = {"entry": "sched_entry_tp", "exit": "sched_exit_tp"}


def boundary_program(name, storage, members, counts, records, capacity, leader_tid, *, worker_limit=3):
    worker_profile = leader_tid is None and (capacity, worker_limit) in ((1024, 16), (ROSLYN_BOUNDARY_SLOTS, 64))
    held_profile = type(leader_tid) is int and leader_tid > 0 and capacity in (1, 1024) and worker_limit == 3
    if name not in HOOKS or type(capacity) is not int or not (worker_profile or held_profile):
        raise ValueError("unsupported fixed boundary program")
    p = Program()
    p.mov(6, 1)
    if leader_tid is not None:
        p.current_storage(storage)
        p.jump(0x15, "member", 0)
        p.emit(0x79, 1, 0)
        p.jump(0x55, "member", 1, imm=ACK)
        p.emit(0x62, 10, off=-24, imm=leader_tid)
        p.emit(0x62, 10, off=-28)
        p.emit(0x62, 10, off=-32)
        p.jump(0x05, "owned")
    p.label("member")
    p.call(35)  # Private current-task key, matching the existing lifetime map.
    p.mov(7, 0)
    get_member(p, members, 7)
    p.emit(0x61, 1, 8, 16)
    p.jump(0x15, "fault", 1)
    p.jump(0x25, "fault", 1, imm=worker_limit)
    p.emit(0x63, 10, 1, -28)
    p.emit(0x61, 1, 8, 12)
    p.emit(0x63, 10, 1, -24)
    p.emit(0x61, 1, 8, 24)
    p.jump(0x25, "fault", 1, imm=1)
    p.emit(0x63, 10, 1, -32)
    p.label("owned")
    p.emit(0x79, 1, 6)
    p.jump(0x25, "fault", 1, imm=1)
    p.emit(0x63, 10, 1, -100)
    p.call(8)
    p.emit(0x63, 10, 0, -84)
    p.call(5)
    p.emit(0x7B, 10, 0, -96)
    p.array(counts, 0)
    p.jump(0x15, "return", 0)
    p.mov(9, 0)
    p.number(1, 1)
    p.emit(0xC3, 9, 1, imm=1)
    p.jump(0x35, "overflow", 1, imm=capacity)
    p.emit(0x63, 10, 1, -4)
    p.array(records)
    p.jump(0x15, "overflow", 0)
    p.mov(7, 0)
    p.emit(0x61, 1, 10, -4)
    p.emit(0x07, 1, imm=1)
    p.emit(0x63, 7, 1)
    for stack, field in ((-28, 4), (-100, 12), (-84, 16), (-32, 24), (-24, 28)):
        p.emit(0x61, 1, 10, stack)
        p.emit(0x63, 7, 1, field)
    p.emit(0x62, 7, off=8, imm=1 if name == "entry" else 2)
    p.emit(0x79, 1, 10, -96)
    p.emit(0x7B, 7, 1, 32)
    p.call(5)
    p.emit(0x7B, 7, 0, 40)
    p.call(8)
    p.emit(0x63, 7, 0, 20)
    p.jump(0x05, "return")
    p.label("overflow")
    p.number(1, 1)
    p.emit(0xC3, 9, 1, off=4)
    p.jump(0x05, "return")
    p.label("fault")
    p.array(counts, 0)
    p.jump(0x15, "return", 0)
    p.number(1, 1)
    p.emit(0xC3, 0, 1, off=8)
    p.exit()
    return p.encode()
