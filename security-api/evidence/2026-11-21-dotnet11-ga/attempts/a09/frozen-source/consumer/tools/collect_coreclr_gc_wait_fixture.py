"""Capture two verified GC wait callsite instructions for one owned fixture worker."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import select
import struct
import subprocess
import time
import zlib
from contextlib import ExitStack

from collect_scheduler_clr_fixture import HOST
from preflight_scheduler_perf import PerfAttr


BUILD_ID = "4edcdbc8ad6233ceb71a8ed685cf2e8dcfcf11df"
RUNTIME_SHA = "835319c93044fb485cf77e524a79afe1d35a2bf3c2e970ef0b2231b8c3399b78"
DEBUG_SHA = "d757b539c4789f9cf42c47ddd991065332dcfe1b6570c6dc623eecef28b178a9"
SITES = {"call": (0x14056E, "ff9050010000"), "return": (0x140574, "85c0")}
ENABLE, DISABLE = 0x2400, 0x2401


def check(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_image(image, debug):
    runtime = image.read_bytes()
    symbols = debug.read_bytes()
    check(sha(runtime) == RUNTIME_SHA and sha(symbols) == DEBUG_SHA, "Runtime or symbol SHA-256 mismatch")
    check(zlib.crc32(symbols) == 0xCFA91156, "Runtime debuglink CRC mismatch")
    for path in (image, debug):
        notes = subprocess.check_output(["readelf", "-n", path], text=True, timeout=8)
        check(f"Build ID: {BUILD_ID}" in notes, "Build ID mismatch")
    for offset, expected in SITES.values():
        check(runtime[offset:offset + len(expected) // 2].hex() == expected, "Site instruction differs")


def live_addresses(pid, tid, image):
    task = Path(f"/proc/{pid}/task/{tid}")
    status = (task / "status").read_text()
    check(f"Tgid:\t{pid}\n" in status and f"Pid:\t{tid}\n" in status, "Worker is outside the owned process")
    check(task.stat().st_uid == 1000, "Worker is outside the declared UID")
    identity = (task / "stat").read_text().rsplit(")", 1)[1].split()[19]
    mappings = []
    for line in (Path(f"/proc/{pid}") / "maps").read_text().splitlines():
        span, mode, offset, device, inode, *path = line.split(maxsplit=5)
        if "x" in mode and path == [str(image)] and int(inode) == image.stat().st_ino:
            low, high = map(lambda piece: int(piece, 16), span.split("-"))
            mappings.append((low, high, int(offset, 16)))
    check(len(mappings) == 1, "Expected one executable mapping of the pinned runtime inode")
    low, high, offset = mappings[0]
    addresses = {key: low + site[0] - offset for key, site in SITES.items()}
    check(all(low <= at < high for at in addresses.values()), "Site addresses are outside the image mapping")
    return identity, addresses


def open_probe(tid, image, offset, event_type):
    check(ctypes.sizeof(PerfAttr) == 128, "Unexpected perf_event_attr layout")
    path = ctypes.create_string_buffer(os.fsencode(image))
    attr = PerfAttr()
    attr.type, attr.size = event_type, 128
    attr.sample_period, attr.sample_type = 1, (1 << 0) | (1 << 1) | (1 << 2)
    attr.read_format = (1 << 2) | (1 << 4)
    attr.flags, attr.clockid = 1 | (1 << 25), time.CLOCK_MONOTONIC
    attr.wakeup_events, attr.config1, attr.config2 = 1, ctypes.addressof(path), offset
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    fd = libc.syscall(ctypes.c_long(298), ctypes.byref(attr), ctypes.c_int(tid),
                      ctypes.c_int(-1), ctypes.c_int(-1), ctypes.c_ulong(8))
    if fd < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return fd


def counters(fd):
    total, identifier, lost = struct.unpack("<QQQ", os.read(fd, 24))
    check(identifier > 0, "Missing perf event identifier")
    return total, identifier, lost


def decode_ring(ring, page_size, site, pid, tid, address):
    head, tail, offset, size = struct.unpack_from("<QQQQ", ring, 1024)
    check(offset == page_size and size == len(ring) - page_size and 0 <= head - tail <= size,
          "Invalid or overrun perf ring")
    data = bytes(ring[offset + tail % size:offset + min(size, tail % size + head - tail)])
    data += bytes(ring[offset:offset + max(0, tail % size + head - tail - size)])
    result = []
    cursor = 0
    while cursor < len(data):
        record, _, length = struct.unpack_from("<IHH", data, cursor)
        check(record == 9 and length == 32 and cursor + length <= len(data),
              f"Unexpected or lost perf record {record}/{length}")
        ip, owner, thread, stamp = struct.unpack_from("<QIIQ", data, cursor + 8)
        check((owner, thread, ip) == (pid, tid, address) and stamp > 0, "Sample owner or site mismatch")
        result.append({"site": site, "pid": owner, "tid": thread, "monotonic_ns": stamp})
        cursor += length
    struct.pack_into("<Q", ring, 1032, head)
    return result


def run_arm(child, command, probes, page_size, pid, tid, addresses):
    for fd, _ in probes.values():
        fcntl.ioctl(fd, ENABLE)
    begin = time.monotonic_ns()
    child.stdin.write(command + "\n")
    child.stdin.flush()
    check(select.select([child.stdout], [], [], 12)[0], f"{command} control timed out")
    result = child.stdout.readline().split()
    end = time.monotonic_ns()
    for fd, _ in probes.values():
        fcntl.ioctl(fd, DISABLE)
    check(len(result) == 4 and result[0] == command, f"Invalid {command} fixture response")
    samples = []
    for site, (fd, ring) in probes.items():
        samples.extend(decode_ring(ring, page_size, site, pid, tid, addresses[site]))
    samples.sort(key=lambda row: row["monotonic_ns"])
    check(all(begin < sample["monotonic_ns"] < end for sample in samples), "Sample outside control clocks")
    return {"gc_collection_deltas": list(map(int, result[1:])), "samples": samples,
            "counters": {site: counters(fd) for site, (fd, _) in probes.items()}}


def run(app, debug, out):
    check(platform.system() == "Linux" and platform.machine() == "x86_64" and os.geteuid() == 0,
          "Declared root coordinator on Linux x86-64 required")
    check(app.name == "GCWaitCallsiteFixture.dll", "Only the owned callsite fixture is supported")
    image = HOST.parent / "shared/Microsoft.NETCore.App/11.0.0-rc.3.26522.148/libcoreclr.so"
    validate_image(image, debug)
    event_type = int(Path("/sys/bus/event_source/devices/uprobe/type").read_text())
    page_size = os.sysconf("SC_PAGE_SIZE")
    out.mkdir()
    report = {"status": "started", "image_sha256": RUNTIME_SHA, "debug_sha256": DEBUG_SHA,
              "fixture_sha256": sha(app.read_bytes()), "host_sha256": sha(HOST.read_bytes()),
              "kernel": platform.release(), "build_id": BUILD_ID, "pmu_type": event_type, "sites": SITES}
    with ExitStack() as resources:
        stderr = resources.enter_context((out / "target.stderr.txt").open("w", encoding="utf-8"))
        child = subprocess.Popen([HOST, app], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=stderr, text=True, user=1000, group=1000, extra_groups=[])
        try:
            check(select.select([child.stdout], [], [], 12)[0], "Fixture worker did not become ready")
            header = child.stdout.readline().split()
            check(len(header) == 3 and header[0] == "worker", "Invalid worker identity response")
            pid, tid = map(int, header[1:])
            check(pid == child.pid and pid != tid, "Expected an ordinary worker of the owned child")
            identity, addresses = live_addresses(pid, tid, image)
            report.update(pid=pid, tid=tid, worker_start_ticks=identity)
            with ExitStack() as scoped:
                probes = {}
                for site, (offset, _) in SITES.items():
                    fd = open_probe(tid, image, offset, event_type)
                    scoped.callback(os.close, fd)
                    check(counters(fd)[::2] == (0, 0), "Fresh disabled perf descriptor has activity")
                    ring = scoped.enter_context(mmap.mmap(fd, 33 * page_size, flags=mmap.MAP_SHARED))
                    probes[site] = fd, ring
                for command in ("negative", "positive"):
                    report[command] = run_arm(child, command, probes, page_size, pid, tid, addresses)
                    check(live_addresses(pid, tid, image) == (identity, addresses), "Owned worker or mapping changed")
            child.stdin.write("close\n")
            child.stdin.flush()
            check(child.wait(timeout=8) == 0, "Fixture did not exit cleanly")
            negative, positive = report["negative"], report["positive"]
            check(negative["gc_collection_deltas"] == [0, 0, 0] and not negative["samples"]
                  and all(total == lost == 0 for total, _, lost in negative["counters"].values()),
                  "Negative control has a callsite, loss or GC")
            samples = positive["samples"]
            check(positive["gc_collection_deltas"] == [12, 12, 12], "Positive GC collection census differs")
            check(samples and len(samples) % 2 == 0 and
                  [row["site"] for row in samples] == ["call", "return"] * (len(samples) // 2)
                  and all(a["monotonic_ns"] < b["monotonic_ns"] for a, b in zip(samples, samples[1:])),
                  "Positive ordered call and return pairs missing")
            check(all(total == len(samples) // 2 and lost == 0 for total, _, lost in positive["counters"].values()),
                  "Terminal counters do not reconcile with raw samples")
            report.update(status="completed", pairs=len(samples) // 2)
        except Exception as exc:
            report.update(status="failed", failure=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()
            report["target_exit_code"] = child.returncode
            report["worker_proc_removed"] = not Path(f"/proc/{child.pid}").exists()
            save(out / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("app", "debug", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    args = parser.parse_args()
    result = run(args.app.resolve(), args.debug.resolve(), args.output.resolve())
    print(json.dumps({"status": result["status"], "pairs": result["pairs"]}))
