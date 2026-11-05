# ADR0030 offline BTF layout

The offline extractor uses the [BTF v1 header and type records from the matching WSL tag](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.54.1/include/uapi/linux/btf.h). It bounds and frames the whole raw type table through kind 19, then validates the reachable layout graph. It expects the declared Linux x86-64 little-endian profile and assumes an eight-byte pointer from that profile. The raw BTF blob does not encode a machine identifier. No full BTF validator, native loader or live kernel compatibility claim follows.

Both Windows Python 3.11.15 and Ubuntu WSL Python 3.10.12 passed the same 20 `unittest` cases using `python -B tools/test_scheduler_dynamic_btf.py -v`. The cases exercise exact expected output, skipped ENUM64 data, duplicate/missing layouts, incorrect bit offsets, shape and width, bounds, reference cycles, ambiguous overlap, the flexible array tail, and the optional exact input SHA pin. The pin rejects mismatches without writing a layout. Each host also ran `python -B tools/scheduler_dynamic_btf.py <retained-vmlinux.btf> --expect-sha256 1c1326be5d6ca0e60ad8790971b6765bba91cc8a3ab897a94794177484c8c9b9`. Both initial fixture/layout attempts exited zero. Their JSON outputs are byte-identical and have SHA-256 `fd3b12609210221618d81350999775ee3112f11c233583f04cfd990edac32092`.

| Structure | Bytes | Requested byte offsets |
| --- | ---: | --- |
| `task_struct` | 3328 | `pid` 1360, `tgid` 1364, `thread_pid` 1464, `start_boottime` 1656 |
| `pid` | 144 | `level` 4, `numbers` 144 |
| `upid` | 16 | `nr` 0, `ns` 8 |
| `pid_namespace` | 344 | `ns` 112 |
| `ns_common` | 80 | `inum` 24 |

`pid.numbers` is a zero-count flexible tail in the BTF with a 16-byte `upid` stride. The [matching WSL declaration](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.54.1/include/linux/pid.h) uses `numbers[]`. The extractor rejects a fixed array. A future reader still needs a live `struct pid` and a checked namespace level before reading an element.

The separate exploratory decoder used before implementing the bounded tool reports 136,350 types and prints the scalar encodings, references and bit offsets underlying the table. A follow-up offline check agrees on argument type-reference lists for the `btf_trace_*` and `__traceiter_*` prototypes of all 11 selected hooks. These are callback prototypes with the leading `__data` slot. The exact source of the raw tracepoint adapter governs the actual context layout. No actors, BPF syscalls, attachments, perf opens or workload attempts occurred here.
