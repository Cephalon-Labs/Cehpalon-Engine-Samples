# ADR0030 passive readiness inventory

This is passive inventory only: zero BPF syscalls/maps/program loads/attachments, zero perf opens, zero actors, zero builds, zero downloads/installs/configuration writes. Existing executable version/readelf/dpkg-query and ldconfig -p commands are read-only. Root and ordinary inventories are separate executions; their transient PIDs are not actor leases or a shared native identity proof.

## Observations

- Kernel: `6.18.54.1-microsoft-standard-WSL2`, x86_64. Root and ordinary snapshots record boot ID `50669d30-6915-4530-9689-c2216d87dfa7` and namespace symlinks. Root/ordinary capability masks, proc limits and sysctls are retained in full.
- Raw `/sys/kernel/btf/vmlinux`: 6,018,902 bytes, SHA256 `1c1326be5d6ca0e60ad8790971b6765bba91cc8a3ab897a94794177484c8c9b9`, copied unchanged to `vmlinux.btf`. Raw little-endian BTF v1 header, not an ELF image. Header length24, type length3484116, string length2534762; declared sections exactly fill input.
- `/sys/kernel/notes` retained unchanged: GNU build-id `de17a562c219da52bb9bb56182d657b775f45676`. The two fixed `/boot` and `/lib/modules` vmlinux candidates are absent. Notes/build-id plus BTF do not establish complete loaded-kernel binary attestation.
- Readable kernel config enables BPF_SYSCALL, BPF_JIT, BPF_EVENTS, DEBUG_INFO_BTF, DEBUG_INFO_BTF_MODULES, TRACEPOINTS, PERF_EVENTS. `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`; unprivileged_bpf_disabled=2, perf_event_paranoid=2, kptr_restrict=1, bpf_stats_enabled=0.
- Ordinary UID1000 has CapEff/Prm/Inh/Amb=0. Root has CapEff/Prm/Bnd=`000001ffffffffff`, Inh/Amb=0. These are inventory observations, not successful BPF access tests.
- Root soft nofile10240/hard1048576; memlock soft/hard67108864. Full ordinary/root limit tables retained. No limits changed.
- No clang/llc/bpftool/gcc/cc/pahole on inventoried WSL PATH; no clang in bounded Linux fallback paths; no clang/llc in fixed Windows LLVM/VS locations. readelf and objdump present with hashes/version retained. No broad drive scan.
- Correction to first quick report: absence of checked `libbpf.so`/`.so.1` is not absence of libbpf. Existing read-only ldconfig cache identifies `/lib/x86_64-linux-gnu/libbpf.so.0` -> `/usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0`, SHA256 `8465ed85b00ed1d838ab919d46b9f9c7e22809617243f9b2c2b3ceee5f6b57c4`,318056 bytes. dpkg reports `libbpf0 1:0.5.0-1ubuntu22.04.1 amd64`. readelf records exports for raw BTF parsing, raw tracepoint open, and ring-buffer consumption. Library was not loaded or called.

## Bounded recommendation and unknowns

Prefer a pure offline, finite raw-BTF parser and hand-generated RAW_TRACEPOINT instruction builder after the source-reviewed hook/identity API is chosen. This avoids requiring an unavailable compiler, new downloads, or old libbpf BTF-kind compatibility. Cross-check extracted layout against exact matching kernel source and require pinned BTF/kernel identity; never treat a hard-coded offset as generic kernel support. No implementation has started in this passive inventory stage.

A later separately declared program could receive transient unowned task pointers at hooks, read just the minimal ownership discriminants, and emit records only after matching owned TGID plus group-leader generation. The source reviewer must confirm exact raw tracepoint argument ABI, helper/program type eligibility, task field semantics, lifetime and generation design before bytecode exists. Redact unowned switch counterpart identity unless a separately declared minimal state relation is required. A rawtp design does not automatically inherit tp_btf typed-pointer/verifier properties.

BPF syscall permission, program/helper acceptance, verifier behavior, attach success, event delivery, ring loss/backpressure, dynamic task admission, and end-to-end cleanup remain UNTESTED. Config/caps/BTF/file visibility and prior perf success establish none of those. No scheduler/Roslyn/GC root cause or performance claim follows. Keep capture/production/causal qualification false and #3 Blocked.
