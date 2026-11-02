# Independent ADR0027 B1 review protocol

Read canonical shared skill/current handoff and preflight-protocol.md. Reviewer performs only static source inspection, mock-backend/pure-byte fixtures and read-only comparison of operator-produced artifacts. No perf_event_open, build, target/capture, privilege or host changes, or remote writes by reviewer. Root sole integrator.

Scope is exactly one disabled sched_switch FD on first declared online CPU. Verify fixed little-endian Linux x86_64 PERF_ATTR_SIZE_VER7 128-byte subset, offsets and allrequested/zero fields, disabled/sample_id_all/use_clockid flags, tracepointconfig and TID/TIME/CPU/RAW1158/readformat23/CLOEXEC8. No inheritance/task/mmap/comm/CPU/raw sampling may be enabled; no ioctl ENABLE, mmap, filter, actor or target call exists in B1.

Purefixtures: exactbool/int/config/CPU/topology/attrbytes/read40bytefiveuint64 tuple; positive perfFDidentifier separate from tracepointconfig. Failureatopen/cloexec/read/decode/close/closurecheck muststayfailed/unknown, preserve errno/rawbytes/cleanup andalwaysactive_capture_readyfalse. Exactly oneopen/read(max)andoneclose(whenowned), noretries/fallbackattrs/EINTRcloseRetry. Closedcheckimmediatelyafterclose withno loggingFDallocation.

Operatorartifact audit: source/planner/bundle/live8ABI/topology freezes, rootUID/EUID/namespaces andkernel/byteABI; syscallargs/flags rawattrbytes, actualreturnFD/CLOEXEC/readtuple/lostfield/closeAck+EBADF andtimestamps. Successonlyprovesonespecificdisabledopen/readlayout, notfilterdelivery, activeclock, positivescheduler/loss/state/nsactorjoins orB2capture readiness. Permissionerrorpreserved andnoautomaticalternativeattempt.

FutureB2remainsseparatefixeddeclaration: ordinarystaticactors versusprivilegedcollector, payloadnamespaceleasesbeforefilters, allCPUFDsdisabled/filterackbeforeenable/actorbarrier, nonoverwriteRingABI/rawbounds/loss/throttle/terminaldrain, negativeoverflowthenpositiveprotocol,lifecycleexitwhilearmed+boundedRCU/migration/clocks/cleanup/privacy. StaticconformancecannotqualifydynamicRoslynThreadPool.
