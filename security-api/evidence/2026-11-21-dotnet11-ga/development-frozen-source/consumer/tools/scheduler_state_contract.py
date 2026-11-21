"""Explicit source-based labels for the retained WSL raw switch-state ABI.

This is an offline label contract. It does not certify physical scheduler
durations or attest correspondence between a source tag and the loaded kernel.
"""

LEGACY = "legacy"
WSL618 = "wsl618-observed-sleep-v1"
PROFILES = (LEGACY, WSL618)
SOURCE_COMMIT = "d504d40ab83839cb61942a812a99d183c42227b9"
SOURCE_BASE = "https://github.com/microsoft/WSL2-Linux-Kernel/blob/" + SOURCE_COMMIT


def validate_profile(profile):
    if profile not in PROFILES:
        raise ValueError("unsupported explicit scheduler state profile")


def classify_switch_out(raw_state, profile=LEGACY):
    validate_profile(profile)
    if type(raw_state) is not int or not 0 <= raw_state < 1 << 32:
        raise ValueError("expected an unsigned 32-bit captured switch-state value")
    # Preserve the existing private preemption marker and basic-state behavior.
    if raw_state & 0x80000000 or raw_state == 0:
        return "runnable_observed"
    if raw_state in (1, 2):
        return "off_cpu_sleep_state"
    # Exact observed combinations only. Do not generalize other qualifier bits.
    if profile == WSL618 and raw_state in (258, 8193):
        return "off_cpu_sleep_state"
    return "unknown"


def profile_details(profile):
    validate_profile(profile)
    result = {"profile": profile, "added_raw_values": [],
              "certifies_physical_scheduler_duration": False}
    if profile == WSL618:
        result.update(
            added_raw_values=[258, 8193],
            source_commit=SOURCE_COMMIT,
            source_tag="linux-msft-wsl-6.18.54.1",
            source_url=SOURCE_BASE + "/include/linux/sched.h",
            raw_argument="unsigned prev_state, raw sched_switch argument 3",
            source_binary_correspondence="tag, retained host/BTF and program checks; no binary attestation",
            interpretation="conditional recorded raw sleep-state label; proxy execution and callback timing remain unresolved",
            order_masks="unchanged legacy masks, including their conservative reset policy",
        )
    return result
