import copy
import unittest

from scheduler_clr_overhead import ORDER, summarize_overhead


EXPECTED = {
    "fixture_sha256": "1" * 64,
    "runtime_sha256": "a" * 64,
    "expected_rounds": 64,
    "expected_checksum": "4fcd3a1dd438d325",
}


def make_rows():
    deltas = (900, 7, -4, 0, 20)
    rows = []
    for pair, modes in enumerate(ORDER):
        for mode in modes:
            slot = len(rows) + 1
            base = slot * 10_000
            ping_ns = 100 + (deltas[pair] if mode == "on" else 0)
            rows.append({
                "slot": slot,
                "phase": "primer" if pair == 0 else "measured",
                "pair": pair,
                "mode": mode,
                "passed": True,
                "fixture_sha256": EXPECTED["fixture_sha256"],
                "runtime_sha256": EXPECTED["runtime_sha256"],
                "controller": {
                    "prepare_start_ns": base,
                    "run_send_ns": base + 10,
                    "done_receive_ns": base + 2_000,
                    "cleanup_end_ns": base + 2_010,
                },
                "ready": {"kind": "ready", "pid": slot + 100, "main_tid": slot + 100,
                          "stopwatch_frequency": 1_000_000_000},
                "completed": {
                    "kind": "completed", "worker_tid": slot + 200,
                    "rounds": EXPECTED["expected_rounds"], "checksum": EXPECTED["expected_checksum"],
                    "work_begin_ns": base + 20, "work_end_ns": base + 49 + ping_ns,
                    "ping_begin_ns": base + 50, "ping_end_ns": base + 50 + ping_ns,
                    "work_begin_ticks": base + 21, "work_end_ticks": base + 50 + ping_ns,
                    "ping_begin_ticks": base + 51, "ping_end_ticks": base + 51 + ping_ns,
                    "ping_begin_process_cpu_ns": 100, "ping_end_process_cpu_ns": 100,
                },
            })
    return rows


class OverheadTests(unittest.TestCase):
    def test_signed_pair_deltas_and_exact_median_exclude_primer(self):
        result = summarize_overhead(make_rows(), **EXPECTED)
        self.assertEqual([pair["ping_ns"]["on_minus_off_ns"] for pair in result["pairs"]], [7, -4, 0, 20])
        self.assertEqual(result["pairs"][1]["order"], ["on", "off"])
        self.assertEqual(result["pairs"][1]["ping_ns"]["on_minus_off_percent_of_off"],
                         {"numerator": -4, "denominator": 1})
        self.assertEqual(result["metrics"]["ping_ns"]["on_minus_off_ns"],
                         {"median": {"numerator": 7, "denominator": 2}, "min": -4, "max": 20})
        self.assertEqual(result["primer_cases"][1]["ping_ns"], 1000)
        self.assertEqual(result["measured_cases"][0]["ping_process_cpu_ns"], 0)

    def test_missing_swapped_or_overlapping_case_is_invalid(self):
        rows = make_rows()
        with self.assertRaisesRegex(ValueError, "all ten cases"):
            summarize_overhead(rows[:-1], **EXPECTED)
        rows[2], rows[3] = rows[3], rows[2]
        with self.assertRaisesRegex(ValueError, "order differs"):
            summarize_overhead(rows, **EXPECTED)
        rows = make_rows()
        for key in rows[1]["controller"]:
            rows[1]["controller"][key] -= 10_000
        for boundary in ("work_begin", "work_end", "ping_begin", "ping_end"):
            for unit in ("ns", "ticks"):
                rows[1]["completed"][f"{boundary}_{unit}"] -= 10_000
        with self.assertRaisesRegex(ValueError, "overlap"):
            summarize_overhead(rows, **EXPECTED)

    def test_invalid_primer_hash_and_frozen_work_are_rejected(self):
        for path, value, message in (
            (("passed",), False, "native run"),
            (("fixture_sha256",), "b" * 64, "source identity"),
            (("completed", "rounds"), 63, "rounds or checksum"),
            (("completed", "checksum"), "4fcd3a1dd438d326", "rounds or checksum"),
            (("ready", "stopwatch_frequency"), 10_000_000, "Stopwatch frequency"),
        ):
            with self.subTest(path=path):
                rows = make_rows()
                receipt = rows[0] if len(path) == 1 else rows[0][path[0]]
                receipt[path[-1]] = value
                with self.assertRaisesRegex(ValueError, message):
                    summarize_overhead(rows, **EXPECTED)

    def test_noninteger_or_zero_work_bracket_is_invalid(self):
        rows = make_rows()
        receipts = rows[-1]["completed"]
        receipts["ping_end_ns"] = receipts["ping_begin_ns"]
        with self.assertRaisesRegex(ValueError, "monotonic bracket"):
            summarize_overhead(rows, **EXPECTED)
        rows = make_rows()
        rows[-1]["completed"]["work_begin_ticks"] = True
        with self.assertRaisesRegex(ValueError, "invalid timestamps"):
            summarize_overhead(rows, **EXPECTED)
        rows = make_rows()
        rows[-1]["completed"]["ping_end_process_cpu_ns"] = 99
        with self.assertRaisesRegex(ValueError, "CPU clock ran backwards"):
            summarize_overhead(rows, **EXPECTED)

    def test_work_end_can_follow_ping_end_without_mutation(self):
        rows = make_rows()
        receipts = rows[0]["completed"]
        receipts["work_end_ns"] = receipts["ping_end_ns"] + 1
        receipts["work_end_ticks"] = receipts["ping_end_ticks"] + 1
        original = copy.deepcopy(rows)
        self.assertEqual(summarize_overhead(rows, **EXPECTED)["primer_cases"][0]["work_ns"], 131)
        self.assertEqual(rows, original)


if __name__ == "__main__":
    unittest.main()
