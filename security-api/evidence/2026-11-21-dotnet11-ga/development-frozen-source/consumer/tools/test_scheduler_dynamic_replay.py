import unittest

from scheduler_dynamic_replay import ReplayError, replay


def event(kind, generation, **fields):
    return {"kind": kind, "generation": generation, **fields}


def lifecycle(generation, parent=1, global_tid=101, local_tid=11):
    return [
        event("birth", generation, parent=parent, global_tid=global_tid, local_tid=local_tid),
        event("wake_new", generation),
        event("switch_in", generation),
        event("waking", generation, emitter_cpu=1, target_cpu=3),
        event("wakeup", generation, emitter_cpu=2, target_cpu=3),
        event("exit", generation),
        event("free", generation),
    ]


def seed():
    return event("seed", 1, global_tid=100, local_tid=10)


def run(rows, expected=1, **counter_changes):
    counters = {
        "attempted": len(rows),
        "published": len(rows),
        "failed": 0,
        "faults": 0,
        **counter_changes,
    }
    return replay(
        [{"sequence": sequence, **row} for sequence, row in enumerate(rows, start=1)],
        counters,
        expected,
    )


class DynamicReplayTests(unittest.TestCase):
    def test_short_lived_child_needs_no_post_birth_proc_poll(self):
        self.assertEqual(
            run([seed(), *lifecycle(2)]),
            {
                "completed_births": 1,
                "remote_waking_generations": 1,
                "remote_wakeup_generations": 1,
                "capture_ready": False,
            },
        )

    def test_later_generation_may_reuse_numeric_ids_after_free(self):
        self.assertEqual(run([seed(), *lifecycle(2), *lifecycle(3)], 2)["completed_births"], 2)

    def test_admitted_child_can_parent_a_later_generation(self):
        first = lifecycle(2)
        nested = lifecycle(3, parent=2, global_tid=102, local_tid=12)
        self.assertEqual(run([seed(), *first[:3], *nested, *first[3:]], 2)["completed_births"], 2)

    def test_numeric_reuse_before_free_is_ambiguous(self):
        first = lifecycle(2)
        for global_tid, local_tid in ((101, 12), (102, 11)):
            with self.subTest(global_tid=global_tid, local_tid=local_tid):
                with self.assertRaisesRegex(ReplayError, "overlaps"):
                    later = lifecycle(3, global_tid=global_tid, local_tid=local_tid)
                    run([seed(), *first[:-1], *later], 2)

    def test_retired_or_unknown_parent_cannot_admit(self):
        for parent in (2, 3):
            with self.subTest(parent=parent):
                with self.assertRaisesRegex(ReplayError, "parent"):
                    run([seed(), *lifecycle(2), *lifecycle(3, parent=parent)], 2)

    def test_birth_cannot_be_learned_from_first_wake(self):
        with self.assertRaisesRegex(ReplayError, "no admitted child"):
            run([seed(), *lifecycle(2)[1:]])

    def test_switch_cannot_precede_first_wake(self):
        child = lifecycle(2)
        with self.assertRaisesRegex(ReplayError, "invalid switch_in"):
            run([seed(), child[0], child[2], child[1], *child[3:]])

    def test_duplicate_first_wake_is_invalid(self):
        child = lifecycle(2)
        with self.assertRaisesRegex(ReplayError, "invalid wake_new"):
            run([seed(), *child[:2], child[1], *child[2:]])

    def test_missing_free_or_exit_does_not_complete(self):
        child = lifecycle(2)
        with self.assertRaisesRegex(ReplayError, "did not complete"):
            run([seed(), *child[:-1]])
        with self.assertRaisesRegex(ReplayError, "invalid free"):
            run([seed(), *child[:-2], child[-1]])

    def test_old_generation_is_rejected_after_numeric_id_reuse(self):
        second = lifecycle(3)
        with self.assertRaisesRegex(ReplayError, "in freed"):
            run([seed(), *lifecycle(2), *second[:3], event("switch_in", 2), *second[3:]], 2)

    def test_rejects_unsanitized_fields_and_non_integer_ids(self):
        child = lifecycle(2)
        child[0]["address"] = 123
        with self.assertRaisesRegex(ReplayError, "unexpected record fields"):
            run([seed(), *child])
        child[0].pop("address")
        child[0]["local_tid"] = True
        with self.assertRaisesRegex(ReplayError, "invalid numeric"):
            run([seed(), *child])

    def test_remote_target_evidence_required_for_each_hook(self):
        for index in (3, 4):
            child = lifecycle(2)
            child[index]["emitter_cpu"] = child[index]["target_cpu"]
            with self.subTest(kind=child[index]["kind"]):
                with self.assertRaisesRegex(ReplayError, "no remote"):
                    run([seed(), *child])

    def test_remote_hook_observations_can_be_on_different_generations(self):
        first, second = lifecycle(2), lifecycle(3)
        first.pop(3)
        second.pop(4)
        result = run([seed(), *first, *second], 2)
        self.assertEqual(result["remote_waking_generations"], 1)
        self.assertEqual(result["remote_wakeup_generations"], 1)

    def test_terminal_fault_loss_and_inconsistent_counts(self):
        for change in ({"failed": 1}, {"faults": 1}, {"attempted": 9}, {"published": 7}):
            with self.subTest(change=change):
                with self.assertRaises(ReplayError):
                    run([seed(), *lifecycle(2)], **change)

    def test_duplicate_sequence_is_rejected(self):
        child = lifecycle(2)
        child[1]["sequence"] = 2
        with self.assertRaisesRegex(ReplayError, "publication sequence"):
            run([seed(), *child])

    def test_fixed_seed_and_bounds(self):
        with self.assertRaisesRegex(ReplayError, "seed"):
            run(lifecycle(2))
        with self.assertRaisesRegex(ReplayError, "seed"):
            run([seed(), seed(), *lifecycle(2)])
        with self.assertRaisesRegex(ReplayError, "bounds"):
            run([seed(), *lifecycle(2)], 17)
        with self.assertRaisesRegex(ReplayError, "bounds"):
            run([seed()] * 4097)


if __name__ == "__main__":
    unittest.main()
