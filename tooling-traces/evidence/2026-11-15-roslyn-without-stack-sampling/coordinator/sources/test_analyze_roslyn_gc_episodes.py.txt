import unittest

from analyze_roslyn_gc_episodes import PHASES, PREFIX, START, STOP, classify, intersect, observed_blocks


def event(shape, stamp, fields, tid=100):
    return dict(zip(("eventId", "opcode", "version", "name"), shape[:4]),
                templateType=PREFIX + shape[4], timeMsec=stamp, threadId=tid, payload=fields)


def block(reason, count):
    return [{"event": event(shape, i + 1, {"ClrInstanceID": 0, **({"Reason": reason, "Count": count} if i == 0 else {})})}
            for i, shape in enumerate(PHASES)]


def collection(count=5, mode=0, stop_tid=100):
    fields = {"Count": count, "Depth": 0, "ClrInstanceID": 0}
    return [(12, event(START, 2.2, {**fields, "Type": mode})),
            (13, event(STOP, 2.8, fields, tid=stop_tid))]


class GcEpisodeTests(unittest.TestCase):
    def test_only_count_linked_nonconcurrent_collection_qualifies(self):
        phases = block(1, 4)
        self.assertEqual(classify(phases, collection(), 0), "blocking_gc_linked")
        for anchors in (collection(6), collection(mode=1), collection(stop_tid=101),
                        collection()[:1], collection() * 2):
            self.assertEqual(classify(phases, anchors, 0), "gc_collection_link_unresolved")

    def test_other_suspensions_and_gc_prep_remain_separate(self):
        self.assertEqual(classify(block(0, -1), [], 5), "other_with_samples")
        self.assertEqual(classify(block(0, -1), [], 0), "other_without_samples")
        self.assertEqual(classify(block(2, -1), [], 0), "appdomain_shutdown")
        self.assertEqual(classify(block(6, 4), collection(), 0), "gc_preparation_unresolved")

    def test_retry_incomplete_and_clock_tie_reject_stream(self):
        phases = block(1, 4)
        self.assertEqual(observed_blocks(phases, 1), [phases])
        self.assertIsNone(observed_blocks(phases, None))
        self.assertIsNone(observed_blocks(phases[:3], 1))
        self.assertIsNone(observed_blocks([phases[i] for i in (0, 2, 3, 1)], 1))
        phases[2]["event"]["timeMsec"] = phases[1]["event"]["timeMsec"]
        self.assertIsNone(observed_blocks(phases, 1))

    def test_overlap_counts_positive_intersection_and_excludes_edges(self):
        episodes = [({"episode_id": 8}, 10, 20)]
        self.assertEqual(intersect((15, 21), episodes), [8])
        self.assertEqual(intersect((3, 10), episodes), [])
        self.assertEqual(intersect((20, 25), episodes), [])
