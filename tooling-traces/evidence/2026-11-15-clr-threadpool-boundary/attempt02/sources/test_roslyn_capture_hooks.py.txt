import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import trace_tooling


class CaptureHookTests(unittest.TestCase):
    def test_original_entrypoint_defaults_leave_hooks_disabled(self):
        params = inspect.signature(trace_tooling.capture_runtime).parameters
        self.assertIsNone(params["owned_identity"].default)
        self.assertIsNone(params["scheduler"].default)

    def test_invalid_child_identity_cleans_scheduler_without_launch(self):
        scheduler = Mock()
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "capture"
            with self.assertRaisesRegex(ValueError, "ordinary diagnostic children"):
                trace_tooling.capture_runtime([], Path(temp), folder, Path(temp) / "no-host",
                                              Path(temp) / "no-tool", Path(temp) / "no-analyzer",
                                              owned_identity=(1, 1), scheduler=scheduler)
            scheduler.close.assert_called_once_with()
            scheduler.arm.assert_not_called()


if __name__ == "__main__":
    unittest.main()
