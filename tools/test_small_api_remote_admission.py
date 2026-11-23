"""Admission regressions for the remote Small API runner."""
import argparse
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from benchmark_small_api import OBSERVATIONAL, Runner, main, read_remote_configuration


class RemoteAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'config.json'
        self.lab = {
            'app': {'listen_ip': '172.20.0.1', 'driver_ip': '172.20.0.2'},
            'driver': {'app_host': '172.20.0.1'},
        }

    def write(self, value):
        self.config.write_text(json.dumps(value), encoding='utf-8')

    def test_laboratory_pins_distinct_private_app_and_peer(self):
        self.write(self.lab)
        self.assertEqual(self.lab, read_remote_configuration(self.config, lab=True))
        for listen, peer, host in [('203.0.113.8', '172.20.0.2', '203.0.113.8'),
                                   ('172.20.0.1', '172.20.0.1', '172.20.0.1'),
                                   ('172.20.0.1', '172.20.0.2', '172.20.0.3')]:
            with self.subTest(listen=listen, peer=peer, host=host):
                self.write({'app': {'listen_ip': listen, 'driver_ip': peer}, 'driver': {'app_host': host}})
                with self.assertRaises(ValueError):
                    read_remote_configuration(self.config, lab=True)

    def test_reference_requires_resource_configuration_and_absolute_build_receipt(self):
        self.write(self.lab)
        with self.assertRaises(ValueError):
            read_remote_configuration(self.config, lab=False)
        self.lab['app']['resources'] = {'cgroup': '/sys/fs/cgroup/reference-app'}
        self.lab['build_manifest'] = 'relative.json'
        self.write(self.lab)
        with self.assertRaises(ValueError):
            read_remote_configuration(self.config, lab=False)
        self.lab['build_manifest'] = str(self.root / 'receipt.json')
        self.write(self.lab)
        self.assertEqual(self.lab, read_remote_configuration(self.config, lab=False))

    def assert_command_rejected(self, extra, diagnostic):
        args = ['benchmark', '--dotnet', sys.executable, '--assembly', str(self.root / 'Sample.dll'),
                '--output', str(self.root / 'unused'), '--server-working-directory', str(self.root)]
        stderr = io.StringIO()
        with patch.object(sys, 'argv', args + extra), patch.object(sys, 'platform', 'linux'), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as error:
                main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn(diagnostic, stderr.getvalue())
        self.assertFalse((self.root / 'unused').exists())

    def test_laboratory_cannot_launch_timing(self):
        self.assert_command_rejected(['--remote-config', str(self.config), '--remote-preflight-lab'],
                                     'Laboratory remote mode requires')
        self.assert_command_rejected(['--remote-preflight-lab', '--preflight-only'],
                                     'Laboratory remote mode requires')

    def test_remote_timing_rejects_partial_or_reordered_series(self):
        for phases in ('startup', 'load,startup,idle,diagnostics'):
            self.assert_command_rejected(['--remote-config', str(self.config), '--phases', phases],
                                         'all W0 phases in the declared order')

    def test_existing_probe_namespace_keeps_observational_runner(self):
        runner = Runner(argparse.Namespace(), self.root)
        self.addCleanup(runner.progress.events.close)
        self.assertEqual(runner.classification, OBSERVATIONAL)
        self.assertFalse(runner.reference_preflight_passed)
        self.assertIsNone(runner.remote_config)


if __name__ == '__main__':
    unittest.main()
