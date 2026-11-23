import copy
import os
from pathlib import Path, PurePosixPath
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import small_api_reference_resources as resources


def node(relative, inode, **controls):
    return {
        'cgroup_relative': relative,
        'directory_id': [1, inode],
        'controls': {name: controls.get(name) for name in resources.CONTROL_FILES},
        'counters': {
            'cpu.stat': {'nr_throttled': 3, 'throttled_usec': 500},
            'memory.events': {'high': 1, 'max': 0, 'oom': 0, 'oom_kill': 0},
            'memory.events.local': None,
        },
    }


def evidence():
    return {
        'mem_total_bytes': 8 * 1024**3,
        'hierarchy': [
            node('/', 1, **{'cpuset.cpus.isolated': '2-3'}),
            node('/experiment', 2, **{'cpu.max': '300000 100000', 'memory.max': str(4 * 1024**3)}),
            node('/experiment/app', 3, **{
                'cgroup.type': 'domain', 'cpuset.cpus.partition': 'isolated', 'cpuset.cpus.effective': '2-3',
                'cpuset.cpus.exclusive.effective': '2-3', 'cpu.max': 'max 100000',
                'memory.max': str(resources.APP_MEMORY_BYTES), 'memory.high': 'max', 'memory.swap.max': 'max',
            }),
        ],
    }


class ResourceTests(unittest.TestCase):
    def test_exact_application_budget_and_ancestor_constraints(self):
        self.assertEqual(resources._app_cpus(evidence()), {2, 3})
        cases = (
            (0, 'cpuset.cpus.isolated', '0-1'),
            (1, 'cpu.max', '180000 100000'),
            (1, 'memory.max', str(1024**3)),
            (1, 'memory.high', str(1024**3)),
            (2, 'cpuset.cpus.partition', 'isolated invalid (parent)'),
            (2, 'cpuset.cpus.effective', '2-4'),
            (2, 'cpuset.cpus.exclusive.effective', '2,4'),
            (2, 'memory.max', 'max'),
            (2, 'memory.max', str(1024**3)),
        )
        for index, control, value in cases:
            with self.subTest(control=control, value=value):
                snapshot = evidence()
                snapshot['hierarchy'][index]['controls'][control] = value
                with self.assertRaises(resources.ReferenceResourceError):
                    resources._app_cpus(snapshot)

    def test_pressure_counters_and_directory_identity(self):
        before = evidence()['hierarchy']
        after = copy.deepcopy(before)
        after[-1]['counters']['cpu.stat']['usage_usec'] = 530
        resources._compare_hierarchy(before, after)
        for index, filename, key in ((1, 'cpu.stat', 'nr_throttled'), (2, 'memory.events', 'oom_kill')):
            with self.subTest(filename=filename):
                modified = copy.deepcopy(before)
                modified[index]['counters'][filename][key] += 1
                with self.assertRaisesRegex(resources.ReferenceResourceError, 'pressure'):
                    resources._compare_hierarchy(before, modified)
        after[-1]['directory_id'][1] += 1
        with self.assertRaisesRegex(resources.ReferenceResourceError, 'hierarchy'):
            resources._compare_hierarchy(before, after)

    def test_app_snapshot_rejects_contaminating_process_affinity_and_lab_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            leaf = root / 'experiment/app'
            leaf.mkdir(parents=True)
            procs = leaf / 'cgroup.procs'
            procs.write_text('', encoding='ascii')
            (leaf / 'cgroup.events').write_text('populated 0\n', encoding='ascii')
            (leaf / 'memory.current').write_text('0\n', encoding='ascii')
            with patch.multiple(resources, CGROUP_ROOT=root, _host=Mock(return_value=evidence()),
                                _verify_visible_root=Mock(), _hierarchy=Mock(return_value=evidence()['hierarchy']),
                                _membership=Mock(return_value=PurePosixPath('/experiment/controller'))), \
                    patch.object(os, 'sched_getaffinity', return_value={0, 1}, create=True) as affinity, \
                    patch.object(os, 'geteuid', return_value=0, create=True):
                observer = resources.AppResources({'cgroup': str(leaf), 'controller_cpus': [0, 1]})
                self.assertEqual(observer.check()['app_cpus'], [2, 3])
                affinity.return_value = {1, 2}
                with self.assertRaisesRegex(resources.ReferenceResourceError, 'overlaps'):
                    observer.check()
                affinity.return_value = {0, 1}
                procs.write_text('24\n', encoding='ascii')
                with self.assertRaisesRegex(resources.ReferenceResourceError, 'expected owned process'):
                    observer.check()
                with self.assertRaisesRegex(resources.ReferenceResourceError, 'canonical non-root'):
                    resources.AppResources({'cgroup': str(root)}).check()

    def test_driver_uses_distinct_host_identity_and_limits_its_hierarchy(self):
        local = {'machine_id_sha256': 'a' * 64, 'boot_id_sha256': 'b' * 64}
        remote = {
            'schema_version': 1, 'system': 'Linux', 'architecture': 'x86_64', 'libc': 'glibc 2.35',
            'cgroup_root_visible': True, 'cgroup_mount_root': '/', 'cgroup_mount_type': 'cgroup2',
            'cgroup_namespace_inode': resources.INITIAL_CGROUP_NAMESPACE,
            'machine_id_sha256': 'c' * 64, 'boot_id_sha256': 'd' * 64,
            'pid': 42, 'affinity_cpus': [0, 1, 2, 3], 'mem_total_bytes': 8 * 1024**3,
            'cgroup_relative': '/driver/app',
            'hierarchy': [node('/', 1), node('/driver', 2, **{'cpu.max': '140000 100000'}),
                          node('/driver/app', 3, **{'cpuset.cpus.effective': '0-3', 'memory.max': str(3 * 1024**3)})],
        }
        result = resources.verify_driver_resources(local, remote)
        self.assertEqual(result['effective_vcpu_capacity'], 1.4)
        self.assertEqual(result['effective_memory_bytes'], 3 * 1024**3)
        for key in local:
            with self.subTest(same_id=key), self.assertRaisesRegex(resources.ReferenceResourceError, 'distinct'):
                resources.verify_driver_resources(local, {**remote, key: local[key]})
        with self.assertRaisesRegex(resources.ReferenceResourceError, 'complete cgroup hierarchy'):
            resources.verify_driver_resources(local, {**remote, 'hierarchy': remote['hierarchy'][1:]})
        with self.assertRaisesRegex(resources.ReferenceResourceError, 'live Linux'):
            resources.verify_driver_resources(local, {**remote, 'cgroup_namespace_inode': 4026532211})
        with self.assertRaisesRegex(resources.ReferenceResourceError, 'malformed'):
            resources.verify_driver_resources(local, {'approved': True, 'resources_ready': True})

    @unittest.skipUnless(all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')),
                         'Linux fd-open flags are required')
    def test_launcher_joins_only_self_and_preserves_the_app_argv(self):
        leaf = '/sys/fs/cgroup/delegated/app'
        argv = ['/tool/dotnet', '/build/sample.dll', '--mode=serve']
        arguments = [leaf, '1', '2', '2,3', *argv]
        with patch.multiple(resources, _require_app_path=Mock(),
                            _membership=Mock(return_value=PurePosixPath('/delegated/app'))), \
                patch.multiple(os, open=Mock(side_effect=[80, 81]), fstat=Mock(return_value=SimpleNamespace(
                    st_dev=1, st_ino=2)), write=Mock(return_value=4), close=Mock(), getpid=Mock(return_value=123),
                    sched_getaffinity=Mock(return_value={2, 3}), execv=Mock()):
            resources._enter(arguments)
            self.assertEqual(os.open.call_count, 2)
            os.open.assert_called_with('cgroup.procs', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=80)
            os.write.assert_called_once_with(81, b'123\n')
            os.execv.assert_called_once_with(argv[0], argv)
            os.open.reset_mock(side_effect=True)
            os.open.return_value = 80
            os.write.reset_mock()
            os.execv.reset_mock()
            os.fstat.return_value = SimpleNamespace(st_dev=1, st_ino=4)
            with self.assertRaisesRegex(resources.ReferenceResourceError, 'changed before launch'):
                resources._enter(arguments)
            os.write.assert_not_called()
            os.execv.assert_not_called()


if __name__ == '__main__':
    unittest.main()
