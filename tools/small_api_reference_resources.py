"""Read Linux benchmark reservations and enter a caller-owned cgroup without changing limits."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import sys
import time
from fractions import Fraction


CGROUP_ROOT = Path('/sys/fs/cgroup')
PROC = Path('/proc')
APP_MEMORY_BYTES = 2 * 1024**3
# Reserved nsfs inode of the initial Linux cgroup namespace (CGROUP_NS_INIT_INO).
INITIAL_CGROUP_NAMESPACE = 0xEFFFFFFB
CONTROL_FILES = (
    'cgroup.type', 'cpuset.cpus.effective', 'cpuset.cpus.exclusive.effective',
    'cpuset.cpus.partition', 'cpuset.cpus.isolated', 'cpu.max', 'memory.max',
    'memory.high', 'memory.swap.max',
)
COUNTER_FILES = ('cpu.stat', 'memory.events', 'memory.events.local')
PRESSURE_COUNTERS = {
    'cpu.stat': ('nr_throttled', 'throttled_usec'),
    'memory.events': ('high', 'max', 'oom', 'oom_kill', 'oom_group_kill'),
    'memory.events.local': ('high', 'max', 'oom', 'oom_kill', 'oom_group_kill'),
}


class ReferenceResourceError(RuntimeError):
    def __init__(self, message, evidence=None):
        super().__init__(message)
        self.evidence = evidence


def _require(condition, message):
    if not condition:
        raise ReferenceResourceError(message)


def _read(path, optional=False):
    try:
        return path.read_text(encoding='ascii').strip()
    except FileNotFoundError:
        if optional:
            return None
        raise


def _number(value, name, minimum=0):
    _require(isinstance(value, str) and re.fullmatch(r'[0-9]+', value) is not None,
             f'Invalid Linux resource value for {name}.')
    result = int(value)
    _require(result >= minimum, f'Invalid Linux resource value for {name}.')
    return result


def _cpu_list(value):
    _require(isinstance(value, str), 'An effective Linux CPU list is missing.')
    cpus = set()
    for item in value.split(',') if value else ():
        ends = item.split('-')
        first = _number(ends[0], 'cpuset')
        last = _number(ends[-1], 'cpuset')
        _require(len(ends) <= 2 and first <= last < 65536, 'Invalid Linux CPU list range.')
        cpus.update(range(first, last + 1))
    return cpus


def _cpu_quota(value):
    if value is None:
        return None
    parts = value.split() if isinstance(value, str) else ()
    _require(len(parts) == 2, 'Invalid Linux cpu.max.')
    period = _number(parts[1], 'cpu.max period', 1)
    if parts[0] == 'max':
        return None
    return Fraction(_number(parts[0], 'cpu.max quota', 1), period)


def _memory_limit(value, name):
    return None if value in (None, 'max') else _number(value, name, 1)


def _counters(value):
    if value is None:
        return None
    counters = {}
    for line in value.splitlines():
        fields = line.split()
        _require(len(fields) == 2 and fields[0] not in counters, 'Invalid Linux resource counters.')
        counters[fields[0]] = _number(fields[1], fields[0])
    return counters


def _fingerprint(path):
    value = _read(path).lower().replace('-', '')
    _require(re.fullmatch(r'[0-9a-f]{32}', value) is not None and value != '0' * 32,
             'A Linux machine or boot identifier is missing or invalid.')
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def _host():
    _require(sys.platform == 'linux', 'The reference resource observer requires Linux.')
    os_info = os.uname()
    libc = os.confstr('CS_GNU_LIBC_VERSION')
    evidence = {'system': os_info.sysname, 'architecture': os_info.machine,
                'kernel': os_info.release, 'libc': libc}
    _require(os_info.machine == 'x86_64' and isinstance(libc, str) and libc.startswith('glibc '),
             'The reference resource observer requires Linux x86_64 with glibc.')
    mem = re.search(r'^MemTotal:\s+([0-9]+) kB$', _read(PROC / 'meminfo'), re.M)
    _require(mem is not None, 'Linux MemTotal is unavailable.')
    evidence.update(schema_version=1, observed_monotonic_ns=time.monotonic_ns(),
                    machine_id_sha256=_fingerprint(Path('/etc/machine-id')),
                    boot_id_sha256=_fingerprint(PROC / 'sys/kernel/random/boot_id'),
                    mem_total_bytes=_number(mem[1], 'MemTotal', 1) * 1024)
    return evidence


def _verify_visible_root(evidence):
    namespace_inode = (PROC / 'self/ns/cgroup').stat().st_ino
    evidence['cgroup_namespace_inode'] = namespace_inode
    _require(namespace_inode == INITIAL_CGROUP_NAMESPACE,
             'The Linux cgroup namespace can hide enclosing resource limits.')
    mounts = []
    for line in _read(PROC / 'self/mountinfo').splitlines():
        before, _, after = line.partition(' - ')
        fields = before.split()
        if len(fields) >= 6 and fields[4] == str(CGROUP_ROOT):
            mounts.append((fields[3], after.split()[0] if after else None))
    _require(mounts == [('/', 'cgroup2')], 'The complete kernel cgroup v2 hierarchy is unavailable.')
    evidence.update(cgroup_root_visible=True, cgroup_mount_root='/', cgroup_mount_type='cgroup2')


def _membership(pid):
    lines = _read(PROC / str(pid) / 'cgroup').splitlines()
    _require(len(lines) == 1 and lines[0].startswith('0::/'), 'Process lacks unified cgroup v2 membership.')
    relative = PurePosixPath(lines[0][3:])
    _require(relative.anchor == '/' and '..' not in relative.parts,
             'Process cgroup membership is outside the visible hierarchy.')
    return relative


def _directory_id(path):
    details = path.stat()
    return [details.st_dev, details.st_ino]


def _require_app_path(path):
    _require(path.is_absolute() and path.resolve(strict=True) == path and CGROUP_ROOT in path.parents,
             'The app cgroup must be a canonical non-root path on the cgroup v2 mount.')


def _hierarchy(leaf):
    paths = list(reversed((leaf, *leaf.parents)))
    hierarchy = []
    for path in paths[paths.index(CGROUP_ROOT):]:
        controls = {name: _read(path / name, optional=True) for name in CONTROL_FILES}
        counters = {name: _counters(_read(path / name, optional=True)) for name in COUNTER_FILES}
        relative = '/' if path == CGROUP_ROOT else '/' + path.relative_to(CGROUP_ROOT).as_posix()
        hierarchy.append({'cgroup_relative': relative,
                          'directory_id': _directory_id(path), 'controls': controls, 'counters': counters})
    return hierarchy


def _effective_capacity(hierarchy, cpus, physical_memory):
    cpu_levels = [Fraction(len(cpus))]
    memory_levels = [physical_memory]
    for node in hierarchy:
        controls = node['controls']
        quota = _cpu_quota(controls['cpu.max'])
        if quota is not None:
            cpu_levels.append(quota)
        maximum = _memory_limit(controls['memory.max'], 'memory.max')
        if maximum is not None:
            memory_levels.append(maximum)
    return min(cpu_levels), min(memory_levels)


def _app_cpus(evidence):
    hierarchy = evidence['hierarchy']
    parent = hierarchy[0]['controls']
    leaf = hierarchy[-1]['controls']
    cpus = _cpu_list(leaf['cpuset.cpus.effective'])
    _require(leaf['cgroup.type'] == 'domain' and leaf['cpuset.cpus.partition'] == 'isolated',
             'The app cgroup must be a valid isolated CPU partition in a domain leaf.')
    _require(len(cpus) == 2 and cpus == _cpu_list(leaf['cpuset.cpus.exclusive.effective'])
             and cpus <= _cpu_list(parent['cpuset.cpus.isolated']),
             'The app partition does not own exactly two active exclusive Linux CPUs.')
    _require(_memory_limit(leaf['memory.max'], 'memory.max') == APP_MEMORY_BYTES,
             'The app leaf memory.max must be 2147483648 bytes.')
    cpu_count, memory_bytes = _effective_capacity(hierarchy, cpus, evidence['mem_total_bytes'])
    _require(cpu_count == 2 and memory_bytes == APP_MEMORY_BYTES,
             'A host or ancestor limit reduces the effective 2-vCPU/2-GiB app budget.')
    for node in hierarchy:
        high = _memory_limit(node['controls']['memory.high'], 'memory.high')
        _require(high is None or high >= APP_MEMORY_BYTES, 'An ancestor or leaf memory.high reduces the app budget.')
        stat = node['counters']['cpu.stat']
        if node['controls']['cpu.max'] is not None:
            _require(stat is not None and {'nr_throttled', 'throttled_usec'} <= stat.keys(),
                     'CPU bandwidth control lacks readable throttle counters.')
    _require(leaf['cpu.max'] is not None, 'The app leaf CPU bandwidth counters are unavailable.')
    memory_events = hierarchy[-1]['counters']['memory.events']
    _require(memory_events is not None and {'high', 'max', 'oom', 'oom_kill'} <= memory_events.keys(),
             'The app leaf memory event counters are unavailable.')
    return cpus


def _compare_hierarchy(before, after):
    fixed = ('cgroup_relative', 'directory_id', 'controls')
    _require(len(before) == len(after) and all(
        all(left[key] == right[key] for key in fixed) for left, right in zip(before, after)),
        'The app cgroup hierarchy or its resource controls changed during the observation.')
    for left, right in zip(before, after):
        for filename, names in PRESSURE_COUNTERS.items():
            start, stop = left['counters'][filename], right['counters'][filename]
            _require((start is None) == (stop is None), 'The resource counter interface changed.')
            if start is not None:
                for name in names:
                    _require(start.get(name) == stop.get(name),
                             f'Observed cgroup pressure or counter reset in {filename}: {name}.')


class AppResources:
    """Validate an existing reservation and place only the owned app process inside it."""

    def __init__(self, config):
        _require(isinstance(config, dict) and isinstance(config.get('cgroup'), str),
                 'Reference resources require an absolute delegated cgroup path.')
        _require(set(config) <= {'cgroup', 'controller_cpus'}, 'Unknown app resource config fields.')
        self.leaf = Path(config['cgroup'])
        self.controller_cpus = config.get('controller_cpus')
        if self.controller_cpus is not None:
            cpus = self.controller_cpus
            _require(isinstance(cpus, list) and cpus and all(type(cpu) is int and cpu >= 0 for cpu in cpus)
                     and len(set(cpus)) == len(cpus), 'controller_cpus must be a nonempty list of unique CPU numbers.')
            self.controller_cpus = set(cpus)
        self._reservation = None
        self._dotnet = None
        self._assembly = None

    def check(self):
        """Read the empty app leaf and the visible ancestor limits before launching work."""
        evidence = self._snapshot(pid=None)
        self._reservation = evidence
        return evidence

    def _snapshot(self, pid):
        evidence = {}
        try:
            evidence.update(_host())
            _verify_visible_root(evidence)
            _require_app_path(self.leaf)
            evidence['hierarchy'] = _hierarchy(self.leaf)
            evidence['app_cgroup_relative'] = evidence['hierarchy'][-1]['cgroup_relative']
            cpus = _app_cpus(evidence)
            evidence['app_cpus'] = sorted(cpus)
            _require(not any(path.is_dir() for path in self.leaf.iterdir()), 'The app cgroup has child cgroups.')
            evidence['processes'] = sorted(_number(value, 'cgroup.procs', 1) for value in
                                           _read(self.leaf / 'cgroup.procs').split())
            evidence['cgroup_events'] = _counters(_read(self.leaf / 'cgroup.events'))
            evidence['memory_current_bytes'] = _number(_read(self.leaf / 'memory.current'), 'memory.current')
            _require(evidence['processes'] == ([] if pid is None else [pid]),
                     'The app cgroup must contain only the expected owned process, or be empty outside its lifetime.')
            _require(evidence['cgroup_events'].get('populated') == int(pid is not None),
                     'The app cgroup population disagrees with its owned process lifetime.')
            affinity = os.sched_getaffinity(0)
            controller = _membership('self')
            evidence['controller_cpus'] = sorted(affinity)
            evidence['controller_cgroup_relative'] = str(controller)
            _require(affinity and not affinity & cpus, 'Controller CPU affinity overlaps the app CPU reservation.')
            _require(self.controller_cpus is None or self.controller_cpus == affinity,
                     'The configured controller CPU list does not match actual controller affinity.')
            procs_file = self.leaf / 'cgroup.procs'
            source = CGROUP_ROOT / controller.relative_to('/')
            common = Path(os.path.commonpath((source, self.leaf))) / 'cgroup.procs'
            _require(os.access(procs_file, os.W_OK) and (os.geteuid() == 0 or os.access(common, os.W_OK)),
                     'The controller lacks delegated access needed to move its owned child process.')
            if pid is not None:
                evidence['worker'] = self._worker(pid, cpus, evidence['app_cgroup_relative'])
        except ReferenceResourceError as error:
            error.evidence = evidence
            raise
        except (OSError, ValueError, IndexError) as error:
            raise ReferenceResourceError('Could not read complete Linux resource evidence.', evidence) from error
        return evidence

    def command(self, dotnet, assembly, *arguments):
        """Return an argv whose launcher enters the leaf and execs the exact .NET host."""
        _require(self._reservation is not None, 'Check reference resources before constructing the app command.')
        try:
            self._dotnet = Path(dotnet).resolve(strict=True)
            self._assembly = Path(assembly).resolve(strict=True)
        except OSError as error:
            raise ReferenceResourceError('The pinned app command inputs cannot be resolved.') from error
        node = self._reservation['hierarchy'][-1]
        device, inode = node['directory_id']
        cpus = ','.join(map(str, self._reservation['app_cpus']))
        return [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), '--enter', str(self.leaf),
                str(device), str(inode), cpus, str(self._dotnet), str(self._assembly), *map(str, arguments)]

    def _worker(self, pid, cpus, expected_membership):
        _require(type(pid) is int and pid > 0 and self._dotnet is not None,
                 'The owned app PID or exact executable is unavailable.')
        process = PROC / str(pid)
        first = _read(process / 'stat').rsplit(')', 1)[1].split()
        membership = str(_membership(pid))
        affinity = os.sched_getaffinity(pid)
        executable = (process / 'exe').resolve(strict=True)
        argv = (process / 'cmdline').read_bytes().split(b'\0', 2)
        _require(membership == expected_membership and affinity == cpus and executable == self._dotnet
                 and argv[:2] == [os.fsencode(self._dotnet), os.fsencode(self._assembly)],
                 'The live app PID does not match the launched .NET command or reservation.')
        second = _read(process / 'stat').rsplit(')', 1)[1].split()
        _require(len(first) > 19 and len(second) > 19 and first[19] == second[19]
                 and _number(second[1], 'app parent PID', 1) == os.getpid(),
                 'The app PID is not the stable direct child launched by the controller.')
        return {'pid': pid, 'start_ticks': _number(second[19], 'app birth ticks', 1),
                'cgroup_relative': membership, 'affinity_cpus': sorted(affinity),
                'executable_verified': True, 'assembly_argv_verified': True}

    def observe(self, pid):
        """Verify the live app PID and reject pressure or reservation drift since check()."""
        _require(self._reservation is not None, 'Check reference resources before observing the app.')
        return self.verify_after(self._reservation, pid=pid)

    def verify_after(self, initial, pid=None):
        """Compare the reservation and pressure counters before or after owned shutdown."""
        evidence = self._snapshot(pid)
        try:
            stable = ('machine_id_sha256', 'boot_id_sha256', 'app_cpus', 'controller_cpus',
                      'controller_cgroup_relative')
            _require(all(initial[key] == evidence[key] for key in stable),
                     'The host identity, app partition or controller affinity changed.')
            _compare_hierarchy(initial['hierarchy'], evidence['hierarchy'])
            if 'worker' in initial and pid is not None:
                _require(initial['worker'] == evidence['worker'], 'The app process was replaced during observation.')
        except ReferenceResourceError as error:
            error.evidence = evidence
            raise
        return evidence


def capture_driver_resources():
    """Capture the actual remote process allocation from Linux, for a trusted live receipt."""
    evidence = {}
    try:
        evidence.update(_host())
        _verify_visible_root(evidence)
        relative = _membership('self')
        evidence.update(pid=os.getpid(), cgroup_relative=str(relative),
                        affinity_cpus=sorted(os.sched_getaffinity(0)),
                        hierarchy=_hierarchy(CGROUP_ROOT / relative.relative_to('/')))
    except ReferenceResourceError as error:
        error.evidence = evidence
        raise
    except (OSError, ValueError) as error:
        raise ReferenceResourceError('Could not read complete driver resource evidence.', evidence) from error
    return evidence


def verify_driver_resources(local_baseline, remote_receipt):
    """Verify distinct live host identity and calculate capacity from observed driver limits."""
    try:
        _require(remote_receipt['schema_version'] == 1 and remote_receipt['system'] == 'Linux'
                 and remote_receipt['architecture'] == 'x86_64' and remote_receipt['libc'].startswith('glibc ')
                 and remote_receipt['cgroup_namespace_inode'] == INITIAL_CGROUP_NAMESPACE
                 and remote_receipt['cgroup_mount_root'] == '/' and remote_receipt['cgroup_mount_type'] == 'cgroup2',
                 'Driver allocation requires a live Linux x86_64/glibc resource receipt.')
        for key in ('machine_id_sha256', 'boot_id_sha256'):
            fingerprint = remote_receipt[key]
            _require(isinstance(fingerprint, str) and re.fullmatch(r'[0-9a-f]{64}', fingerprint) is not None
                     and fingerprint != local_baseline[key],
                     'The driver must have distinct Linux machine and boot identities.')
        cpus = remote_receipt['affinity_cpus']
        memory = remote_receipt['mem_total_bytes']
        pid = remote_receipt['pid']
        hierarchy = remote_receipt['hierarchy']
        relative = PurePosixPath(remote_receipt['cgroup_relative'])
        _require(isinstance(cpus, list) and cpus and all(type(cpu) is int and cpu >= 0 for cpu in cpus)
                 and len(set(cpus)) == len(cpus) and type(memory) is int and memory > 0
                 and type(pid) is int and pid > 0, 'The driver resource receipt lacks effective CPU or memory facts.')
        expected = list(reversed((relative, *relative.parents)))
        _require(relative.anchor == '/' and '..' not in relative.parts
                 and [node['cgroup_relative'] for node in hierarchy] == list(map(str, expected)),
                 'The driver resource receipt lacks its complete cgroup hierarchy.')
        actual_cpus = hierarchy[-1]['controls']['cpuset.cpus.effective']
        if actual_cpus is not None:
            _require(set(cpus) <= _cpu_list(actual_cpus), 'Driver CPU affinity differs from its effective cpuset.')
        cpu_capacity, memory_capacity = _effective_capacity(hierarchy, cpus, memory)
        _require(cpu_capacity > 0 and memory_capacity > 0, 'The driver has no effective CPU or memory capacity.')
        return {'effective_vcpu_capacity': float(cpu_capacity), 'effective_memory_bytes': memory_capacity,
                'observation': remote_receipt}
    except ReferenceResourceError as error:
        error.evidence = remote_receipt
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        raise ReferenceResourceError('The driver resource receipt is malformed.') from error


def _enter(arguments):
    leaf, device, inode, cpus, *command = arguments
    _require_app_path(Path(leaf))
    directory = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        details = os.fstat(directory)
        _require((details.st_dev, details.st_ino) == (int(device), int(inode)), 'The app cgroup changed before launch.')
        writer = os.open('cgroup.procs', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            data = f'{os.getpid()}\n'.encode('ascii')
            _require(os.write(writer, data) == len(data), 'The owned app PID was not joined to the cgroup.')
        finally:
            os.close(writer)
    finally:
        os.close(directory)
    _require(CGROUP_ROOT / _membership('self').relative_to('/') == Path(leaf),
             'The owned app PID did not enter the selected cgroup.')
    _require(os.sched_getaffinity(0) == _cpu_list(cpus), 'The app did not enter the exact reserved CPU set.')
    os.execv(command[0], command)


if __name__ == '__main__':
    try:
        _require(len(sys.argv) >= 8 and sys.argv[1] == '--enter', 'This helper only launches the owned app process.')
        _enter(sys.argv[2:])
    except (OSError, ReferenceResourceError, ValueError) as error:
        print(f'App cgroup launcher refused to start: {error}', file=sys.stderr)
        sys.exit(1)
