"""Offline byte fixtures for the ADR0030 layout extraction boundary."""

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import scheduler_dynamic_btf as tool


class Fixture:
    def __init__(self):
        self.strings = bytearray(b'\0')
        self.names = {'': 0}
        self.records = [None]
        self.signed = self.type('int', 1, 4, struct.pack('<I', 0x01000020))
        self.unsigned = self.type('unsigned int', 1, 4, struct.pack('<I', 0x20))
        self.wide = self.type('unsigned long long', 1, 8, struct.pack('<I', 0x40))
        self.pid_t = self.type('pid_t', 8, self.signed)
        self.ns_common = self.structure('ns_common', 8, [('inum', self.unsigned, 32)])
        self.namespace = self.structure('pid_namespace', 16, [('ns', self.ns_common, 64)])
        self.namespace_ptr = self.type('', 2, self.namespace)
        self.upid = self.structure('upid', 16, [('nr', self.pid_t, 0), ('ns', self.namespace_ptr, 64)])
        self.numbers = self.type('', 3, 0, struct.pack('<III', self.upid, self.signed, 0))
        self.pid = self.structure('pid', 8, [('level', self.unsigned, 32), ('numbers', self.numbers, 64)])
        self.pid_ptr = self.type('', 2, self.pid)
        self.task_fields = [
            ('flags', self.unsigned, (3 << 24) | 256),
            ('pid', self.pid_t, 0), ('tgid', self.pid_t, 32),
            ('thread_pid', self.pid_ptr, 64), ('start_boottime', self.wide, 128),
        ]
        self.task = self.structure('task_struct', 40, self.task_fields, kind_flag=True)

    def name(self, name):
        if name not in self.names:
            self.names[name] = len(self.strings)
            self.strings.extend(name.encode('ascii') + b'\0')
        return self.names[name]

    def type(self, name, kind, size_or_ref, tail=b'', *, entries=0, kind_flag=False):
        info = (kind_flag << 31) | (kind << 24) | entries
        self.records.append(struct.pack('<III', self.name(name), info, size_or_ref) + tail)
        return len(self.records) - 1

    def structure(self, name, size, fields, *, kind_flag=False):
        tail = b''.join(struct.pack('<III', self.name(field), reference, offset)
                        for field, reference, offset in fields)
        return self.type(name, 4, size, tail, entries=len(fields), kind_flag=kind_flag)

    def replace_word(self, record, word, value):
        data = bytearray(self.records[record])
        struct.pack_into('<I', data, 4 * word, value)
        self.records[record] = bytes(data)

    def data(self):
        types = b''.join(self.records[1:])
        header = struct.pack('<HBB5I', 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(self.strings))
        return header + types + self.strings


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def assert_rejected(self, pattern):
        with self.assertRaisesRegex(tool.BtfError, pattern):
            tool.extract_layout(self.fixture.data())

    def test_typed_layout(self):
        data = self.fixture.data()
        result = tool.extract_layout(data)
        self.assertEqual(result['btf_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['pointer_bytes'], 8)
        self.assertEqual(result['btf_bytes'], len(data))
        self.assertEqual(result['structures'], {
            'task_struct': {'size': 40, 'members': {
                'pid': {'kind': 'integer', 'offset': 0, 'size': 4, 'signed': True},
                'tgid': {'kind': 'integer', 'offset': 4, 'size': 4, 'signed': True},
                'thread_pid': {'kind': 'pointer', 'offset': 8, 'size': 8, 'target': 'pid'},
                'start_boottime': {'kind': 'integer', 'offset': 16, 'size': 8, 'signed': False},
            }},
            'pid': {'size': 8, 'members': {
                'level': {'kind': 'integer', 'offset': 4, 'size': 4, 'signed': False},
                'numbers': {'kind': 'flexible_array', 'offset': 8, 'size': 0,
                            'element': 'upid', 'stride': 16, 'declared_count': 0},
            }},
            'upid': {'size': 16, 'members': {
                'nr': {'kind': 'integer', 'offset': 0, 'size': 4, 'signed': True},
                'ns': {'kind': 'pointer', 'offset': 8, 'size': 8, 'target': 'pid_namespace'},
            }},
            'pid_namespace': {'size': 16, 'members': {
                'ns': {'kind': 'struct', 'offset': 8, 'size': 8, 'target': 'ns_common'},
            }},
            'ns_common': {'size': 8, 'members': {
                'inum': {'kind': 'integer', 'offset': 4, 'size': 4, 'signed': False},
            }},
        })

    def test_enum64_payload_and_forward_declaration(self):
        fixture = self.fixture
        old_task = fixture.records.pop()
        enum_value = struct.pack('<III', fixture.name('VALUE'), 17, 12)
        fixture.type('big_enum', 19, 8, enum_value, entries=1, kind_flag=True)
        fixture.type('task_struct', 7, 0)
        fixture.records.append(old_task)
        self.assertEqual(tool.extract_layout(fixture.data())['structures']['task_struct']['size'], 40)

    def test_header_and_section_rejections(self):
        data = self.fixture.data()
        for malformed in (data[:23], b'\xeb\x9f' + data[2:], data[:-1], data + b'\0', data[:-1] + b'X'):
            with self.subTest(data=malformed[:24]), self.assertRaises(tool.BtfError):
                tool.extract_layout(malformed)
        for index, value in ((2, 2), (3, 1), (4, 28), (8, 4), (12, 13), (16, 4), (20, 0)):
            malformed = bytearray(data)
            malformed[index] = value
            with self.subTest(index=index), self.assertRaises(tool.BtfError):
                tool.extract_layout(bytes(malformed))

    def test_invalid_type_framing(self):
        for kind, tail, entries, pattern in (
            (20, b'', 0, 'Unsupported type kind'),
            (2, b'', 1, 'Invalid type entry count'),
            (19, b'\0' * 8, 1, 'Truncated type payload'),
        ):
            with self.subTest(kind=kind):
                self.fixture = Fixture()
                self.fixture.type('', kind, 0, tail, entries=entries)
                self.assert_rejected(pattern)

    def test_malformed_string_reference(self):
        self.fixture.replace_word(self.fixture.task, 3, 0xFFFF)
        self.assert_rejected('String reference outside')

    def test_duplicate_structure(self):
        self.fixture.structure('task_struct', 40, self.fixture.task_fields, kind_flag=True)
        self.assert_rejected('exactly one struct task_struct')

    def test_missing_member(self):
        self.fixture.replace_word(self.fixture.task, 6, self.fixture.name('other'))
        self.assert_rejected('exactly one direct member pid')

    def test_duplicate_member(self):
        self.fixture.replace_word(self.fixture.task, 9, self.fixture.name('pid'))
        self.assert_rejected('exactly one direct member pid')

    def test_invalid_and_cyclic_type_references(self):
        for ref in (0, 0xFFFF, self.fixture.pid_t):
            with self.subTest(ref=ref):
                self.fixture.replace_word(self.fixture.pid_t, 2, ref)
                self.assert_rejected('Invalid, cyclic or excessively deep')

    def test_excessive_type_depth(self):
        ref = self.fixture.signed
        for index in range(33):
            ref = self.fixture.type(f'wrapped{index}', 8, ref)
        self.fixture.replace_word(self.fixture.pid_t, 2, ref)
        self.assert_rejected('excessively deep')

    def test_wrong_integer_encoding(self):
        for encoding in (0x20, 0x0100001F, 0x01010020, 0x03000020):
            with self.subTest(encoding=encoding):
                self.fixture.replace_word(self.fixture.signed, 3, encoding)
                self.assert_rejected('full-width integer')

    def test_wrong_pointer_target(self):
        self.fixture.replace_word(self.fixture.pid_ptr, 2, self.fixture.upid)
        self.assert_rejected('Expected a pointer to struct pid')

    def test_wrong_embedded_type(self):
        self.fixture.replace_word(self.fixture.namespace, 4, self.fixture.upid)
        self.assert_rejected('Expected an embedded struct ns_common')

    def test_fixed_size_array_rejected(self):
        self.fixture.replace_word(self.fixture.numbers, 5, 1)
        self.assert_rejected('zero-count flexible upid array')

    def test_array_element_type_mismatch(self):
        self.fixture.replace_word(self.fixture.numbers, 3, self.fixture.namespace)
        self.assert_rejected('zero-count flexible upid array')

    def test_flexible_array_before_end_rejected(self):
        self.fixture.replace_word(self.fixture.pid, 2, 16)
        self.assert_rejected('flexible upid array at the struct tail')

    def test_required_bitfield_and_nonbyte_offsets_rejected(self):
        for offset in ((1 << 24) | 32, 35):
            with self.subTest(offset=offset):
                self.fixture.replace_word(self.fixture.task, 11, offset)
                self.assert_rejected('bitfield or not byte-aligned')

    def test_required_misaligned_and_out_of_bounds_offsets_rejected(self):
        for offset in (8, 328):
            with self.subTest(offset=offset):
                self.fixture.replace_word(self.fixture.task, 11, offset)
                self.assert_rejected('misaligned or exceeds its structure')

    def test_overlapping_members_rejected(self):
        self.fixture.replace_word(self.fixture.task, 11, 0)
        self.assert_rejected('Overlapping requested members')

    def test_cli_pin_and_stable_lf_output(self):
        data = self.fixture.data()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'snapshot.btf')
            path.write_bytes(data)
            command = [sys.executable, '-B', tool.__file__, str(path), '--expect-sha256']
            good = subprocess.run([*command, hashlib.sha256(data).hexdigest()], capture_output=True, check=True)
            bad = subprocess.run([*command, '0' * 64], capture_output=True, check=False)
        self.assertEqual(json.loads(good.stdout), tool.extract_layout(data))
        self.assertTrue(good.stdout.endswith(b'\n'))
        self.assertNotIn(b'\r', good.stdout)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(bad.stdout, b'')
        self.assertIn(b'SHA-256 does not match', bad.stderr)


if __name__ == '__main__':
    unittest.main()
