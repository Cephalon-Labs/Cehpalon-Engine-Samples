"""Extract the bounded ADR0030 layout from an offline Linux x86-64 raw BTF file."""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import NamedTuple


# WSL 6.18.54.1 include/uapi/linux/btf.h (BTF v1, kinds through ENUM64).
HEADER = struct.Struct('<HBB5I')
TYPE = struct.Struct('<III')
INT, PTR, ARRAY, STRUCT = 1, 2, 3, 4
QUALIFIERS = {8, 9, 10, 11, 18}
FIXED_TAIL = {INT: 4, ARRAY: 12, 14: 4, 17: 4}
ENTRY_WIDTH = {STRUCT: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}
FLAG_KINDS = {STRUCT, 5, 6, 7, 17, 18, 19}
MAX_BYTES = 32 * 1024 * 1024
MAX_TYPES = 0x000FFFFF
MAX_STRINGS = 0x01000000
MAX_STRUCT_BYTES = 1024 * 1024
POINTER_BYTES = 8  # An input profile assumption, not an architecture inferred from BTF.


class BtfError(ValueError):
    """The input is outside the reviewed BTF layout profile."""


class BtfType(NamedTuple):
    name_offset: int
    kind: int
    entries: int
    size_or_reference: int
    kind_flag: bool
    tail_offset: int


class Btf:
    """Frame the type table, then resolve only the requested layout graph."""

    def __init__(self, data):
        if not isinstance(data, bytes) or not HEADER.size <= len(data) <= MAX_BYTES:
            raise BtfError('Expected a bounded raw BTF byte string')
        magic, version, flags, header, type_off, type_len, str_off, str_len = HEADER.unpack_from(data)
        if (magic, version, flags, header) != (0xEB9F, 1, 0, HEADER.size):
            raise BtfError('Expected the little-endian BTF v1 header')
        if (type_off != 0 or type_len < TYPE.size or type_len % 4 or str_off != type_len
                or not 1 <= str_len <= MAX_STRINGS or header + str_off + str_len != len(data)):
            raise BtfError('Inconsistent type/string section bounds')

        self.data = data
        self.strings = data[header + str_off:]
        if self.strings[0] != 0 or self.strings[-1] != 0:
            raise BtfError('Invalid string section boundaries')

        # Slot zero is void. Reject split BTF and unknown record kinds rather than
        # guessing where the next type starts.
        self.types = [None]
        offset = header
        end = header + type_len
        while offset < end:
            if end - offset < TYPE.size or len(self.types) > MAX_TYPES:
                raise BtfError('Truncated or oversized type table')
            name, info, value = TYPE.unpack_from(data, offset)
            kind = (info >> 24) & 31
            flag = bool(info >> 31)
            entries = info & 0xFFFF
            if not 1 <= kind <= 19 or info & 0x60FF0000 or (flag and kind not in FLAG_KINDS):
                raise BtfError('Unsupported type kind or info bits')
            if kind not in ENTRY_WIDTH and (entries > 2 if kind == 12 else entries != 0):
                raise BtfError('Invalid type entry count')
            self.check_string_offset(name)
            offset += TYPE.size
            tail_size = FIXED_TAIL.get(kind, 0) + ENTRY_WIDTH.get(kind, 0) * entries
            if offset + tail_size > end:
                raise BtfError('Truncated type payload')
            self.types.append(BtfType(name, kind, entries, value, flag, offset))
            offset += tail_size

    def check_string_offset(self, offset):
        if offset >= len(self.strings):
            raise BtfError('String reference outside the BTF string section')

    def name_is(self, offset, name):
        self.check_string_offset(offset)
        return self.strings.startswith(name, offset)

    def structure(self, name):
        encoded = name.encode('ascii') + b'\0'
        matches = [type_id for type_id, record in enumerate(self.types[1:], 1)
                   if record.kind == STRUCT and self.name_is(record.name_offset, encoded)]
        if len(matches) != 1:
            raise BtfError(f'Expected exactly one struct {name}')
        type_id = matches[0]
        if not 1 <= self.types[type_id].size_or_reference <= MAX_STRUCT_BYTES:
            raise BtfError(f'Unsupported struct {name} byte size')
        return type_id

    def resolve(self, reference):
        seen = set()
        while 0 < reference < len(self.types) and reference not in seen and len(seen) < 32:
            record = self.types[reference]
            if record.kind not in QUALIFIERS:
                return reference, record
            seen.add(reference)
            reference = record.size_or_reference
        raise BtfError('Invalid, cyclic or excessively deep layout type reference')

    def member(self, structure, name):
        record = self.types[structure]
        encoded = name.encode('ascii') + b'\0'
        matches = []
        for index in range(record.entries):
            offset = record.tail_offset + index * TYPE.size
            member_name, reference, bit_offset = TYPE.unpack_from(self.data, offset)
            if self.name_is(member_name, encoded):
                matches.append((index, reference, bit_offset))
        if len(matches) != 1:
            raise BtfError(f'Expected exactly one direct member {name}')
        index, reference, bit_offset = matches[0]
        if (record.kind_flag and bit_offset >> 24) or bit_offset % 8:
            raise BtfError(f'Member {name} is a bitfield or not byte-aligned')
        return index, reference, bit_offset // 8

    def integer(self, reference, size, signed):
        _, record = self.resolve(reference)
        encoding = (int(signed) << 24) | (8 * size)
        if (record.kind != INT or record.size_or_reference != size
                or struct.unpack_from('<I', self.data, record.tail_offset)[0] != encoding):
            raise BtfError('Expected a full-width integer with the reviewed signedness')


def extract_layout(data):
    """Return byte layout and input hash, without runtime identity or readiness claims."""
    btf = Btf(data)
    specifications = {
        'task_struct': {
            'pid': (4, True), 'tgid': (4, True), 'start_boottime': (8, False), 'thread_pid': '*pid',
        },
        'pid': {'level': (4, False), 'numbers': 'upid[]'},
        'upid': {'nr': (4, True), 'ns': '*pid_namespace'},
        'pid_namespace': {'ns': 'ns_common'},
        'ns_common': {'inum': (4, False)},
    }
    structures = {name: btf.structure(name) for name in specifications}
    layout = {}
    for name, fields in specifications.items():
        type_id = structures[name]
        struct_size = btf.types[type_id].size_or_reference
        members = {}
        for field, expected in fields.items():
            try:
                members[field] = layout_member(btf, structures, type_id, field, expected)
            except BtfError as error:
                raise BtfError(f'{name}.{field}: {error}') from error

        intervals = sorted((field['offset'], field['offset'] + field['size']) for field in members.values())
        if any(end > start for (_, end), (start, _) in zip(intervals, intervals[1:])):
            raise BtfError(f'Overlapping requested members in struct {name}')
        layout[name] = {'size': struct_size, 'members': members}

    return {
        'schema': 'scheduler-dynamic-btf-layout-v1',
        'layout_profile': 'linux-x86_64-le',
        'pointer_bytes': POINTER_BYTES,
        'btf_sha256': hashlib.sha256(data).hexdigest(),
        'btf_bytes': len(data),
        'structures': layout,
    }


def layout_member(btf, structures, structure, name, expected):
    index, reference, offset = btf.member(structure, name)
    struct_record = btf.types[structure]
    _, record = btf.resolve(reference)

    if isinstance(expected, tuple):
        size, signed = expected
        btf.integer(reference, size, signed)
        alignment = size
        shape = {'kind': 'integer', 'signed': signed}
    elif expected.startswith('*'):
        target = expected[1:]
        if record.kind != PTR or btf.resolve(record.size_or_reference)[0] != structures[target]:
            raise BtfError(f'Expected a pointer to struct {target}')
        size = alignment = POINTER_BYTES
        shape = {'kind': 'pointer', 'target': target}
    elif expected == 'upid[]':
        if record.kind != ARRAY or record.size_or_reference != 0:
            raise BtfError('Expected an array of struct upid')
        element, index_type, count = TYPE.unpack_from(btf.data, record.tail_offset)
        if (count != 0 or btf.resolve(element)[0] != structures['upid']
                or index != struct_record.entries - 1 or offset != struct_record.size_or_reference):
            raise BtfError('Expected a zero-count flexible upid array at the struct tail')
        btf.integer(index_type, 4, True)
        stride = btf.types[structures['upid']].size_or_reference
        if stride % POINTER_BYTES:
            raise BtfError('Expected aligned upid array elements')
        size = 0
        alignment = POINTER_BYTES
        shape = {'kind': 'flexible_array', 'element': 'upid', 'stride': stride, 'declared_count': count}
    else:
        if btf.resolve(reference)[0] != structures[expected]:
            raise BtfError(f'Expected an embedded struct {expected}')
        size = record.size_or_reference
        alignment = POINTER_BYTES
        shape = {'kind': 'struct', 'target': expected}

    if offset % alignment or offset + size > struct_record.size_or_reference:
        raise BtfError('Member offset is misaligned or exceeds its structure')
    return {'offset': offset, 'size': size, **shape}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('btf', type=Path, help='retained raw BTF file')
    parser.add_argument('--expect-sha256', help='optional pinned SHA-256 of the retained file')
    args = parser.parse_args(argv)
    try:
        if not args.btf.is_file():
            raise BtfError('Expected a regular BTF file')
        with args.btf.open('rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        if args.expect_sha256 is not None and hashlib.sha256(data).hexdigest() != args.expect_sha256:
            raise BtfError('Input BTF SHA-256 does not match the pin')
        layout = extract_layout(data)
    except (BtfError, OSError) as error:
        print(f'BTF layout rejected: {error}', file=sys.stderr)
        return 2

    sys.stdout.buffer.write((json.dumps(layout, indent=2, sort_keys=True) + '\n').encode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
