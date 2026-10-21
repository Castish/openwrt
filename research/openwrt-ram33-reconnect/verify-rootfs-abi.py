#!/usr/bin/env python3
"""Verify ARM soft-float EABI and all dynamic-library dependencies, even after sstrip."""
from pathlib import Path
import hashlib
import json
import os
import struct

base = Path(__file__).resolve().parent
root = base / 'rootfs'
evidence = []

def resolve(name):
    parts = []
    todo = name.strip('/').split('/')
    depth = 0
    while todo:
        item = todo.pop(0)
        if item in ('', '.'):
            continue
        if item == '..':
            assert parts
            parts.pop()
            continue
        path = root.joinpath(*parts, item)
        if path.is_symlink():
            target = os.readlink(path)
            depth += 1
            assert depth < 30
            if target.startswith('/'):
                parts = []
            todo = target.split('/') + todo
        else:
            parts.append(item)
    return root.joinpath(*parts)

for path in sorted(root.rglob('*')):
    if path.is_symlink() or not path.is_file():
        continue
    data = path.read_bytes()
    if not data.startswith(b'\x7fELF'):
        continue
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    assert data[4:6] == b'\x01\x01' and header[2] == 40, path
    flags = header[7]
    assert flags & 0xff000000 == 0x05000000 and flags & 0x200 and not flags & 0x400, path
    segments = [struct.unpack_from('<8I', data, header[5] + n * header[9])
                for n in range(header[10])]
    interpreter = [data[s[1]:s[1] + s[4]].rstrip(b'\0').decode()
                   for s in segments if s[0] == 3]
    assert not interpreter or interpreter == ['/lib/ld-musl-arm.so.1'], path
    dynamic = []
    for segment in segments:
        if segment[0] != 2:
            continue
        for offset in range(segment[1], segment[1] + segment[4], 8):
            tag, value = struct.unpack_from('<II', data, offset)
            if tag == 0:
                break
            dynamic.append((tag, value))
    tags = dict(dynamic)
    needed = []
    if 5 in tags:
        address = tags[5]
        loads = [s for s in segments if s[0] == 1 and s[2] <= address < s[2] + s[4]]
        assert len(loads) == 1
        start = loads[0][1] + address - loads[0][2]
        for tag, value in dynamic:
            if tag == 1:
                end = data.index(0, start + value)
                name = data[start + value:end].decode()
                assert any(resolve(directory + '/' + name).is_file()
                           for directory in ('/lib', '/usr/lib')), (path, name)
                needed.append(name)
    evidence.append({'path': str(path.relative_to(root)), 'bytes': len(data),
                     'sha256': hashlib.sha256(data).hexdigest(), 'abi_flags': hex(flags),
                     'interpreter': interpreter, 'needed': needed})
assert len(evidence) >= 58
(base / 'evidence/rootfs-elf-closure.json').write_text(json.dumps(evidence, indent=2) + '\n')
print(f'ARM EABI5 soft-float ELF files and library closure verified: {len(evidence)}')
