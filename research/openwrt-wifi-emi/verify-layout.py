#!/usr/bin/env python3
"""Verify that the compiled C80 DTB changes only Linux/CONNSYS memory ownership."""
from pathlib import Path
import difflib
import hashlib
import json
import struct

base = Path(__file__).resolve().parent
parent = base.parent / 'openwrt-ram1'

def parse(data):
    magic, total, off_struct, off_strings, _, _, _, _, str_size, _ = struct.unpack_from('>10I', data)
    assert magic == 0xd00dfeed and total == len(data)
    strings = data[off_strings:off_strings + str_size]
    stack, props, nodes = [], {}, []
    offset = off_struct
    while True:
        token, = struct.unpack_from('>I', data, offset)
        offset += 4
        if token == 1:
            end = data.index(0, offset)
            stack.append(data[offset:end].decode())
            offset = (end + 4) & ~3
            nodes.append('/' + '/'.join(stack[1:]))
        elif token == 2:
            stack.pop()
        elif token == 3:
            length, name_offset = struct.unpack_from('>2I', data, offset)
            offset += 8
            name = strings[name_offset:strings.index(0, name_offset)].decode()
            props[('/' + '/'.join(stack[1:]), name)] = data[offset:offset + length]
            offset = (offset + length + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            return props, nodes
        else:
            raise AssertionError(token)

old, old_nodes = parse((parent / 'artifacts/c80-openwrt-ram1.dtb').read_bytes())
new, new_nodes = parse((base / 'c80-openwrt-ram1-emi.dtb').read_bytes())
for key, value in old.items():
    assert new[key] == value, key
expected = {
    ('/chosen', 'linux,usable-memory-range'): struct.pack('>2I', 0x40200000, 0x01e00000),
    ('/reserved-memory', '#address-cells'): struct.pack('>I', 1),
    ('/reserved-memory', '#size-cells'): struct.pack('>I', 1),
    ('/reserved-memory', 'ranges'): b'',
    ('/reserved-memory/memory@40000000', 'reg'): struct.pack('>2I', 0x40000000, 0x00200000),
    ('/reserved-memory/memory@40000000', 'no-map'): b'',
}
assert {key: value for key, value in new.items() if key not in old} == expected
assert set(new_nodes) - set(old_nodes) == {'/reserved-memory', '/reserved-memory/memory@40000000'}
assert set(old_nodes) <= set(new_nodes)
pins = {
    'c80-openwrt-ram1-zImage': '6eb8252fe975ec52bd61443f9fb52bd8f4618139704baeb534c3c20a641574c0',
    'c80-openwrt-ram1-handoff.bin': '3fffeec01561fb1976d0faec4b262d4ff829aad1dc0e1f9f2a92cbee9a38a083',
}
for name, digest in pins.items():
    assert hashlib.sha256((base / name).read_bytes()).hexdigest() == digest
old_end = int(json.loads((parent / 'artifacts/artifact-verification.json').read_text())['kernel_runtime_end_physical'], 16)
new_end = old_end + 0x200000
assert 0x40200000 <= 0x40208000 < new_end < 0x40e00000
assert 0x40f00000 + (base / 'c80-openwrt-ram1-emi.dtb').stat().st_size < 0x41000000
assert 0x41000000 + (base / 'c80-openwrt-ram1-zImage').stat().st_size < 0x41c00000
qemu = json.loads((base / 'evidence/qemu-openwrt-result.json').read_text())
assert qemu['passed'] and qemu['kernel_entry_physical'] == '0x40208000'
assert qemu['linux_usable_ram_bytes'] == 30 * 1024 * 1024
report = {'passed': True, 'changed_properties': [list(key) for key in expected],
          'all_other_compiled_dtb_properties_identical': True,
          'kernel_and_handoff_identical': pins, 'physical_dram_described_bytes': 33554432,
          'linux_usable_base': '0x40200000', 'linux_usable_bytes':31457280,
          'reserved_emi': ['0x40000000', '0x40200000'],
          'kernel_entry_physical': '0x40208000', 'kernel_bss_end_physical': hex(new_end),
          'ram_regions_do_not_overlap': True, 'new_dtb_hardware_tested':False,
          'radio_power_reset_firmware_or_dma_enabled_by_this_change':False}
(base / 'evidence/layout-result.json').write_text(json.dumps(report, indent=2) + '\n')
diff = ''.join(difflib.unified_diff(
    (parent / 'mt7626-archer-c80-v1-ram.dts').read_text().splitlines(True),
    (base / 'mt7626-archer-c80-v1-emi.dts').read_text().splitlines(True),
    fromfile='a/mt7626-archer-c80-v1-ram.dts', tofile='b/mt7626-archer-c80-v1-emi.dts'))
(base / 'c80-wifi-memory.patch').write_text(diff)
print('Compiled DTB memory-only scope verified; kernel+BSS ends at', hex(new_end))
