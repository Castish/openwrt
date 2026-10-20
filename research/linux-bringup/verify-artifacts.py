#!/usr/bin/env python3
"""Check actual kernel/DTB/initramfs outputs, configuration and RAM placement."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / 'build'
ART = ROOT / 'artifacts'
ART.mkdir(exist_ok=True)
kernel = (BUILD / 'arch/arm/boot/zImage').read_bytes()
dtb = (BUILD / 'arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
init = (BUILD / 'userspace/init').read_bytes()
assert struct.unpack_from('<I', kernel, 0x24)[0] == 0x016F2818
assert struct.unpack_from('<I', kernel, 0x2C)[0] == len(kernel)

# Validate the compiled DTB, not just its source.
magic, total, off_struct, off_strings, off_reserve, version, last, bootcpu, str_size, struct_size = struct.unpack_from('>10I', dtb)
assert magic == 0xD00DFEED and total == len(dtb)
strings = dtb[off_strings:off_strings + str_size]
props = {}
nodes = []
stack = []
pos = off_struct
while True:
    token = struct.unpack_from('>I', dtb, pos)[0]
    pos += 4
    if token == 1:
        end = dtb.index(0, pos)
        stack.append(dtb[pos:end].decode())
        pos = (end + 4) & ~3
        nodes.append('/' + '/'.join(stack[1:]))
    elif token == 2:
        stack.pop()
    elif token == 3:
        size, nameoff = struct.unpack_from('>2I', dtb, pos)
        pos += 8
        name = strings[nameoff:strings.index(0, nameoff)].decode()
        props[('/' + '/'.join(stack[1:]), name)] = dtb[pos:pos + size]
        pos = (pos + size + 3) & ~3
    elif token == 4:
        pass
    elif token == 9:
        break
    else:
        raise AssertionError(('Invalid DT token', token))
assert props[('/', 'compatible')].split(b'\0')[:2] == [b'tplink,archer-c80-v1', b'mediatek,mt7626']
assert struct.unpack('>2I', props[('/memory@40000000', 'reg')]) == (0x40000000, 0x02000000)
assert [n for n in nodes if n.startswith('/cpus/cpu@')] == ['/cpus/cpu@0']
assert struct.unpack('>4I', props[('/soc/interrupt-controller@10310000', 'reg')]) == (0x10310000, 0x1000, 0x10320000, 0x1000)
assert ('/soc/serial@11002000', 'tplink,bringup-polling') in props
assert ('/soc/serial@11002000', 'interrupts') not in props
assert struct.unpack('>I', props[('/timer', 'clock-frequency')])[0] == 20_000_000
assert struct.unpack('>I', props[('/uart-clock', 'clock-frequency')])[0] == 40_000_000

# Verify all initramfs entries and the exact executable included in the kernel.
cpio = (BUILD / 'usr/initramfs_data.cpio').read_bytes()
packed = (BUILD / 'usr/initramfs_inc_data').read_bytes()
assert gzip.decompress(packed) == cpio
entries = {}
pos = 0
while True:
    assert cpio[pos:pos + 6] == b'070701'
    fields = [int(cpio[pos + 6 + n * 8:pos + 14 + n * 8], 16) for n in range(13)]
    namesize, filesize = fields[11], fields[6]
    name = cpio[pos + 110:pos + 110 + namesize - 1].decode()
    start = (pos + 110 + namesize + 3) & ~3
    content = cpio[start:start + filesize]
    pos = (start + filesize + 3) & ~3
    if name == 'TRAILER!!!':
        break
    entries[name.lstrip('/')] = (fields, content)
assert entries['init'][1] == init
assert entries['init'][0][1] & 0o111 and entries['init'][0][2:4] == [0, 0]
assert entries['dev/console'][0][1] & 0o170000 == 0o020000
assert entries['dev/console'][0][9:11] == [5, 1]
assert {'dev', 'proc', 'sys', 'tmp', 'dev/null'} <= set(entries)

config = (BUILD / '.config').read_text()
for name in ('MMU', 'ARCH_MULTI_V7', 'MACH_MT7626', 'ARM_ARCH_TIMER',
             'SERIAL_8250_MT6577', 'SERIAL_8250_CONSOLE', 'ARM_PATCH_PHYS_VIRT',
             'ARM_ERRATA_814220'):
    assert f'CONFIG_{name}=y\n' in config, name
for name in ('MTD', 'NET', 'SMP', 'HIGHMEM', 'ARM_LPAE'):
    assert f'CONFIG_{name}=y\n' not in config, name
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = str(ROOT / 'tools/usr/lib/x86_64-linux-gnu') + ':' + env.get('LD_LIBRARY_PATH', '')
symbols = subprocess.check_output([str(ROOT / 'tools/usr/bin/arm-linux-gnueabi-nm'), '-n', str(BUILD / 'vmlinux')], env=env, text=True)
match = re.search(r'^([0-9a-f]+) B _end$', symbols, re.M)
assert match
kernel_runtime_end = int(match[1], 16) - 0xC0000000 + 0x40000000
assert kernel_runtime_end < 0x40600000
assert 0x40800000 + len(kernel) < 0x41C00000
assert 0x40700000 + len(dtb) < 0x40800000

for source, name in [(BUILD / 'arch/arm/boot/zImage', 'c80-linux-zImage'),
                     (BUILD / 'arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb', 'c80-linux.dtb'),
                     (BUILD / '.config', 'kernel.config')]:
    shutil.copyfile(source, ART / name)
files = ['c80-linux-zImage', 'c80-linux.dtb', 'c80-linux-handoff.bin']
records = [{'file': name, 'bytes': (ART / name).stat().st_size,
            'sha256': hashlib.sha256((ART / name).read_bytes()).hexdigest()}
           for name in files]
(ART / 'SHA256SUMS').write_text(''.join(r['sha256'] + '  ' + r['file'] + '\n' for r in records))
result = {'kernel_version': '6.12.113-c80-ram1', 'artifacts': records,
          'kernel_runtime_end_physical': hex(kernel_runtime_end),
          'memory_bytes_configured': 0x02000000, 'physical_ram_capacity_measured': False,
          'dtb_structure_and_hardware_addresses_verified': True,
          'initramfs_entries': sorted(entries), 'initramfs_init_matches_tested_elf': True,
          'kernel_boot_on_hardware': 'not yet tested',
          'emulation_scope': 'Separate handoff and userspace tests; full Linux boot not emulated'}
(ART / 'artifact-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
