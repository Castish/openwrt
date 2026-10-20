#!/usr/bin/env python3
"""Issue a memory-only C80 bundle without private logs or vendor binaries."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

base = Path(__file__).resolve().parent
parent = base.parent / 'openwrt-ram1'
wifi = base.parent / 'wifi-bringup'
destination = base / 'c80-openwrt-ram1-wifi-memory.zip'
assert not destination.exists(), 'Issued ZIP files must never be replaced'
members = {}
top = '''README.md LICENSES.md PROVENANCE.json FILES.json SHA256SUMS
c80-openwrt-ram1-zImage c80-openwrt-ram1-emi.dtb c80-openwrt-ram1-handoff.bin
mt7626-archer-c80-v1-emi.dts c80-openwrt-ram1-emi.preprocessed.dts
c80-wifi-memory.patch build-dtb.sh verify-layout.py verify-decompressor.py
verify-handoff.py verify-qemu-emi.py run-qemu-emi-check.sh qemu-emi.dts
qemu-emi.dtb package.py'''.split()
for name in top:
    members[name] = base / name
for name in '''layout-result.json decompressor-result.json handoff-verification.json
qemu-openwrt-result.json qemu-openwrt-boot.log'''.split():
    members['evidence/' + name] = base / 'evidence' / name
for name in '''README.md LICENSES.md AUTHENTICITY.md PROVENANCE.json
linux-mt7626-bringup.patch minimal.config build-kernel.sh prepare-kernel.py
build-rootfs.sh prepare-rootfs.py make-initramfs-list.py patch-dsa.py
mt7626-archer-c80-v1-ram.dts c80_ram_eth.c c80_pdma_core.h c80_ram_mdio.c
c80_ram_mdio.h c80_rtl8367s.h rtl8365mb-patched.c make-source-patch.py
handoff.S handoff.ld build-handoff.sh packages.lock openwrt-packages.json
rootfs-overrides.json repositories kernel-source-manifest.json
toolchain-manifest.json parent-source-manifest.json'''.split():
    members['source-ram1/' + name] = parent / name
for name in '''kernel.config artifact-verification.json'''.split():
    members['source-ram1/artifacts/' + name] = parent / 'artifacts' / name
for name in '''config.buildinfo feeds.buildinfo version.buildinfo sha256sums
sha256sums.asc openwrt-signing.asc signature-status.txt signature-verification.txt
linux-6.12.113.tar.sign gregkh-complete.key'''.split():
    members['source-ram1/downloads/' + name] = parent / 'downloads' / name
for name in ('REPORT.md', 'firmware-metadata.json', 'inspect-firmware.py'):
    members['wifi-research/' + name] = wifi / name
for name in ('stock-emi-remap-disassembly.txt', 'stock-connsys-version-disassembly.txt'):
    members['wifi-research/' + name] = wifi / name
for name in ('REPORT.md', 'result.json', 'netifd-status.json'):
    members['prior-hardware/' + name] = parent / 'hardware-boot-1' / name
members['source-ram1/COPYING'] = parent / 'linux-6.12.113/COPYING'
members['source-ram1/LICENSES/GPL-2.0'] = parent / 'linux-6.12.113/LICENSES/preferred/GPL-2.0'
members['source-ram1/LICENSES/Linux-syscall-note'] = parent / 'linux-6.12.113/LICENSES/exceptions/Linux-syscall-note'

private_macs = set()
for path in (parent / 'hardware-boot-1/uart-private.log',
             base.parent / 'linux-ethernet-ram9/hardware-ethernet-1/uart-private.log'):
    if path.exists():
        private_macs.update(re.findall(rb'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', path.read_bytes()))
records = []
for name, path in sorted(members.items()):
    assert not name.startswith('/') and '..' not in Path(name).parts
    assert path.is_file(), name
    if path.is_symlink():
        assert name in ('c80-openwrt-ram1-zImage', 'c80-openwrt-ram1-handoff.bin')
        assert path.resolve().parent == (parent / 'artifacts').resolve()
    data = path.read_bytes()
    assert not any(value.lower() in data.lower() for value in private_macs), name
    assert b'C:\\Users\\Admin' not in data, name
    records.append({'file': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
manifest = {'files': records, 'flash_writes': False, 'wifi_enabled': False,
            'hardware_status': 'Original RAM1 OpenWrt/LAN1 passed; new memory-only DTB awaits C80 test',
            'qemu_status': '23 integration checks passed on virt with the unchanged CPIO and 2MiB excluded'}
(base / 'package-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
members['package-manifest.json'] = base / 'package-manifest.json'
with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name, path in sorted(members.items()):
        archive.write(path, 'c80-openwrt-ram1-wifi-memory/' + name)
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(members)
    for record in records:
        data = archive.read('c80-openwrt-ram1-wifi-memory/' + record['file'])
        assert len(data) == record['bytes']
        assert hashlib.sha256(data).hexdigest() == record['sha256']
result = {'file': str(destination), 'bytes': destination.stat().st_size,
          'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
          'files': len(members), 'crc_and_all_member_hashes_verified': True,
          'private_mac_strings_scanned': True}
(base / 'bundle-result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
