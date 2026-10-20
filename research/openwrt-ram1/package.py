#!/usr/bin/env python3
"""Issue an immutable public C80 OpenWrt RAM bundle using an explicit allowlist."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

base = Path(__file__).resolve().parent
destination = base / 'c80-openwrt-ram1.zip'
assert not destination.exists(), 'Issued archives must never be overwritten'
top = '''README.md AUTHENTICITY.md PROVENANCE.json LICENSES.md
build-rootfs.sh prepare-rootfs.py make-initramfs-list.py verify-rootfs-abi.py
build-kernel.sh prepare-kernel.py patch-dsa.py minimal.config
mt7626-archer-c80-v1-ram.dts c80_ram_eth.c c80_pdma_core.h c80_ram_mdio.c
c80_ram_mdio.h c80_rtl8367s.h rtl8365mb-patched.c linux-mt7626-bringup.patch
make-source-patch.py kernel-source-manifest.json signature-status.txt
signature-verification.txt toolchain-manifest.json parent-source-manifest.json
handoff.S handoff.ld build-handoff.sh verify-handoff.py verify-artifacts.py
build-qemu-check.sh run-qemu-check.sh verify-qemu-boot.py qemu-system-packages.json
packages.lock openwrt-packages.json rootfs-overrides.json repositories package.py'''.split()
artifacts = '''c80-openwrt-ram1-zImage c80-openwrt-ram1.dtb c80-openwrt-ram1-handoff.bin
SHA256SUMS kernel.config artifact-verification.json handoff.elf
handoff-disassembly.txt handoff-elf.txt patch-verification.txt'''.split()
evidence = '''rootfs-elf-closure.json uci-network.txt uci-system.txt openwrt-init-elf.txt
artifact-verification.txt handoff-verification.txt patch-verification.txt
apk-index-signature-verification.txt apk-package-digest-recheck.txt
qemu-openwrt-boot.log qemu-openwrt-result.json rootfs-rebuild.txt
ram9-source-reuse.json ram9-hardware-result.json ram9-hardware-report.md
ram9-uart-redacted.log'''.split()
downloads = '''sha256sums sha256sums.asc openwrt-signing.asc signature-status.txt
signature-verification.txt key-fingerprints.txt config.buildinfo feeds.buildinfo
version.buildinfo openwrt-init initramfs-base-files.txt
linux-6.12.113.tar.sign gregkh-complete.key'''.split()
names = top + ['artifacts/' + name for name in artifacts]
names += ['evidence/' + name for name in evidence]
names += ['downloads/' + name for name in downloads]
names += [str(path.relative_to(base)) for path in sorted((base / 'apk-cache').iterdir())
          if path.is_file() and not path.is_symlink() and
          (path.suffix == '.apk' or path.name.startswith('APKINDEX.') or path.name == 'SHA256SUMS')]
assert len(names) == len(set(names))
records = []
private_capture = base.parent / 'linux-ethernet-ram9/hardware-ethernet-1/uart-private.log'
private_macs = set(re.findall(rb'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',
                             private_capture.read_bytes())) if private_capture.exists() else set()
for name in sorted(names):
    path = base / name
    assert path.is_file() and not path.is_symlink(), name
    data = path.read_bytes()
    assert not any(value.lower() in data.lower() for value in private_macs), name
    records.append({'file': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
manifest = {'files': records, 'flash_writes': False,
            'hardware_status': 'This OpenWrt image awaits C80 test; inherited Ethernet source passed RAM9 LAN1',
            'qemu_status': 'Exact rootfs passed22 checks on32MiB QEMU virt with a separate verification kernel'}
(base / 'package-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name in sorted(names + ['package-manifest.json']):
        archive.write(base / name, 'c80-openwrt-ram1/' + name)
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(names) + 1
    for record in records:
        data = archive.read('c80-openwrt-ram1/' + record['file'])
        assert len(data) == record['bytes']
        assert hashlib.sha256(data).hexdigest() == record['sha256']
result = {'file': str(destination), 'bytes': destination.stat().st_size,
          'sha256': hashlib.file_digest(destination.open('rb'), 'sha256').hexdigest(),
          'files': len(names) + 1, 'crc_and_all_member_hashes_verified': True}
(base / 'bundle-result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
