#!/usr/bin/env python3
"""Issue an explicit allowlist; verify every ZIP CRC, member length and hash."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

r=Path(__file__).resolve().parent
destination=r/'c80-openwrt-ram2-mcu.zip'
assert not destination.exists(),'Issued archives are immutable'
names='''README.md LICENSES.md RUNNER-LICENSE AUTHENTICITY.md PROVENANCE.json
FIRMWARE-SOURCES.json openwrt-packages.json packages.lock toolchain-manifest.json
kernel-source-manifest.json rootfs-overrides.json
c80-openwrt-ram2-mcu-zImage c80-openwrt-ram2-mcu.dtb c80-openwrt-ram2-handoff.bin
c80-script-runner.bin c80-start.txt make-script.py handoff.S
c80_mcu_core.h c80_mcu_transport.c c80_restart.c restart-evidence.md
mt7626-archer-c80-v1-emi.dts minimal.config build-kernel.sh prepare-kernel.py
build-qemu-check.sh run-qemu-emi-check.sh qemu-emi.dts qemu-emi.dtb
make-initramfs-list.py make-source-patch.py linux-mt7626-bringup.patch
verify-core.c verify-core.sh verification-core.log stock-command-oracle.bin
verify-rootfs-abi.py verify-rootfs-scope.py verify-artifacts.py verify-restart.py
verify-qemu-emi.py verify-decompressor.py verify-handoff.py finalize-artifacts.py package.py
artifacts/kernel.config artifacts/artifact-verification.json artifacts/patch-verification.txt
evidence/rootfs-elf-closure.json evidence/rootfs-scope.json evidence/source-scope.json
evidence/stock-mcu-command-traces.json evidence/restart-result.json
evidence/rebuild-result.json evidence/script-result.json evidence/decompressor-result.json
evidence/handoff-verification.json evidence/qemu-missing-firmware-result.json
evidence/qemu-aon-refusal-result.json evidence/qemu-missing-firmware-boot.log
evidence/qemu-aon-refusal-boot.log
rootfs/lib/firmware/c80/test_mcu.bin rootfs/lib/firmware/c80/test_wifi.bin
rootfs/lib/firmware/c80/WIFI_RAM_CODE_iemi.bin rootfs/lib/firmware/c80/WIFI_RAM_CODE_demi.bin
'''.split()
assert len(set(names))==len(names)
records=[]
for name in names:
    p=r/name;assert p.is_file() and not p.is_symlink(),name
    data=p.read_bytes()
    if p.suffix in ('.md','.json','.c','.h','.py','.sh','.dts','.txt','.log'):
        assert b'-----BEGIN '+b'PRIVATE KEY-----' not in data,name
        # The virtual NIC MAC is not a router-specific secret. Any other MAC
        # in evidence must be reviewed before a private device artifact leaves.
        macs=re.findall(rb'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',data)
        assert all(x.lower()==b'52:54:00:12:34:56' for x in macs),(name,macs)
    records.append({'file':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
(r/'SHA256SUMS').write_text(''.join(x['sha256']+'  '+x['file']+'\n' for x in records))
records.append({'file':'SHA256SUMS','bytes':(r/'SHA256SUMS').stat().st_size,
 'sha256':hashlib.sha256((r/'SHA256SUMS').read_bytes()).hexdigest()})
(r/'package-manifest.json').write_text(json.dumps({'files':records,
 'hardware_restart_tested':False,'hardware_MCU_DMA_tested':False,
 'contains_only_four_supplied_generic_OEM_firmware_components':True,
 'no_full_proprietary_OS_bootloader_flash_or_individual_calibration':True},indent=2)+'\n')
with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
    for name in sorted([x['file'] for x in records]+['package-manifest.json']):
        archive.write(r/name,'c80-openwrt-ram2-mcu/'+name)
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None and len(archive.namelist())==len(records)+1
    for row in records:
        data=archive.read('c80-openwrt-ram2-mcu/'+row['file'])
        assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
result={'file':str(destination),'bytes':destination.stat().st_size,
 'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'files':len(records)+1,
 'all_ZIP_CRCS_lengths_and_SHA256_verified':True}
destination.chmod(0o600)
(r/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
