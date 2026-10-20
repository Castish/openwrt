#!/usr/bin/env python3
"""Issue an explicit allowlist; verify every ZIP CRC, member length and hash."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

r=Path(__file__).resolve().parent
destination=r/'c80-openwrt-ram24-tx-free.zip'
assert not destination.exists(),'Issued archives are immutable'
names='''README.md README-template.md LICENSES.md RUNNER-LICENSE AUTHENTICITY.md PROVENANCE.json
ram23-to-ram24.patch verify-parent-scope.py evidence/ram23-change-scope.json prior-hardware/RAM4-REPORT.md prior-hardware/RAM4-result.json prior-hardware/reboot-REPORT.md prior-hardware/RAM5-REPORT.md prior-hardware/RAM5-result.json prior-hardware/RAM6-REPORT.md prior-hardware/RAM6-result.json prior-hardware/RAM7-REPORT.md prior-hardware/RAM7-result.json prior-hardware/RAM8-REPORT.md prior-hardware/RAM8-result.json prior-hardware/RAM9-REPORT.md prior-hardware/RAM9-result.json prior-hardware/RAM10-REPORT.md prior-hardware/RAM10-result.json prior-hardware/RAM11-REPORT.md prior-hardware/RAM11-result.json prior-hardware/RAM12-REPORT.md prior-hardware/RAM12-result.json prior-hardware/RAM13-REPORT.md prior-hardware/RAM13-result.json prior-hardware/RAM14-REPORT.md prior-hardware/RAM14-result.json prior-hardware/RAM15-REPORT.md prior-hardware/RAM15-result.json prior-hardware/RAM16-REPORT.md prior-hardware/RAM16-result.json prior-hardware/RAM17-REPORT.md prior-hardware/RAM17-result.json prior-hardware/RAM18-REPORT.md prior-hardware/RAM18-result.json prior-hardware/RAM19-REPORT.md prior-hardware/RAM19-result.json prior-hardware/RAM20-REPORT.md prior-hardware/RAM20-result.json prior-hardware/RAM21-REPORT.md prior-hardware/RAM21-result.json prior-hardware/RAM22-REPORT.md prior-hardware/RAM22-result.json prior-hardware/RAM23-REPORT.md prior-hardware/RAM23-result.json
FIRMWARE-SOURCES.json openwrt-packages.json packages.lock toolchain-manifest.json
kernel-source-manifest.json rootfs-overrides.json
c80-openwrt-ram24-tx-free-zImage c80-openwrt-ram24-tx-free.dtb c80-openwrt-ram24-handoff.bin
c80-script-runner.bin c80-start.txt make-script.py handoff.S
c80_mcu_core.h c80_mcu_transport.c c80_restart.c restart-evidence.md
mt7626-archer-c80-v1-emi.dts minimal.config build-kernel.sh prepare-kernel.py
build-qemu-check.sh run-qemu-emi-check.sh qemu-emi.dts qemu-emi.dtb
make-initramfs-list.py make-source-patch.py linux-mt7626-bringup.patch
verify-core.c verify-core.sh verification-core.log verify-irq-wrapper.py irq-wrapper-verification.log evidence/irq-wrapper-result.json verify-nvm-reader.py nvm-reader-verification.log evidence/nvm-reader-result.json stock-synthetic-eeprom.bin synthetic-radio-fixture.bin stock-command-oracle.bin stock-auth-txd.bin
verify-rootfs-abi.py verify-rootfs-scope.py verify-artifacts.py verify-restart.py
verify-qemu-emi.py verify-decompressor.py verify-handoff.py finalize-artifacts.py package.py
artifacts/kernel.config artifacts/artifact-verification.json artifacts/patch-verification.txt
evidence/rootfs-elf-closure.json evidence/rootfs-scope.json
evidence/trace-stock-download.py evidence/stock-download-traces.json evidence/download-contract.md
evidence/trace-stock-main.py evidence/stock-main-traces.json evidence/main-contract.md
evidence/trace-stock-dma-mode.py evidence/stock-dma-mode-traces.json evidence/dma-mode-contract.md
evidence/trace-stock-query.py evidence/stock-query-traces.json evidence/runtime-query-contract.md evidence/trace-stock-irq.py evidence/stock-irq-traces.json evidence/irq-contract.md evidence/trace-stock-nvm.py evidence/stock-nvm-traces.json evidence/nvm-contract.md evidence/nvm-wait-contract.json
evidence/trace-stock-devinfo.py evidence/stock-devinfo-traces.json evidence/devinfo-contract.md evidence/devinfo-variable-result.json evidence/trace-stock-bss.py evidence/stock-bss-traces.json evidence/bss-contract.md evidence/trace-stock-radio.py evidence/stock-radio-traces.json evidence/radio-contract.md evidence/trace-stock-beacon.py evidence/stock-beacon-traces.json evidence/beacon-contract.md evidence/watch-contract.md evidence/rx-recycle-contract.md evidence/trace-stock-rx.py evidence/stock-rx-traces.json verify-rx-recycle.c verify-rx-recycle.sh verification-rx-recycle.log evidence/rx-recycle-result.json evidence/beacon-offload-contract.md evidence/trace-stock-offload.py evidence/stock-offload-traces.json evidence/TXD-wire-change-result.json evidence/beacon-state-contract.md evidence/trace-stock-beacon-state.py evidence/stock-beacon-state-traces.json evidence/state-wire-change-result.json evidence/bss-period-contract.md evidence/trace-stock-bss-period.py evidence/stock-bss-period-traces.json evidence/period-wire-change-result.json evidence/client-rx-contract.md evidence/client-rx-result.json verify-client-rx.c verify-client-rx.sh verification-client-rx.log evidence/ram24-wire-result.json evidence/trace-stock-management.py evidence/stock-management-traces.json evidence/auth-tx-contract.md evidence/auth-tx-result.json verify-auth-tx.c verify-auth-tx.sh verification-auth-tx.log verify-pool-lifetime.py restore-source.py verify-tx-free.c verify-tx-free.sh verification-tx-free.log evidence/tx-free-result.json evidence/tx-free-contract.md evidence/trace-stock-tx-free.py evidence/stock-tx-free-traces.json evidence/source-restore-result.json verification-pool-lifetime.log evidence/pool-lifetime-result.json verify-beacon-state.c verify-beacon-state.sh verification-beacon-state.log evidence/beacon-state-result.json
evidence/restart-result.json
evidence/script-result.json evidence/decompressor-result.json
evidence/handoff-verification.json evidence/qemu-missing-firmware-result.json
evidence/qemu-aon-refusal-result.json evidence/qemu-missing-firmware-boot.log
evidence/qemu-aon-refusal-boot.log
rootfs/lib/firmware/c80/test_mcu.bin rootfs/lib/firmware/c80/test_wifi.bin
rootfs/lib/firmware/c80/WIFI_RAM_CODE_iemi.bin rootfs/lib/firmware/c80/WIFI_RAM_CODE_demi.bin
rootfs/lib/firmware/c80/mt7626_patch_e1_hdr.bin
rootfs/lib/firmware/c80/WIFI_RAM_CODE_7626.bin
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
 'new_build_hardware_beacon_tested':False,'new_build_HIF_watch_tested':False,'new_build_RX0_recycling_hardware_tested':False,'parent_RAM18_RX0_recycling_and_both_windows_passed':True,'parent_RAM18_all_ON_OFF_ACK_passed':True,'parent_RAM18_SSID_not_visible':True,'new_build_TXD_format_hardware_tested':False,'parent_RAM19_corrected_TXD_all_ACK_windows_cleanup_passed':True,'parent_RAM19_SSID_not_visible':True,'new_build_MAC_TSF_diagnostic_hardware_tested':False,'parent_RAM17_control_failed_before_beacon':True,'parent_RAM17_RX0_packets_at_DMA_loss':59,'parent_RAM16_beacon_ON_ACK_passed':True,'parent_RAM16_SSID_not_visible':True,'parent_RAM16_beacon_OFF_DMA_timeout':True,'parent_RAM15_radio_MAC_RX_cleanup_passed':True,'parent_RAM14_BSS_ON_OFF_cleanup_passed':True,'parent_RAM13_DEVINFO_ON_OFF_cleanup_passed':True,'parent_RAM12_DEVINFO_response40_before_body_parse':True,'parent_RAM12_NVM_equality_and_cleanup_passed':True,'no_individual_NVM_bytes_bundled':True,
 'contains_only_six_supplied_generic_OEM_firmware_components':True,
 'no_full_proprietary_OS_bootloader_flash_or_individual_calibration':True},indent=2)+'\n')
with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
    for name in sorted([x['file'] for x in records]+['package-manifest.json']):
        archive.write(r/name,'c80-openwrt-ram24-tx-free/'+name)
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None and len(archive.namelist())==len(records)+1
    for row in records:
        data=archive.read('c80-openwrt-ram24-tx-free/'+row['file'])
        assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
result={'file':str(destination),'bytes':destination.stat().st_size,
 'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'files':len(records)+1,
 'all_ZIP_CRCS_lengths_and_SHA256_verified':True}
destination.chmod(0o600)
(r/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
