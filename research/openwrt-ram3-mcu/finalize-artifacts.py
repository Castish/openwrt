#!/usr/bin/env python3
"""Tie final build/rebuild, compiled tests, script and package provenance."""
from pathlib import Path
import datetime
import hashlib
import json
import zoneinfo
import zlib

r=Path(__file__).resolve().parent;e=r/'evidence'
assert not (r/'c80-openwrt-ram3-mcu.zip').exists(),'Issued artifacts are immutable'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(name,value):(e/name).write_text(json.dumps(value,indent=2)+'\n')
checks={}
for built,name in [('build/arch/arm/boot/zImage','c80-openwrt-ram3-mcu-zImage'),
 ('build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb','c80-openwrt-ram3-mcu.dtb')]:
    assert (r/built).read_bytes()==(r/name).read_bytes(),name
    checks[name]=sha(r/name)
save('rebuild-result.json',{'passed':True,'full_saved_build_script_repeated':True,
 'byte_identical':checks,'fixed_build_timestamp':'Sun Oct 18 13:00:00 UTC 2026'})
assert sha(r/'build/vmlinux')==json.loads((e/'restart-result.json').read_text())['Linux_vmlinux_sha256']
qemu={}
for mode in ('missing-firmware','aon-refusal'):
    q=json.loads((e/f'qemu-{mode}-result.json').read_text());assert q['passed']
    assert sha(r/'build/usr/initramfs_data.cpio')==q['rootfs_cpio_sha256']
    assert sha(r/'build-qemu/arch/arm/boot/zImage')==q['qemu_kernel_sha256']
    if mode=='aon-refusal':assert q['normal_reboot_and_C80_callback_before_PSCI_fallback']
    qemu[mode]=len(q['commands'])
eth=['drivers/net/ethernet/mediatek/'+n for n in
 ('c80_ram_eth.c','c80_pdma_core.h','c80_ram_mdio.c','c80_ram_mdio.h')]
eth+=['drivers/net/dsa/realtek/'+n for n in ('rtl8365mb.c','c80_rtl8367s.h')]
for n in eth:
    assert (r/'linux-6.12.113'/n).read_bytes()==(r.parent/'openwrt-ram1/linux-6.12.113'/n).read_bytes()
save('source-scope.json',{'passed':True,'unchanged_parent_Ethernet_sources':eth,
 'new_sources':['c80_mcu_core.h','c80_mcu_transport.c','c80_restart.c'],
 'MCU_reset_and_system_restart_resources_disjoint':True,
 'MCU_inactive_until_manual_run':True,'flash_write_drivers_disabled':True})
lines=(r/'c80-start.txt').read_text().splitlines()
assert lines[0]=='C80SCRIPT1' and lines[-1]=='end'
records=[]
for line in lines:
    if not line.startswith('load '):continue
    _,address,name,size,crc=line.split();p=r/name;data=p.read_bytes()
    assert int(size,16)==len(data) and int(crc,16)==zlib.crc32(data)
    assert int(address,16)+len(data)<0x41c00000
    records.append({'file':name,'address':hex(int(address,16)),'bytes':len(data),
      'crc32':crc,'sha256':sha(p)})
assert [x['address'] for x in records]==['0x41000000','0x40f00000','0x40e00000']
assert (r/'c80-script-runner.bin').read_bytes()==(r.parent/'uboot-script-runner/c80-script-runner.bin').read_bytes()
save('script-result.json',{'passed':True,'script_bytes':(r/'c80-start.txt').stat().st_size,
 'records':records,'unchanged_hardware_confirmed_runner':True})
assert 'PASS:41' in (r/'verification-core.log').read_text()
assert 'twenty files' in (r/'artifacts/patch-verification.txt').read_text()
provenance={
 'recorded_at':datetime.datetime.now(zoneinfo.ZoneInfo('Europe/Moscow')).isoformat(),
 'userspace':'OpenWrt25.12.5 r33051-f5dae5ece4;35 official signed packages;57 unchanged parent ELF files',
 'kernel':'6.12.113-c80-openwrt-ram3-mcu','load_files':records,
 'hardware_tested':False,'hardware_restart_tested':False,'MCU_DMA_hardware_tested':False,
 'parent_hardware_confirmed':['OpenWrt RAM1/LAN1/MTU','EMI no-map relocation','RAM2 Linux boot and normal reboot','RAM2 initial MCU DMA semaphore acquire2/release3; primary0, cleanup16 from control snapshot mismatch',
 'CONNSYS bootstrap','host ownership30001->30000 and HIF10001870/0/0'],
 'current_user_test':'Boot RAM3 from current U-Boot, short status/run/status commands; inspect cleanup bitmap and ring readbacks',
 'new':['manual-once MCU transport with coherent DMA and uncached EMI',
 'same four supplied OEM firmware files and hardware-confirmed restart handler','owned-control-bit verification with visible other-bit differences and ring mismatch bitmap'],
 'local_checks':{'native_actual_core_ASan_UBSan':41,'OEM_ARM_MCU_contract_model':15,
 'actual_ARM_restart':8,'actual_decompressor':6,'actual_handoff':5,
 'QEMU_command_checks':qemu,'QEMU_normal_procd_reboot_C80_callback_and_PSCI_fallback':True,
 'ELF_ABI_closure':57,'Linux_patch_files_apply_exact':20,'saved_build_script_repeated_identical':True},
 'not_proven':['physical reset propagation','power-cycle equivalence/CONNSYS state after reset',
 'Wi-Fi IRQ route','AP/association/RF/calibration','flash installation'],
 'firmware_origin':'User-supplied Archer C80(RU)_V1_240812.zip; FIRMWARE-SOURCES.json',
 'private_data_included':False,'full_TPOS_or_Uboot_or_NOR_included':False,
 'Linux_source_license':'GPL-2.0-only','runner_license':'MIT','OEM_firmware_license_unchanged':True,
 'cleanup_contract':'Compare only owned control masks; report all other control differences; retain GLO/IRQmask/ring/critical checks',
 'detailed_ring_and_cleanup_bitmaps_in_status':True,
 'ram2_change_scope_evidence':'evidence/ram2-change-scope.json',
 'reserved_EMI':['0x40000000','0x401fffff'],'Linux_RAM':['0x40200000','0x41ffffff'],
 'post_MCU_software_only_reboot_parent_confirmed_by_user':True,'CONNSYS_after_that_reboot_not_yet_measured':True,'cold_power_equivalence_unproven':True}
(r/'PROVENANCE.json').write_text(json.dumps(provenance,indent=2)+'\n')
print('Final rebuild, compiled QEMU image ties, Ethernet scope and script pins verified.')
