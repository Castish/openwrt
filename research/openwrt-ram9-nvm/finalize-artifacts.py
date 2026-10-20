#!/usr/bin/env python3
"""Tie final RAM9 files to completed checks; write metadata and instructions."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence'
assert not (r/'c80-openwrt-ram9-nvm.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=(r/'verification-core.log').read_text()
assert 'PASS:128 actual-core scenarios + 18 IRQ gate cases' in log
assert len([x for x in log.splitlines() if x.startswith('PASS ')])==146
for name,count in [('stock-download-traces',23),('stock-main-traces',27),('stock-dma-mode-traces',15),('stock-query-traces',8),('stock-irq-traces',13),('stock-nvm-traces',15)]:
 assert json.loads((e/(name+'.json')).read_text())['cases_passed']==count
wrapper=json.loads((e/'irq-wrapper-result.json').read_text())
assert wrapper['passed'] and wrapper['cases_passed']==12
text=(r/'c80_mcu_transport.c').read_text()
callbacks=text[text.index('static irqreturn_t c80_mcu_irq'):text.index('static ssize_t status_show')]
assert wrapper['actual_callback_source_sha256']==hashlib.sha256(callbacks.encode()).hexdigest()
reader=json.loads((e/'nvm-reader-result.json').read_text())
assert reader['passed'] and reader['cases_passed']==13 and not reader['private_calibration_included']
body=text[text.index('static c80_u32 c80_linux_nvm_read'):text.index('static irqreturn_t c80_mcu_irq')]
assert reader['actual_callback_source_sha256']==hashlib.sha256(body.encode()).hexdigest()
assert len(json.loads((e/'rootfs-elf-closure.json').read_text()))==57
assert len(json.loads((r/'FIRMWARE-SOURCES.json').read_text())['files'])==6
qemu={}
for mode in ('missing-firmware','aon-refusal'):
 q=json.loads((e/f'qemu-{mode}-result.json').read_text());assert q['passed']
 assert sha(r/'build/usr/initramfs_data.cpio')==q['rootfs_cpio_sha256']
 assert sha(r/'build-qemu/arch/arm/boot/zImage')==q['qemu_kernel_sha256']
 qemu[mode]=len(q['commands'])
 if mode=='aon-refusal':assert q['normal_reboot_and_C80_callback_before_PSCI_fallback']
assert 'All twenty files match' in (r/'artifacts/patch-verification.txt').read_text()
assert json.loads((e/'ram8-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram9-nvm-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram9-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram9-nvm-zImage'),(0x40f00000,'c80-openwrt-ram9-nvm.dtb'),(0x40e00000,'c80-openwrt-ram9-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram9-nvm-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram9-nvm.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram9-handoff.bin').read_bytes()==(r.parent/'openwrt-ram8-irq/c80-openwrt-ram8-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')]
assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:
 assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
p=json.loads((r.parent/'openwrt-ram8-irq/PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram9-nvm',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,physical_runtime_query_tested=False,physical_RX1_CPU_IRQ_tested=False,
 parent_RAM7_main_runtime_GET_and_cleanup_hardware_passed=True,
 source_scope='evidence/ram8-change-scope.json',
 scope='Read local ROM RADIO sector, validate CRC/ID before MCU release, upload960 bytes+64zeros via OEM EXT21, then read back and compare1024 bytes via OEM EXT9b. No RF/AP/nonvolatile-write commands.',
 not_proven=['physical MCU NVM SET/GET and byte equality','RF initialization/AP/association','cold power rail-cut equivalence','flash installation'])
p.pop('parent_RAM6_main_result',None)
p['parent_RAM7_result']={'result':0,'primary':0,'cleanup':0,'critical':0,'TX':41,'RX':10,'runtime_GET_valid':1,'IRQ_mask_after':'00000000'}
p['download_mode']['runtime_mode_off_hardware_unproven']=False
p['checks'].update(actual_OEM_ARM_IRQ_contract=13,actual_C_core_ASan_UBSan=128,actual_OEM_ARM_NVM_contract=15,actual_Linux_ROM_MTD_callback=13,
 shared_IRQ_gate_ASan_UBSan=18,actual_Linux_IRQ_callbacks_with_synthetic_services=12,QEMU_command_checks=qemu)
p['IRQ_mask_cleanup']={'runtime_enable_mask':'00000002','W1C_only_RX1_bit1':True,
 'CPU_and_peripheral_one_shot':True,'CPU_disable_and_synchronize_before_pool_free':True,
 'strict_zero_readback_after_stop_and_controls_restore':True,
 'main_and_runtime_stage_snapshots':True}
p['IRQ_test']={'raw_GIC_ID':243,'SPI':211,'controller':'MT_SYSIRQ active-low','source_mask':'00000002',
 'initial_CPU_IRQ':'IRQF_NO_AUTOEN','enable_only_after_main_ready':True,
 'CPU_IRQ_required_despite_valid_DMA_response':True,'missing_IRQ_result':25,'invalid_IRQ_result':26,
 'IRQ_handler_waits_allocations_or_descriptor_access':False,
 'physical_route_proven':True,'parent_RAM8_IRQ_events':1}
p['parent_RAM8_main_GET_IRQ_cleanup_hardware_passed']=True
p['NVM']={'ROM_MTD_name':'30000000.flash','ROM_bytes':4194304,'read_offset':'0x3ff000','read_bytes':4096,'required_RADIO_CRC32':'5c6536a7','required_EEPROM_ID':'7626','EEPROM_bytes':1024,'copied_bytes':960,'zero_padding':64,'SET_ext':'21','SET_query':1,'GET_ext':'9b','GET_query':0,'GET_reply_extensions':['8a','9b'],'physical_NVM_tested':False,'individual_calibration_packaged':False,'synthetic_fixtures_only':True,'private_snapshot_and_pool_zeroed_on_safe_free':True}
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
