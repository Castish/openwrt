#!/usr/bin/env python3
"""Tie the exact RAM12 images to completed verification and immutable RAM11."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram11-nvm-pad'
assert not (r/'c80-openwrt-ram12-devinfo.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=(r/'verification-core.log').read_text()
assert 'PASS:198 actual-core scenarios + 18 IRQ gate cases' in log
assert len([x for x in log.splitlines() if x.startswith('PASS ')])==216
for name,count in [('stock-download-traces',23),('stock-main-traces',27),('stock-dma-mode-traces',15),('stock-query-traces',8),('stock-irq-traces',13),('stock-nvm-traces',19),('stock-devinfo-traces',18)]:
 assert json.loads((e/(name+'.json')).read_text())['cases_passed']==count
nvm=json.loads((e/'stock-nvm-traces.json').read_text())
assert nvm['GET_compatible_event_lengths']==[1042,1044]
assert bytes.fromhex(nvm['synthetic_EEPROM_hex'])[4:10]==bytes.fromhex('525400123456')
assert len([x for x in nvm['cases'] if x.get('copied_bytes')==1024 and x.get('tail_canary_preserved')])==6
wire=(r/'stock-command-oracle.bin').read_bytes();count=0
while wire:
 n=int.from_bytes(wire[:4],'little');assert n and len(wire)>=4+n
 wire=wire[4+n:];count+=1
assert count==44
text=(r/'c80_mcu_transport.c').read_text()
for name,n,begin,end in [('irq-wrapper',12,'static irqreturn_t c80_mcu_irq','static ssize_t status_show'),('nvm-reader',13,'static c80_u32 c80_linux_nvm_read','static irqreturn_t c80_mcu_irq')]:
 q=json.loads((e/(name+'-result.json')).read_text());assert q['passed'] and q['cases_passed']==n
 body=text[text.index(begin):text.index(end)]
 assert q['actual_callback_source_sha256']==hashlib.sha256(body.encode()).hexdigest()
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
assert json.loads((e/'ram11-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram12-devinfo-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram12-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram12-devinfo-zImage'),(0x40f00000,'c80-openwrt-ram12-devinfo.dtb'),(0x40e00000,'c80-openwrt-ram12-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram12-devinfo-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram12-devinfo.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram12-devinfo.dtb').read_bytes()==(parent/'c80-openwrt-ram11-nvm-pad.dtb').read_bytes()
assert (r/'c80-openwrt-ram12-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram11-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').read_bytes()==(parent/'c80-script-runner.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')]
assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:
 assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram12-devinfo',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,physical_runtime_query_tested=False,physical_RX1_CPU_IRQ_tested=False,
 source_scope='evidence/ram11-change-scope.json',
 scope='After proven full NVM equality, DEVINFO_UPDATE Active1 then Active0 for OwnMac0/Band0 using EEPROM MAC. Exact OEM20B body/query0 header,16B reply,6s default limit; bounded failure/cleanup; no BSS/RF/MAC TX/RX commands.',
 not_proven=['physical RAM12 DEVINFO MCU acceptance/context lifecycle','MAC readback or BSS/radio/AP/association','cold power rail-cut equivalence','flash installation'])
p['parent_RAM11_result']={'result':0,'primary':0,'cleanup':0,'critical':0,'NVM_SET_valid':1,'NVM_SET_status':0,'NVM_GET_valid':1,'NVM_equal':1,'NVM_compared':1024,'NVM_padding':2,'NVM_crc32':'7be47979','TX':43,'RX':12,'sequence':13,'DMA_idle':1,'MCU_stopped':1,'pools_retained':0,'MemAvailable_KiB':12884,'console_sha256':'47a2ae909ea4f33ab1458ca3cf77b854bb869a1fe2a4bd79587124ef33d18246'}
p['checks'].pop('new_NVM_response_alignment_fault_cases',None)
p['checks'].update(inherited_NVM_response_alignment_fault_cases=16,actual_C_core_ASan_UBSan=198,new_DEVINFO_fault_cases=38,actual_OEM_ARM_DEVINFO_contract=18,independent_OEM_packet_oracles=44,QEMU_command_checks=qemu)
p['NVM'].update(physical_NVM_tested_on_parent_RAM11=True,physical_NVM_tested=False)
p['DEVINFO']={'builder':'0x402edd44','ASIC_wrapper':'0x4029f878','board_wrapper':'0x402a3634','callback':'0x402ecc4c','extension':'2a','query':0,'ACK':1,'body_bytes':20,'response_body_bytes':16,'outer_response_extensions':['00','2a'],'OwnMac':0,'Band':0,'Active_sequence':[1,0],'MAC_EEPROM_offset':4,'MAC_invalid_refused_before_peripheral_writes':True,'MAC_printed_or_packaged':False,'timeout_ms':6000,'poll_us':1000,'max_polls':6000,'command_retries':0,'full_32bit_status_preserved':True,'TX_expected':45,'RX_expected':14,'sequence_expected':15,'command_slots':14,'MCU_reset_on_all_post_release_exits':True,'physical_tested':False,'BSS_RF_MAC_TX_RX_commands':False}
p['hardware_tested']=False
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
