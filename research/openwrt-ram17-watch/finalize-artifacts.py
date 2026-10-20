#!/usr/bin/env python3
"""Tie RAM17 to completed verification and immutable hardware-tested RAM16."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram16-beacon'
assert not (r/'c80-openwrt-ram17-watch.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=(r/'verification-core.log').read_text()
assert 'PASS:495 actual-core scenarios + 18 IRQ gate cases' in log
assert len([x for x in log.splitlines() if x.startswith('PASS ')])==513
for name,count in [('stock-download-traces',23),('stock-main-traces',27),('stock-dma-mode-traces',15),('stock-query-traces',8),('stock-irq-traces',13),('stock-nvm-traces',19),('stock-devinfo-traces',39),('stock-bss-traces',28),('stock-radio-traces',63),('stock-beacon-traces',26)]:
 assert json.loads((e/(name+'.json')).read_text())['cases_passed']==count
nvm=json.loads((e/'stock-nvm-traces.json').read_text())
assert nvm['GET_compatible_event_lengths']==[1042,1044]
assert bytes.fromhex(nvm['synthetic_EEPROM_hex'])[4:10]==bytes.fromhex('525400123456')
assert len([x for x in nvm['cases'] if x.get('copied_bytes')==1024 and x.get('tail_canary_preserved')])==6
wire=(r/'stock-command-oracle.bin').read_bytes();count=0
while wire:
 n=int.from_bytes(wire[:4],'little');assert n and len(wire)>=4+n
 wire=wire[4+n:];count+=1
assert count==55
var=json.loads((e/'devinfo-variable-result.json').read_text())
assert var['passed'] and var['actual_core_cases']==214 and var['actual_OEM_DEVINFO_cases']==39
assert var['packet_oracles_unchanged']==44
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
assert json.loads((e/'ram16-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram17-watch-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram17-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram17-watch-zImage'),(0x40f00000,'c80-openwrt-ram17-watch.dtb'),(0x40e00000,'c80-openwrt-ram17-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram17-watch-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram17-watch.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram17-watch.dtb').read_bytes()==(parent/'c80-openwrt-ram16-beacon.dtb').read_bytes()
assert (r/'c80-openwrt-ram17-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram16-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').read_bytes()==(parent/'c80-script-runner.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')]
assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:
 assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram17-watch',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram16-change-scope.json',
 scope='Read-only HIF watch during matched30s radio-only control and30s beacon windows; abort before later commands on lost DMA/ownership/main state; all55 command oracles unchanged',
 not_proven=['physical RAM17 control/beacon window outcomes','cause of RAM16 WPDMA enable loss','beacon RF TX/SSID visibility/timestamp/FCS','authentication/association/clientdata','cold rail-cut equivalence','flash installation'])
p['parent_RAM16_result']=json.loads((r/'prior-hardware/RAM16-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=495,new_watch_fault_cases=36,QEMU_command_checks=qemu)
p['checks']['inherited_beacon_fault_cases']=p['checks'].pop('new_beacon_fault_cases',78)
p['watch']={'sysfs_attribute':'watch','control_phase':38,'beacon_phase':37,'target_us_per_window':30000000,'max_samples_per_window':30001,'delay_us':1000,
 'samples_nonatomic':True,'MMIO_reads':['18004208','18007000','180c1140','18004200','18004204','180043f8','180043fc','1800440c','1800441c'],
 'fault_bits':{'01':'TX enable0 clear','02':'RX enable2 clear','04':'GLO/OWN/SYNC allones','08':'OWN bit0 set','10':'main-state bits3:1 !=3','20':'download mode bit9 set'},
 'new_error':44,'transient_GLO_busy_bits_1_3_allowed':True,'window_MMIO_writes':0,'auto_reenable':False,'new_command_packets':0,
 'RX0_rearming':False,'SSID_and_beacon_template_identical_to_RAM16':True,'physical_tested':False}
p['BSS']['order'].insert(p['BSS']['order'].index('SYNC ON'),'control30s/no beacon')
p['BSS']['phase_order'].insert(p['BSS']['phase_order'].index(33),38)
p['beacon']['parent_RAM16_ON_ACK_passed']=True
p['beacon']['parent_RAM16_SSID_seen']=False
p['beacon']['parent_RAM16_OFF_DMA_timeout']=True
p['beacon']['physical_tested']=False
p['radio']['legacy_listen_limit_us_when_beacon_disabled']=p['radio'].pop('listen_limit_us')
p['radio']['watch_control_window_us']=30000000
p['radio'].pop('AP_dataTX_beacon_sync_STArecord',None)
p['radio'].update(beacon_sync_commands=True,STA_record=False,AP_client_data_TX=False)
p['BSS']['channel_beacon_sync_RF_MAC_TX_RX_commands']='channel08/path4e/MAC46/SYNC26/beacon49;no clientdata'
p['hardware_tested']=False
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
