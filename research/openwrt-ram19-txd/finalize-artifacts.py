#!/usr/bin/env python3
"""Tie RAM19 firmware-beacon TXD to OEM-mode evidence and immutable RAM18."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram18-rx'
assert not (r/'c80-openwrt-ram19-txd.zip').exists()
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
assert json.loads((e/'ram18-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram19-txd-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram19-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram19-txd-zImage'),(0x40f00000,'c80-openwrt-ram19-txd.dtb'),(0x40e00000,'c80-openwrt-ram19-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram19-txd-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram19-txd.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram19-txd.dtb').read_bytes()==(parent/'c80-openwrt-ram18-rx.dtb').read_bytes()
assert (r/'c80-openwrt-ram19-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram18-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').read_bytes()==(parent/'c80-script-runner.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')]
assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:
 assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
rx=json.loads((e/'rx-recycle-result.json').read_text())
assert rx['passed'] and rx['cases_passed']==64 and rx['core_source_sha256']==sha(r/'c80_mcu_core.h') and rx['tests_source_sha256']==sha(r/'verify-rx-recycle.c')
assert len([x for x in (r/'verification-rx-recycle.log').read_text().splitlines() if x.startswith('PASS RX-')])==64
assert json.loads((e/'stock-rx-traces.json').read_text())['cases_passed']==28
off=json.loads((e/'stock-offload-traces.json').read_text())
assert off['cases_passed']==24 and off['actual_MT7626_beacon_method']==2
assert off['TXD_hex']=='5e00004800cc0003080400a001f8000000000000000000000400000000c00800'
assert off['TXD_changes']==[{'offset':7,'old':0,'new':3},{'offset':8,'old':0,'new':8}]
def split_wire(w):
 rows=[]
 while w:
  n=int.from_bytes(w[:4],'little');assert n and len(w)>=n+4
  rows.append(w[4:4+n]);w=w[4+n:]
 return rows
old=split_wire((parent/'stock-command-oracle.bin').read_bytes())
new=split_wire((r/'stock-command-oracle.bin').read_bytes())
assert len(old)==len(new)==55
changes=[]
for i,(a,b) in enumerate(zip(old,new)):
 if a!=b:
  assert len(a)==len(b)==592 and b[41]==0x49
  diff=[(k,x,y) for k,(x,y) in enumerate(zip(a,b)) if x!=y]
  assert diff==[(83,0,3),(84,0,8)],(i,diff)
  changes.append(i)
assert changes==[52,53],changes
(e/'TXD-wire-change-result.json').write_text(json.dumps({'passed':True,'packets':55,'byte_identical_packets':53,'changed_packet_indices':changes,'each_changed_packet_offsets':[[83,0,3],[84,0,8]],'core_wire_verified_by_ASan_tests':True},indent=2)+'\n')
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram19-txd',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram18-change-scope.json',
 scope='Correct two OEM MCU-generated beacon TXD fields:pkt_ft3/subtype8;retain RX0 recycling/two30s watch windows/SSID C80-RAM16/other53 commands;no clientdata/NORwrites',
 not_proven=['physical RAM19 beacon RF TX/SSID visibility/timestamp/FCS','authentication/association/clientdata','cold rail-cut equivalence','flash installation'])
p['parent_RAM18_result']=json.loads((r/'prior-hardware/RAM18-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=559,actual_OEM_ARM_beacon_offload_mode=24,QEMU_command_checks=qemu,wire_packets_byte_identical_to_RAM18=53,wire_packets_only_two_TXD_bytes_changed=2)
p['checks']['inherited_RX0_recycling_cases']=p['checks'].pop('new_RX0_recycling_cases',64)
p['watch'].pop('SSID_and_beacon_template_identical_to_RAM16',None)
p['watch'].update(SSID_and_raw_frame_identical_to_RAM16=True,TXD_two_fields_corrected=True,parent_RAM18_both_windows_hardware_passed=True)
p['RX0_recycling'].pop('all_55_packets_unchanged',None)
p['RX0_recycling'].update(parent_RAM18_hardware_tested=True,parent_RAM18_packets=448,parent_RAM18_rearmed=448,parent_RAM18_published=448)
p['radio']['parent_RAM18_physical_tested']=True
p['beacon'].update(parent_RAM18_ALL_ON_OFF_ACK_passed=True,parent_RAM18_SSID_seen=False,TXD_packet_format=3,TXD_frame_type=0,TXD_subtype=8,TXD_hex=off['TXD_hex'],OEM_WDEV_beacon_method=2,OEM_capability_prefix='4030a1a4..4030a1e0',OEM_buffer_init='4029592c',firmware_mode_verified_against_actual_OEM=True,physical_tested=False)
p['hardware_tested']=False
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
