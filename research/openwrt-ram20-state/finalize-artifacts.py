#!/usr/bin/env python3
"""Tie RAM20 TSF/MAC snapshots to actual OEM/native evidence and immutable RAM19."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram19-txd'
assert not (r/'c80-openwrt-ram20-state.zip').exists()
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
assert count==57
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
assert json.loads((e/'ram19-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram20-state-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram20-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram20-state-zImage'),(0x40f00000,'c80-openwrt-ram20-state.dtb'),(0x40e00000,'c80-openwrt-ram20-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram20-state-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram20-state.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram20-state.dtb').read_bytes()==(parent/'c80-openwrt-ram19-txd.dtb').read_bytes()
assert (r/'c80-openwrt-ram20-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram19-handoff.bin').read_bytes()
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
off=json.loads((e/'stock-offload-traces.json').read_text());assert off['cases_passed']==24
state=json.loads((e/'stock-beacon-state-traces.json').read_text());assert state['cases_passed']==35 and len(state['registers'])==12
native=json.loads((e/'beacon-state-result.json').read_text())
assert native['passed'] and native['cases_passed']==42 and native['core_source_sha256']==sha(r/'c80_mcu_core.h') and native['tests_source_sha256']==sha(r/'verify-beacon-state.c')
assert len([x for x in (r/'verification-beacon-state.log').read_text().splitlines() if x.startswith('PASS STATE-')])==42
def split_wire(w):
 rows=[]
 while w:
  n=int.from_bytes(w[:4],'little');assert n and len(w)>=n+4
  rows.append(w[4:4+n]);w=w[4+n:]
 return rows
old=split_wire((parent/'stock-command-oracle.bin').read_bytes());new=split_wire((r/'stock-command-oracle.bin').read_bytes())
assert len(old)==55 and len(new)==57 and old==new[:55]
for i,name in enumerate(('tsf-own0-seq7','tsf-own0-seq8')):
 packet=next(x for x in state['packets'] if x['name']==name)
 assert new[55+i]==bytes.fromhex(packet['packet_hex']) and len(new[55+i])==168
(e/'state-wire-change-result.json').write_text(json.dumps({'passed':True,'packets':57,'first55_oracles_byte_identical_to_RAM19':True,'two_appended_TSF_oracles':True,'actual_runtime_sequences_shift_after_new_queries':True,'native_checks_every_published_byte_with_actual_rolling_sequence':True},indent=2)+'\n')
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram20-state',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram19-change-scope.json',
 scope='Five guarded raw MAC snapshots+two fixed12B TSF queries around same30s beacon window;unchanged RF configuration/SSID/template/RX/cleanup;no clientdata/NORwrites',
 not_proven=['physical RAM20 MAC snapshot/TSF reply outcome','beacon RF TX/SSID visibility/timestamp/FCS','authentication/association/clientdata','cold rail-cut equivalence','flash installation'])
p['parent_RAM19_result']=json.loads((r/'prior-hardware/RAM19-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=601,new_beacon_state_native_cases=42,actual_OEM_ARM_beacon_state=35,QEMU_command_checks=qemu,independent_OEM_packet_oracles=57)
p['checks'].pop('wire_packets_byte_identical_to_RAM18',None);p['checks'].pop('wire_packets_only_two_TXD_bytes_changed',None)
p['beacon_state']={'registers':state['registers'],'snapshot_names':['mac_on','sync_on','beacon_begin','beacon_end','sync_off'],
 'snapshot_phases':[30,33,34,37,36],'snapshot_register_reads':60,'snapshots_nonatomic':True,'MIB_may_clear_on_read':True,'MMIO_config_writes':0,'selectors_written':False,
 'sysfs_reads_only_saved_RAM':True,'counter_meaning':'MIBSDR0 low16 vendorDMAC beacon TX count;not external RF or FCS verification;zero not conclusive',
 'TSF_query_builder':'4031469c','TSF_callback':'4030ec1c','TSF_phases':[39,40],'TSF_category':2,'OwnMac':0,'TSF_query_bytes':104,
 'CID':'ed','extension':'3c','query':0,'ACK':1,'flags':'07','response_body_bytes':12,'response_event_bytes':24,'minimum_DMA_bytes':40,'response_low_high_offsets':[4,8],
 'strict_PID_EID_sequence_extension_category_length_bounds':True,'timeout_ms':6000,'poll_us':1000,'max_polls':6000,'retries':0,
 'zero_stationary_allones_TSF_allowed':True,'backwards_TSF_recorded_without_delta':True,'TSF_not_host_clock_and_not_RF_proof':True,
 'new_errors':{'46':'malformed TSF body/category','47':'missing diagnostic prerequisites'},'normal_TX':58,'normal_command_TX':27,'normal_RX_events':27,'normal_sequence':13,
 'patchready_TX':52,'patchready_RX_events':23,'patchready_sequence':7,'command_slots':27,'pool_bytes':268180,'DMA_pool_increase_bytes':2304,'physical_tested':False}
p['beacon'].update(parent_RAM19_ALL_ON_OFF_ACK_passed=True,parent_RAM19_SSID_seen=False,pool_bytes=268180)
p['watch']['parent_RAM19_both_windows_hardware_passed']=True
p['RX0_recycling']['parent_RAM19_hardware_tested']=True
p['RX0_recycling']['pool_bytes']=268180
for name in ('BSS','radio'):
 p[name]['pool_bytes']=268180;p[name]['command_slots']=27
p['DEVINFO'].update(TX_expected=58,RX_expected=27,sequence_expected=13,command_slots=27)
p['BSS'].update(TX_expected=58,RX_events_expected=27,sequence_expected=13)
p['radio'].update(normal_TX=58,normal_RX_events=27,normal_sequence=13,patchready_TX=52,patchready_RX_events=23,patchready_sequence=7)
p['hardware_tested']=False
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
