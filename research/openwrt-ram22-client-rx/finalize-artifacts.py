#!/usr/bin/env python3
"""Tie RAM22 client RX/RX1 evidence to immutable, physically tested RAM21."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram21-period'
assert not (r/'c80-openwrt-ram22-client-rx.zip').exists()
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
assert count==59
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
assert json.loads((e/'ram21-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram22-client-rx-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram22-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram22-client-rx-zImage'),(0x40f00000,'c80-openwrt-ram22-client-rx.dtb'),(0x40e00000,'c80-openwrt-ram22-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram22-client-rx-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram22-client-rx.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram22-client-rx.dtb').read_bytes()==(parent/'c80-openwrt-ram21-period.dtb').read_bytes()
assert (r/'c80-openwrt-ram22-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram21-handoff.bin').read_bytes()
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
assert native['passed'] and native['cases_passed']==46 and native['core_source_sha256']==sha(r/'c80_mcu_core.h') and native['tests_source_sha256']==sha(r/'verify-beacon-state.c')
assert len([x for x in (r/'verification-beacon-state.log').read_text().splitlines() if x.startswith('PASS STATE-')])==46
def split_wire(w):
 rows=[]
 while w:
  n=int.from_bytes(w[:4],'little');assert n and len(w)>=n+4
  rows.append(w[4:4+n]);w=w[4+n:]
 return rows
old=split_wire((parent/'stock-command-oracle.bin').read_bytes());new=split_wire((r/'stock-command-oracle.bin').read_bytes())
assert len(old)==len(new)==59 and old==new
assert json.loads((e/'stock-bss-period-traces.json').read_text())['cases_passed']==11
client=json.loads((e/'client-rx-result.json').read_text())
assert client['passed'] and client['cases_passed']==366
assert client['core_source_sha256']==sha(r/'c80_mcu_core.h') and client['tests_source_sha256']==sha(r/'verify-client-rx.c')
assert len([x for x in (r/'verification-client-rx.log').read_text().splitlines() if x.startswith('PASS CLIENT-')])==366
assert 'c80_management_receive' in (r/'c80_mcu_core.h').read_text()
for fn,finish in [('static ssize_t mgmt_show','static ssize_t events_show'),('static ssize_t events_show','static ssize_t run_store')]:
 body=text[text.index(fn):text.index(finish)]
 assert 'mutex_lock' in body and 'c80_read(' not in body and 'readl' not in body and 'io->' not in body and 'pool->' not in body
(e/'ram22-wire-result.json').write_text(json.dumps({'passed':True,'all_59_packet_oracles_byte_identical_to_RAM21':True,'new_MCU_command_packets':0,'coherent_pool_bytes':268180,'new_DMA_pool_bytes':0,'new_packet_TX':False,'MGMT_events_sysfs_saved_RAM_only':True},indent=2)+'\n')
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram22-client-rx',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram21-change-scope.json',
 scope='Bounded raw management RX candidates and RX1 descriptor recycling; same RAM21 beacon/BSS/MCU packets; no management response, association, data TX or persistent writes',
 not_proven=['physical RAM22 management RX and RX1 recycling','management responses/authentication/association/clientdata','external RF FCS validation','cold rail-cut equivalence','flash installation'])
p['parent_RAM21_result']=json.loads((r/'prior-hardware/RAM21-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=971,new_client_RX_RX1_native_cases=366,new_beacon_state_native_cases=46,actual_OEM_normal_AP_period=11,actual_OEM_ARM_beacon_state=35,QEMU_command_checks=qemu,independent_OEM_packet_oracles=59)
p['checks'].pop('wire_packets_byte_identical_to_RAM18',None);p['checks'].pop('wire_packets_only_two_TXD_bytes_changed',None)
p['checks']['all_59_packet_oracles_byte_identical_to_RAM21']=True
p['beacon_state']={'registers':state['registers'],'snapshot_names':['mac_on','sync_on','beacon_begin','beacon_end','sync_off'],
 'snapshot_phases':[30,33,34,37,36],'snapshot_register_reads':60,'snapshots_nonatomic':True,'MIB_may_clear_on_read':True,'MMIO_config_writes':0,'selectors_written':False,
 'sysfs_reads_only_saved_RAM':True,'counter_meaning':'MIBSDR0 low16 vendorDMAC beacon TX count;not external RF or FCS verification;zero not conclusive',
 'TSF_query_builder':'4031469c','TSF_callback':'4030ec1c','TSF_phases':[39,40],'TSF_category':2,'OwnMac':0,'TSF_query_bytes':104,
 'CID':'ed','extension':'3c','query':0,'ACK':1,'flags':'07','response_body_bytes':12,'response_event_bytes':24,'minimum_DMA_bytes':40,'response_low_high_offsets':[4,8],
 'strict_PID_EID_sequence_extension_category_length_bounds':True,'timeout_ms':6000,'poll_us':1000,'max_polls':6000,'retries':0,
 'zero_stationary_allones_TSF_allowed':True,'backwards_TSF_recorded_without_delta':True,'TSF_not_host_clock_and_not_RF_proof':True,
 'new_errors':{'46':'malformed TSF body/category','47':'missing diagnostic prerequisites'},'normal_TX':58,'normal_command_TX':27,'normal_RX_events':27,'normal_sequence':13,
 'patchready_TX':52,'patchready_RX_events':23,'patchready_sequence':7,'command_slots':27,'pool_bytes':268180,'DMA_pool_increase_bytes':0,'DMA_pool_comparison_parent':'RAM21','physical_tested':False}
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
p['BSS'].pop('BMC_WMM_PHY_beacon_DTIM',None)
p['BSS'].update(BMC_WMM_PHY=0,beacon_interval_TU=100,DTIM_period=1,
 normal_AP_argument_initializer='403606f8',normal_period_source='adapter+1e22ac',normal_DTIM_source='adapter+ceb70',
 timing_in_BSS_ON_and_OFF=True,only_changed_packet_offsets={'ON':[98,107],'OFF':[82,91]},
 timing_prerequisite_error=48,physical_tested=False,
 phase_order=[23,25,27,28,29,30,38,33,34,39,37,40,35,36,32,26,24,90])
p['beacon_state']['parent_RAM20_physical_snapshots_and_TSF_passed']=True
p['beacon_state']['parent_RAM20_TSF_delta_us']=30030049
p['beacon_state']['parent_RAM20_TBTT_period_and_CAL_EN']=0
p['beacon_state']['parent_RAM20_SSID_visible']=False
p['BSS']['physical_tested']=False
p['BSS']['parent_RAM21_same_BSS_hardware_passed']=True
p['BSS']['physical_result_scope']='Unchanged RAM21 BSS period100TU/DTIM1 observed and SSID discovered; RAM22 changes not yet physically tested'
p['beacon_state']['parent_RAM21_physical_snapshots_and_TSF_passed']=True
p['beacon_state']['parent_RAM21_TSF_delta_us']=30030005
p['beacon_state']['parent_RAM21_SSID_visible_on_phone_and_PC']=True
p['beacon']['parent_RAM21_SSID_visible_on_phone_and_PC']=True
p['RX1_recycling']={'enabled':True,'ring_entries':64,'buffer_bytes':1536,'read_only_descriptor_validation':['DONE','LS0','size16..1536','exactDMAaddress','zeroaddress1'],
 'CPU_register':'18004418','CPU_index':'consumed slot','modulo_wrap':True,'budget_per_receive_call':64,'parse_before_dma_wmb_and_publish':True,'matched_and_ignored_events_returned':True,
 'malformed_matching_event_aborts_without_return':True,'saved_unknown_metadata_only':True,'no_packet_pointer_retained':True,'errors':{'49':'CPU index readback mismatch','50':'missing RX1 prerequisites'},'physical_tested':False}
p['management_RX']={'enabled':True,'windows':['control','beacon'],'phase':[38,37],'raw_RX0_only':True,'source_MAC_not_saved':True,'packet_payload_not_saved':True,
 'probe_first_SSID_IE_only':True,'auth_open_request':['algorithm0','transaction1','status0'],'subtypes_counted':16,'FCS_verified':False,
 'responses_sent':0,'association_supported':False,'saved_sysfs':['mgmt','events'],'new_MCU_commands':0,'error51':'missing management prerequisites','physical_tested':False}
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
