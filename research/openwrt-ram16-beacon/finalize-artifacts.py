#!/usr/bin/env python3
"""Tie the exact RAM16 images to completed verification and immutable RAM15."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram15-radio'
assert not (r/'c80-openwrt-ram16-beacon.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=(r/'verification-core.log').read_text()
assert 'PASS:459 actual-core scenarios + 18 IRQ gate cases' in log
assert len([x for x in log.splitlines() if x.startswith('PASS ')])==477
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
assert json.loads((e/'ram15-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram16-beacon-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram16-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram16-beacon-zImage'),(0x40f00000,'c80-openwrt-ram16-beacon.dtb'),(0x40e00000,'c80-openwrt-ram16-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram16-beacon-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram16-beacon.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram16-beacon.dtb').read_bytes()==(parent/'c80-openwrt-ram15-radio.dtb').read_bytes()
assert (r/'c80-openwrt-ram16-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram15-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').read_bytes()==(parent/'c80-script-runner.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')]
assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:
 assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram16-beacon',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,physical_runtime_query_tested=False,physical_RX1_CPU_IRQ_tested=False,
 source_scope='evidence/ram15-change-scope.json',
 scope='Channel/MAC receive experiment after confirmed RAM14 BSS lifecycle',
 not_proven=['physical RAM15 MCU acceptance/RF','AP/association','flash installation'])
p['parent_RAM11_result']={'result':0,'primary':0,'cleanup':0,'critical':0,'NVM_SET_valid':1,'NVM_SET_status':0,'NVM_GET_valid':1,'NVM_equal':1,'NVM_compared':1024,'NVM_padding':2,'NVM_crc32':'7be47979','TX':43,'RX':12,'sequence':13,'DMA_idle':1,'MCU_stopped':1,'pools_retained':0,'MemAvailable_KiB':12884,'console_sha256':'47a2ae909ea4f33ab1458ca3cf77b854bb869a1fe2a4bd79587124ef33d18246'}
p['checks'].pop('new_NVM_response_alignment_fault_cases',None)
p['checks'].update(inherited_NVM_response_alignment_fault_cases=16,actual_C_core_ASan_UBSan=247,inherited_DEVINFO_fault_cases=38,new_variable_DEVINFO_fault_cases=16,actual_OEM_ARM_DEVINFO_contract=39,independent_OEM_packet_oracles=46,new_BSS_fault_cases=33,actual_OEM_ARM_BSS_contract=28,QEMU_command_checks=qemu)
p['NVM'].update(physical_NVM_tested_on_parent_RAM11=True,physical_NVM_tested_on_parent_RAM12=True,physical_NVM_tested=False)
p['DEVINFO']={'builder':'0x402edd44','ASIC_wrapper':'0x4029f878','board_wrapper':'0x402a3634','callback':'0x402ecc4c','extension':'2a','query':0,'ACK':1,'body_bytes':20,'response_body_bytes':16,'outer_response_extensions':['00','2a'],'OwnMac':0,'Band':0,'Active_sequence':[1,0],'MAC_EEPROM_offset':4,'MAC_invalid_refused_before_peripheral_writes':True,'MAC_printed_or_packaged':False,'timeout_ms':6000,'poll_us':1000,'max_polls':6000,'command_retries':0,'full_32bit_status_preserved':True,'TX_expected':45,'RX_expected':14,'sequence_expected':15,'command_slots':14,'MCU_reset_on_all_post_release_exits':True,'physical_tested':False,'BSS_RF_MAC_TX_RX_commands':False}
p['parent_RAM12_result']=json.loads((r/'prior-hardware/RAM12-result.json').read_text())
p['checks'].pop('new_DEVINFO_fault_cases',None)
p['DEVINFO'].pop('response_body_bytes',None)
p['DEVINFO'].update(minimum_response_body_bytes=16,variable_response_flag='20',
 maximum_body_bytes_within1536B_DMA=1508,base_bytes_parsed=16,tail_semantics_not_assumed=True,
 physical_parent_event_bytes=40,physical_parent_base_fields_parsed=False,
 new_telemetry=['event_bytes','dma_bytes','tail_bytes','base_read','echo'],private_tail_logged=False)
p['parent_RAM13_result']=json.loads((r/'prior-hardware/RAM13-result.json').read_text())
p['DEVINFO'].update(parent_RAM13_physical_tested=True,physical_parent_base_fields_parsed=True,TX_expected=47,RX_expected=16,sequence_expected=2,command_slots=16)
p['NVM'].update(physical_NVM_tested_on_parent_RAM13=True)
p['BSS']={'builder':'0x402ee440','ASIC_wrapper':'0x4029f8f4','board_wrapper':'0x402a3640','callback':'0x402eccdc',
 'AP_basic_helper':'0x4031d708','OWN_handler':'0x402eca04','BASIC_handler':'0x402ecb94',
 'extension':'26','query':0,'ACK':1,'minimum_response_body_bytes':16,'variable_response':True,
 'header_BSS_index':0,'OwnMac':0,'Band':0,'ON_TLVs':['OWN0_length16','BASIC1_length28'],
 'OFF_TLVs':['BASIC1_length28'],'network':'00010000','connection':'00010002','cipher':1,
 'BMC_WMM_PHY_beacon_DTIM':0,'MAC_source':'validated private EEPROM+4,not logged',
 'timeout_ms':6000,'poll_us':1000,'max_polls':6000,'command_retries':0,'command_slots':16,
 'pool_bytes':254980,'pool_below256KiB':True,'order':['DEVINFO ON','BSS ON','BSS OFF','DEVINFO OFF'],
 'phase_order':[23,25,26,24,90],'physical_tested':False,'AP_or_MAC_readback_tested':False,
 'channel_beacon_sync_RF_MAC_TX_RX_commands':False}
p.update(scope='Bounded channel6/2.4GHz20MHz/1x1/MAC ON/RX500ms/OFF inside DEVINFO/BSS; no dataTX/AP/NORwrites',
 not_proven=['physical RAM15 channel/path/MAC acceptance or RF reception','complete RF/filter/calibration initialization','beacon transmission/AP/association','cold rail-cut equivalence','flash installation'])
p['parent_RAM14_result']=json.loads((r/'prior-hardware/RAM14-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=381,independent_OEM_packet_oracles=51,new_radio_fault_cases=134,actual_OEM_ARM_radio_contract=63)
p['BSS'].update(parent_RAM14_physical_tested=True,TX_expected=52,RX_events_expected=21,sequence_expected=7,command_slots=21,pool_bytes=260740,
 order=['DEVINFO ON','BSS ON','MAC OFF','channel6','path1x1','MAC ON','listen','MAC OFF','BSS OFF','DEVINFO OFF'],phase_order=[23,25,27,28,29,30,31,32,26,24,90],channel_beacon_sync_RF_MAC_TX_RX_commands='channel08/path4e/MAC46;no beacon/sync')
p['DEVINFO'].update(TX_expected=52,RX_expected=21,sequence_expected=7,command_slots=21)
p['radio']={'channel':6,'band':0,'width_MHz':20,'TX_streams':1,'RX_streams':1,
 'builders':['4031479c','40310114','403103d0'],'CID':'ed','extensions':['46','08','4e','46','46'],
 'query':1,'ACK':1,'attributes_flags':'0f','response_body_bytes':8,'response_event_bytes':20,
 'full32status_checked':True,'channel_timeout_ms':5000,'other_timeout_ms':6000,'poll_us':1000,'retries':0,
 'listen_limit_us':500000,'listen_iteration_limit':500,'RX0_descriptor_limit':63,'RX0_rearming':False,
 'raw_beacon_header_candidates_only':True,'FCS_verified':False,'RX_payload_logged':False,
 'command_slots':21,'pool_bytes':260740,'pool_below256KiB':True,'normal_TX':52,'normal_RX_events':21,'normal_sequence':7,
 'patchready_TX':46,'patchready_RX_events':17,'patchready_sequence':1,'sysfs_attribute':'radio','physical_tested':False,
 'AP_dataTX_beacon_sync_STArecord':False}
p.update(scope='30s firmware beacon advertisement test C80-RAM16,channel6/20MHz/1Mbps/SYNC/beacon ON/OFF inside proven radio;no association/clientdata/NORwrites',
 not_proven=['physical RAM16 SYNC/beacon offload acceptance','beacon RF TX/SSID visibility/timestamp/FCS','authentication/association/clientdata','cold rail-cut equivalence','flash installation'])
p['parent_RAM15_result']=json.loads((r/'prior-hardware/RAM15-result.json').read_text())
p['checks']['inherited_radio_fault_cases']=p['checks'].pop('new_radio_fault_cases',134)
p['checks'].update(actual_C_core_ASan_UBSan=459,independent_OEM_packet_oracles=55,new_beacon_fault_cases=78,actual_OEM_ARM_beacon_contract=26)
p['radio'].update(parent_RAM15_physical_tested=True,command_slots=25,pool_bytes=265876,pool_below256KiB=False,normal_TX=56,normal_RX_events=25,normal_sequence=11,patchready_TX=50,patchready_RX_events=21,patchready_sequence=5)
p['DEVINFO'].update(TX_expected=56,RX_expected=25,sequence_expected=11,command_slots=25)
p['BSS'].update(TX_expected=56,RX_events_expected=25,sequence_expected=11,command_slots=25,pool_bytes=265876,pool_below256KiB=False,
 order=['DEVINFO ON','BSS ON','MAC OFF','channel6','path1x1','MAC ON','SYNC ON','beacon ON','window30s','beacon OFF','SYNC OFF','MAC OFF','BSS OFF','DEVINFO OFF'],phase_order=[23,25,27,28,29,30,33,34,37,35,36,32,26,24,90])
p['beacon']={'SSID':'C80-RAM16','frame_bytes':62,'TXD_bytes':32,'template_bytes':94,'TIM_frame_offset':56,'TIM_template_offset':88,
 'interval_TU':100,'DTIM':1,'rate_Mbps':1,'channel':6,'width_MHz':20,'TXD_helper':'4031a734','TXD_builder':'403199fc','offload_builder':'403131e8','offload_worker':'402f5a68','sync_handler':'402ec78c',
 'offload_CID':'ed','offload_extension':'49','offload_query':1,'offload_ACK':1,'offload_flags':'0f','offload_expected_response':'ffff/skip OEM lengthcheck','host_minimum_response_body':8,'offload_body_bytes':528,
 'sync_CID':'ed','sync_extension':'26','sync_query':0,'sync_flags':'27','sync_minimum_response_body':16,'sync_body_bytes':24,'sync_tag':9,
 'timeout_ms':6000,'poll_us':1000,'max_command_polls':6000,'retries':0,'window_target_us':30000000,'max_window_polls':30000,'RX0_full_shortens_window':False,
 'physical_tested':False,'SSID_seen':None,'timestamp_and_FCS_HW_verified':False,'client_association_data_supported':False,'private_MAC_or_payload_logged':False,'CPU_scratch_bytes':528,'pool_bytes':265876}
p['hardware_tested']=False
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
