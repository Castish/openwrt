#!/usr/bin/env python3
"""Bind RAM25 bounded association evidence to immutable RAM24 and actual outputs."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram24-tx-free'
assert not (r/'c80-openwrt-ram25-assoc.zip').exists()
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
assert json.loads((e/'ram24-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram25-assoc-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram25-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram25-assoc-zImage'),(0x40f00000,'c80-openwrt-ram25-assoc.dtb'),(0x40e00000,'c80-openwrt-ram25-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram25-assoc-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram25-assoc.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram25-assoc.dtb').read_bytes()==(parent/'c80-openwrt-ram24-tx-free.dtb').read_bytes()
assert (r/'c80-openwrt-ram25-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram24-handoff.bin').read_bytes()
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
auth=json.loads((e/'auth-tx-result.json').read_text());oem=json.loads((e/'stock-management-traces.json').read_text())
assert auth['passed'] and auth['cases_passed']==60 and oem['passed'] and oem['cases_passed']==40
assert auth['core_source_sha256']==sha(r/'c80_mcu_core.h') and auth['tests_source_sha256']==sha(r/'verify-auth-tx.c')
assert (r/'stock-auth-txd.bin').read_bytes()==bytes.fromhex(oem['auth_TxD_CCK1']['TXD_hex'])
assert auth['oracle_sha256']==sha(r/'stock-auth-txd.bin')
assert len([x for x in (r/'verification-auth-tx.log').read_text().splitlines() if x.startswith('PASS AUTH-')])==60
body=text[text.index('static ssize_t reply_show'):text.index('static ssize_t run_store')]
assert 'mutex_lock' in body and 'readl' not in body and 'c80_read(' not in body and 'pool->' not in body
life=json.loads((e/'pool-lifetime-result.json').read_text())
assert life['passed'] and life['cases_passed']==22
run_body=text[text.index('static ssize_t run_store('):text.index('static struct kobj_attribute reply_attr=')]
assert life['actual_callback_source_sha256']==hashlib.sha256(run_body.encode()).hexdigest()
assert life['verification_source_sha256']==sha(r/'verify-pool-lifetime.py')
txf=json.loads((e/'tx-free-result.json').read_text());stock=json.loads((e/'stock-tx-free-traces.json').read_text())
assert txf['passed'] and txf['cases_passed']==84 and stock['passed'] and stock['cases_passed']==31
assert txf['core_source_sha256']==sha(r/'c80_mcu_core.h') and txf['tests_source_sha256']==sha(r/'verify-tx-free.c')
assert len([x for x in (r/'verification-tx-free.log').read_text().splitlines() if x.startswith('PASS TXFREE-')])==84
assert stock['MCU_packet_type']==7 and stock['packet_type']==6 and stock['verification_source_sha256']==sha(e/'trace-stock-tx-free.py')
body=text[text.index('static ssize_t completion_show'):text.index('static ssize_t run_store')]
assert 'mutex_lock' in body and 'readl' not in body and 'c80_read(' not in body and 'pool->' not in body
assert '.rx1_packet_test=1' in text
restore=json.loads((e/'source-restore-result.json').read_text())
assert restore['passed'] and restore['full_source_entries_compared']==86717
assert restore['patch_sha256']==sha(r/'linux-mt7626-bringup.patch') and restore['verification_source_sha256']==sha(r/'restore-source.py')
assoc=json.loads((e/'association-result.json').read_text());sta=json.loads((e/'stock-station-traces.json').read_text());atx=json.loads((e/'stock-association-tx-traces.json').read_text())
assert assoc['passed'] and assoc['cases_passed']==123 and sta['passed'] and sta['cases_passed']==30 and atx['passed'] and atx['cases_passed']==8
assert assoc['core_source_sha256']==sha(r/'c80_mcu_core.h') and assoc['tests_source_sha256']==sha(r/'verify-association.c')
assert assoc['STA_oracle_sha256']==sha(r/'stock-station-command-oracle.bin') and assoc['TXD_oracle_sha256']==sha(r/'stock-association-txd.bin')
assert len([x for x in (r/'verification-association.log').read_text().splitlines() if x.startswith('PASS ASSOC-')])==123
for key,fn in [(sta,'trace-stock-station.py'),(atx,'trace-stock-association-tx.py')]:assert key['verification_source_sha256']==sha(e/fn)
assert (r/'stock-association-txd.bin').read_bytes()==bytes.fromhex(atx['profile']['TXD_hex'])
assert split_wire((r/'stock-station-command-oracle.bin').read_bytes())==[bytes.fromhex(x['packet_hex']) for x in sta['profile_packets']]
body=text[text.index('static ssize_t association_show'):text.index('static ssize_t run_store')]
assert 'mutex_lock' in body and 'readl' not in body and 'c80_read(' not in body and 'pool->' not in body
assert '.assoc_reply_test=1' in text and 'c->result.assoc_submitted ||' in text
(e/'ram25-wire-result.json').write_text(json.dumps({'passed':True,'legacy_59_packet_oracles_byte_identical_to_RAM24':True,
 'new_STA_command_oracles':2,'STA_create_bytes':308,'STA_delete_bytes':92,'new_management_frame_type':'association response1','new_management_frame_max':1,'auth_response_max':1,
 'coherent_pool_bytes':271216,'new_DMA_pool_bytes':2416,'command_slots':29,'RX1_previous_TX_free_logic_extended_for_token1':True,
 'pool_release_or_reuse_on_TXfree':False,'association_sysfs_saved_scalars_only':True,'physical_tested':False},indent=2)+'\n')
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram25-assoc',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram24-change-scope.json',
 scope='One minimal peer STA/WTBL create, one association response/token1 after auth and firmware ACK, normal BASIC delete, data/null header candidates only; full pool pinned until reboot',
 not_proven=['physical STA create/delete acceptance and single association response in RAM25','peer association acceptance and independent RF ACK/FCS','WLAN netdev/mac80211/hostapd/data path/DHCP','cold rail-cut equivalence','flash installation'])
p['parent_RAM24_result']=json.loads((r/'prior-hardware/RAM24-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=1238,new_association_STA_cases=123,actual_OEM_STA_cases=30,actual_OEM_association_TX_cases=8,
 actual_Linux_run_store_lifetime_cases=22,QEMU_command_checks=qemu,legacy_OEM_packet_oracles=59,new_STA_packet_oracles=2,
 legacy_59_packet_oracles_byte_identical_to_RAM24=True,full_source_restore_entries=restore['full_source_entries_compared'])
p['checks'].pop('all_59_packet_oracles_byte_identical_to_RAM23',None)
for name in ('beacon_state','beacon','RX0_recycling','BSS','radio'):p[name]['pool_bytes']=271216
for name in ('BSS','radio','DEVINFO'):p[name]['command_slots']=29
p['beacon_state'].update(normal_TX_with_peer=60,normal_command_TX_with_peer=29,normal_sequence_with_peer=15,DMA_pool_increase_bytes=2416,DMA_pool_comparison_parent='RAM24')
p['auth_response'].update(physical_tested=False,parent_RAM24_header_and_TX_free_passed=True,
 physical_scope='Unchanged single auth frame/ring format previously passed in RAM24; larger pool geometry/new image still pending',pool_bytes=271216,
 DMA_pool_increase_bytes=2416,DMA_pool_comparison_parent='RAM24',all_buffers_retained_unchanged_until_reboot_after_any_submission=True)
p['TX_free'].update(physical_tested=False,parent_RAM24_type6_report0_v1_token0_passed=True,
 only_live_test_tokens=[0,1],only_live_test_token=None,association_token1_never_completed_before_submit=True,
 auth_and_association_tokens_never_reused=True,pool_released_or_token_reused_on_completion=False)
p['management_RX'].update(physical_tested=False,parent_RAM24_same_peer_assoc_candidate=True,
 physical_test_scope='Parent auth/candidate path passed; new bounded association parsing/response/data candidates await RAM25')
p['association_response']={'enabled':True,'physical_tested':False,'maximum_peers':1,'maximum_responses':1,
 'trigger':'first eligible same-peer assoc request after auth header done; first28s phase37; current clock not stale sample',
 'requires_auth_token0_return_before_STA_create':True,'STA_create_features':'2001 BASIC+WTBL','STA_delete_features':'0001 BASIC-only',
 'STA_create_body_bytes':244,'STA_delete_body_bytes':28,'STA_command_bytes':[308,92],'STA_states':[2,0],'STA_new_flags':[1,0],
 'connection_type':'00010001','BSS':0,'WCID':1,'MUAR':0,'AID':1,'WMM':False,'HT':False,'encryption':False,
 'STA_command_extension':'25','STA_minimum_reply_body_bytes':16,'STA_variable_length_reply':True,
 'strict_PID_EID_sequence_extension_echo_status_DMA_bounds':True,'unproved_base_metadata_observed_only':True,'OEM_callback_consumes_status_at_body_offset':4,
 'STA_wait_us':1000000,'STA_max_polls':1000,'association_post_deadline_us':29000000,'association_DMA_timeout_us':1000000,
 'hardware_ring':5,'slot':1,'token':1,'CPU_next_producer':2,'ring_entries':32,'PHY':'CCK1/20MHz','packet_format':0,
 'frame_bytes':36,'TXD_bytes':32,'TXP_bytes':32,'header_bytes':64,'duration_us':304,'sequence_control':16,
 'capability':1,'status':0,'AID_wire':'c001','rates_Mbps':[1,2,5.5,11],
 'delete_before_normal_beacon_SYNC_MAC_BSS_DEVINFO_OFF':True,'errors_take_MCU_hold_DMA_stop_cleanup':True,
 'normal_TX_command_FWDL_sequence_with_peer':[60,29,31,15],'no_peer_TX_command_FWDL_sequence':[58,27,31,13],
 'raw_same_peer_ToDS_data_and_null_header_candidates_only':True,'FCS_verified':False,'RF_ACK_confirmed':False,'IP_or_data_path_implemented':False,
 'peer_MAC_source':'validated same-peer RX frame only; never recorded in result/sysfs/logs','pool_retained_unchanged_after_any_submission_until_reboot':True,
 'errors':{'59':'missing association prerequisites','60':'malformed STA reply','61':'STA rejected','62':'CPU publish','63':'deadline/header/token timeout','64':'ring or descriptor mismatch'}}
p['source_storage'].update(independent_cache='/tmp/c80-ram25-source/linux-6.12.113',restore_command='python3 restore-source.py',entries_compared=restore['full_source_entries_compared'])
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
