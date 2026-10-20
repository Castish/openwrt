#!/usr/bin/env python3
"""Bind RAM26 bounded ARP/ICMP evidence to immutable RAM25 and actual outputs."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram25-assoc'
assert not (r/'c80-openwrt-ram26-echo.zip').exists()
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
assert json.loads((e/'ram25-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram26-echo-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram26-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram26-echo-zImage'),(0x40f00000,'c80-openwrt-ram26-echo.dtb'),(0x40e00000,'c80-openwrt-ram26-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram26-echo-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram26-echo.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram26-echo.dtb').read_bytes()==(parent/'c80-openwrt-ram25-assoc.dtb').read_bytes()
assert (r/'c80-openwrt-ram26-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram25-handoff.bin').read_bytes()
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
assert life['passed'] and life['cases_passed']==25
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
data=json.loads((e/'data-result.json').read_text());dt=json.loads((e/'stock-data-traces.json').read_text())
assert data['passed'] and data['cases_passed']==589 and dt['passed'] and dt['cases_passed']==68
assert data['core_source_sha256']==sha(r/'c80_mcu_core.h') and data['tests_source_sha256']==sha(r/'verify-data.c')
assert data['TXD_oracle_sha256']==sha(r/'stock-data-txd.bin') and data['wire_fixtures_sha256']==sha(r/'data-protocol-fixtures.bin')
assert dt['script_sha256']==sha(e/'trace-stock-data.py')
assert (r/'stock-data-txd.bin').read_bytes()==bytes.fromhex(dt['profile']['TXD_hex'])
assert len([x for x in (r/'verification-data.log').read_text().splitlines() if x.startswith('PASS DATA-')])==589
assert json.loads((e/'data-protocol-fixtures.json').read_text())['source_sha256']==sha(r/'make-data-fixtures.py')
body=text[text.index('static ssize_t data_show'):text.index('static ssize_t run_store')]
assert 'mutex_lock' in body and 'c80_read(' not in body and 'readl' not in body and 'pool->' not in body
assert '.data_echo_test=1' in text and 'c->result.diag_submissions ||' in text
(e/'ram26-wire-result.json').write_text(json.dumps({'passed':True,'legacy_59_and_2_STA_oracles_byte_identical_to_RAM25':True,
 'MCU_commands_unchanged':True,'new_data_frame_types':['raw nonQOS FromDS ARP reply','raw nonQOS FromDS ICMP echo reply'],
 'maximum_responses':{'auth':1,'association':1,'ARP':1,'ICMP':1},'coherent_pool_bytes':271664,'new_DMA_pool_bytes':448,
 'command_slots':29,'unique_test_tokens':[0,1,2,3],'pool_release_or_reuse_on_TXfree':False,
 'data_sysfs_saved_scalars_only':True,'physical_tested':False},indent=2)+'\n')
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram26-echo',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram25-change-scope.json',
 scope='One ARP and one ICMP echo response after inherited single-peer STA/association lifecycle; strict RX bounds/peer/open/error/checksums; no netdev/DHCP/general IP stack; complete pool pinned until reboot',
 not_proven=['physical ARP/ICMP RX/TX and ping in RAM26','independent RF ACK/FCS','WLAN netdev/mac80211/hostapd/general data path/DHCP','cold rail-cut equivalence','flash installation'])
p['parent_RAM25_result']=json.loads((r/'prior-hardware/RAM25-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=1827,new_data_cases=589,actual_OEM_data_cases=68,
 actual_Linux_run_store_lifetime_cases=25,QEMU_command_checks=qemu,legacy_OEM_packet_oracles=59,new_STA_packet_oracles=2,
 all_61_MCU_packet_oracles_byte_identical_to_RAM25=True,full_source_restore_entries=restore['full_source_entries_compared'])
for name in ('beacon_state','beacon','RX0_recycling','BSS','radio'):p[name]['pool_bytes']=271664
p['beacon_state'].update(DMA_pool_increase_bytes=448,DMA_pool_comparison_parent='RAM25')
p['auth_response'].update(physical_tested=False,parent_RAM25_header_and_TX_free_passed=True,
 physical_scope='Unchanged frame/ring format passed in RAM25; new larger-pool image pending',pool_bytes=271664,
 DMA_pool_increase_bytes=448,DMA_pool_comparison_parent='RAM25',all_buffers_retained_unchanged_until_reboot_after_any_submission=True)
p['TX_free'].update(physical_tested=False,parent_RAM25_type6_report0_v1_tokens0_1_passed=True,
 only_live_test_tokens=[0,1,2,3],all_tokens_never_completed_before_submit=True,all_tokens_never_reused=True,pool_released_or_token_reused_on_completion=False)
p['management_RX'].update(physical_tested=False,parent_RAM25_raw_same_peer_data_and_null_candidates=True,
 physical_test_scope='Parent management/data-header candidates passed; new payload classification awaits RAM26')
p['association_response'].update(physical_tested=False,parent_RAM25_STA_create_delete_header_token1_passed=True,
 physical_test_scope='Exact original STA/association packets retained; new image still pending')
p['data_echo']={'enabled':True,'physical_tested':False,'endpoint':'192.168.2.1','client':'192.168.2.2','requires_static_client':True,
 'maximum_peers':1,'maximum_ARP_responses':1,'maximum_ICMP_responses':1,'maximum_ICMP_payload_bytes':64,
 'raw_RX_and_translated_with_group4':True,'require_ToDS_pinned_peer_WCID1_open_no_fragment_no_AMSDU':True,
 'check_HW_FCS_and_ICV_and_conservative_family_error_flags':True,'independent_FCS_verified':False,
 'RFC1042_LLC_only':True,'ARP_hardware1_protocol0800_sizes6_4_request1_SHA_peer_target_IP_checked':True,
 'IPv4_IHL20_no_fragments_header_checksum_checked':True,'ICMP_echo_type8_code0_checksum_checked':True,
 'incoming_optional_FCS_or_padding_never_assumed_stripped':True,'DHCP_UDP68_67_candidates_count_only':True,
 'response_frames':['FromDS nonQoS ARP reply60B','FromDS nonQoS IPv4/ICMP reply60..124B'],
 'PHY':'CCK1/20','WCID':1,'hardware_ring':5,'unused_slots':[2,3],'tokens':[2,3],
 'submission_order':'first captured eligible response first; prior token/header complete before second','capture_deadline_us':28000000,
 'post_deadline_us':29000000,'header_and_token_wait_us':1000000,'all_DMA_buffers_retained_until_full_reboot':True,
 'pool_bytes':271664,'increase_bytes':448,'saved_sysfs':'data','packet_or_learned_address_logged':False,
 'Linux_WLAN_netdev':False,'hostapd':False,'DHCP':False,'general_IP_stack':False,
 'errors':{'65':'missing association prerequisites','66':'CPU publication','67':'ring/descriptor mismatch','68':'reply/header/token/deadline timeout'}}
p['source_storage'].update(independent_cache='/tmp/c80-ram26-source/linux-6.12.113',restore_command='python3 restore-source.py',entries_compared=restore['full_source_entries_compared'])
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
