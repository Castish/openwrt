#!/usr/bin/env python3
"""Bind RAM24 classified RX1 evidence to immutable RAM23 and actual outputs."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram23-auth-tx'
assert not (r/'c80-openwrt-ram24-tx-free.zip').exists()
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
assert json.loads((e/'ram23-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram24-tx-free-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram24-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram24-tx-free-zImage'),(0x40f00000,'c80-openwrt-ram24-tx-free.dtb'),(0x40e00000,'c80-openwrt-ram24-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram24-tx-free-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram24-tx-free.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram24-tx-free.dtb').read_bytes()==(parent/'c80-openwrt-ram23-auth-tx.dtb').read_bytes()
assert (r/'c80-openwrt-ram24-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram23-handoff.bin').read_bytes()
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
assert life['passed'] and life['cases_passed']==19
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
(e/'ram24-wire-result.json').write_text(json.dumps({'passed':True,'all_59_MCU_packet_oracles_byte_identical_to_RAM23':True,
 'new_MCU_command_packets':0,'new_management_frame_types':0,'unchanged_management_frame_max':1,'coherent_pool_bytes':268800,
 'new_DMA_pool_bytes':0,'new_TX_MMIO_or_interrupt_writes':0,'new_RX1_descriptor_return_policy':'classify type7 MCU and type6 TX-free before bounded parse',
 'pool_release_on_TXfree':False,'completion_sysfs_saved_scalars_only':True,'RAM24_physical_tested':False},indent=2)+'\n')
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram24-tx-free',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram23-change-scope.json',
 scope='Classify RX1 by actual OEM type; bounded TX-free parsing and saved completion telemetry; unchanged one-auth-response/RF sequence and pool retention after any submission',
 not_proven=['RAM24 physical short RX1 packet content and TX-free token return','RAM24 complete30s lifecycle after management TX','independent RF ACK/FCS validation','association/client data','cold rail-cut equivalence','flash installation'])
p['parent_RAM23_result']=json.loads((r/'prior-hardware/RAM23-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=1115,new_RX1_TX_free_cases=84,actual_OEM_TX_free_cases=31,
 actual_Linux_run_store_lifetime_cases=19,actual_OEM_management_TX_cases=40,QEMU_command_checks=qemu,
 independent_OEM_packet_oracles=59,all_59_packet_oracles_byte_identical_to_RAM23=True,
 full_source_restore_entries=restore['full_source_entries_compared'])
p['checks'].pop('all_59_packet_oracles_byte_identical_to_RAM22',None)
p['RX1_recycling'].update(read_only_descriptor_validation=['DONE','LS0','size4..1536','exactDMAaddress','zeroaddress1'],
 MCU_packet_type=7,TX_free_packet_type=6,unknown_non_MCU_types_counted_and_recycled=True,
 malformed_TX_free_aborts_without_return=True,physical_tested=False,
 physical_scope='RAM23 same descriptor-return path21 events passed; new packet classification and notifications hardware pending')
p['management_RX'].update(physical_tested=True,physical_test_scope='RAM23 one auth request and same-peer association-request candidate after one reply; separate FCS/ACK/association success not established')
p['auth_response'].update(physical_tested=True,physical_scope='Unchanged RAM23 one header DDONE/CPU/DMA1 and subsequent same-peer association-request candidate1; not a complete30s pass',
 DMA_pool_increase_bytes=0,DMA_pool_comparison_parent='RAM23',minimal_BSS_WCID0_sufficiency_unverified=False,
 minimal_BSS_scope='One auth reply plus association-request candidate, not a complete AP/association context',
 all_buffers_retained_unchanged_until_reboot_after_any_submission=True,TXfree_or_payload_engine_drain_proven=False)
p['TX_free']={'enabled':True,'physical_tested':False,'packet_type':6,'MCU_event_packet_type':7,
 'OEM_handler':'402b2f2c','OEM_dispatcher':'402b327c','OEM_MCU_handler':'402ad92c',
 'header_bytes':8,'token_offset':8,'token_bits':16,'token_count_bits':[16,22],'report_type_bits':[23,28],
 'report0_only_completes_token':True,'version_bits_DW1':[16,18],'version0_stride':2,'nonzero_version_stride':4,
 'descriptor_bytes_must_equal_ALIGN4_embedded_bytes':True,'embedded_bytes_must_equal_header_plus_count_stride':True,
 'maximum_token':4095,'whole_list_validated_before_counters':True,'only_live_test_token':0,
 'before_submit_foreign_duplicate_counts_separate':True,'malformed_report_error':58,
 'unknown_non_MCU_types_recycled_without_event_parsing':True,'unknown_report_subtype_no_token_reads':True,
 'packet_pointer_or_address_saved':False,'completion_sysfs_saved_scalars_only':True,
 'pool_released_or_token_reused_on_completion':False,'RF_ACK_proven':False,'association_supported':False}
p['source_storage']={'independent_cache':'/tmp/c80-ram24-source/linux-6.12.113',
 'research_source_entry_is_symlink_to_own_temporary_cache':True,'restore_command':'python3 restore-source.py',
 'restore_inputs':['verified linux-6.12.113.tar.xz','issued linux-mt7626-bringup.patch'],
 'restored_full_tree_matches_actual_build_source':True,'entries_compared':restore['full_source_entries_compared']}
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
