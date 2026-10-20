#!/usr/bin/env python3
"""Tie RAM18 RX0 recycling to verification and immutable RAM17."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';parent=r.parent/'openwrt-ram17-watch'
assert not (r/'c80-openwrt-ram18-rx.zip').exists()
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
assert json.loads((e/'ram17-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram18-rx-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram18-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram18-rx-zImage'),(0x40f00000,'c80-openwrt-ram18-rx.dtb'),(0x40e00000,'c80-openwrt-ram18-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram18-rx-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram18-rx.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram18-rx.dtb').read_bytes()==(parent/'c80-openwrt-ram17-watch.dtb').read_bytes()
assert (r/'c80-openwrt-ram18-handoff.bin').read_bytes()==(parent/'c80-openwrt-ram17-handoff.bin').read_bytes()
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
assert (r/'stock-command-oracle.bin').read_bytes()==(parent/'stock-command-oracle.bin').read_bytes()
p=json.loads((parent/'PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram18-rx',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,source_scope='evidence/ram17-change-scope.json',
 scope='Bounded RX0 consume/rearm/CPU-index publish and wrap inside retained30s control/beacon HIF watch;same55 packets/C80-RAM16 template;no clientdata/NORwrites',
 not_proven=['physical RAM18 RX0 recycling/long-window outcome','whether RX starvation caused RAM16/17 DMA disable','beacon RF TX/SSID visibility/timestamp/FCS','authentication/association/clientdata','cold rail-cut equivalence','flash installation'])
p['parent_RAM17_result']=json.loads((r/'prior-hardware/RAM17-result.json').read_text())
p['checks'].update(actual_C_core_ASan_UBSan=559,new_RX0_recycling_cases=64,actual_OEM_ARM_RX_contract=28,QEMU_command_checks=qemu)
p['checks']['inherited_watch_cases']=p['checks'].pop('new_watch_fault_cases',36)
p['watch'].pop('window_MMIO_writes',None)
p['watch'].update(sampler_MMIO_writes=0,RX_consumer_MMIO_writes=['18004408'],auto_reenable=False,RX0_rearming=True,physical_tested=False)
p['RX0_recycling']={'ASIC_wrapper':'402a09ac','OEM_callback':'402f3d64','refill':'402f3f6c..402f402c','publisher_prefix':'402b2620..402b2644',
 'descriptor_count':64,'buffer_bytes':1536,'allocation':'same coherent265876B pool;no per-packet allocation','preserve_LS0':True,'clear_DONE_after_processing':True,
 'DMA_read_barrier_before_payload':True,'DMA_write_barrier_before_CPU_publish':True,'CPU_index_register':'18004408','CPU_index_is_consumed_slot':True,
 'CPU_readback_checked':True,'cursor_wrap':64,'budget_per_receive_call':64,'MCU_RX1_recycled':False,'MCU_RX1_bound':63,'rearm_error':45,
 'no_received_packet_pointer_retained':True,'no_payload_logged':True,'all_55_packets_unchanged':True,'normal_TX':56,'pool_bytes':265876,'physical_tested':False,
 'RX_starvation_causality_proven':False,'synthetic_sustained_both_windows_RX':60001}
p['radio']['RX0_rearming']=True
p['radio']['RX0_descriptor_limit']=64
p['beacon']['RX0_rearming']=True
p['hardware_tested']=False
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=(r/'README-template.md').read_text().replace('{{LOAD_TABLE}}',''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records))
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
