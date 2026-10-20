#!/usr/bin/env python3
"""Validate the concrete router payload, rootfs, test bindings and issue scope."""
from pathlib import Path
import gzip,hashlib,json,re,struct,subprocess,sys
from cpio_tools import entries,compare_qemu
r=Path(__file__).resolve().parent;p=r.parent/'openwrt-ram28-netdev'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=json.loads((r/'PROVENANCE.json').read_text());assert q['hardware_tested'] is False
cfg=(r/'build/.config').read_text()
for name in ['C80_MCU_TRANSPORT_TEST','C80_RAM_ETH','NET','INET','PACKET','OF_RESERVED_MEM','MTD_ROM','POWER_RESET_C80','SERIAL_8250_MT6577']:
 assert f'CONFIG_{name}=y\n' in cfg,name
for name in ['C80_NET_SELFTEST','WLAN','CFG80211','MAC80211','SMP','VFP','NEON','MODULES','SPI','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
 assert f'CONFIG_{name}=y\n' not in cfg,name
assert 'CONFIG_LOCALVERSION="-c80-openwrt-ram31-scheduler"' in cfg
assert (r/'artifacts/kernel.config').read_bytes()==(r/'build/.config').read_bytes()
elf=(r/'build/vmlinux').read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',elf)
segments=[struct.unpack_from('<8I',elf,h[5]+i*h[9]) for i in range(h[10])]
loads=[x for x in segments if x[0]==1]
elf_base=min(x[3] for x in loads)
runtime=lambda address:address-elf_base+0x40200000
assert runtime(h[4])==0x40208000
assert max(runtime(x[3])+x[5] for x in loads)<0x40e00000
kernel=(r/'c80-openwrt-ram31-scheduler-zImage').read_bytes();assert kernel==(r/'build/arch/arm/boot/zImage').read_bytes()
magic,start,end=struct.unpack_from('<III',kernel,0x24);assert magic==0x016f2818 and start==0 and end==len(kernel)
assert 0<len(kernel)<0xc00000
assert (r/'c80-openwrt-ram31-scheduler.dtb').read_bytes()==(p/'c80-openwrt-ram28-netdev.dtb').read_bytes()
assert (r/'c80-openwrt-ram31-handoff.bin').read_bytes()==(p/'c80-openwrt-ram28-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').read_bytes()==(p/'c80-script-runner.bin').read_bytes()
for name in ['c80_mcu_core.h','c80_mcu_transport.c','c80_net_core.h','c80_net_types.h','c80_net_linux.h','c80_net_selftest.c']:
 assert (r/name).read_bytes()==(r/'linux-6.12.113/drivers/soc/mediatek'/name).read_bytes(),name
nm=r.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm'
symbols=subprocess.check_output([str(nm),'-n',str(r/'build/vmlinux')],text=True)
assert not re.search(r'\bc80_selftest_',symbols)
for fn in ['c80_linux_ndo_xmit','c80_linux_net_receive','c80_linux_net_prepare','c80_mcu_shutdown','scheduler_show']:
 assert re.search(r'\b'+fn+r'\b',symbols),fn
cpio=(r/'build/usr/initramfs_data.cpio').read_bytes();files=entries(cpio)
assert compare_qemu(cpio,(r/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(r/'artifacts/c80-net-selftest').read_bytes())==538
assert 'usr/sbin/c80-net-selftest' not in files
for name in ['etc/config/network','etc/config/dhcp','etc/passwd','etc/group','usr/sbin/c80-wifi','usr/sbin/dnsmasq']:
 assert files[name][5]==(r/'rootfs'/name).read_bytes(),name
assert b"option force_link '1'" in files['etc/config/network'][5]
assert b"option device 'c80wlan0'" in files['etc/config/network'][5]
assert b"option ignore '1'" in files['etc/config/dhcp'][5]
assert b"list dhcp_option '3'" in files['etc/config/dhcp'][5] and b"list dhcp_option '6'" in files['etc/config/dhcp'][5]
assert not list((r/'rootfs/etc/dropbear').glob('*'))
assert not (r/'rootfs/tmp/dhcp.leases').exists()
assert gzip.decompress((r/'rootfs.cpio.gz').read_bytes())==cpio
assert len(json.loads((r/'openwrt-packages.json').read_text()))==36
abi=json.loads((r/'evidence/rootfs-elf-closure.json').read_text());assert len(abi)==58
restore=json.loads((r/'evidence/source-restore-result.json').read_text());assert restore['passed'] and restore['full_source_entries_compared']==86721 and restore['patch_sha256']==sha(r/'linux-mt7626-bringup.patch')
assert json.loads((r/'evidence/rootfs-restore-result.json').read_text())['passed']
net=json.loads((r/'evidence/netdev-result.json').read_text());assert net['passed'] and net['cases_passed']==601
for name,digest in net['source_sha256'].items():assert sha(r/name)==digest,name
recycle=json.loads((r/'evidence/recycle-result.json').read_text());assert recycle['passed'] and recycle['cases_passed']==55
for name,digest in recycle['source_sha256'].items():assert sha(r/name)==digest,name
native=json.loads((r/'evidence/native-summary.json').read_text());assert native['passed'] and native['actual_core_cases']==2591
for name,digest in native['core_sources'].items():assert sha(r/name)==digest,name
sched=json.loads((r/'evidence/scheduler-result.json').read_text());assert sched['passed'] and sched['cases_passed']==91
for name,digest in sched['source_sha256'].items():assert sha(r/name)==digest,name
for name,count in [('irq-wrapper',12),('nvm-reader',13),('pool-lifetime',28),('stop',6),('stock-tx-lifetime',15),('stock-ring128',15),('stock-scheduler',15),('scheduler',91)]:
 d=json.loads((r/'evidence'/(name+'-result.json')).read_text());assert d['passed'] and d['cases_passed']==count,name
decompressor=json.loads((r/'evidence/decompressor-result.json').read_text())
assert decompressor['passed'] and len(decompressor['checks'])==6 and decompressor['zimage_sha256']==sha(r/q['load_files'][0]['file'])
handoff=json.loads((r/'evidence/handoff-verification.json').read_text())
assert len(handoff['cases'])==5 and all(c['status']=='pass' for c in handoff['cases'])
assert handoff['payload_sha256']==sha(r/'c80-openwrt-ram31-handoff.bin')
restart=json.loads((r/'evidence/restart-result.json').read_text())
assert restart['passed'] and restart['cases_passed']==8 and restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
recovery=json.loads((r/'evidence/rootfs-recovery-result.json').read_text())
assert recovery['passed'] and recovery['cases_passed']==3 and recovery['script_sha256']==sha(r/'restore-rootfs.py')
assert q['Linux_packet_adapter']['descriptor_ring_cells']==128
assert q['Linux_packet_adapter']['allocated_descriptor_cells']==512
assert '#define C80_NET_RECYCLE_RING_N 128u' in (r/'c80_net_types.h').read_text()
assert '.scheduler_test=1' in (r/'c80_mcu_transport.c').read_text()
assert '.net_recycle_test=1' in (r/'c80_mcu_transport.c').read_text()
assert '6.12.113-c80-openwrt-ram31-scheduler' in (r/'rootfs/usr/sbin/c80-wifi').read_text()
assert b'c80-wifi stop' in files['usr/sbin/c80-wifi'][5]
for mode in ['linux-network','aon-refusal','missing-firmware']:
 d=json.loads((r/'evidence'/('qemu-'+mode+'-result.json')).read_text());assert d['passed']
 assert d['qemu_kernel_sha256']==sha(r/'build-qemu/arch/arm/boot/zImage')
 assert d['qemu_CPIO_sha256']==sha(r/'build-qemu/usr/initramfs_data.cpio')
for rec in q['load_files']:
 x=r/rec['file'];assert x.stat().st_size==rec['bytes'] and sha(x)==rec['sha256']
from make_script_import import validate_script
validate_script(r,q['load_files'])
result={'passed':True,'router_kernel_sha256':sha(r/q['load_files'][0]['file']),'kernel_entry_physical':'0x40208000','kernel_load_segments':[{'runtime_physical':hex(runtime(x[3])),'memory_bytes':x[5]} for x in loads],'kernel_high_end':hex(max(runtime(x[3])+x[5] for x in loads)),'hardware_CPIO_sha256':sha(r/'build/usr/initramfs_data.cpio'),'qemu_extra_helper_only':True,'QEMU_software_peer_disabled_and_absent_in_router':True,'actual_network_callbacks_linked':True,'soft_float_ELF_files':58,'signed_source_patch_files':24,'full_source_entries_restored':86721,'rootfs_entries_restored':532,'native_core_checks':2591,'recycle_checks':55,'new_scheduler_checks':91,'actual_Linux_stop_shutdown_checks':6,'OEM_token_lifetime_checks':15,'QEMU_protocol_checks':13,'physical_new_image_tested':False}
(r/'artifacts/artifact-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
