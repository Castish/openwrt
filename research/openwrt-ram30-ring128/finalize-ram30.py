#!/usr/bin/env python3
"""Finalize verified RAM30 inputs; do not rerun an issued release."""
from pathlib import Path
import hashlib,json,subprocess,zlib
r=Path(__file__).resolve().parent
assert not (r/'c80-openwrt-ram30-ring128.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def evidence(name):
 d=json.loads((r/'evidence'/name).read_text());assert d['passed'],name;return d
native=evidence('native-summary.json');assert native['actual_core_cases']==2500 and native['new_recycle_cases']==5
for name,digest in native['core_sources'].items():assert sha(r/name)==digest,name
recycle=evidence('recycle-result.json');assert recycle['cases_passed']==55
assert recycle['maximum_full_lifecycle_posts']==131074 and recycle['mixed_size_recycling_posts']==8193
ring=evidence('stock-ring128-result.json');assert ring['cases_passed']==15 and ring['verification_source_sha256']==sha(r/'trace-stock-ring128.py')
oem=evidence('stock-tx-lifetime-result.json');assert oem['cases_passed']==15
assert oem['verification_source_sha256']==sha(r/'trace-stock-tx-lifetime.py')
qemu={}
for mode,commands in [('linux-network',20),('aon-refusal',51),('missing-firmware',53)]:
 d=evidence('qemu-'+mode+'-result.json')
 assert d['qemu_kernel_sha256']==sha(r/'build-qemu/arch/arm/boot/zImage')
 assert d['qemu_CPIO_sha256']==sha(r/'build-qemu/usr/initramfs_data.cpio')
 assert len(d['commands'])==commands
 qemu[mode]={'commands':commands,'protocol_checks':d.get('protocol_checks',0),'memory_available_KiB':d.get('memory_available_KiB',d.get('mem_available_kib_after_services'))}
assert qemu['linux-network']['protocol_checks']==13
source=evidence('source-restore-result.json');assert source['full_source_entries_compared']==86721 and source['patch_sha256']==sha(r/'linux-mt7626-bringup.patch')
rootfs=evidence('rootfs-restore-result.json');assert rootfs['entries_compared']==532
scope=evidence('ram29-to-ram30-scope.json');assert len(scope['Linux_changed'])==4 and scope['rootfs_changed']==['usr/sbin/c80-wifi']
loads=[]
for name,address in [('c80-openwrt-ram30-ring128-zImage',0x41000000),('c80-openwrt-ram30-ring128.dtb',0x40f00000),('c80-openwrt-ram30-handoff.bin',0x40e00000)]:
 p=r/name;b=p.read_bytes();loads.append({'file':name,'address':f'{address:08x}','bytes':len(b),'crc32':f'{zlib.crc32(b):08x}','sha256':sha(p)})
subprocess.run(['python3',str(r/'make-script.py'),'41000000',str(r/loads[0]['file']),'40f00000',str(r/loads[1]['file']),'40e00000',str(r/loads[2]['file']),'--go','40e00000','--output',str(r/'c80-start.txt'),'--force'],check=True,capture_output=True)
provenance={'release':'C80 OpenWrt RAM30 recyclable Wi-Fi transport','kernel':'6.12.113-c80-openwrt-ram30-ring128','board':'TP-Link Archer C80 v1 RU, TP1900BN, MT7626 E2','hardware_tested':False,'parent_RAM28_Linux_IP_DHCP_MTU1400_TCP22_passed':True,'parent_hardware_evidence':'prior-hardware/RAM29-result.json','parent_RAM29_failed_descriptor127_CPU128':True,'underlying_RAM29_stall_cause_proved':False,'new128_ring_hardware_success_proved':False,'load_files':loads,'script_bytes':(r/'c80-start.txt').stat().st_size,'runner_bytes':4732,'runner_sha256':sha(r/'c80-script-runner.bin'),'native_checks':native,'OEM_token_lifetime_cases':15,'OEM_ring128_candidate_cases':15,'QEMU_checks':qemu,'Linux_packet_adapter':{'name':'c80wlan0','Linux_ARP_IP_ICMP_UDP_TCP':True,'old_diagnostic_echo_enabled':False,'OpenWrt_netifd_address':'192.168.2.1/24','DHCP_server':'official dnsmasq2.93-r1 unchanged','DHCP_lease':'192.168.2.2/24','DHCP_default_router_or_DNS_advertised':False,'MTU':1400,'one_open_client':True,'CONTROL_us':30000000,'active_window':'until explicit stop, fault or reboot','old_180s_256_frame_cutoff_removed':True,'packet_counter_exhaustion_stops_at':4294967295,'inflight_packets':1,'resident_data_buffers':16,'descriptor_ring_cells':128,'allocated_descriptor_cells':512,'token_range':[16,4095],'DMA_pool_bytes':665792,'active_header_payload_token_descriptor_reuse':True,'requires_header_DDONE_and_DMA_index_and_TX_free':True,'firmware_exactly_once_no_access_after_free_contract_required':True,'token_has_no_generation_field':True,'entire_pool_retained_unchanged_after_stop_until_reboot':True,'Linux_skb_is_copied_before_DMA':True,'RX_is_copied_before_device_return':True,'ordinary_stop_drains_inflight_then_OFF':True,'shutdown_requests_stop_before_waiting_for_cleanup':True},'not_implemented':['multiple clients or re-association lifecycle','cfg80211/mac80211/hostapd integration','WPA encryption','configured NAT/Internet','flash installation'],'QEMU_software_peer_enabled_in_router':False,'source_patch_sha256':sha(r/'linux-mt7626-bringup.patch'),'source_restore':source,'rootfs_restore':rootfs,'no_persistent_uboot_flash_efuse_changes':True,'scope':'evidence/ram29-to-ram30-scope.json','Windows_operator_script_executed_in_cloud':False,'QEMU_boots_should_run_sequentially':True}
(r/'PROVENANCE.json').write_text(json.dumps(provenance,indent=2)+'\n')
(r/'evidence/script-result.json').write_text(json.dumps({'passed':True,'load_files':loads,'script_bytes':provenance['script_bytes'],'steps':4,'runner_unchanged_from_hardware_proven_parent':True},indent=2)+'\n')
(r/'kernel-source-manifest.json').write_text(json.dumps({'linux_version':'6.12.113','signed_source_sha256':source['verified_archive_sha256'],'full_patch_sha256':sha(r/'linux-mt7626-bringup.patch'),'full_patch_files':24,'full_source_entries_verified':86721,'cache':'/tmp/c80-ram30-source/linux-6.12.113','restore_command':'python3 restore-source.py','rootfs_restore_command':'python3 restore-rootfs.py'},indent=2)+'\n')
(r/'rootfs-overrides.json').write_text(json.dumps({'parent':'immutable openwrt-ram29-recycle ZIP rootfs.cpio.gz','changed_files':['usr/sbin/c80-wifi'],'added_files':[],'complete_rootfs_archive':'rootfs.cpio.gz','actual_hardware_CPIO_sha256':sha(r/'build/usr/initramfs_data.cpio'),'exact_rootfs_restore_entries':532,'rationale':'RAM30 exact-version helper and explicit stop instructions; all packages, DHCP/netifd, firmware and other rootfs files unchanged'},indent=2)+'\n')
validation='''Пройдены2500 сценариев общего ядра ASan/UBSan, включая55 проверок
оборота памяти:131074 последовательных передачи,8193 передачи переменной
длины20..1400байт, обороты дескрипторов/токенов/sequence, оба порядка
подтверждений, потеря/повтор токенов, ошибки журналов, остановка, потеря HIF,
обратное/замершее время и переход через32-битный счётчик микросекунд.
Отдельно18 IRQ-gate,12IRQ+13ROM+28lifetime+6stop/shutdown проверок.

Заводской ARM-код выполнил15 сценариев,4925 циклов выделения/возврата,
включая полный оборот4096-ID очереди. В QEMU прошли13 проверок настоящих
Linux/DHCP/ARP/ICMP/TCP/SSH и20 команд, ещё51+53 проверки OpenWrt/refusal/
перезагрузки. Аппаратные MCU/DMA/радио в этих моделях не эмулируются.
После служб QEMU осталось более10МиБ памяти при32МиБ физической RAM.

Проверены58 ARM ELF и зависимости,6ARM decompressor/5handoff/8restart
случаев. Полный патч24файла применён без fuzz/offset; все86721 записи
исходников и532 записи rootfs восстановлены и сравнены. Тестовый Ethernet
peer QEMU отсутствует в ядре роутера. Новая RAM30 на плате пока не проверена. Отдельно15 сценариев заводского
ARM-кода подтвердили настройку и оборот128-записного кольца при явно
заданном host-параметре128 вместо заводского512. MMIO/DMA синтетические;
причину аппаратной остановки RAM29 эта проверка не устанавливает.
'''
table='| Файл | Байт | CRC32 |\n| --- | ---: | --- |\n'+''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in loads)
template=(r/'README-template.md').read_text()
(r/'README.md').write_text(template.replace('{{VALIDATION}}',validation).replace('{{LOAD_TABLE}}',table))
assert '{{' not in (r/'README.md').read_text()
print(json.dumps({'load_files':loads,'script_bytes':provenance['script_bytes'],'actual_core_cases':2500,'new_recycle_cases':5,'QEMU':qemu,'hardware_tested':False},indent=2))
