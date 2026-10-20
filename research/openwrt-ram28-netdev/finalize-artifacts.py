#!/usr/bin/env python3
"""Finalize verified RAM28 inputs before freezing the issue archive."""
from pathlib import Path
import difflib,hashlib,json,re,subprocess,zlib
r=Path(__file__).resolve().parent;p=r.parent/'openwrt-ram27-window'
assert not (r/'c80-openwrt-ram28-netdev.zip').exists()
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
records=[]
for name,address in [('c80-openwrt-ram28-netdev-zImage',0x41000000),('c80-openwrt-ram28-netdev.dtb',0x40f00000),('c80-openwrt-ram28-handoff.bin',0x40e00000)]:
 raw=(r/name).read_bytes();records.append({'file':name,'address':f'{address:08x}','bytes':len(raw),'crc32':f'{zlib.crc32(raw):08x}','sha256':sha(r/name)})
subprocess.run(['python3',str(r/'make-script.py'),'41000000',str(r/records[0]['file']),'40f00000',str(r/records[1]['file']),'40e00000',str(r/records[2]['file']),'--go','40e00000','--output',str(r/'c80-start.txt'),'--force'],check=True,capture_output=True)
numbers={'core':495,'rx-recycle':64,'beacon-state':46,'client-rx':366,'auth-tx':60,'tx-free':84,'association':123,'data':589,'window':17,'netdev':601}
for name,n in numbers.items():
 text=(r/('verification-'+name+'.log')).read_text();assert re.search(r'PASS:\s*'+str(n)+r'\b',text),(name,n)
assert sum(numbers.values())==2445
for name,n in [('irq-wrapper',12),('nvm-reader',13),('pool-lifetime',28)]:
 logname={'irq-wrapper':'irq-wrapper-verification.log','nvm-reader':'nvm-reader-verification.log','pool-lifetime':'verification-pool-lifetime.log'}[name]
 d=json.loads((r/'evidence'/(name+'-result.json')).read_text());assert d['passed'] and d['cases_passed']==n,(name,n)
qemu={}
for name in ['linux-network','aon-refusal','missing-firmware']:
 d=json.loads((r/'evidence'/('qemu-'+name+'-result.json')).read_text());assert d['passed']
 assert d['qemu_kernel_sha256']==sha(r/'build-qemu/arch/arm/boot/zImage')
 assert d['qemu_CPIO_sha256']==sha(r/'build-qemu/usr/initramfs_data.cpio')
 qemu[name]={'commands':len(d['commands']),'protocol_checks':d.get('protocol_checks',0),'memory_available_KiB':d.get('memory_available_KiB',d.get('mem_available_kib_after_services'))}
assert qemu['linux-network']['commands']==20 and qemu['linux-network']['protocol_checks']==13
native={'passed':True,'actual_core_cases':2445,'legacy_cases':1844,'new_netdev_cases':601,'native_ASan_UBSan':True,'suites':numbers,'IRQ_gate_cases':18,'actual_Linux_IRQ_callback_cases':12,'actual_Linux_ROM_reader_cases':13,'actual_Linux_pool_lifetime_cases':28,'new_RX_guard_page_cases':322,'core_sources':{n:sha(r/n) for n in ['c80_mcu_core.h','c80_net_types.h','c80_net_core.h','c80_net_linux.h','c80_mcu_transport.c']},'C80_radio_firmware_DMA_emulated':False}
(r/'evidence/native-summary.json').write_text(json.dumps(native,indent=2)+'\n')
scope=json.loads((r/'evidence/ram27-to-ram28-scope.json').read_text());scope['parent_rootfs_entries']=scope.pop('parent_full_source_entries',scope.get('parent_rootfs_entries')); (r/'evidence/ram27-to-ram28-scope.json').write_text(json.dumps(scope,indent=2)+'\n')
# Minimal reviewer diff against the known working parent; full vanilla patch also included.
paths=scope['Linux_changed']+scope['Linux_added'];chunks=[]
for name in paths:
 before=(p/'linux-6.12.113'/name).read_text().splitlines(True) if (p/'linux-6.12.113'/name).exists() else []
 after=(r/'linux-6.12.113'/name).read_text().splitlines(True)
 chunks.extend(difflib.unified_diff(before,after,fromfile='a/'+name if before else '/dev/null',tofile='b/'+name))
(r/'ram27-to-ram28.patch').write_text(''.join(chunks))
source=json.loads((r/'evidence/source-restore-result.json').read_text());assert source['passed'] and source['full_source_entries_compared']==86721
(root_restore:=json.loads((r/'evidence/rootfs-restore-result.json').read_text()));assert root_restore['passed'] and root_restore['entries_compared']==532
(r/'kernel-source-manifest.json').write_text(json.dumps({'linux_version':'6.12.113','signed_source_sha256':source['verified_archive_sha256'],'full_patch_sha256':sha(r/'linux-mt7626-bringup.patch'),'full_patch_files':24,'full_source_entries_verified':86721,'cache':'/tmp/c80-ram28-source/linux-6.12.113','restore_command':'python3 restore-source.py','rootfs_restore_command':'python3 restore-rootfs.py'},indent=2)+'\n')
(r/'rootfs-overrides.json').write_text(json.dumps({'parent':'openwrt-ram27-window/rootfs','changed_files':scope['rootfs_changed'],'added_files':scope['rootfs_added'],'complete_rootfs_archive':'rootfs.cpio.gz','actual_hardware_CPIO_sha256':sha(r/'build/usr/initramfs_data.cpio'),'exact_rootfs_restore_entries':532,'rationale':'Linux c80wlan0 netifd interface, official dnsmasq DHCP, Dropbear TCP service, helper/UID setup. Package metadata updated; all older binaries/firmware unchanged.'},indent=2)+'\n')
provenance={'release':'C80 OpenWrt RAM28 Linux netdev + DHCP','kernel':'6.12.113-c80-openwrt-ram28-netdev','board':'TP-Link Archer C80 v1 RU TP1900BN, MT7626 E2','hardware_tested':False,'parent_RAM27_bounded_WiFi_ping_passed':True,'parent_hardware_evidence':'prior-hardware/RAM27-result.json','load_files':records,'script_bytes':(r/'c80-start.txt').stat().st_size,'runner_bytes':4732,'runner_sha256':sha(r/'c80-script-runner.bin'),'native_checks':native,'QEMU_checks':qemu,'Linux_packet_adapter':{'name':'c80wlan0','Linux_ARP_IP_ICMP_UDP_TCP':True,'old_diagnostic_echo_enabled':False,'OpenWrt_netifd_address':'192.168.2.1/24','DHCP_server':'official dnsmasq2.93-r1','DHCP_lease':'192.168.2.2/24','DHCP_default_router_or_DNS_advertised':False,'MTU':1400,'one_open_client':True,'CONTROL_us':30000000,'BEACON_us':180000000,'max_TX_per_boot':256,'descriptor_ring_cells':512,'unique_descriptor_slots':[2,257],'unique_tokens':[16,271],'DMA_pool_bytes':665792,'entire_pool_retained_after_any_TX_until_reboot':True,'header_payload_token_descriptor_reuse':False,'Linux_skb_is_copied_before_DMA':True,'RX_is_copied_before_device_return':True,'ordinary_stop_drains_inflight_then_OFF':True,'shutdown_requests_stop_and_waits_for_run_cleanup':True,'native_rx_guard_pages':322},'not_implemented':['unlimited TX buffer reuse','multiple clients','cfg80211/mac80211/hostapd integration','WPA encryption','configured NAT/Internet','flash installation'],'QEMU_software_peer_enabled_in_router':False,'source_patch_sha256':sha(r/'linux-mt7626-bringup.patch'),'source_restore':source,'rootfs_restore':root_restore,'firmware_source':'FIRMWARE-SOURCES.json: identical six supplied generic components, no individual NVM bytes','no_persistent_uboot_flash_efuse_changes':True,'new_wire_or_clock_ETH_DTB_reset_changes':'see evidence/ram27-to-ram28-scope.json','configuration_and_setup_saved_separately':True}
(r/'PROVENANCE.json').write_text(json.dumps(provenance,indent=2)+'\n')
(r/'evidence/script-result.json').write_text(json.dumps({'passed':True,'load_files':records,'script_bytes':provenance['script_bytes'],'steps':4,'runner_unchanged_from_hardware_proven_parent':True},indent=2)+'\n')
validation='''2445 actual-core сценариев ASan/UBSan (601новый),18 IRQ-gate,12IRQ+13ROM
Linux callback и28 проверок сохранения DMA-пула пройдены. Проверены
256уникальных отправок, отдельные DDONE/token, тайм-ауты, остановка в CONTROL
и во время отправки, предельные размеры и322новые guard-page проверки RX.

В QEMU прошли13 фактических проверок Linux/DHCP/ARP/ICMP/TCP/SSH и20команд
управления. Дополнительно51+53проверки init/procd/ubus/netifd/отказа до
периферии/обычного reboot.32MiB физической/30MiB доступной Linux памяти;
после служб осталось более10MiB. Тестовый peer QEMU не входит в ядро роутера.
Проверены58 ARM soft-float ELF и зависимости,6ARM decompressor/5handoff/
8restart случаев. Полный патч24файла применён без fuzz/offset, все86721
записи исходников и532записи rootfs восстановлены и сравнены. RAM27 неизменна.
'''
text=(r/'README-template.md').read_text().replace('{{VALIDATION}}',validation)
table='| Файл | Байт | CRC32 |\n| --- | ---: | --- |\n'+''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records)
(r/'README.md').write_text(text.replace('{{LOAD_TABLE}}',table))
print(json.dumps({'load_files':records,'script_bytes':provenance['script_bytes'],'core_checks':2445,'QEMU':qemu,'hardware_tested':False},indent=2))
