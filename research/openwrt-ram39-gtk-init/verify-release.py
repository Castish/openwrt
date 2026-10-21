#!/usr/bin/env python3
"""Bind exact RAM39 artifacts and fresh checks to frozen RAM38. No RF claim."""
from pathlib import Path
import difflib,gzip,hashlib,json,os,shutil,struct,subprocess,zlib
from cpio_tools import entries,compare_qemu
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram38-bmc-profile'
assert not (R/'c80-openwrt-ram39-gtk-init.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def proof(name):
    j=json.loads((R/'evidence'/name).read_text());assert j['passed'],name;return j
parent=json.loads((P/'package-manifest.json').read_text())['files'];assert len(parent)==252
for row in parent:
    p=P/row['file'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['file']
assert sha(P/'c80-openwrt-ram38-bmc-profile.zip')=='5642cf907919d5cede3bb3d55fea6a1e0cfde45031af804cb26dbbbf676da37c'
assert sha(R/'c80-auth.cpio')==sha(P/'c80-auth.cpio')=='e97b79c9bf15089bbdd0f9a564698f63f61f7afc4ab1a135aaa6fd11a8f2e5b5'
assert sha(R/'c80-openwrt-ram39-handoff.bin')==sha(P/'c80-openwrt-ram38-handoff.bin')
inputs={p.name:sha(p) for p in P.iterdir() if p.suffix in {'.c','.h','.S'}}
changed=sorted(n for n,h in inputs.items() if sha(R/n)!=h)
assert changed==['c80_mcu_transport.c','c80_net_selftest.c','c80_security_core.h','c80_security_types.h'],changed
native=proof('native-summary.json');assert native['cases_passed']==3753 and native['all_suites_rerun']
for n,h in native['sources'].items():assert sha(R/n)==h,n
for n,h in native['logs'].items():assert sha(R/('verification-'+n+'.log'))==h,n
for name in ['cfg-control-result.json','session-result.json','security-result.json','beacon-diag-result.json','channel-result.json','bmc-profile-result.json','gtk-refresh-result.json']:
    for n,h in proof(name)['sources'].items():assert sha(R/n)==h,n
assert proof('beacon-diag-result.json')['cases_passed']==48
oracle=proof('stock-security-traces.json');assert oracle['cases_passed']==13
channel=proof('stock-channel-traces.json');assert channel['cases_passed']==6 and channel['verification_source_sha256']==sha(R/'trace-stock-channel.py')
assert proof('channel-result.json')['cases_passed']==76
assert proof('bmc-profile-result.json')['cases_passed']==12
for name,script in [('bmc-profile-comparison.json','trace-bmc-profile.py'),('normal-ap-request.json','trace-normal-ap-request.py')]:
    bmc=proof(name);assert bmc['cases_passed']==2 and bmc['verification_source_sha256']==sha(R/script)
assert len(bytes.fromhex(next(x for x in oracle['cases'] if x['kind']=='bmc-on')['body_hex']))==252
oldsec=(P/'c80_security_core.h').read_text();newsec=(R/'c80_security_core.h').read_text()
assert oldsec.split('static c80_u32 c80_security_key',1)[0]==newsec.split('static c80_u32 c80_security_key',1)[0]
assert oldsec.split('static c80_u32 c80_security_key',1)[1].split('static c80_u32 c80_security_authorize',1)[0]==newsec.split('static c80_u32 c80_security_key',1)[1].split('static c80_u32 c80_security_authorize',1)[0]
assert proof('gtk-refresh-result.json')['cases_passed']==41
assert proof('gtk-refresh-result.json')['old_RAM38_actual_core_refusal_reproduced']
assert proof('gtk-refresh-result.json')['parent_core_sha256']==sha(P/'c80_security_core.h')
assert oracle['cases']==json.loads((P/'evidence/stock-security-traces.json').read_text())['cases']
assert (R/'c80_key_linux.h').read_bytes()==(P/'c80_key_linux.h').read_bytes()
assert (R/'c80_radio.h').read_bytes()==(P/'c80_radio.h').read_bytes()
assert (R/'rootfs/etc/c80-hostapd.conf').read_text().count('channel=1\n')==1
assert 'C80_EXPERIMENT_CHANNEL 1u' in (R/'c80_radio.h').read_text()
assert oracle['verification_source_sha256']==sha(R/'trace-stock-security.py')
source=proof('source-restore-result.json');assert source['full_source_entries_compared']==86729
assert source['patch_sha256']==sha(R/'linux-mt7626-bringup.patch') and source['verification_source_sha256']==sha(R/'restore-source.py')
for mode in ['build','build-qemu']:
    cfg=(R/mode/'.config').read_text()
    expected='gtk-init' if mode=='build' else 'qemu-check'
    assert f'CONFIG_LOCALVERSION="-c80-openwrt-ram39-{expected}"' in cfg
    assert ('CONFIG_C80_NET_SELFTEST=y' in cfg)==(mode=='build-qemu')
shutil.copy2(R/'build/.config',R/'artifacts/kernel.config');shutil.copy2(R/'build-qemu/.config',R/'artifacts/qemu-kernel.config')
for n in ['SMP','MAC80211','VFP','NEON','MODULES','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
    assert f'CONFIG_{n}=y\n' not in (R/'build/.config').read_text(),n
raw=(R/'build/usr/initramfs_data.cpio').read_bytes();cp=entries(raw);base=entries(gzip.decompress((P/'rootfs.cpio.gz').read_bytes()))
assert gzip.decompress((R/'rootfs.cpio.gz').read_bytes())==raw
assert compare_qemu(raw,(R/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(R/'artifacts/c80-net-selftest').read_bytes())==len(cp)
root_changes=sorted(n for n in cp.keys()&base.keys() if cp[n]!=base[n])
assert cp.keys()==base.keys() and root_changes==['etc/c80-hostapd.conf','usr/sbin/c80-wifi'],root_changes
assert cp['usr/libexec/c80-wifi-lifecycle.sh'][5]==(R/'c80_wifi_lifecycle.sh').read_bytes()==(P/'c80_wifi_lifecycle.sh').read_bytes()
assert cp['usr/sbin/c80-wifi'][5]==(R/'rootfs/usr/sbin/c80-wifi').read_bytes()
assert not list((R/'rootfs/etc/dropbear').glob('*')) and 'usr/sbin/c80-net-selftest' not in cp
assert proof('rootfs-restore-result.json')['entries_compared']==601
proof('rootfs-scope.json');proof('rootfs-recovery-result.json')
for n in ['openwrt-packages.json','packages.lock','FIRMWARE-SOURCES.json']:
    assert (R/n).read_bytes()==(P/n).read_bytes(),n
assert len(json.loads((R/'openwrt-packages.json').read_text()))==45
elf=json.loads((R/'evidence/rootfs-elf-closure.json').read_text());assert len(elf)==66
for row in elf:assert sha(R/'rootfs'/row['path'])==row['sha256']
patch=[]
for n in ['verify-gtk-refresh.c','verify-gtk-refresh.sh']:
    patch.extend(difflib.unified_diff([], (R/n).read_text().splitlines(True),fromfile='/dev/null',tofile='b/'+n))
for n in changed:
    patch.extend(difflib.unified_diff((P/n).read_text().splitlines(True),(R/n).read_text().splitlines(True),fromfile='a/'+n,tofile='b/'+n))
for n in root_changes:
    patch.extend(difflib.unified_diff(base[n][5].decode().splitlines(True),cp[n][5].decode().splitlines(True),fromfile='a/rootfs/'+n,tofile='b/rootfs/'+n))
(R/'ram38-to-ram39.patch').write_text(''.join(patch))
q=proof('qemu-wpa2-result.json');fault=proof('qemu-startup-removal-result.json')
assert q['cases_passed']==43 and q['real_Linux_protocol_cases']==13 and q['strict_pinned_SSH_password_cases']==1
assert 'actual-ARM-report-lock-and-snapshot-callbacks' in q['cases']
assert q['shared_key_add_policy'] and q['first_station_GTK_refresh_required_by_check']
assert 'stock-hostapd-first-station-GTK-refresh-accepted-by-shared-policy' in q['cases']
assert 'hostapd-GMK-GTK-setup-succeeds' in q['cases']
assert q['verification_source_sha256']==sha(R/'verify-qemu-wpa2.py') and q['hostapd_sha256']==sha(R/'rootfs/usr/sbin/hostapd')
assert q['kernel_sha256']==fault['kernel_sha256']==sha(R/'build-qemu/arch/arm/boot/zImage')
assert fault['commands_passed']==13 and fault['actual_shared_helper_rejected_false_success']
assert fault['verification_source_sha256']==sha(R/'verify-qemu-startup-removal.py') and fault['lifecycle_source_sha256']==sha(R/'c80_wifi_lifecycle.sh')
assert proof('decompressor-result.json')['zimage_sha256']==sha(R/'c80-openwrt-ram39-gtk-init-zImage')
h=json.loads((R/'evidence/handoff-verification.json').read_text());assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert proof('restart-result.json')['Linux_vmlinux_sha256']==sha(R/'build/vmlinux')
layouts={}
for mode in ['build','build-qemu']:
    b=(R/mode/'vmlinux').read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
    seg=[struct.unpack_from('<8I',b,h[5]+i*h[9]) for i in range(h[10])];seg=[p for p in seg if p[0]==1]
    low=min(p[3] for p in seg);end=max(p[3]-low+0x40200000+p[5] for p in seg)
    assert h[4]-low+0x40200000==0x40208000 and end<0x40d00000,(mode,hex(end))
    layouts[mode]={'entry':'40208000','high_end':f'{end:08x}','auth_initrd_start':'40d00000'}
nm=R.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm';env=dict(os.environ)
env['LD_LIBRARY_PATH']=str(R.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
symbols=subprocess.check_output([str(nm),'-n',str(R/'build/vmlinux')],text=True,env=env)
assert 'c80_selftest_' not in symbols and 'c80_report_lock_selftest' not in symbols
kernel=(R/'c80-openwrt-ram39-gtk-init-zImage').read_bytes()
assert kernel==(R/'build/arch/arm/boot/zImage').read_bytes() and struct.unpack_from('<III',kernel,0x24)==(0x016f2818,0,len(kernel))
assert (R/'c80-openwrt-ram39-gtk-init.dtb').read_bytes()==(R/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
load=[];lines=['C80SCRIPT1','# RAM39 first-station GTK refresh; channel1 and existing personal SSH overlay.']
for address,n in [('41000000','c80-openwrt-ram39-gtk-init-zImage'),('40f00000','c80-openwrt-ram39-gtk-init.dtb'),('40e00000','c80-openwrt-ram39-handoff.bin'),('40d00000','c80-auth.cpio')]:
    p=R/n;b=p.read_bytes();crc=f'{zlib.crc32(b):08x}'
    load.append({'file':n,'address':address,'bytes':len(b),'crc32':crc,'sha256':sha(p)});lines.append(f'load {address} {n} {len(b):08x} {crc}')
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
result={'passed':True,'release':'C80 OpenWrt RAM39 first-station GTK refresh trial','kernel':'6.12.113-c80-openwrt-ram39-gtk-init','load_files':load,'layout':layouts,'changed_parent_C_header_assembly_files':changed,'unchanged_parent_C_header_assembly_files':len(inputs)-len(changed),'native_cases':3753,'new_GTK_refresh_native_cases':41,'retained_BMC_profile_native_cases':12,'retained_channel_native_cases':76,'retained_beacon_diag_native_cases':48,'native_cases_rerun':True,'OEM_ARM_builder_cases':23,'OEM_ARM_normal_BMC_cases':4,'OEM_ARM_channel_cases':6,'QEMU_WPA2_checks':43,'actual_ARM_report_callback_cases':32,'QEMU_startup_removal_checks':13,'QEMU_real_Linux_protocol_cases':13,'QEMU_memory_available_KiB':q['memory_available_KiB'],'rootfs_changed':root_changes,'full_patch_files':32,'full_source_entries_restored':86729,'rootfs_host_entries_restored':601,'signed_packages_unchanged':45,'ELF_files':66,'DMA_pool_bytes':668112,'retained_diagnostic_copy_CPU_only':True,'four_extra_MAC_snapshots_MIB_may_clear_on_read':True,'radio_channel1_retained':True,'BMC_create_body_bytes':252,'BMC_create_TLV_tags':[0,8,13],'BMC_TLV8_flags':1,'BMC_delete_body_bytes':28,'BMC_order_unchanged':True,'hostapd_and_nl80211_channel':1,'frequency_MHz':2412,'key_command_constructors_unchanged':True,'first_station_GTK_refresh_supported':True,'same_key_reinstallation_skipped':True,'GTK_refresh_requires_no_PTK_and_no_authorization':True,'GTK_delete_both_ACK_DDONE_before_install':True,'live_PTK_replacement_supported':False,'QEMU_uses_shared_key_add_policy':True,'RAM38_actual_core_refusal_reproduced':True,'legacy_default_channel6_regression_retained':True,'SSID_visibility_fix_claimed':False,'hardware_tested':False,'physical_MCU_CCMP_DMA_RF_emulated':False,'QEMU_key_backend_synthetic':True,'AP_restart_same_boot_supported':False,'new_NOR_or_UBoot_write_required':False}
for n in ['PROVENANCE.json','artifacts/artifact-verification.json','evidence/ram38-to-ram39-scope.json']:
    (R/n).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
