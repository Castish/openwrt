#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind RAM40 RX gate trial artifacts to exact sources and fresh checks."""
from pathlib import Path
import difflib,gzip,hashlib,json,os,re,shutil,struct,subprocess,zlib
from cpio_tools import entries,compare_qemu
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram39-gtk-init'
assert not (R/'c80-openwrt-ram40-rx-status.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def proof(name):
 j=json.loads((R/'evidence'/name).read_text());assert j['passed'],name;return j
parent=json.loads((P/'package-manifest.json').read_text())['files']
assert len(parent)==260
for row in parent:
 assert sha(P/row['file'])==row['sha256'] and (P/row['file']).stat().st_size==row['bytes'],row['file']
assert sha(P/'c80-openwrt-ram39-gtk-init.zip')=='9389077729a0970d32b940e60f37e9a194a5e213d119aab195d6503f8735a22c'
production=[p.name for p in P.glob('c80_*') if p.suffix in {'.c','.h'}]
changed=sorted(n for n in production if sha(R/n)!=sha(P/n))
assert changed==['c80_mcu_core.h','c80_mcu_transport.c'],changed
for n in ['c80_security_types.h','c80_security_core.h','c80_security_parse.h',
          'c80_key_linux.h','c80_session_core.h','c80_net_core.h','c80_radio.h']:
 assert sha(R/n)==sha(P/n),n
native=proof('native-summary.json');assert native['cases_passed']==3871 and native['all_suites_rerun']
for n,h in native['sources'].items():assert sha(R/n)==h,n
for n,h in native['logs'].items():assert sha(R/('verification-'+n+'.log'))==h,n
rx=proof('management-status-result.json');assert rx['cases_passed']==118 and rx['old_RAM39_actual_gate_refusal_reproduced']
for name in ['management-status-result.json','cfg-control-result.json','session-result.json','security-result.json',
             'beacon-diag-result.json','channel-result.json','bmc-profile-result.json','gtk-refresh-result.json']:
 for n,h in proof(name)['sources'].items():assert sha(R/n)==h,(name,n)
assert proof('gtk-refresh-result.json')['cases_passed']==41
q=proof('qemu-wpa2-result.json');stop=proof('qemu-startup-removal-result.json')
assert q['cases_passed']==48 and q['real_Linux_protocol_cases']==13
assert q['strict_pinned_SSH_password_cases']==1 and q['shared_key_add_policy']
for name in ['actual-helper-accepts-exact-physical-kernel-release','actual-helper-rejects-wrong-suffix',
             'actual-helper-rejects-QEMU-version-before-worker','actual-ARM-report-lock-and-snapshot-callbacks']:
 assert name in q['cases'],name
assert q['verification_source_sha256']==sha(R/'verify-qemu-wpa2.py')
assert q['hostapd_sha256']==sha(R/'rootfs/usr/sbin/hostapd')==sha(P/'rootfs/usr/sbin/hostapd')
assert q['kernel_sha256']==stop['kernel_sha256']==sha(R/'build-qemu/arch/arm/boot/zImage')
assert stop['commands_passed']==13 and stop['actual_shared_helper_rejected_false_success']
assert stop['verification_source_sha256']==sha(R/'verify-qemu-startup-removal.py')
assert stop['lifecycle_source_sha256']==sha(R/'c80_wifi_lifecycle.sh')==sha(P/'c80_wifi_lifecycle.sh')
release=(R/'build/include/config/kernel.release').read_text().strip()
assert release=='6.12.113-c80-openwrt-ram40-rx-status'
helper=(R/'rootfs/usr/sbin/c80-wifi').read_text()
expected=helper.split('[ "$(uname -r)" = ',1)[1].split(' ]',1)[0].strip("'")
assert expected==release,(expected,release)
assert 'beacon_diag security session mgmt status scheduler' in helper
subprocess.run(['sh','-n',str(R/'rootfs/usr/sbin/c80-wifi')],check=True)
raw=(R/'build/usr/initramfs_data.cpio').read_bytes();cp=entries(raw)
base=entries(gzip.decompress((P/'rootfs.cpio.gz').read_bytes()))
assert gzip.decompress((R/'rootfs.cpio.gz').read_bytes())==raw
assert cp.keys()==base.keys()
root_changes=sorted(n for n in cp if cp[n]!=base[n])
assert root_changes==['etc/c80-hostapd.conf','usr/sbin/c80-wifi'],root_changes
assert cp['usr/sbin/c80-wifi'][5]==helper.encode() and cp['usr/sbin/c80-wifi'][0]&0o777==0o755
assert cp['usr/sbin/c80-wifi'][1:3]==(0,0)
assert compare_qemu(raw,(R/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(R/'artifacts/c80-net-selftest').read_bytes())==len(cp)
assert 'ssid=C80-RAM40\n' in cp['etc/c80-hostapd.conf'][5].decode()
assert 'channel=1\n' in cp['etc/c80-hostapd.conf'][5].decode()
assert proof('rootfs-restore-result.json')['entries_compared']==601
assert proof('rootfs-scope.json')['kernel_CPIO_entries']==607
assert proof('rootfs-recovery-result.json')['cases_passed']==3
elf=json.loads((R/'evidence/rootfs-elf-closure.json').read_text());assert len(elf)==66
for row in elf:assert sha(R/'rootfs'/row['path'])==row['sha256']
for n in ['packages.lock','openwrt-packages.json','FIRMWARE-SOURCES.json']:
 assert sha(R/n)==sha(P/n),n
assert len(json.loads((R/'openwrt-packages.json').read_text()))==45
source=proof('source-restore-result.json');assert source['full_source_entries_compared']==86729
assert source['patch_sha256']==sha(R/'linux-mt7626-bringup.patch')
assert source['verification_source_sha256']==sha(R/'restore-source.py')
for n in production:
 target=R/'linux-6.12.113/drivers/soc/mediatek'/n
 if target.exists():assert sha(target)==sha(R/n),n
assert sha(R/'c80-auth.cpio')==sha(P/'c80-auth.cpio')=='e97b79c9bf15089bbdd0f9a564698f63f61f7afc4ab1a135aaa6fd11a8f2e5b5'
assert sha(R/'c80-openwrt-ram40-handoff.bin')==sha(P/'c80-openwrt-ram39-handoff.bin')
assert proof('decompressor-result.json')['zimage_sha256']==sha(R/'c80-openwrt-ram40-rx-status-zImage')
h=json.loads((R/'evidence/handoff-verification.json').read_text());assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert proof('restart-result.json')['Linux_vmlinux_sha256']==sha(R/'build/vmlinux')
layouts={}
for mode in ['build','build-qemu']:
 cfg=(R/mode/'.config').read_text();suffix='rx-status' if mode=='build' else 'qemu-check'
 assert f'CONFIG_LOCALVERSION="-c80-openwrt-ram40-{suffix}"' in cfg
 assert ('CONFIG_C80_NET_SELFTEST=y' in cfg)==(mode=='build-qemu')
 if mode=='build':
  for n in ['SMP','MAC80211','VFP','NEON','MODULES','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
   assert f'CONFIG_{n}=y\n' not in cfg,n
 b=(R/mode/'vmlinux').read_bytes();head=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 seg=[struct.unpack_from('<8I',b,head[5]+i*head[9]) for i in range(head[10])];seg=[p for p in seg if p[0]==1]
 low=min(p[3] for p in seg);end=max(p[3]-low+0x40200000+p[5] for p in seg)
 assert head[4]-low+0x40200000==0x40208000 and end<0x40d00000,(mode,hex(end))
 layouts[mode]={'entry':'40208000','high_end':f'{end:08x}','auth_initrd_start':'40d00000'}
 shutil.copy2(R/mode/'.config',R/'artifacts'/('kernel.config' if mode=='build' else 'qemu-kernel.config'))
env=dict(os.environ);env['LD_LIBRARY_PATH']=str(R.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')
nm=subprocess.check_output([str(R.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm'),'-n',str(R/'build/vmlinux')],env=env,text=True)
assert 'c80_selftest_' not in nm and 'c80_report_lock_selftest' not in nm
kernel=(R/'c80-openwrt-ram40-rx-status-zImage').read_bytes()
assert kernel==(R/'build/arch/arm/boot/zImage').read_bytes()
assert struct.unpack_from('<III',kernel,0x24)==(0x016f2818,0,len(kernel))
assert (R/'c80-openwrt-ram40-rx-status.dtb').read_bytes()==(R/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
patch=[]
for n in ['verify-management-status.c','verify-management-status.sh']:
 patch.extend(difflib.unified_diff([], (R/n).read_text().splitlines(True),fromfile='/dev/null',tofile='b/'+n))
for n in changed:
 patch.extend(difflib.unified_diff((P/n).read_text().splitlines(True),(R/n).read_text().splitlines(True),fromfile='a/'+n,tofile='b/'+n))
for n in root_changes:
 patch.extend(difflib.unified_diff(base[n][5].decode().splitlines(True),cp[n][5].decode().splitlines(True),fromfile='a/rootfs/'+n,tofile='b/rootfs/'+n))
(R/'ram39-to-ram40.patch').write_text(''.join(patch))
loads=[];lines=['C80SCRIPT1','# RAM40 current-peer plaintext management RX status trial.']
for addr,n in [('41000000','c80-openwrt-ram40-rx-status-zImage'),('40f00000','c80-openwrt-ram40-rx-status.dtb'),('40e00000','c80-openwrt-ram40-handoff.bin'),('40d00000','c80-auth.cpio')]:
 b=(R/n).read_bytes();crc=f'{zlib.crc32(b):08x}'
 loads.append({'address':addr,'file':n,'bytes':len(b),'crc32':crc,'sha256':sha(R/n)})
 lines.append(f'load {addr} {n} {len(b):08x} {crc}')
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
result={'passed':True,'release':'C80 OpenWrt RAM40 current-peer plaintext management RX status trial',
 'kernel':release,'load_files':loads,'layout':layouts,'changed_production_sources':changed,
 'native_cases':3871,'all_native_suites_rerun':True,'new_RX_status_cases':118,
 'old_RAM39_actual_gate_refusal_reproduced':True,'physical_failed_frame_RXD_flags_known':False,
 'exception_requires_live_current_peer_WPA2_PTK':True,'exception_only_plaintext_lifecycle_management':True,
 'FCS_ICV_MIC_length_translation_errors_not_waived':True,'encrypted_data_key_PN_policy_unchanged':True,
 'initial_GTK_refresh_unchanged':True,'RX_gate_saved_scalar_metadata_no_keys_addresses_packets':True,
 'QEMU_WPA2_checks':48,'QEMU_actual_helper_guard_checks':5,'actual_ARM_report_callback_cases':32,
 'QEMU_startup_removal_checks':13,'QEMU_real_Linux_protocol_cases':13,
 'QEMU_memory_available_KiB':q['memory_available_KiB'],'helper_expected_release_matches_actual_kernel':True,
 'rootfs_changed':root_changes,'full_patch_files':32,'full_source_entries_restored':86729,
 'signed_packages_unchanged':45,'ELF_files':66,'DMA_pool_bytes':668112,
 'parent_OEM_ARM_builder_cases_inherited_not_rerun':23,'OEM_key_BMC_channel_packet_constructors_unchanged':True,
 'hostapd_channel':1,'frequency_MHz':2412,'AP_restart_same_boot_supported':False,
 'new_NOR_or_UBoot_write_required':False,'hardware_tested':False,
 'QEMU_MCU_DMA_CCMP_RF_emulated':False,'SSID_visibility_fix_claimed':False}
for n in ['PROVENANCE.json','artifacts/artifact-verification.json','evidence/ram39-to-ram40-scope.json']:
 (R/n).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
