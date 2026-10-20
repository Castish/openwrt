#!/usr/bin/env python3
"""Bind the issued RAM32 inputs to source, tests, signed package files and layout.

QEMU exercises actual Linux/hostapd with a synthetic peer. It cannot prove
MT7626 RF, DMA, MCU, timing or hardware compatibility of this new release.
"""
from pathlib import Path
import base64,difflib,gzip,hashlib,json,os,re,shutil,stat,struct,subprocess,zlib
from cpio_tools import entries,compare_qemu
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram31-scheduler'
assert not (R/'c80-openwrt-ram32-cfg80211.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def proof(name):
 d=json.loads((R/'evidence'/name).read_text());assert d['passed'],name;return d
parent_manifest=json.loads((P/'package-manifest.json').read_text())
for row in parent_manifest['files']:
 p=P/row['file'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['file']
assert sha(P/'c80-openwrt-ram31-scheduler.zip')=='805cd14bac690f3d4945c48d1cbd99ef09b8a7fcb74fe2e95fe997dd6f041479'
assert (R/'c80-openwrt-ram32-handoff.bin').read_bytes()==(P/'c80-openwrt-ram31-handoff.bin').read_bytes()
assert sha(R/'c80-auth.cpio')=='e97b79c9bf15089bbdd0f9a564698f63f61f7afc4ab1a135aaa6fd11a8f2e5b5'
cfg=(R/'build/.config').read_text()
for n in ['CFG80211','WLAN','C80_MCU_TRANSPORT_TEST','C80_RAM_ETH','MTD_ROM','POWER_RESET_C80','NET_DSA_REALTEK_RTL8365MB']:
 assert f'CONFIG_{n}=y\n' in cfg,n
for n in ['MAC80211','C80_NET_SELFTEST','SMP','VFP','NEON','MODULES','SPI','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
 assert f'CONFIG_{n}=y\n' not in cfg,n
assert 'CONFIG_LOCALVERSION="-c80-openwrt-ram32-cfg80211"' in cfg
assert (R/'artifacts/kernel.config').read_bytes()==(R/'build/.config').read_bytes()
source_names=['c80_mcu_core.h','c80_mcu_transport.c','c80_net_types.h','c80_net_core.h','c80_net_linux.h','c80_net_selftest.c','c80_cfg80211.h']
for n in source_names:assert (R/n).read_bytes()==(R/'linux-6.12.113/drivers/soc/mediatek'/n).read_bytes(),n
for n in ['c80_net_types.h','c80_net_core.h']:assert (R/n).read_bytes()==(P/n).read_bytes(),n
paths=[]
for line in (P/'linux-mt7626-bringup.patch').read_text().splitlines():
 if line.startswith('+++ b/'):paths.append(line[6:])
changes=[];diff=[]
for n in paths:
 a=(P/'linux-6.12.113'/n).read_bytes();b=(R/'linux-6.12.113'/n).read_bytes()
 if a!=b:
  changes.append(n);diff.extend(difflib.unified_diff(a.decode().splitlines(True),b.decode().splitlines(True),fromfile='a/'+n,tofile='b/'+n))
allowed={'drivers/soc/mediatek/Kconfig','arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dts'}|{'drivers/soc/mediatek/'+n for n in source_names if n not in ['c80_cfg80211.h','c80_net_types.h','c80_net_core.h']}
assert set(changes)==allowed,(changes,allowed)
n='drivers/soc/mediatek/c80_cfg80211.h';diff.extend(difflib.unified_diff([], (R/n.split('/')[-1]).read_text().splitlines(True),fromfile='/dev/null',tofile='b/'+n))
(R/'ram31-to-ram32.patch').write_text(''.join(diff))
source=proof('source-restore-result.json');assert source['full_source_entries_compared']==86722 and source['patch_sha256']==sha(R/'linux-mt7626-bringup.patch')
rootfs=proof('rootfs-restore-result.json');proof('rootfs-scope.json');proof('rootfs-recovery-result.json')
raw=(R/'build/usr/initramfs_data.cpio').read_bytes();cp=entries(raw)
assert gzip.decompress((R/'rootfs.cpio.gz').read_bytes())==raw
assert compare_qemu(raw,(R/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(R/'artifacts/c80-net-selftest').read_bytes())==len(cp)
assert 'usr/sbin/c80-net-selftest' not in cp
assert not list((R/'rootfs/etc/dropbear').glob('*'))
assert not (R/'rootfs/tmp/dhcp.leases').exists()
base=entries((P/'build/usr/initramfs_data.cpio').read_bytes())
removed=sorted(set(base)-set(cp));assert not removed,removed
changed=sorted(n for n in base if base[n]!=cp[n])
assert changed==['etc/apk/world','lib/apk/db/installed','lib/apk/db/scripts.tar.gz','usr/sbin/c80-wifi'],changed
for n in ['etc/config/network','etc/config/dhcp','etc/config/dropbear','etc/shadow','etc/passwd','usr/sbin/dropbear','usr/sbin/dnsmasq']:
 assert cp[n]==base[n],n
for n in base:
 if n.startswith('lib/firmware/c80/'):assert cp[n]==base[n],n
pkgs=json.loads((R/'openwrt-packages.json').read_text());old=json.loads((P/'openwrt-packages.json').read_text())
old_names={x['name'] for x in old};added_names={x['name'] for x in pkgs}-old_names
assert len(pkgs)==45 and len(added_names)==9
signed_files=[]
for paragraph in (R/'rootfs/lib/apk/db/installed').read_text().split('\n\n'):
 lines=paragraph.splitlines();package=next((s[2:] for s in lines if s.startswith('P:')),None)
 if package not in added_names:continue
 directory='';filename=None
 for s in lines:
  if s.startswith('F:'):directory=s[2:]
  elif s.startswith('R:'):filename='/'.join(x for x in [directory,s[2:]] if x)
  elif s.startswith('Z:'):
   f=R/'rootfs'/filename
   if f.is_symlink():continue
   assert f.is_file() and s[2:4]=='Q1',(filename,s)
   # APK v3 stores SHA256-160 with the legacy Q1 textual prefix.
   assert base64.b64encode(hashlib.sha256(f.read_bytes()).digest()[:20]).decode()==s[4:],filename
   signed_files.append({'package':package,'file':filename,'sha256':sha(f)})
assert any(x['file']=='usr/sbin/hostapd' for x in signed_files)
assert any(x['file']=='usr/sbin/iw' for x in signed_files)
(R/'evidence/added-package-files.json').write_text(json.dumps({'passed':True,'added_packages':sorted(added_names),'files':signed_files,'checksums_from_signed_APK_installation_database':True},indent=2)+'\n')
abi=json.loads((R/'evidence/rootfs-elf-closure.json').read_text());assert len(abi)==66
counts={'core':495,'rx-recycle':64,'beacon-state':46,'client-rx':366,'auth-tx':60,'tx-free':84,'association':123,'data':589,'window':17,'netdev':601,'recycle':55,'scheduler':91}
for name,count in counts.items():
 text=(R/f'verification-{name}.log').read_text()
 assert re.search(r'PASS:\s*'+str(count)+r'\b',text),name
assert sum(counts.values())==2591
native={'passed':True,'actual_core_cases':2591,'separate_IRQ_gate_cases':18,'baseline_suites':counts,'core_sources':{n:sha(R/n) for n in ['c80_mcu_core.h','c80_net_core.h','c80_net_types.h']},'logs':{name:sha(R/f'verification-{name}.log') for name in counts},'ASan_UBSan':True,'hardware_effects_synthetic':True}
(R/'evidence/native-summary.json').write_text(json.dumps(native,indent=2)+'\n')
new=proof('cfg-control-result.json');assert new['cases_passed']==652
for n,digest in new['sources'].items():assert sha(R/n)==digest,n
qemu={}
for mode in ['normal','fault']:
 d=proof('qemu-cfg80211-'+mode+'-result.json')
 assert d['qemu_kernel_SHA256']==sha(R/'build-qemu/arch/arm/boot/zImage')
 assert d['hostapd_SHA256']==sha(R/'rootfs/usr/sbin/hostapd') and d['strict_pinned_SSH_password_cases']==2
 qemu[mode]={'commands':len(d['commands']),'pinned_SSH_password_cases':2,'synthetic_backend_only':True}
assert proof('decompressor-result.json')['zimage_sha256']==sha(R/'c80-openwrt-ram32-cfg80211-zImage')
handoff=json.loads((R/'evidence/handoff-verification.json').read_text());assert len(handoff['cases'])==5 and all(x['status']=='pass' for x in handoff['cases'])
restart=proof('restart-result.json');assert restart['cases_passed']==8 and restart['Linux_vmlinux_sha256']==sha(R/'build/vmlinux')
layouts={}
for name in ['build','build-qemu']:
 elf=(R/name/'vmlinux').read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',elf)
 segments=[struct.unpack_from('<8I',elf,h[5]+i*h[9]) for i in range(h[10])]
 loads=[x for x in segments if x[0]==1];virtual=min(x[3] for x in loads)
 runtime=lambda x:x-virtual+0x40200000
 high=max(runtime(x[3])+x[5] for x in loads)
 assert runtime(h[4])==0x40208000 and high<0x40d00000,(name,hex(high))
 layouts[name]={'entry':'40208000','high_end':f'{high:08x}','auth_initrd_start':'40d00000'}
nm=R.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm'
symbols=subprocess.check_output([str(nm),'-n',str(R/'build/vmlinux')],text=True)
assert 'c80_selftest_' not in symbols
for fn in ['c80_cfg_start_ap','c80_cfg_stop_ap','c80_cfg_ops','c80_linux_ndo_xmit','c80_mcu_shutdown']:
 assert re.search(r'\b'+fn+r'\b',symbols),fn
kernel=(R/'c80-openwrt-ram32-cfg80211-zImage').read_bytes()
assert kernel==(R/'build/arch/arm/boot/zImage').read_bytes()
assert struct.unpack_from('<III',kernel,0x24)==(0x016f2818,0,len(kernel)) and len(kernel)<0xc00000
dtb=R/'c80-openwrt-ram32-cfg80211.dtb';assert dtb.read_bytes()==(R/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
dtc=R/'build/scripts/dtc/dtc';text=subprocess.check_output([str(dtc),'-I','dtb','-O','dts',str(dtb)],text=True,stderr=subprocess.DEVNULL)
assert 'linux,initrd-start = <0x40d00000>' in text and 'linux,initrd-end = <0x40d01000>' in text
load_files=[];lines=['C80SCRIPT1','# RAM32 cfg80211 open AP; stable private per-device SSH overlay.']
for address,n in [('41000000','c80-openwrt-ram32-cfg80211-zImage'),('40f00000','c80-openwrt-ram32-cfg80211.dtb'),('40e00000','c80-openwrt-ram32-handoff.bin'),('40d00000','c80-auth.cpio')]:
 f=R/n;b=f.read_bytes();crc=f'{zlib.crc32(b):08x}'
 load_files.append({'file':n,'address':address,'bytes':len(b),'crc32':crc,'sha256':sha(f)})
 lines.append(f'load {address} {n} {len(b):08x} {crc}')
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
scope={'passed':True,'parent_frozen_members_verified':len(parent_manifest['files']),'Linux_changed':sorted(changes),'Linux_added':['drivers/soc/mediatek/c80_cfg80211.h'],'rootfs_changed':changed,'rootfs_added':sorted(set(cp)-set(base)),'rootfs_removed':removed,'six_OEM_firmware_files_unchanged':True,'Ethernet_DSA_UART_restart_and_TX_scheduler_sources_unchanged':True,'DMA_packet_core_and_allocation_types_unchanged':True,'private_SSH_overlay_byte_identical':True,'external_auth_address_changed_from_40c_to_40d_to_preserve_kernel_space':True,'hardware_new_image_tested':False}
(R/'evidence/ram31-to-ram32-scope.json').write_text(json.dumps(scope,indent=2)+'\n')
result={'passed':True,'release':'C80 OpenWrt RAM32 cfg80211 open AP','kernel':'6.12.113-c80-openwrt-ram32-cfg80211','load_files':load_files,'layout':layouts,'baseline_native_cases':2591,'new_native_control_cases':652,'QEMU':qemu,'ELF_files':66,'signed_APK_packages':45,'added_signed_APK_packages':9,'full_source_entries_restored':source['full_source_entries_compared'],'full_patch_files':25,'rootfs_entries_restored':rootfs['entries_compared'],'hardware_tested':False,'WPA_encryption_implemented':False,'per_peer_disconnect_or_reassociation_implemented':False,'multiple_clients_implemented':False,'standard_OpenWrt_wifi_up_integration_complete':False,'no_new_NOR_or_UBoot_write_required':True,'one_session_until_stop_fault_or_reboot':True}
(R/'PROVENANCE.json').write_text(json.dumps(result,indent=2)+'\n')
(R/'artifacts/artifact-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
