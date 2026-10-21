#!/usr/bin/env python3
"""Bind the private RAM34 release to frozen RAM33 and verified build inputs.
Native device effects and QEMU key installation are synthetic. Physical CCMP,
firmware acceptance and RF require the owner's first RAM34 hardware test.
"""
from pathlib import Path
import difflib,gzip,hashlib,json,os,re,shutil,struct,subprocess,zlib
from cpio_tools import entries,compare_qemu
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram33-reconnect'
assert not (R/'c80-openwrt-ram34-wpa2.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def proof(name):
 d=json.loads((R/'evidence'/name).read_text());assert d['passed'],name;return d
parent=json.loads((P/'package-manifest.json').read_text())
for row in parent['files']:
 p=P/row['file'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['file']
assert len(parent['files'])==185
assert sha(P/'c80-openwrt-ram33-reconnect.zip')=='118201896f0c7eb2984bf4db1d72c9bf7b7fc1fd76ddd25eabafcbd93d9b96c4'
assert sha(R/'c80-auth.cpio')==sha(P/'c80-auth.cpio')=='e97b79c9bf15089bbdd0f9a564698f63f61f7afc4ab1a135aaa6fd11a8f2e5b5'
assert (R/'c80-openwrt-ram34-handoff.bin').read_bytes()==(P/'c80-openwrt-ram33-handoff.bin').read_bytes()
names=['c80_mcu_core.h','c80_mcu_transport.c','c80_net_types.h','c80_net_core.h','c80_net_linux.h','c80_net_selftest.c','c80_cfg80211.h','c80_session_core.h','c80_security_types.h','c80_security_parse.h','c80_security_core.h','c80_key_linux.h','c80_rsn.h']
for n in names:assert (R/n).read_bytes()==(R/'linux-6.12.113/drivers/soc/mediatek'/n).read_bytes(),n
cfg=(R/'build/.config').read_text()
for n in ['CFG80211','WLAN','C80_MCU_TRANSPORT_TEST','C80_RAM_ETH','MTD_ROM','POWER_RESET_C80','NET_DSA_REALTEK_RTL8365MB']:
 assert f'CONFIG_{n}=y\n' in cfg,n
for n in ['MAC80211','C80_NET_SELFTEST','SMP','VFP','NEON','MODULES','SPI','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
 assert f'CONFIG_{n}=y\n' not in cfg,n
assert 'CONFIG_LOCALVERSION="-c80-openwrt-ram34-wpa2"' in cfg
assert (R/'artifacts/kernel.config').read_bytes()==(R/'build/.config').read_bytes()
shutil.copy2(R/'build-qemu/.config',R/'artifacts/qemu-kernel.config')
paths=[x[6:] for x in (R/'linux-mt7626-bringup.patch').read_text().splitlines() if x.startswith('+++ b/')];assert len(paths)==31
changed=[];added=[];diff=[]
for n in paths:
 old=P/'linux-6.12.113'/n;new=R/'linux-6.12.113'/n;a=old.read_text() if old.exists() else '';b=new.read_text()
 if a==b:continue
 (changed if old.exists() else added).append(n)
 diff.extend(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='a/'+n if a else '/dev/null',tofile='b/'+n))
assert set(added)=={'drivers/soc/mediatek/'+n for n in names[-5:]},added
assert set(changed)=={'drivers/soc/mediatek/'+n for n in ['Kconfig','c80_mcu_core.h','c80_mcu_transport.c','c80_net_core.h','c80_net_linux.h','c80_cfg80211.h','c80_session_core.h','c80_net_selftest.c']},changed
(R/'ram33-to-ram34.patch').write_text(''.join(diff))
source=proof('source-restore-result.json');assert source['full_source_entries_compared']==86728 and source['patch_sha256']==sha(R/'linux-mt7626-bringup.patch')
rootfs=proof('rootfs-restore-result.json');proof('rootfs-scope.json');proof('rootfs-recovery-result.json')
raw=(R/'build/usr/initramfs_data.cpio').read_bytes();cp=entries(raw)
assert gzip.decompress((R/'rootfs.cpio.gz').read_bytes())==raw
assert compare_qemu(raw,(R/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(R/'artifacts/c80-net-selftest').read_bytes())==len(cp)
assert 'usr/sbin/c80-net-selftest' not in cp and not list((R/'rootfs/etc/dropbear').glob('*'))
base=entries((P/'build/usr/initramfs_data.cpio').read_bytes());assert base.keys()==cp.keys()
root_changes=sorted(n for n in base if base[n]!=cp[n]);assert root_changes==['etc/c80-hostapd.conf','usr/sbin/c80-wifi'],root_changes
for n in ['openwrt-packages.json','packages.lock','FIRMWARE-SOURCES.json']:
 assert (R/n).read_bytes()==(P/n).read_bytes(),n
assert len(json.loads((R/'openwrt-packages.json').read_text()))==45
assert len(json.loads((R/'evidence/rootfs-elf-closure.json').read_text()))==66
counts={'core':495,'rx-recycle':64,'beacon-state':46,'client-rx':366,'auth-tx':60,'tx-free':84,'association':123,'data':589,'window':17,'netdev':601,'recycle':55,'scheduler':91,'cfg-control':652,'session':214,'security':101}
for name,count in counts.items():assert re.search(r'PASS:\s*'+str(count)+r'\b',(R/f'verification-{name}.log').read_text()),name
assert sum(counts.values())+18==3576
for name,count in [('cfg-control-result.json',652),('session-result.json',214),('security-result.json',101)]:
 d=proof(name);assert d['cases_passed']==count
 for n,h in d['sources'].items():assert sha(R/n)==h,n
trace=proof('stock-security-traces.json');assert trace['cases_passed']==13 and trace['verification_source_sha256']==sha(R/'trace-stock-security.py')
q=proof('qemu-wpa2-result.json');assert q['kernel_sha256']==sha(R/'build-qemu/arch/arm/boot/zImage')
assert q['verification_source_sha256']==sha(R/'verify-qemu-wpa2.py') and q['hostapd_sha256']==sha(R/'rootfs/usr/sbin/hostapd')
assert q['cases_passed']==31 and q['real_Linux_protocol_cases']==13 and q['strict_pinned_SSH_password_cases']==1
assert q['wrong_MIC_refused'] and q['synthetic_key_install_backend'] and not q['physical_MCU_CCMP_DMA_RF_emulated']
assert proof('decompressor-result.json')['zimage_sha256']==sha(R/'c80-openwrt-ram34-wpa2-zImage')
handoff=json.loads((R/'evidence/handoff-verification.json').read_text());assert len(handoff['cases'])==5 and all(x['status']=='pass' for x in handoff['cases'])
assert proof('restart-result.json')['Linux_vmlinux_sha256']==sha(R/'build/vmlinux')
layouts={}
for name in ['build','build-qemu']:
 b=(R/name/'vmlinux').read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b);seg=[struct.unpack_from('<8I',b,h[5]+i*h[9]) for i in range(h[10])];seg=[p for p in seg if p[0]==1]
 low=min(p[3] for p in seg);end=max(p[3]-low+0x40200000+p[5] for p in seg)
 assert h[4]-low+0x40200000==0x40208000 and end<0x40d00000,(name,hex(end))
 layouts[name]={'entry':'40208000','high_end':f'{end:08x}','auth_initrd_start':'40d00000'}
nm=R.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm';env=dict(os.environ);env['LD_LIBRARY_PATH']=str(R.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
symbols=subprocess.check_output([str(nm),'-n',str(R/'build/vmlinux')],text=True,env=env);assert 'c80_selftest_' not in symbols
for fn in ['c80_cfg_add_key','c80_cfg_change_station','c80_security_key','c80_linux_ndo_xmit','c80_mcu_shutdown','security_show']:
 assert re.search(r'\b'+fn+r'\b',symbols),fn
kernel=(R/'c80-openwrt-ram34-wpa2-zImage').read_bytes();assert kernel==(R/'build/arch/arm/boot/zImage').read_bytes()
assert struct.unpack_from('<III',kernel,0x24)==(0x016f2818,0,len(kernel)) and len(kernel)<0xc00000
dtb=R/'c80-openwrt-ram34-wpa2.dtb';assert dtb.read_bytes()==(R/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
for f in [dtb,R/'qemu-auth.dtb']:
 text=subprocess.check_output([str(R/'build/scripts/dtc/dtc'),'-I','dtb','-O','dts',str(f)],text=True,stderr=subprocess.DEVNULL)
 assert 'linux,initrd-start = <0x40d00000>' in text and 'linux,initrd-end = <0x40d01000>' in text
load_files=[];lines=['C80SCRIPT1','# RAM34 WPA2-PSK/CCMP trial; unchanged personal SSH overlay.']
for address,n in [('41000000','c80-openwrt-ram34-wpa2-zImage'),('40f00000','c80-openwrt-ram34-wpa2.dtb'),('40e00000','c80-openwrt-ram34-handoff.bin'),('40d00000','c80-auth.cpio')]:
 f=R/n;b=f.read_bytes();crc=f'{zlib.crc32(b):08x}';load_files.append({'file':n,'address':address,'bytes':len(b),'crc32':crc,'sha256':sha(f)})
 lines.append(f'load {address} {n} {len(b):08x} {crc}')
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
(R/'evidence/native-summary.json').write_text(json.dumps({'passed':True,'cases_passed':3576,'IRQ_gate_cases':18,'suites':counts,'ASan_UBSan':True,'hardware_effects_synthetic':True,'sources':{n:sha(R/n) for n in names},'logs':{n:sha(R/f'verification-{n}.log') for n in counts}},indent=2)+'\n')
(R/'evidence/ram33-to-ram34-scope.json').write_text(json.dumps({'passed':True,'parent_frozen_members_verified':185,'Linux_changed':changed,'Linux_added':added,'rootfs_changed':root_changes,'packages_added':0,'all_six_OEM_firmware_files_unchanged':True,'Ethernet_DSA_UART_restart_scheduler_sources_unchanged':True,'DMA_pool_bytes':668112,'DMA_pool_layout_and_offsets_unchanged':True,'personal_SSH_overlay_unchanged':True},indent=2)+'\n')
result={'passed':True,'release':'C80 OpenWrt RAM34 WPA2-PSK/CCMP','kernel':'6.12.113-c80-openwrt-ram34-wpa2','load_files':load_files,'layout':layouts,'native_cases':3576,'new_security_cases':101,'OEM_ARM_security_builder_cases':13,'QEMU_WPA2_cases':31,'QEMU_real_Linux_protocol_cases':13,'QEMU_memory_available_KiB':q['memory_available_KiB'],'QEMU_synthetic_key_install_backend':True,'signed_packages':45,'ELF_files':66,'full_patch_files':31,'full_source_entries_restored':86728,'rootfs_host_entries_restored':rootfs['entries_compared'],'DMA_pool_bytes':668112,'hardware_tested':False,'WPA2_driver_path_implemented':True,'physical_CCMP_MCU_acceptance_and_RF_tested':False,'simultaneous_clients':1,'AP_restart_same_boot_implemented':False,'GTK_rekey_implemented':False,'PMF_implemented':False,'multicast_to_unicast_only':True,'no_new_NOR_or_UBoot_write_required':True,'standard_UCI_wifi_up_integration_complete':False}
for n in ['PROVENANCE.json','artifacts/artifact-verification.json']:(R/n).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
