#!/usr/bin/env python3
"""Bind RAM35 userspace startup fix to frozen RAM34 and new lifecycle checks.
The C/header/assembly and complete Linux patch are unchanged. Native/ARM cases
are inherited by exact input comparison; QEMU integration is freshly executed.
"""
from pathlib import Path
import difflib,gzip,hashlib,json,os,re,shutil,struct,subprocess,zlib
from cpio_tools import entries,compare_qemu
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram34-wpa2'
assert not (R/'c80-openwrt-ram35-netup.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def proof(name):
 j=json.loads((R/'evidence'/name).read_text());assert j['passed'],name;return j
parent=json.loads((P/'package-manifest.json').read_text())['files'];assert len(parent)==215
for row in parent:
 p=P/row['file'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['file']
assert sha(P/'c80-openwrt-ram34-wpa2.zip')=='9dfb2142b640e7b07498923032e6093063ccf3178af630bf671f119aac7fdcd4'
assert sha(R/'c80-auth.cpio')==sha(P/'c80-auth.cpio')=='e97b79c9bf15089bbdd0f9a564698f63f61f7afc4ab1a135aaa6fd11a8f2e5b5'
assert (R/'c80-openwrt-ram35-handoff.bin').read_bytes()==(P/'c80-openwrt-ram34-handoff.bin').read_bytes()
unchanged=proof('unchanged-native-inputs.json');assert unchanged['source_files_compared']==32 and unchanged['parent_native_passed']==3576
for n,h in unchanged['files'].items():assert sha(R/n)==sha(P/n)==h,n
assert (R/'linux-mt7626-bringup.patch').read_bytes()==(P/'linux-mt7626-bringup.patch').read_bytes()
source=proof('source-restore-result.json');assert source['full_source_entries_compared']==86728 and source['patch_sha256']==sha(R/'linux-mt7626-bringup.patch')
for mode in ['build','build-qemu']:
 cfg=(R/mode/'.config').read_text();assert ('CONFIG_LOCALVERSION="-c80-openwrt-ram35-'+('netup' if mode=='build' else 'qemu-check')+'"') in cfg
 assert ('CONFIG_C80_NET_SELFTEST=y' in cfg)==(mode=='build-qemu')
shutil.copy2(R/'build/.config',R/'artifacts/kernel.config');shutil.copy2(R/'build-qemu/.config',R/'artifacts/qemu-kernel.config')
for n in ['SMP','MAC80211','VFP','NEON','MODULES','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
 assert f'CONFIG_{n}=y\n' not in (R/'build/.config').read_text(),n
native=proof('native-summary.json');assert native['cases_passed']==3576
for n,h in native['sources'].items():assert sha(R/n)==sha(P/n)==h,n
for name in ['cfg-control-result.json','session-result.json','security-result.json']:
 j=proof(name)
 for n,h in j['sources'].items():assert sha(R/n)==sha(P/n)==h,n
raw=(R/'build/usr/initramfs_data.cpio').read_bytes();cp=entries(raw);base=entries((P/'build/usr/initramfs_data.cpio').read_bytes())
assert gzip.decompress((R/'rootfs.cpio.gz').read_bytes())==raw
assert compare_qemu(raw,(R/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(R/'artifacts/c80-net-selftest').read_bytes())==len(cp)
added=sorted(cp.keys()-base.keys());removed=sorted(base.keys()-cp.keys());changed=sorted(n for n in cp.keys()&base.keys() if cp[n]!=base[n])
assert added==['usr/libexec/c80-wifi-lifecycle.sh'] and not removed and changed==['etc/c80-hostapd.conf','usr/sbin/c80-wifi'],(added,removed,changed)
assert cp['usr/libexec/c80-wifi-lifecycle.sh'][5]==(R/'c80_wifi_lifecycle.sh').read_bytes()
assert cp['usr/sbin/c80-wifi'][5]==(R/'rootfs/usr/sbin/c80-wifi').read_bytes()
assert not list((R/'rootfs/etc/dropbear').glob('*')) and 'usr/sbin/c80-net-selftest' not in cp
rootfs=proof('rootfs-restore-result.json');assert rootfs['entries_compared']==601;proof('rootfs-scope.json');proof('rootfs-recovery-result.json')
for n in ['openwrt-packages.json','packages.lock','FIRMWARE-SOURCES.json']:
 assert (R/n).read_bytes()==(P/n).read_bytes(),n
assert len(json.loads((R/'openwrt-packages.json').read_text()))==45 and len(json.loads((R/'evidence/rootfs-elf-closure.json').read_text()))==66
patch=[]
for name in added+changed:
 a=base[name][5].decode() if name in base else '';b=cp[name][5].decode();patch.extend(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='a/'+name if a else '/dev/null',tofile='b/'+name))
(R/'ram34-to-ram35-rootfs.patch').write_text(''.join(patch))
if (R/'ram33-to-ram34.patch').exists():(R/'ram33-to-ram34.patch').unlink()
q=proof('qemu-wpa2-result.json');fault=proof('qemu-startup-removal-result.json')
assert q['cases_passed']==36 and q['real_Linux_protocol_cases']==13 and q['strict_pinned_SSH_password_cases']==1
assert q['verification_source_sha256']==sha(R/'verify-qemu-wpa2.py') and q['hostapd_sha256']==sha(R/'rootfs/usr/sbin/hostapd')
assert q['kernel_sha256']==fault['kernel_sha256']==sha(R/'build-qemu/arch/arm/boot/zImage')
assert fault['commands_passed']==13 and fault['actual_shared_helper_rejected_false_success'] and not fault['hardware_ifup_timing_reproduced']
assert fault['verification_source_sha256']==sha(R/'verify-qemu-startup-removal.py') and fault['lifecycle_source_sha256']==sha(R/'c80_wifi_lifecycle.sh')
assert proof('decompressor-result.json')['zimage_sha256']==sha(R/'c80-openwrt-ram35-netup-zImage')
handoff=json.loads((R/'evidence/handoff-verification.json').read_text());assert len(handoff['cases'])==5 and all(x['status']=='pass' for x in handoff['cases'])
assert proof('restart-result.json')['Linux_vmlinux_sha256']==sha(R/'build/vmlinux')
layouts={}
for name in ['build','build-qemu']:
 b=(R/name/'vmlinux').read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b);seg=[struct.unpack_from('<8I',b,h[5]+i*h[9]) for i in range(h[10])];seg=[p for p in seg if p[0]==1];low=min(p[3] for p in seg);end=max(p[3]-low+0x40200000+p[5] for p in seg)
 assert h[4]-low+0x40200000==0x40208000 and end<0x40d00000,(name,hex(end));layouts[name]={'entry':'40208000','high_end':f'{end:08x}','auth_initrd_start':'40d00000'}
nm=R.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm';env=dict(os.environ);env['LD_LIBRARY_PATH']=str(R.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
symbols=subprocess.check_output([str(nm),'-n',str(R/'build/vmlinux')],text=True,env=env);assert 'c80_selftest_' not in symbols
kernel=(R/'c80-openwrt-ram35-netup-zImage').read_bytes();assert kernel==(R/'build/arch/arm/boot/zImage').read_bytes() and struct.unpack_from('<III',kernel,0x24)==(0x016f2818,0,len(kernel))
dtb=R/'c80-openwrt-ram35-netup.dtb';assert dtb.read_bytes()==(R/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
load=[];lines=['C80SCRIPT1','# RAM35 userspace startup fix; unchanged WPA2 transport and personal SSH overlay.']
for address,n in [('41000000','c80-openwrt-ram35-netup-zImage'),('40f00000','c80-openwrt-ram35-netup.dtb'),('40e00000','c80-openwrt-ram35-handoff.bin'),('40d00000','c80-auth.cpio')]:
 f=R/n;b=f.read_bytes();crc=f'{zlib.crc32(b):08x}';load.append({'file':n,'address':address,'bytes':len(b),'crc32':crc,'sha256':sha(f)});lines.append(f'load {address} {n} {len(b):08x} {crc}')
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
result={'passed':True,'release':'C80 OpenWrt RAM35 AP startup fix','kernel':'6.12.113-c80-openwrt-ram35-netup','load_files':load,'layout':layouts,'C_header_assembly_inputs_unchanged':32,'Linux_patch_unchanged':True,'inherited_native_cases':3576,'native_cases_rerun':False,'inherited_OEM_ARM_cases':13,'QEMU_WPA2_checks':36,'QEMU_startup_removal_checks':13,'QEMU_real_Linux_protocol_cases':13,'QEMU_memory_available_KiB':q['memory_available_KiB'],'rootfs_changed':changed,'rootfs_added':added,'full_patch_files':31,'full_source_entries_restored':86728,'rootfs_host_entries_restored':601,'signed_packages':45,'ELF_files':66,'DMA_pool_bytes':668112,'hardware_tested':False,'physical_CCMP_and_visibility_confirmed':False,'QEMU_key_backend_synthetic':True,'AP_restart_same_boot_supported':False,'new_NOR_or_UBoot_write_required':False}
for n in ['PROVENANCE.json','artifacts/artifact-verification.json','evidence/ram34-to-ram35-scope.json']:(R/n).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
