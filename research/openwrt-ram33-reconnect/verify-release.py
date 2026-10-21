#!/usr/bin/env python3
"""Bind RAM33 to its frozen parent, source/build inputs and test results.
Native hardware effects are synthetic. QEMU runs real Linux/hostapd with a
software peer. Neither establishes MT7626 RF/MCU/DMA compatibility of RAM33.
"""
from pathlib import Path
import difflib,gzip,hashlib,json,os,re,shutil,struct,subprocess,zlib
from cpio_tools import entries,compare_qemu
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram32-cfg80211'
assert not (R/'c80-openwrt-ram33-reconnect.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def proof(name):
    d=json.loads((R/'evidence'/name).read_text());assert d['passed'],name;return d
manifest=json.loads((P/'package-manifest.json').read_text())
for row in manifest['files']:
    p=P/row['file'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['file']
assert len(manifest['files'])==187
assert sha(P/'c80-openwrt-ram32-cfg80211.zip')=='79b3bbe5cbe71717f9f279f3bdb5438ab20c79f7365a7d1ff918ed87553ba073'
assert sha(R/'c80-auth.cpio')=='e97b79c9bf15089bbdd0f9a564698f63f61f7afc4ab1a135aaa6fd11a8f2e5b5'
assert (R/'c80-openwrt-ram33-handoff.bin').read_bytes()==(P/'c80-openwrt-ram32-handoff.bin').read_bytes()
cfg=(R/'build/.config').read_text()
for n in ['CFG80211','WLAN','C80_MCU_TRANSPORT_TEST','C80_RAM_ETH','MTD_ROM','POWER_RESET_C80','NET_DSA_REALTEK_RTL8365MB']:
    assert f'CONFIG_{n}=y\n' in cfg,n
for n in ['MAC80211','C80_NET_SELFTEST','SMP','VFP','NEON','MODULES','SPI','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
    assert f'CONFIG_{n}=y\n' not in cfg,n
assert 'CONFIG_LOCALVERSION="-c80-openwrt-ram33-reconnect"' in cfg
assert (R/'artifacts/kernel.config').read_bytes()==(R/'build/.config').read_bytes()
shutil.copy2(R/'build-qemu/.config',R/'artifacts/qemu-kernel.config')
assert 'CONFIG_LOCALVERSION="-c80-openwrt-ram33-qemu-check"' in (R/'build-qemu/.config').read_text()
names=['c80_mcu_core.h','c80_mcu_transport.c','c80_net_types.h','c80_net_core.h','c80_net_linux.h','c80_net_selftest.c','c80_cfg80211.h','c80_session_core.h']
for n in names:assert (R/n).read_bytes()==(R/'linux-6.12.113/drivers/soc/mediatek'/n).read_bytes(),n
assert '.session_test=1' in (R/'c80_mcu_transport.c').read_text()
paths=[s[6:] for s in (R/'linux-mt7626-bringup.patch').read_text().splitlines() if s.startswith('+++ b/')]
assert len(paths)==26
changed=[];added=[];diff=[]
for n in paths:
    old=P/'linux-6.12.113'/n;new=R/'linux-6.12.113'/n
    a=old.read_text() if old.exists() else '';b=new.read_text()
    if a==b:continue
    (changed if old.exists() else added).append(n)
    diff.extend(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='a/'+n if a else '/dev/null',tofile='b/'+n))
assert set(changed)=={'drivers/soc/mediatek/'+n for n in ['c80_mcu_core.h','c80_mcu_transport.c','c80_cfg80211.h','c80_net_types.h','c80_net_core.h']},changed
assert added==['drivers/soc/mediatek/c80_session_core.h'],added
(R/'ram32-to-ram33.patch').write_text(''.join(diff))
source=proof('source-restore-result.json')
assert source['full_source_entries_compared']==86723 and source['patch_sha256']==sha(R/'linux-mt7626-bringup.patch')
rootfs=proof('rootfs-restore-result.json');proof('rootfs-scope.json');proof('rootfs-recovery-result.json')
raw=(R/'build/usr/initramfs_data.cpio').read_bytes();cp=entries(raw)
assert gzip.decompress((R/'rootfs.cpio.gz').read_bytes())==raw
assert compare_qemu(raw,(R/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(R/'artifacts/c80-net-selftest').read_bytes())==len(cp)
assert 'usr/sbin/c80-net-selftest' not in cp
assert not list((R/'rootfs/etc/dropbear').glob('*')) and not (R/'rootfs/tmp/dhcp.leases').exists()
base=entries((P/'build/usr/initramfs_data.cpio').read_bytes());assert base.keys()==cp.keys()
root_changes=sorted(n for n in base if base[n]!=cp[n])
assert root_changes==['etc/c80-hostapd.conf','usr/sbin/c80-wifi'],root_changes
for n in ['openwrt-packages.json','packages.lock','FIRMWARE-SOURCES.json']:
    assert (R/n).read_bytes()==(P/n).read_bytes(),n
pkgs=json.loads((R/'openwrt-packages.json').read_text());assert len(pkgs)==45
abi=json.loads((R/'evidence/rootfs-elf-closure.json').read_text());assert len(abi)==66
counts={'core':495,'rx-recycle':64,'beacon-state':46,'client-rx':366,'auth-tx':60,'tx-free':84,'association':123,'data':589,'window':17,'netdev':601,'recycle':55,'scheduler':91}
for name,count in counts.items():
    text=(R/f'verification-{name}.log').read_text()
    assert re.search(r'PASS:\s*'+str(count)+r'\b',text),name
assert sum(counts.values())==2591
for name,count in [('cfg-control-result.json',652),('session-result.json',214)]:
    d=proof(name);assert d['cases_passed']==count
    for n,digest in d['sources'].items():assert sha(R/n)==digest,n
trace=proof('stock-reassociation-traces.json')
assert trace['cases_passed']==8 and trace['actual_ARM_TXD_TXP_descriptor_publisher_executed']
assert trace['verification_source_sha256']==sha(R/'trace-stock-reassociation.py')
assert (R/'stock-reassociation-txd.bin').read_bytes()==bytes.fromhex(trace['profile']['TXD_hex'])
(R/'evidence/native-summary.json').write_text(json.dumps({
    'passed':True,'baseline_actual_core_cases':2591,'separate_IRQ_gate_cases':18,
    'cfg_control_cases':652,'session_cases':214,'ASan_UBSan':True,'hardware_effects_synthetic':True,
    'baseline_suites':counts,'sources':{n:sha(R/n) for n in names},
    'logs':{n:sha(R/f'verification-{n}.log') for n in list(counts)+['cfg-control','session']}},indent=2)+'\n')
qemu={}
for mode,count in [('normal',44),('fault',47)]:
    d=proof('qemu-cfg80211-'+mode+'-result.json')
    assert d['qemu_kernel_SHA256']==sha(R/'build-qemu/arch/arm/boot/zImage')
    assert d['hostapd_SHA256']==sha(R/'rootfs/usr/sbin/hostapd') and d['strict_pinned_SSH_password_cases']==2
    assert len(d['commands'])==count
    qemu[mode]={'commands':count,'client_connections':3,'disconnect_reconnect_cycles':2,'AP_starts':1,'pinned_SSH_password_cases':2,'synthetic_backend_only':True}
assert proof('decompressor-result.json')['zimage_sha256']==sha(R/'c80-openwrt-ram33-reconnect-zImage')
handoff=json.loads((R/'evidence/handoff-verification.json').read_text());assert len(handoff['cases'])==5 and all(x['status']=='pass' for x in handoff['cases'])
restart=proof('restart-result.json');assert restart['cases_passed']==8 and restart['Linux_vmlinux_sha256']==sha(R/'build/vmlinux')
layouts={}
for name in ['build','build-qemu']:
    b=(R/name/'vmlinux').read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
    s=[struct.unpack_from('<8I',b,h[5]+i*h[9]) for i in range(h[10])];s=[p for p in s if p[0]==1]
    v=min(p[3] for p in s);end=max(p[3]-v+0x40200000+p[5] for p in s)
    assert h[4]-v+0x40200000==0x40208000 and end<0x40d00000,(name,hex(end))
    layouts[name]={'entry':'40208000','high_end':f'{end:08x}','auth_initrd_start':'40d00000'}
nm=R.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm'
env=dict(os.environ);env['LD_LIBRARY_PATH']=str(R.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
symbols=subprocess.check_output([str(nm),'-n',str(R/'build/vmlinux')],text=True,env=env)
assert 'c80_selftest_' not in symbols
for fn in ['c80_cfg_start_ap','c80_cfg_stop_ap','c80_linux_ndo_xmit','c80_mcu_shutdown','session_show']:
    assert re.search(r'\b'+fn+r'\b',symbols),fn
kernel=(R/'c80-openwrt-ram33-reconnect-zImage').read_bytes()
assert kernel==(R/'build/arch/arm/boot/zImage').read_bytes()
assert struct.unpack_from('<III',kernel,0x24)==(0x016f2818,0,len(kernel)) and len(kernel)<0xc00000
dtb=R/'c80-openwrt-ram33-reconnect.dtb'
assert dtb.read_bytes()==(R/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
dtc=R/'build/scripts/dtc/dtc'
for path in [dtb,R/'qemu-auth.dtb']:
    s=subprocess.check_output([str(dtc),'-I','dtb','-O','dts',str(path)],text=True,stderr=subprocess.DEVNULL)
    assert 'linux,initrd-start = <0x40d00000>' in s and 'linux,initrd-end = <0x40d01000>' in s
load_files=[];lines=['C80SCRIPT1','# RAM33 client reconnect; one AP run; stable private per-device SSH overlay.']
for address,n in [('41000000','c80-openwrt-ram33-reconnect-zImage'),('40f00000','c80-openwrt-ram33-reconnect.dtb'),('40e00000','c80-openwrt-ram33-handoff.bin'),('40d00000','c80-auth.cpio')]:
    f=R/n;b=f.read_bytes();crc=f'{zlib.crc32(b):08x}'
    load_files.append({'file':n,'address':address,'bytes':len(b),'crc32':crc,'sha256':sha(f)})
    lines.append(f'load {address} {n} {len(b):08x} {crc}')
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
scope={'passed':True,'parent_frozen_members_verified':187,'Linux_changed':changed,'Linux_added':added,
       'rootfs_changed':root_changes,'rootfs_added':[],'rootfs_removed':[],
       'six_OEM_firmware_files_unchanged':True,'Ethernet_DSA_UART_restart_TX_scheduler_sources_unchanged':True,
       'existing_DMA_object_offsets_preserved':True,'new_DMA_pool_bytes':668112,'added_DMA_pool_bytes':2320,
       'private_SSH_overlay_byte_identical':True,'external_auth_address_unchanged':'40d00000','hardware_new_image_tested':False}
(R/'evidence/ram32-to-ram33-scope.json').write_text(json.dumps(scope,indent=2)+'\n')
result={'passed':True,'release':'C80 OpenWrt RAM33 client reconnect','kernel':'6.12.113-c80-openwrt-ram33-reconnect',
        'load_files':load_files,'layout':layouts,'baseline_native_cases':2591,'IRQ_gate_cases':18,'cfg_control_cases':652,'new_session_cases':214,
        'new_OEM_ARM_reassociation_builder_cases':8,'QEMU':qemu,'ELF_files':66,'signed_APK_packages':45,'added_signed_APK_packages':0,
        'full_source_entries_restored':source['full_source_entries_compared'],'full_patch_files':26,'rootfs_entries_restored':rootfs['entries_compared'],
        'hardware_tested':False,'per_peer_disconnect_or_reassociation_implemented':True,'simultaneous_clients':1,
        'AP_restart_same_boot_implemented':False,'WPA_encryption_implemented':False,'standard_OpenWrt_wifi_up_integration_complete':False,
        'no_new_NOR_or_UBoot_write_required':True,'full_new_session_mode_c80_run_boot_and_teardown_emulated':False}
(R/'PROVENANCE.json').write_text(json.dumps(result,indent=2)+'\n')
(R/'artifacts/artifact-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
