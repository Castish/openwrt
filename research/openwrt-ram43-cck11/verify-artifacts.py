#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the RAM43 CCK11 trial to fresh checks and the frozen RAM42 baseline."""
from pathlib import Path
import difflib,gzip,hashlib,json,os,re,shutil,struct,subprocess,zlib
from cpio_tools import entries,compare_qemu

R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram42-boot-timing'
assert not (R/'c80-openwrt-ram43-cck11.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def proof(name):
    value=json.loads((R/'evidence'/name).read_text())
    assert value['passed'],name
    return value
def dump(name,value):
    (R/name).write_text(json.dumps(value,indent=2)+'\n')

frozen=json.loads((P/'package-manifest.json').read_text())['files']
assert len(frozen)==261
for row in frozen:
    p=P/row['file'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['file']
assert sha(P/'c80-openwrt-ram42-boot-timing.zip')=='f616553e831236136344242345a7e45ae730ac5ed555da107657dbd3c8e9dd98'
production=sorted(p.name for p in P.glob('c80_*') if p.suffix in {'.c','.h'})
changed=sorted(n for n in production if sha(R/n)!=sha(P/n))
assert changed==['c80_mcu_core.h','c80_mcu_transport.c','c80_net_core.h','c80_net_types.h'],changed
assert (R/'c80_mcu_core.h').read_text().replace('    c80_u32 data_cck11_test; /* WPA2 ARP/IP TX only; EAPOL/management stay CCK1. */\n','')==(P/'c80_mcu_core.h').read_text()
assert (R/'c80_net_types.h').read_text().replace('    c80_u32 data_cck1_submitted,data_cck11_submitted; /* Selected TXD, not RF telemetry. */\n','')==(P/'c80_net_types.h').read_text()
assert '.wpa2_test=1,.data_cck11_test=1,' in (R/'c80_mcu_transport.c').read_text()
assert sha(R/'c80_timing.h')==sha(P/'c80_timing.h')
for name in ['c80_cfg80211.h','c80_security_core.h','c80_session_core.h']:assert sha(R/name)==sha(P/name)
native=proof('native-summary.json')
assert native['cases_passed']==3871
for name,expected in native['sources'].items():assert sha(R/name)==expected,name
for name,expected in native['logs'].items():
    assert sha(R/('verification-'+name+'.log'))==expected,name
for name in ['packages.lock','openwrt-packages.json','FIRMWARE-SOURCES.json','c80_wifi_lifecycle.sh']:
    assert sha(R/name)==sha(P/name),name
assert len(json.loads((R/'openwrt-packages.json').read_text()))==45
assert sha(R/'linux-mt7626-bringup.patch')!=sha(P/'linux-mt7626-bringup.patch')
boot=proof('boot-timing-result.json');assert boot['cases_passed']==12
for name,expected in boot['sources'].items():assert sha(R/name)==expected,name
rate=proof('data-rate-result.json');assert rate['cases_passed']==250 and rate['mixed_posts']==15000
for name,expected in rate['sources'].items():assert sha(R/name)==expected,name
oem=proof('data-rate-OEM-result.json');assert oem['cases_passed']==44
assert oem['verification_source_sha256']==sha(R/'trace-data-rate.py')
assert oem['oracle_sha256']==rate['oracle_sha256']==sha(R/'stock-data-rate-oracle.bin')
source=proof('source-restore-result.json')
assert source['full_source_entries_compared']==86730
assert source['patch_sha256']==sha(R/'linux-mt7626-bringup.patch')
assert source['verification_source_sha256']==sha(R/'restore-source.py')
for name in production:
    p=R/'linux-6.12.113/drivers/soc/mediatek'/name
    if p.exists():assert sha(p)==sha(R/name),name

q=proof('qemu-wpa2-result.json');stop=proof('qemu-startup-removal-result.json')
assert q['cases_passed']==48 and q['real_Linux_protocol_cases']==13
assert q['strict_pinned_SSH_password_cases']==1 and q['shared_key_add_policy']
assert q['verification_source_sha256']==sha(R/'verify-qemu-wpa2.py')
assert q['hostapd_sha256']==sha(R/'rootfs/usr/sbin/hostapd')==sha(P/'rootfs/usr/sbin/hostapd')
assert q['kernel_sha256']==stop['kernel_sha256']==sha(R/'build-qemu/arch/arm/boot/zImage')
assert stop['commands_passed']==13 and stop['actual_shared_helper_rejected_false_success']
assert stop['verification_source_sha256']==sha(R/'verify-qemu-startup-removal.py')
assert stop['lifecycle_source_sha256']==sha(R/'c80_wifi_lifecycle.sh')
for name in ['actual-helper-accepts-exact-physical-kernel-release','actual-helper-rejects-wrong-suffix',
             'actual-helper-rejects-QEMU-version-before-worker','actual-ARM-report-lock-and-snapshot-callbacks']:
    assert name in q['cases'],name

timers={}
diagnostic=R/'rootfs/usr/sbin/c80-timer-check'
build=proof('timer-diagnostic-build.json')
assert build['source_sha256']==sha(R/'c80_timer_check.c') and build['binary_sha256']==sha(diagnostic)
v=proof('qemu-timer-hires-result.json')
assert v['cases_passed']==5 and v['statistics']['samples']==64
assert v['statistics']['monotonic_res_ns']==v['statistics']['realtime_res_ns']==1
assert v['same_diagnostic_binary_sha256']==sha(diagnostic)==sha(P/'rootfs/usr/sbin/c80-timer-check')
assert v['diagnostic_source_sha256']==sha(R/'c80_timer_check.c')
assert v['verification_source_sha256']==sha(R/'verify-qemu-timers.py')
assert v['QEMU_kernel_sha256']==sha(R/'build-qemu/arch/arm/boot/zImage')
timers['current']=v['statistics']

release=(R/'build/include/config/kernel.release').read_text().strip()
assert release=='6.12.113-c80-openwrt-ram43-cck11'
helper=(R/'rootfs/usr/sbin/c80-wifi').read_text()
expected=helper.split('[ "$(uname -r)" = ',1)[1].split(' ]',1)[0].strip("'")
assert expected==release
previous=(P/'rootfs/usr/sbin/c80-wifi').read_text()
assert helper.replace('ram43-cck11','ram42-boot-timing').replace('RAM43','RAM42')==previous
subprocess.run(['sh','-n',str(R/'rootfs/usr/sbin/c80-wifi')],check=True)
raw=(R/'build/usr/initramfs_data.cpio').read_bytes();cp=entries(raw)
base=entries(gzip.decompress((P/'rootfs.cpio.gz').read_bytes()))
assert gzip.decompress((R/'rootfs.cpio.gz').read_bytes())==raw
added=set(cp)-set(base);assert added==set()
assert set(base)<=set(cp)
root_changes=sorted(n for n in base if cp[n]!=base[n])
assert root_changes==['etc/c80-hostapd.conf','usr/sbin/c80-wifi'],root_changes
assert cp['usr/sbin/c80-timer-check'][5]==diagnostic.read_bytes()
assert cp['usr/sbin/c80-wifi'][5]==helper.encode()
for name in added|set(root_changes):
    assert cp[name][1:3]==(0,0)
    assert cp[name][0]&0o777==(base[name][0]&0o777 if name in base else 0o755),name
assert cp['etc/c80-hostapd.conf'][5].replace(b'ssid=C80-RAM43\n',b'ssid=C80-RAM42\n')==base['etc/c80-hostapd.conf'][5]
assert compare_qemu(raw,(R/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(R/'artifacts/c80-net-selftest').read_bytes())==608
assert proof('rootfs-restore-result.json')['entries_compared']==602
assert proof('rootfs-scope.json')['kernel_CPIO_entries']==608
assert proof('rootfs-recovery-result.json')['cases_passed']==3
elf=json.loads((R/'evidence/rootfs-elf-closure.json').read_text());assert len(elf)==67
for row in elf:assert sha(R/'rootfs'/row['path'])==row['sha256'],row['path']
assert sha(R/'c80-auth.cpio')==sha(P/'c80-auth.cpio')=='e97b79c9bf15089bbdd0f9a564698f63f61f7afc4ab1a135aaa6fd11a8f2e5b5'
assert sha(R/'c80-openwrt-ram43-handoff.bin')==sha(P/'c80-openwrt-ram42-handoff.bin')
assert proof('decompressor-result.json')['zimage_sha256']==sha(R/'c80-openwrt-ram43-cck11-zImage')
handoff=json.loads((R/'evidence/handoff-verification.json').read_text())
assert len(handoff['cases'])==5 and all(x['status']=='pass' for x in handoff['cases'])
assert handoff['payload_sha256']==sha(R/'c80-openwrt-ram43-handoff.bin')
assert proof('restart-result.json')['Linux_vmlinux_sha256']==sha(R/'build/vmlinux')

def config(path):
    return dict(line.split('=',1) for line in path.read_text().splitlines() if line.startswith('CONFIG_'))
layouts={};changes={}
for mode,suffix in [('build','cck11'),('build-qemu','qemu-check')]:
    a,b=config(P/mode/'.config'),config(R/mode/'.config')
    delta={k:{'before':a.get(k),'after':b.get(k)} for k in sorted(a.keys()|b.keys()) if a.get(k)!=b.get(k)}
    assert set(delta)=={'CONFIG_LOCALVERSION','CONFIG_INITRAMFS_SOURCE'},delta
    for k in ['CONFIG_HIGH_RES_TIMERS','CONFIG_TICK_ONESHOT','CONFIG_SCHED_HRTICK','CONFIG_HZ_PERIODIC']:
        assert b[k]=='y',k
    assert a['CONFIG_HZ']==b['CONFIG_HZ']=='100'
    assert b['CONFIG_LOCALVERSION']=='"-c80-openwrt-ram43-'+suffix+'"'
    assert (b.get('CONFIG_C80_NET_SELFTEST')=='y')==(mode=='build-qemu')
    if mode=='build':
        for name in ['SMP','MAC80211','VFP','NEON','MODULES','MTD_SPI_NOR','MTD_CFI','MTD_RAM','MTD_BLOCK']:
            assert b.get('CONFIG_'+name)!='y',name
    binary=(R/mode/'vmlinux').read_bytes();header=struct.unpack_from('<16sHHIIIIIHHHHHH',binary)
    segments=[struct.unpack_from('<8I',binary,header[5]+i*header[9]) for i in range(header[10])]
    segments=[s for s in segments if s[0]==1]
    low=min(s[3] for s in segments);end=max(s[3]-low+0x40200000+s[5] for s in segments)
    assert header[4]-low+0x40200000==0x40208000 and end<0x40d00000,(mode,hex(end))
    layouts[mode]={'entry':'40208000','high_end':f'{end:08x}','auth_initrd_start':'40d00000'}
    changes[mode]=delta
    shutil.copy2(R/mode/'.config',R/'artifacts'/('kernel.config' if mode=='build' else 'qemu-kernel.config'))
env=dict(os.environ);env['LD_LIBRARY_PATH']=str(R.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')
symbols=subprocess.check_output([str(R.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm'),'-n',str(R/'build/vmlinux')],env=env,text=True)
assert 'c80_selftest_' not in symbols and 'c80_report_lock_selftest' not in symbols
assert re.search(r' T hrtimer_interrupt$',symbols,re.M)
kernel=(R/'c80-openwrt-ram43-cck11-zImage').read_bytes()
assert kernel==(R/'build/arch/arm/boot/zImage').read_bytes()
assert struct.unpack_from('<III',kernel,0x24)==(0x016f2818,0,len(kernel))
assert 0x41000000+len(kernel)<0x41e00000
assert (R/'c80-openwrt-ram43-cck11.dtb').read_bytes()==(R/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert sha(R/'c80-openwrt-ram43-cck11.dtb')==sha(P/'c80-openwrt-ram42-boot-timing.dtb')
load_script=R.parent/'ram40-wpa2-load-test/c80-wifi-load.ps1'
assert sha(load_script)=='3dd4608bd82447640617a3248149e21396cdb25a11e8e89a60381a8083a788a1'
shutil.copy2(load_script,R/'c80-wifi-load.ps1')

patch=[]
for name in ['c80_mcu_core.h','c80_mcu_transport.c','c80_net_core.h','c80_net_types.h','minimal.config','rootfs/etc/c80-hostapd.conf','rootfs/usr/sbin/c80-wifi']:
    patch.extend(difflib.unified_diff((P/name).read_text().splitlines(True),(R/name).read_text().splitlines(True),fromfile='a/'+name,tofile='b/'+name))
(R/'ram42-to-ram43.patch').write_text(''.join(patch))
loads=[];lines=['C80SCRIPT1','# RAM43 WPA2 data CCK11; CCK1 EAPOL/management, RAM42 timings retained.']
for address,name in [('41000000','c80-openwrt-ram43-cck11-zImage'),('40f00000','c80-openwrt-ram43-cck11.dtb'),('40e00000','c80-openwrt-ram43-handoff.bin'),('40d00000','c80-auth.cpio')]:
    data=(R/name).read_bytes();crc=f'{zlib.crc32(data):08x}'
    loads.append({'address':address,'file':name,'bytes':len(data),'crc32':crc,'sha256':sha(R/name)})
    lines.append(f'load {address} {name} {len(data):08x} {crc}')
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
result={'passed':True,'release':'C80 OpenWrt RAM43 CCK11 data trial','kernel':release,
        'load_files':loads,'layout':layouts,'changed_production_driver_sources':changed,'added_production_headers':[],
        'unchanged_production_driver_sources':[n for n in production if n not in changed],'kernel_config_changes':changes,
        'HIGH_RES_TIMERS':True,'HZ':100,'configured_AP_data_rate_Mbps':11,'EAPOL_management_rate_Mbps':1,'rate_adaptation':False,'on_air_rate_measured':False,'channel':1,'MTU':1400,
        'WPA2_CCMP_policy_unchanged':True,'TXD_rate_byte_changed':26,'packet_layout_unchanged':True,
        'startup_sleep_floor_us':10000,'ownership_settle_us':10000,'active_AP_poll_us':1000,
        'ownership_retries':0,'ownership_timeout_us':2000000,'physical_failure_cause_proven':False,
        'native_cases_fresh':3871,'new_boot_timing_cases_fresh':12,'new_data_rate_cases_fresh':250,'native_total_cases_fresh':4133,'fresh_OEM_rate_cases':44,'native_cases_inherited':0,'native_source_identity_verified':True,
        'all_native_suites_rerun':True,'parent_OEM_ARM_cases_inherited_not_rerun':23,
        'fresh_QEMU_WPA2_checks':48,'fresh_QEMU_timer_checks':5,'fresh_QEMU_timer_samples':64,
        'QEMU_timer_comparison':timers,'QEMU_WiFi_RTT_or_physical_radio_measurement':False,
        'fresh_QEMU_startup_removal_checks':13,'actual_ARM_report_callback_cases':34,
        'QEMU_real_Linux_protocol_cases':13,'QEMU_memory_available_KiB':q['memory_available_KiB'],
        'fresh_decompressor_checks':6,'fresh_handoff_checks':5,'fresh_restart_checks':8,
        'rootfs_changed':root_changes,'rootfs_added':sorted(added),'ELF_files':67,
        'signed_packages_unchanged':45,'DMA_pool_bytes':668112,'full_patch_files':33,
        'full_source_entries_restored':86730,'Linux_patch_byte_identical_to_RAM42':False,
        'Windows_comparison_script_byte_identical_to_RAM40':True,'helper_guard_matches_kernel':True,
        'new_NOR_or_UBoot_write_required':False,'hardware_tested':False,
        'physical_MCU_CCMP_DMA_RF_emulated':False}
for name in ['PROVENANCE.json','artifacts/artifact-verification.json','evidence/ram42-to-ram43-scope.json']:
    dump(name,result)
print(json.dumps(result,indent=2))
