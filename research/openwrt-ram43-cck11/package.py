#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze the personal RAM43 CCK11 trial; never overwrite issued archives."""
from pathlib import Path
import hashlib,json,zipfile

R=Path(__file__).resolve().parent
archive=R/'c80-openwrt-ram43-cck11.zip'
assert not archive.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proof=json.loads((R/'artifacts/artifact-verification.json').read_text())
assert proof['passed'] and proof['native_cases_fresh']==3871 and proof['native_cases_inherited']==0 and proof['new_boot_timing_cases_fresh']==12
assert proof['fresh_QEMU_WPA2_checks']==48 and proof['fresh_QEMU_timer_checks']==5
assert proof['changed_production_driver_sources']==['c80_mcu_core.h','c80_mcu_transport.c','c80_net_core.h','c80_net_types.h'] and proof['new_data_rate_cases_fresh']==250 and proof['fresh_OEM_rate_cases']==44 and not proof['hardware_tested']
names=set()
for p in R.iterdir():
    if p.is_file() and not p.is_symlink() and (p.suffix in {'.c','.h','.S','.py','.sh','.ps1','.config','.dts','.dtso','.dtb','.bin','.json','.patch'} or p.name.endswith('-zImage')):
        if p.name not in {'package-manifest.json','bundle-result.json'}:names.add(p.name)
names.update(['README.md','c80-start.txt','c80-auth.cpio','rootfs.cpio.gz','packages.lock',
              'source-patch.log','source-restore.log','source-rebuild-verification.log',
              'rootfs-recovery-verification.log','kernel-final-build.log','qemu-last-build.log',
              'decompressor-verification.log','handoff-verification.log',
              'restart-verification.log','artifact-verification.log'])
names.update(p.name for p in R.glob('verification-*.log'))
for folder in ['artifacts','evidence']:
    for p in (R/folder).rglob('*'):
        if p.is_file() and (p.suffix in {'.json','.log'} or p.name in ['kernel.config','qemu-kernel.config','patch-verification.txt','c80-net-selftest']):
            names.add(str(p.relative_to(R)))
for name in ['etc/config/network','etc/config/dhcp','etc/config/dropbear','etc/c80-hostapd.conf',
             'etc/init.d/c80-hostapd','usr/sbin/c80-wifi','usr/libexec/c80-wifi-lifecycle.sh']:
    names.add('rootfs/'+name)
for name in names:
    p=R/name
    assert p.is_file() and not p.is_symlink(),name
    assert not set(Path(name).parts)&{'build','build-qemu','linux-6.12.113','private','downloads'},name
(R/'SHA256SUMS').write_text(''.join(f'{sha(R/n)}  {n}\n' for n in sorted(names)))
names.add('SHA256SUMS')
rows=[{'file':n,'bytes':(R/n).stat().st_size,'sha256':sha(R/n)} for n in sorted(names)]
manifest={'release':'C80 OpenWrt RAM43 CCK11 data trial','hardware_tested_at_issuance':False,
          'private_server_keys_in_c80_auth_cpio':True,'not_for_public_Git_or_other_devices':True,
          'all_issued_members_frozen':True,'files':rows}
(R/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for name in sorted(names|{'package-manifest.json'}):z.write(R/name,archive.stem+'/'+name)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for row in rows:
        b=z.read(archive.stem+'/'+row['file'])
        assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256'],row['file']
result={'archive':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),
        'ZIP_files':len(rows)+1,'frozen_manifest_members':len(rows),
        'all_ZIP_CRC_and_member_SHA_verified':True,'hardware_tested':False,
        'personal_archive_not_for_public_Git':True}
(R/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
