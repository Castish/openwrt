#!/usr/bin/env python3
"""Freeze the private, verified RAM32 archive. Never overwrite an issued ZIP."""
from pathlib import Path
import hashlib,json,zipfile
R=Path(__file__).resolve().parent
archive=R/'c80-openwrt-ram32-cfg80211.zip';assert not archive.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proof=json.loads((R/'artifacts/artifact-verification.json').read_text());assert proof['passed']
names=set()
for p in R.iterdir():
 if p.is_file() and (p.suffix in {'.c','.h','.S','.py','.sh','.config','.dts','.dtso','.dtb','.bin','.json','.patch'} or p.name.endswith('-zImage')):
  if p.name not in {'package-manifest.json','bundle-result.json'}:names.add(p.name)
for n in ['README.md','c80-start.txt','c80-auth.cpio','rootfs.cpio.gz','packages.lock','FIRMWARE-SOURCES.json','source-patch.log','source-restore.log','rootfs-abi-verification.log','rootfs-scope.log','rootfs-restore.log','rootfs-recovery-verification.log','kernel-final-build.log','qemu-last-build.log','qemu-normal-verification.log','qemu-fault-verification.log','decompressor-verification.log','handoff-verification.log','restart-verification.log','artifact-verification.log']:
 names.add(n)
for pattern in ['verification-*.log','native-*-run.log']:
 names.update(p.name for p in R.glob(pattern))
for folder in ['artifacts','evidence']:
 for p in (R/folder).iterdir():
  if p.is_file() and (p.suffix=='.json' or p.name in ['kernel.config','qemu-kernel.config','patch-verification.txt','c80-net-selftest']):
   if p.name not in {'qemu-cfg80211-result.json'}:names.add(str(p.relative_to(R)))
for n in ['etc/config/network','etc/config/dhcp','etc/config/dropbear','etc/c80-hostapd.conf','etc/init.d/c80-hostapd','usr/sbin/c80-wifi']:
 names.add('rootfs/'+n)
for name in list(names):
 p=R/name;assert p.is_file() and not p.is_symlink(),name
 assert not set(p.relative_to(R).parts)&{'build','build-qemu','linux-6.12.113','private','downloads'},name
(R/'SHA256SUMS').write_text(''.join(f'{sha(R/n)}  {n}\n' for n in sorted(names)))
names.add('SHA256SUMS')
rows=[{'file':n,'bytes':(R/n).stat().st_size,'sha256':sha(R/n)} for n in sorted(names)]
manifest={'release':'C80 OpenWrt RAM32 cfg80211','hardware_tested_at_issuance':False,'private_server_keys_in_c80_auth_cpio':True,'not_for_public_Git_or_other_devices':True,'all_issued_members_frozen':True,'files':rows}
(R/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for n in sorted(names|{'package-manifest.json'}):z.write(R/n,archive.stem+'/'+n)
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None
 for row in rows:
  b=z.read(archive.stem+'/'+row['file']);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
result={'archive':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),'ZIP_files':len(rows)+1,'frozen_manifest_members':len(rows),'all_ZIP_CRC_and_member_SHA_verified':True,'physical_new_image_tested':False,'personal_archive_not_for_public_Git':True}
(R/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
