#!/usr/bin/env python3
"""Freeze the personal RAM38 BMC normal-profile archive; never overwrite an issued ZIP."""
from pathlib import Path
import hashlib,json,zipfile
R=Path(__file__).resolve().parent;archive=R/'c80-openwrt-ram38-bmc-profile.zip';assert not archive.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proof=json.loads((R/'artifacts/artifact-verification.json').read_text());assert proof['passed'] and proof['native_cases']==3712
names=set()
for p in R.iterdir():
 if p.is_file() and not p.is_symlink() and (p.suffix in {'.c','.h','.S','.py','.sh','.config','.dts','.dtso','.dtb','.bin','.json','.patch'} or p.name.endswith('-zImage')):
  if p.name not in {'package-manifest.json','bundle-result.json'}:names.add(p.name)
for n in ['README.md','c80-start.txt','c80-auth.cpio','rootfs.cpio.gz','packages.lock','source-patch.log','source-restore.log','rootfs-abi-verification.log','rootfs-scope.log','rootfs-restore.log','rootfs-recovery-verification.log','kernel-final-build.log','qemu-last-build.log','decompressor-verification.log','handoff-verification.log','restart-verification.log','stock-security-verification.log','stock-key-verification.log','stock-channel-verification.log','stock-bmc-profile-verification.log','stock-normal-ap-verification.log','artifact-verification.log']:
 names.add(n)
for pattern in ['verification-*.log','native-*-run.log']:names.update(p.name for p in R.glob(pattern))
for folder in ['artifacts','evidence']:
 for p in (R/folder).iterdir():
  if p.is_file() and (p.suffix=='.json' or p.name in ['kernel.config','qemu-kernel.config','patch-verification.txt','c80-net-selftest']):names.add(str(p.relative_to(R)))
for n in ['etc/config/network','etc/config/dhcp','etc/config/dropbear','etc/c80-hostapd.conf','etc/init.d/c80-hostapd','usr/sbin/c80-wifi','usr/libexec/c80-wifi-lifecycle.sh']:names.add('rootfs/'+n)
for n in names:
 p=R/n;assert p.is_file() and not p.is_symlink(),n
 assert not set(Path(n).parts)&{'build','build-qemu','linux-6.12.113','private','downloads'},n
(R/'SHA256SUMS').write_text(''.join(f'{sha(R/n)}  {n}\n' for n in sorted(names)));names.add('SHA256SUMS')
rows=[{'file':n,'bytes':(R/n).stat().st_size,'sha256':sha(R/n)} for n in sorted(names)]
manifest={'release':'C80 OpenWrt RAM38 BMC normal-profile trial','hardware_tested_at_issuance':False,'private_server_keys_in_c80_auth_cpio':True,'not_for_public_Git_or_other_devices':True,'all_issued_members_frozen':True,'files':rows}
(R/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for n in sorted(names|{'package-manifest.json'}):z.write(R/n,archive.stem+'/'+n)
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None
 for row in rows:
  b=z.read(archive.stem+'/'+row['file']);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
result={'archive':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),'ZIP_files':len(rows)+1,'frozen_manifest_members':len(rows),'all_ZIP_CRC_and_member_SHA_verified':True,'hardware_tested':False,'personal_archive_not_for_public_Git':True}
(R/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
