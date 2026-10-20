#!/usr/bin/env python3
"""Freeze the verified RAM31 issue; never rerun on a published directory."""
from pathlib import Path
import hashlib,json,zipfile
r=Path(__file__).resolve().parent;zip_path=r/'c80-openwrt-ram31-scheduler.zip';assert not zip_path.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert json.loads((r/'artifacts/artifact-verification.json').read_text())['passed']
names=set()
for p in r.iterdir():
 if p.is_file() and (p.suffix in ['.py','.sh','.c','.h','.S','.config','.bin','.dtb','.dts','.md','.json','.ps1'] or p.name.endswith('-zImage')):
  if p.name in ['STATUS.md','bundle-result.json','package-manifest.json']:continue
  names.add(str(p.relative_to(r)))
for name in ['README.md','rootfs.cpio.gz','c80-start.txt','packages.lock','artifact-verification.log','finalization.log','source-patch.log','source-restore.log','rootfs-scope.log','rootfs-restore.log','rootfs-recovery-verification.log','ram31-scope.log','stock-tx-lifetime-verification.log','stock-ring128-verification.log','stock-scheduler-verification.log','kernel-build.log','qemu-build.log','decompressor-verification.log','handoff-verification.log','restart-verification.log','irq-wrapper-verification.log','nvm-reader-verification.log','verification-pool-lifetime.log','qemu-linux-network-verification.log','qemu-aon-refusal-verification.log','qemu-missing-firmware-verification.log','ram30-to-ram31.patch','linux-mt7626-bringup.patch']:
 names.add(name)
for p in r.glob('verification-*.log'):names.add(p.name)
for folder in ['artifacts','downloads','prior-hardware','prior-evidence','parent-source-inputs']:
 for p in (r/folder).rglob('*'):
  if p.is_file():names.add(str(p.relative_to(r)))
# Keep authoritative current results and inherited ABI/oracle evidence.
stale={'TXD-wire-change-result.json','period-wire-change-result.json','state-wire-change-result.json','ram26-change-scope.json','ram27-wire-result.json','devinfo-variable-result.json'}
for p in (r/'evidence').iterdir():
 if p.is_file() and p.name not in stale:names.add(str(p.relative_to(r)))
# Exact readable operator configuration accompanies the complete CPIO archive.
for name in ['etc/config/network','etc/config/dhcp','etc/passwd','etc/group','usr/sbin/c80-wifi']:
 names.add('rootfs/'+name)
for p in (r/'rootfs/lib/firmware/c80').iterdir():names.add(str(p.relative_to(r)))
for name in names:
 p=r/name;assert p.is_file() and not p.is_symlink(),name
 assert not any(part in ('build','build-qemu','linux-6.12.113','__pycache__') for part in p.relative_to(r).parts),name
assert not any('dropbear_host' in name or 'dhcp.leases' in name for name in names)
(r/'SHA256SUMS').write_text(''.join(f'{sha(r/n)}  {n}\n' for n in sorted(names)))
names.add('SHA256SUMS')
rows=[{'file':n,'bytes':(r/n).stat().st_size,'sha256':sha(r/n)} for n in sorted(names)]
manifest={'release':'C80 OpenWrt RAM31 exact OEM DMA scheduler','hardware_tested':False,'parent_RAM28_Linux_IP_DHCP_MTU1400_TCP22_passed':True,'individual_calibration_or_full_factory_OS_bootloader_included':False,'all_issued_members_frozen':True,'files':rows}
(r/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(zip_path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for name in sorted(names|{'package-manifest.json'}):z.write(r/name,'c80-openwrt-ram31-scheduler/'+name)
with zipfile.ZipFile(zip_path) as z:
 assert z.testzip() is None
 for row in rows:
  data=z.read('c80-openwrt-ram31-scheduler/'+row['file']);assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
result={'archive':str(zip_path),'bytes':zip_path.stat().st_size,'sha256':sha(zip_path),'ZIP_files':len(rows)+1,'frozen_manifest_members':len(rows),'all_ZIP_CRC_and_member_SHA_verified':True,'hardware_new_image_tested':False}
(r/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
