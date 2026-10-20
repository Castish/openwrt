#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze the personal ready-to-use TFTP bundle; private build caches excluded."""
from pathlib import Path
import hashlib,json,zipfile
R=Path(__file__).resolve().parent
archive=R/'c80-ram-auth-v1.zip';assert not archive.exists()
files=['README.md','LICENSES.md','AUTH-LICENSE','GPL-2.0','Linux-syscall-note',
 'PROVENANCE.json','parent-openwrt-packages.json','parent-FIRMWARE-SOURCES.json',
 'c80-start.txt','c80-auth.cpio','c80-openwrt-ram31-scheduler-zImage',
 'c80-openwrt-ram31-auth.dtb','c80-openwrt-ram31-handoff.bin',
 'c80-host-ed25519.pub','ssh-host-public.json','auth-initrd.dtso','auth-initrd.dtbo',
 'qemu-bootargs.dtso','qemu-bootargs.dtbo','qemu-auth.dtb','qemu-bootshim.bin',
 'make-auth.py','build.sh','run-qemu-auth.sh','verify-auth.py','verify-scope.py','package.py',
 'build.log','auth-verification.log','scope-verification.log',
 'evidence/auth-image.json','evidence/boot-inputs.json','evidence/test-tools.json',
 'evidence/auth-verification.json','evidence/scope-verification.json',
 'evidence/rebuild-identity-preserved.json','evidence/qemu-test-notes.md',
 'evidence/qemu-stable-password-1-boot.log','evidence/qemu-stable-password-2-boot.log']
assert len(files)==len(set(files))
for name in files:assert (R/name).is_file() and not name.startswith(('private/','tools/','downloads/'))
for name in ['evidence/auth-verification.json','evidence/scope-verification.json','evidence/rebuild-identity-preserved.json']:
 assert json.loads((R/name).read_text())['passed']
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(R/'SHA256SUMS').write_text(''.join(digest(R/n)+'  '+n+'\n' for n in sorted(files)))
files.append('SHA256SUMS')
rows=[{'file':n,'bytes':(R/n).stat().st_size,'sha256':digest(R/n)} for n in sorted(files)]
(R/'package-manifest.json').write_text(json.dumps({'release':'C80 personal RAM auth v1',
 'all_issued_members_frozen':True,'contains_unique_private_server_identity':True,
 'personal_configuration_only_not_for_general_distribution':True,'hardware_tested':False,
 'client_key_required':False,'QEMU_boots':2,'SSH_cases_passed':8,'files':rows},indent=2)+'\n')
files.append('package-manifest.json')
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for name in sorted(files):z.write(R/name,'c80-ram-auth-v1/'+name)
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None and len(z.namelist())==len(files)
 for row in rows:
  data=z.read('c80-ram-auth-v1/'+row['file'])
  assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
 assert z.read('c80-ram-auth-v1/package-manifest.json')==(R/'package-manifest.json').read_bytes()
result={'passed':True,'archive':archive.name,'bytes':archive.stat().st_size,
 'ZIP_SHA256':digest(archive),'ZIP_files':len(files),'frozen_manifest_members':len(rows),
 'contains_unique_private_server_identity':True,'hardware_tested':False}
(R/'release-integrity.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
