#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze the separate personal helper fix without editing issued RAM39."""
from pathlib import Path
import hashlib,json,zipfile
R=Path(__file__).resolve().parent
archive=R/'c80-openwrt-ram39-helper-fix1.zip'
assert not archive.exists(),'Issued archives must never be overwritten'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proof=json.loads((R/'PROVENANCE.json').read_text())
check=json.loads((R/'evidence/qemu-helper-result.json').read_text())
assert proof['passed'] and check['passed'] and check['cases_passed']==15
assert sha(R/'c80-auth-helper-fix1.cpio')==check['external_CPIO_sha256']
assert sha(R/'c80-wifi')==check['helper_sha256']==proof['helper_sha256']
for row in proof['load_files']:
 assert sha(R/row['file'])==row['sha256'] and (R/row['file']).stat().st_size==row['bytes']
assert sha(R/'verify-qemu-helper.py')==check['verification_source_sha256']
assert sha(R/'build-overlay.py')==proof['build_source_sha256']
names={'README.md','PROVENANCE.json','build-overlay.py','verify-qemu-helper.py',
       'package.py','auth-helper.dtso','auth-helper.dtbo','run-qemu-auth.sh',
       'qemu-auth-helper-fix1.dtb','c80-wifi','c80-start.txt','build-overlay.log',
       'verification-qemu-helper.log','evidence/qemu-helper-result.json'}
names.update(row['file'] for row in proof['load_files'])
(R/'SHA256SUMS').write_text(''.join(f'{sha(R/n)}  {n}\n' for n in sorted(names)))
names.add('SHA256SUMS')
rows=[{'file':n,'bytes':(R/n).stat().st_size,'sha256':sha(R/n)} for n in sorted(names)]
(R/'package-manifest.json').write_text(json.dumps({'release':proof['release'],
 'personal_archive_with_private_server_keys':True,'frozen':True,
 'physical_hardware_tested':False,'files':rows},indent=2)+'\n')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for n in sorted(names|{'package-manifest.json'}):z.write(R/n,archive.stem+'/'+n)
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None
 for row in rows:
  b=z.read(archive.stem+'/'+row['file'])
  assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
result={'archive':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),
        'ZIP_files':len(rows)+1,'frozen_manifest_members':len(rows),
        'all_member_SHA_and_ZIP_CRC_verified':True,'personal_not_for_public_Git':True}
(R/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
