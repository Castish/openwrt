#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package verified RAM9 ECO guard fix inputs, binaries and public evidence."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import posixpath
import re
import zipfile

root = Path(__file__).resolve().parent
archive_path = root/'c80-linux-ram9-guard-fix.zip'
if archive_path.exists():
    raise SystemExit('Issued archive exists: do not overwrite it.')
sha = lambda b: hashlib.sha256(b).hexdigest()
files = [root/n for n in (
    'README.md','FILE-SIZES.txt','PROVENANCE.json','DSA-NOTES.md','PORT-SELECTION.md',
    'build-kernel.sh','build-handoff.sh','prepare-kernel.py','minimal.config',
    'init.c','net-commands.inc','flash-reader.inc',
    'c80_ram_eth.c','c80_pdma_core.h','c80_ram_mdio.c','c80_ram_mdio.h',
    'c80_rtl8367s.h','rtl8365mb-patched.c','patch-dsa.py','verify-dsa.py',
    'test-dsa-control.c','test-dsa-tag.c',
    'handoff.S','handoff.ld','mt7626-archer-c80-v1-ram.dts',
    'verify-artifacts.py','verify-driver.py','verify-mdio.py','verify-userspace.py','verify-change-scope.py',
    'verify-handoff.py','verify-flash-reader.py','decode-flash.py','make-source-patch.py',
    'test-driver.c','driver-test-shim.h','test-mdio.c','mdio-test-shim.h',
    'driver-tests/bsp-descriptors.h','linux-mt7626-bringup.patch','build.log',
    'kernel-source-manifest.json','toolchain-manifest.json',
    'signature-status.txt','signature-verification.txt','package.py',
)]
files += [p for p in (root/'artifacts').rglob('*') if p.is_file() and p.suffix not in ('.o','.elf')]
files += [p for p in (root/'evidence').rglob('*') if p.is_file()]
files = sorted(set(files), key=lambda p: str(p.relative_to(root)))
assert all(p.is_file() and not p.is_symlink() for p in files)
names = {str(p.relative_to(root)) for p in files}
assert 'artifacts/init' in names
assert not any('flash-full' in n or 'capture-original' in n for n in names)

artifact = json.loads((root/'artifacts/artifact-verification.json').read_text())
assert artifact['kernel_version'] == '6.12.113-c80-ram9'
for item in artifact['artifacts']:
    data=(root/'artifacts'/item['file']).read_bytes()
    assert len(data)==item['bytes'] and sha(data)==item['sha256']
for report, source, key in (
    ('mdio-verification.json','c80_ram_mdio.c','source_sha256'),
    ('driver-verification.json','c80_ram_eth.c','driver_sha256'),
    ('userspace-verification.json','artifacts/init','init_sha256'),
    ('flash-reader-verification.json','artifacts/init','init_sha256'),
    ('handoff-verification.json','artifacts/c80-linux-ram9-handoff.bin','payload_sha256'),
):
    result=json.loads((root/'artifacts'/report).read_text())
    assert result[key] == sha((root/source).read_bytes()), report
dsa=json.loads((root/'artifacts/dsa-verification.json').read_text())
assert dsa['status']=='pass'
assert dsa['control_sha256']==sha((root/'c80_rtl8367s.h').read_bytes())
assert dsa['dsa_driver_sha256']==sha((root/'rtl8365mb-patched.c').read_bytes())
scope=json.loads((root/'artifacts/change-scope-verification.json').read_text())
assert scope['status']=='pass' and scope['kernel_feature_changes'] is False
userspace=json.loads((root/'artifacts/userspace-verification.json').read_text())
assert userspace['status']=='pass' and len(userspace['cases'])==73 and userspace['fault_injection_cases']==44
assert 'All thirteen files match' in (root/'artifacts/patch-verification.txt').read_text()

# Public evidence must not accidentally contain the private client identifiers.
for p in files:
    data=p.read_bytes()
    assert not re.search(rb'(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])',data), str(p)
    assert not re.search(rb'C:\\Users\\[A-Za-z0-9_.-]+',data), str(p)
    if p.suffix=='.md':
        for link in re.findall(r'\]\(([^)]+)\)',data.decode()):
            if '://' in link or link.startswith('#'):
                continue
            target=posixpath.normpath(str(PurePosixPath(p.relative_to(root)).parent/link.split('#')[0]))
            assert target in names, (p.name,link)

manifest = {
    'package':'c80-linux-ram9-guard-fix',
    'hardware_status':'RAM9 ECO guard fix hardware test pending; local checks pass',
    'prior_hardware_evidence':'RAM8 boot DSA detect EINVAL, snapshotECO0000, actual old guard reproduces -22; RAM7 LAN1/MTU1500 and down/up200/200 passed with priorECO001f',
    'files':[{'file':str(p.relative_to(root)),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in files]
}
(root/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(archive_path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
    for p in files+[root/'package-manifest.json']:
        archive.write(p,str(p.relative_to(root)))
with zipfile.ZipFile(archive_path) as archive:
    assert archive.testzip() is None
    assert set(archive.namelist()) == names|{'package-manifest.json'}
    for item in manifest['files']:
        data=archive.read(item['file'])
        assert len(data)==item['bytes'] and sha(data)==item['sha256']
result={'file':str(archive_path),'bytes':archive_path.stat().st_size,
    'sha256':sha(archive_path.read_bytes()),'files':len(files)+1,
    'zip_crc_and_manifest_verification':'pass', 'hardware_execution':'RAM9 ECO guard fix pending'}
(root/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
