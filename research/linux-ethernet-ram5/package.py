#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package verified RAM5 inputs, binaries and public evidence; never a flash dump."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import posixpath
import re
import zipfile

root = Path(__file__).resolve().parent
archive_path = root/'c80-linux-ram5-mdio.zip'
if archive_path.exists():
    raise SystemExit('Issued archive exists: do not overwrite it.')
sha = lambda b: hashlib.sha256(b).hexdigest()
files = [root/n for n in (
    'README.md','FILE-SIZES.txt','PROVENANCE.json',
    'build-kernel.sh','build-handoff.sh','prepare-kernel.py','minimal.config',
    'init.c','net-commands.inc','flash-reader.inc',
    'c80_ram_eth.c','c80_pdma_core.h','c80_ram_mdio.c','c80_ram_mdio.h',
    'handoff.S','handoff.ld','mt7626-archer-c80-v1-ram.dts',
    'verify-artifacts.py','verify-driver.py','verify-mdio.py','verify-userspace.py',
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
assert artifact['kernel_version'] == '6.12.113-c80-ram5'
for item in artifact['artifacts']:
    data=(root/'artifacts'/item['file']).read_bytes()
    assert len(data)==item['bytes'] and sha(data)==item['sha256']
for report, source, key in (
    ('mdio-verification.json','c80_ram_mdio.c','source_sha256'),
    ('driver-verification.json','c80_ram_eth.c','driver_sha256'),
    ('userspace-verification.json','artifacts/init','init_sha256'),
    ('flash-reader-verification.json','artifacts/init','init_sha256'),
    ('handoff-verification.json','artifacts/c80-linux-ram5-handoff.bin','payload_sha256'),
):
    result=json.loads((root/'artifacts'/report).read_text())
    assert result[key] == sha((root/source).read_bytes()), report
assert 'All eleven files match' in (root/'artifacts/patch-verification.txt').read_text()

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
    'package':'c80-linux-ram5-mdio',
    'hardware_status':'RAM5 Linux MDIO test pending; local checks pass',
    'prior_hardware_evidence':'RAM4 Ethernet IRQ/NAPI, stop/reopen/MTU; MDIO v1 port map; CPU-link v2 HSGMII/option1',
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
    'zip_crc_and_manifest_verification':'pass', 'hardware_execution':'RAM5 MDIO pending'}
(root/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
