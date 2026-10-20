#!/usr/bin/env python3
"""Issue a private allowlisted bootstrap/test bundle; never overwrite it."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

root=Path(__file__).resolve().parent
destination=root/'c80-connsys-bootstrap.zip'
assert not destination.exists(),'Issued archives are immutable'
names='''README.md LICENSE LICENSES.md PROVENANCE.json FIRMWARE-SOURCES.json
baseline.json entry.S blobs.S bootstrap.c bootstrap.ld build.sh
c80-connsys-bootstrap.bin c80-connsys-bootstrap.elf c80-script-runner.bin
c80-start.txt make-script.py verify-binary.py verification-full.json
verification-fast.json verification.json verify-artifacts.py artifact-verification.json
example-emulated-output.txt disassembly.txt elf-inspection.txt symbols.txt
SHA256SUMS tools-manifest.json package.py blobs/test_mcu.bin blobs/test_wifi.bin'''.split()
records=[]
for name in names:
    path=root/name
    assert path.is_file() and not path.is_symlink()
    data=path.read_bytes()
    if path.suffix in ('.json','.md','.py','.c','.S','.ld','.sh','.txt'):
        assert not re.search(rb'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',data),name
        # Build the search sentinel from parts so it does not match this scanner's source.
        assert (b'-----BEGIN '+b'PRIVATE KEY-----') not in data,name
    records.append({'file':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
manifest={'files':records,'hardware_MCU_bootstrap_tested':False,
          'contains_OEM_bootstrap_blobs':True,'individual_calibration_flash_dump_included':False}
(root/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
    for name in sorted(names+['package-manifest.json']):
        archive.write(root/name,'c80-connsys-bootstrap/'+name)
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None and len(archive.namelist())==len(names)+1
    for row in records:
        data=archive.read('c80-connsys-bootstrap/'+row['file'])
        assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
result={'file':str(destination),'bytes':destination.stat().st_size,
        'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'files':len(names)+1,
        'zip_member_crcs_sizes_hashes_verified':True}
(root/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
