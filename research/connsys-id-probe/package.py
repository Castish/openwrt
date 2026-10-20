#!/usr/bin/env python3
"""Issue an immutable, allowlisted ID probe bundle without vendor binaries."""
from pathlib import Path
import hashlib
import json
import zipfile

root = Path(__file__).resolve().parent
destination = root / 'c80-connsys-id-probe.zip'
names = '''README.md LICENSE PROVENANCE.json baseline.json build.sh
c80-connsys-id-probe.S uart-print.S probe.ld c80-connsys-id-probe.bin
c80-connsys-id-probe.elf disassembly.txt elf-inspection.txt SHA256SUMS
verify-binary.py verification.json example-emulated-output.txt
tools-manifest.json package.py'''.split()
assert not destination.exists(), 'Issued bundles must not be replaced'
records = []
for name in names:
    path = root / name
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    records.append({'file': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
manifest = {'files': records, 'hardware_connsys_read_tested':False,
            'peripheral_writes':'UART TX only; no reset/clock/power/EMI/flash writes'}
(root / 'package-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name in sorted(names + ['package-manifest.json']):
        archive.write(root / name, 'c80-connsys-id-probe/' + name)
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(names) + 1
    for record in records:
        data = archive.read('c80-connsys-id-probe/' + record['file'])
        assert len(data) == record['bytes']
        assert hashlib.sha256(data).hexdigest() == record['sha256']
result = {'file':str(destination), 'bytes':destination.stat().st_size,
          'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),
          'files':len(names) + 1, 'crc_and_all_member_hashes_verified':True}
(root / 'bundle-result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
