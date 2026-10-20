#!/usr/bin/env python3
"""Issue one immutable, allowlisted source/binary/example bundle."""
from pathlib import Path
import hashlib
import json
import zipfile

root = Path(__file__).resolve().parent
destination = root / 'c80-script-runner.zip'
assert not destination.exists(), 'Issued archives are immutable'
names = '''README.md LICENSE PROVENANCE.json loader-profile.json
entry.S runner.c runner.ld build.sh c80-script-runner.bin c80-script-runner.elf
c80-ram-probe.bin c80-ram-probe.S c80-start.txt c80-start-openwrt.txt
make-script.py verify-binary.py verification.json verify-artifacts.py
artifact-verification.json example-emulated-output.txt disassembly.txt
elf-inspection.txt symbols.txt SHA256SUMS tools-manifest.json package.py'''.split()
records = []
for name in names:
    path = root / name
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    assert len(data) < 100000, 'Unexpected large source/binary member'
    records.append({'file':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
manifest = {'hardware_runner_tested':False, 'files':records,
            'default_scenario':'Load/run an existing UART-only RAM probe and return',
            'factory_image_flash_calibration_mcu_included':False}
(root/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
    for name in sorted(names + ['package-manifest.json']):
        archive.write(root/name, 'c80-script-runner/' + name)
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(names)+1
    for record in records:
        data = archive.read('c80-script-runner/' + record['file'])
        assert len(data) == record['bytes']
        assert hashlib.sha256(data).hexdigest() == record['sha256']
result = {'file':str(destination), 'bytes':destination.stat().st_size,
          'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),
          'files':len(names)+1, 'all_zip_member_crcs_hashes_verified':True}
(root/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
