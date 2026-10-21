#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package only this connected-client tool; no firmware or personal inputs."""
from pathlib import Path
import hashlib, json, zipfile

stage = Path(__file__).resolve().parent
sha = lambda b: hashlib.sha256(b).hexdigest()
result = json.loads((stage / 'private/verification.json').read_text(encoding='utf-8-sig'))
assert result['Passed'] and result['CasesPassed'] >= 16
for name, key in [('c80-wifi-load.ps1', 'ProductionScriptSha256'),
                  ('verify-load-test.ps1', 'VerifierSha256')]:
    assert sha((stage / name).read_bytes()) == result[key], name
payload = {name: (stage / name).read_bytes() for name in
           ['c80-wifi-load.ps1', 'verify-load-test.ps1', 'package.py', 'README.md', 'LATENCY.md']}
payload['VERIFICATION.json'] = (json.dumps(result, indent=2) + '\n').encode()
manifest = {'stage': 'ram40-wpa2-load-test', 'firmware_changed': False,
            'files': [{'file': name, 'bytes': len(data), 'sha256': sha(data)}
                      for name, data in sorted(payload.items())]}
payload['MANIFEST.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
payload['SHA256SUMS'] = ''.join(sha(data) + '  ' + name + '\n'
                               for name, data in sorted(payload.items())).encode()
archive = stage / 'c80-ram40-wpa2-load-test.zip'
if not archive.exists():
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(payload.items()):
            item = zipfile.ZipInfo('c80-ram40-wpa2-load-test/' + name, (2026, 10, 21, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            z.writestr(item, data)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    assert len(z.namelist()) == len(payload)
    for name, data in payload.items():
        assert z.read('c80-ram40-wpa2-load-test/' + name) == data, name
print(json.dumps({'passed': True, 'archive': archive.name, 'bytes': archive.stat().st_size,
                  'sha256': sha(archive.read_bytes()), 'files': len(payload),
                  'PowerShell_checks': result['CasesPassed'],
                  'physical_Windows_load_tested': False, 'firmware_changed': False}, indent=2))
