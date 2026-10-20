#!/usr/bin/env python3
"""Verify examples, issued inputs and a separate byte-exact native rebuild."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent
research = root.parent
spec = importlib.util.spec_from_file_location('make_script', root / 'make-script.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
inputs = [
    (0x41000000, 'c80-openwrt-ram1-zImage', 3382648, '6eb8252fe975ec52bd61443f9fb52bd8f4618139704baeb534c3c20a641574c0'),
    (0x40f00000, 'c80-openwrt-ram1-emi.dtb', 3364, '983672239457797c71451a391e86cb34e7ee83ba705f2fa4218af8d34bc669b2'),
    (0x40e00000, 'c80-openwrt-ram1-handoff.bin', 576, '3fffeec01561fb1976d0faec4b262d4ff829aad1dc0e1f9f2a92cbee9a38a083'),
]
pairs = []
for address, name, size, sha in inputs:
    path = research / 'openwrt-wifi-emi' / name
    data = path.read_bytes()
    assert len(data) == size and hashlib.sha256(data).hexdigest() == sha
    pairs.append((f'{address:08x}', str(path)))
assert generator.make(pairs, ['40e00000']) == (root / 'c80-start-openwrt.txt').read_text()
assert generator.make([('40270000',str(root / 'c80-ram-probe.bin'))], ['40270000']) == (root / 'c80-start.txt').read_text()
for pairs_bad, entries in [
    ([('40000000',str(root/'c80-ram-probe.bin'))], []),
    ([('40280000',str(root/'c80-ram-probe.bin'))], []),
    ([('40a00000',str(root/'c80-ram-probe.bin'))], []),
    ([('40270000',str(root/'c80-ram-probe.bin'))], ['40270004']),
    ([('40270000',str(root/'c80-ram-probe.bin'))] * 2, []),
]:
    try: generator.make(pairs_bad, entries)
    except ValueError: pass
    else: raise AssertionError('Generator accepted invalid plan')
original = (root / 'c80-script-runner.bin').read_bytes()
with tempfile.TemporaryDirectory(prefix='c80-runner-rebuild-') as folder:
    temporary = Path(folder)
    for name in ('entry.S','runner.c','runner.ld','build.sh'):
        (temporary / name).write_bytes((root / name).read_bytes())
    environment = dict(os.environ, ARM_TOOLCHAIN_ROOT=str(research / 'linux-bringup/tools'))
    rebuilt = subprocess.run(['bash',str(temporary/'build.sh')], env=environment,
                             check=True, capture_output=True, text=True)
    assert (temporary/'c80-script-runner.bin').read_bytes() == original
report = {'passed':True, 'separate_rebuild_byte_exact':True,
          'bytes':len(original),'sha256':hashlib.sha256(original).hexdigest(),
          'openwrt_script_pins_match_previously_issued_artifacts':True,
          'default_probe_script_regenerated_exactly':True,
          'generator_negative_cases':5,
          'payloads': [{'address':hex(a),'file':n,'bytes':s,'sha256':h} for a,n,s,h in inputs],
          'hardware_script_runner_tested':False}
(root/'artifact-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: byte-exact independent rebuild; both scripts; immutable OpenWrt inputs; 5 generator refusals.')
