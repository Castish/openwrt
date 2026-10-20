#!/usr/bin/env python3
"""Additional checks of unchanged v1 bytes after the first MDIO hardware result.

Use measured MDIO config/readback behavior and repeat go without reloading or
resetting CPU/memory/device state. Only model audit logs reset between calls.
Port changes below are synthetic fixtures, not the measured board map.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('switch_probe_model', ROOT / 'verify-binary.py')
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
samples = []
for linked in [None, 1, 4, 2, 3, 0]:
    values = [0xe0] * 5 + [0x16]
    if linked is not None:
        values[linked] = 0x196
    samples.append(values)
assert hashlib.sha256(model.PAYLOAD).hexdigest() == '83f545bfa59bddf98120fe295ee79637e9a71c0863aec42b38e4d72fb8c02d03'
cases = [
    model.run_case('measured-register-behavior-and-reentry', initial_mdio=0x2bd50003,
                   mdio_config=0x45000504, retain_command_bits=False,
                   repeats=6, port_samples=samples),
    model.run_case('preserve-existing-key-on-reentry', initial_mdio=0x16,
                   mdio_config=0x45000504, retain_command_bits=False,
                   magic=0x249, repeats=2),
]
report = {'scope': __doc__, 'binary_sha256': hashlib.sha256(model.PAYLOAD).hexdigest(),
          'binary_changed': False, 'original_issued_archive_changed': False,
          'cases_passed': len(cases), 'successive_invocations_executed': 8,
          'model_source_sha256': hashlib.sha256((ROOT / 'verify-binary.py').read_bytes()).hexdigest(),
          'physical_port_map_tested': False, 'cases': cases}
(ROOT / 'hardware-result-1/reentry-verification.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: eight successive ARM invocations in two cases; unchanged v1 binary')
