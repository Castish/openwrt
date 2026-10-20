#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the actual Linux MDIO helper with an independent MMIO/SMI model.

Models Linux API calls, not a Linux boot or electrical bus timing. Injects
timeouts at all 100 transfers, before/after effects, and validates cleanup,
guards, write allowlist, scan suppression, devres and concurrent readers.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shlex
import subprocess

root = Path(__file__).resolve().parent
test = root/'mdio-tests'
test.mkdir(exist_ok=True)
source = (root/'c80_ram_mdio.c').read_bytes()
for name in ('c80_ram_mdio.c', 'c80_ram_mdio.h'):
    assert (root/name).read_bytes() == (root/'linux-6.12.113/drivers/net/ethernet/mediatek'/name).read_bytes()
(test/'mdio-under-test.inc').write_bytes(b''.join(line for line in source.splitlines(True)
    if not line.startswith(b'#include <linux/') and line != b'#include "c80_ram_mdio.h"\n'))
command = shlex.split(os.environ.get('HOSTCC', 'gcc')) + ['-O1','-g','-std=gnu11',
    '-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-pthread',
    '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(root),'-I',str(test),
    str(root/'test-mdio.c'),'-o',str(test/'test-mdio')]
subprocess.run(command, check=True)
run = subprocess.run([str(test/'test-mdio')], capture_output=True, text=True)
if run.returncode:
    print(run.stderr, end='')
run.check_returncode()
assert not run.stderr, run.stderr
match = re.fullmatch(r'PASS: (\d+) checks; (\d+) injected transfer failures; 80 concurrent snapshots; actual MDIO C, independent protocol model\n', run.stdout)
assert match, run.stdout
result = {'scope': __doc__, 'status':'pass', 'checks':int(match[1]),
    'injected_transfer_failure_cases':int(match[2]), 'concurrent_snapshots':80,
    'sanitizers':['address','undefined'], 'sanitizer_diagnostics':None,
    'source_sha256':hashlib.sha256(source).hexdigest(),
    'header_sha256':hashlib.sha256((root/'c80_ram_mdio.h').read_bytes()).hexdigest(),
    'normal_mdio_transfers':100, 'hardware_tested_ram5':False,
    'scenarios':['hardware register values, option0 and four original key combinations',
        'repeated snapshots on one live bus', '100 individual pre-effect and post-effect timeouts',
        'partial/unconfirmed key writes and both key restore paths',
        'unknown/unstable IDs, wrong versions and invalid original keys',
        'key unlock/restore readback errors', 'stuck bus bounded waits',
        'MDIO configuration guard/change, taint blocks further commands',
        'configuration write rejection and raw Clause22 bounds',
        'scan suppression, bus allocation/register/devres cleanup',
        'four concurrent readers, no SMI interleaving or output under lock']}
(root/'artifacts/mdio-verification.json').write_text(json.dumps(result,indent=2)+'\n')
(root/'artifacts/mdio-verification.log').write_text(run.stdout)
print(json.dumps(result,indent=2))
