#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the actual Linux MDIO helper with an independent MMIO/SMI model.

Models Linux API calls, not a Linux boot or electrical bus timing. Injects
before/after-effect timeouts at all 100 snapshot and 140 CPU-link transfers,
and validates cleanup, guards, write allowlist, devres and concurrent readers.
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
match = re.fullmatch(r'PASS: (\d+) checks; (\d+) injected transfer failures; (\d+) CPU-link transfer failures; 80 concurrent snapshots; actual MDIO C, independent protocol model\n', run.stdout)
assert match, run.stdout
result = {'scope': __doc__, 'status':'pass', 'checks':int(match[1]),
    'injected_transfer_failure_cases':int(match[2]), 'concurrent_snapshots':80,
    'cpu_link_transfer_failure_cases':int(match[3]), 'normal_cpu_link_test_transfers':140,
    'sanitizers':['address','undefined'], 'sanitizer_diagnostics':None,
    'source_sha256':hashlib.sha256(source).hexdigest(),
    'header_sha256':hashlib.sha256((root/'c80_ram_mdio.h').read_bytes()).hexdigest(),
    'normal_mdio_transfers':100, 'hardware_tested_ram9':False,
    'scenarios':['hardware register values, option0 and four original key combinations',
        'repeated snapshots on one live bus', '100 individual pre-effect and post-effect timeouts',
        'partial/unconfirmed key writes and both key restore paths',
        'unknown/unstable IDs, wrong versions and invalid original keys',
        'key unlock/restore readback errors', 'stuck bus bounded waits',
        'MDIO configuration guard/change, taint blocks further commands',
        'configuration write rejection and raw Clause22 bounds',
        'scan suppression, bus allocation/register/devres cleanup',
        'four concurrent readers, no SMI interleaving or output under lock',
        'CPU-link baseline/option/HSGMII/control/ECO guards',
        'CPU-link disable/status/readback and restoration, repeated calls',
        'every CPU-link transfer timeout before/after effect, both restore paths',
        'delayed/missing link transitions and ignored control writes',
        'permanent bus failure after a CPU-link write stays bounded and blocks reuse',
        'failed restoration blocks MDIO and subsequent Ethernet open']}
(root/'artifacts/mdio-verification.json').write_text(json.dumps(result,indent=2)+'\n')
(root/'artifacts/mdio-verification.log').write_text(run.stdout)
print(json.dumps(result,indent=2))
