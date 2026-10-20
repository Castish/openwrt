#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the actual driver C with model Linux APIs/MMIO and ASan/UBSan.

This tests ring logic, allocation/stop failures and the MMIO write allowlist.
It does not boot Linux or emulate the physical MT7626 DMA/cache hardware.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent
TEST = ROOT / 'driver-tests'
TEST.mkdir(exist_ok=True)
driver = (ROOT / 'c80_ram_eth.c').read_bytes()
header = (ROOT / 'c80_pdma_core.h').read_bytes()
for name in ('c80_ram_eth.c', 'c80_pdma_core.h'):
    built = ROOT / 'linux-6.12.113/drivers/net/ethernet/mediatek' / name
    if built.exists():
        assert built.read_bytes() == (ROOT / name).read_bytes(), 'Tests differ from built driver input'
(TEST / 'driver-under-test.inc').write_bytes(b''.join(
    line for line in driver.splitlines(True) if not line.startswith(b'#include <linux/')))
(TEST / 'c80_ram_mdio.h').write_bytes(b''.join(
    line for line in (ROOT / 'c80_ram_mdio.h').read_bytes().splitlines(True)
    if not line.startswith(b'#include <linux/')))
bsp = ROOT.parent / 'c88-drivers-net-rt2880_eth.c'
if bsp.exists():
    source = bsp.read_bytes()
    start = source.index(b'typedef struct _PDMA_RXD_INFO1_')
    end = source.index(b'typedef enum _EXTERNAL_SWITCH_TYPE', start)
    (TEST / 'bsp-descriptors.h').write_bytes(
        b'/* GPL-2.0-or-later: descriptor declarations from the reviewed MediaTek GPL BSP. */\n' + source[start:end])
assert (TEST / 'bsp-descriptors.h').exists(), 'BSP descriptor oracle missing'
compiler = shlex.split(os.environ.get('HOSTCC', 'gcc'))
binary = TEST / 'test-driver'
command = compiler + ['-O1', '-g', '-std=gnu11', '-Wall', '-Wextra',
    '-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-function',
    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(ROOT),
    '-I', str(TEST), str(ROOT / 'test-driver.c'), '-o', str(binary)]
subprocess.run(command, check=True)
run = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
assert not run.stderr, run.stderr
match = re.fullmatch(r'PASS: (\d+) checks; actual driver with model Linux APIs/MMIO; BSP descriptor oracle\n', run.stdout)
assert match, run.stdout
result = {
    'scope': __doc__, 'status': 'pass', 'checks': int(match[1]),
    'sanitizers': ['address', 'undefined'], 'sanitizer_diagnostics': None,
    'driver_sha256': hashlib.sha256(driver).hexdigest(),
    'core_sha256': hashlib.sha256(header).hexdigest(),
    'bsp_descriptor_oracle_sha256': hashlib.sha256((TEST / 'bsp-descriptors.h').read_bytes()).hexdigest(),
    'scenarios': ['TX/RX descriptor fields against independent GPL BSP bitfields',
        'RX ownership and length bounds', 'ring wrap', 'state-guard rejection without writes',
        'all four partial allocation failures',
        'IRQ registration/unwind and NO_AUTOEN', 'idle IRQ polarity/query and status-clear guards before DMA',
        'IRQ masking, known-bit W1C acknowledgement and NAPI rearm',
        'budget-zero TX-only poll', 'NAPI ownership prevents early rearm',
        'RX event during NAPI completion/rearm is not lost',
        'unexpected IRQ disables line; stop/reopen balances IRQ depth',
        'stop cancels scheduled NAPI before DMA/free', 'DMA ring setup and bounded write allowlist',
        'CPU-link sysfs action parsing and RTNL serialization',
        'CPU-link action refuses administrative/running/DMA-pool/IRQ/busy states',
        'MDIO taint blocks Ethernet open before DMA startup',
        'TX ring full without consuming busy skb', 'short-frame zero padding',
        'TX completion and wakeup across ring wrap', 'oversized and copy-failure TX drops',
        'RX payload copy and descriptor rearm', 'bad RX length and CPU-loopback drops',
        'RX skb allocation failure', 'bounded 64-frame NAPI budget', 'sysfs state',
        'normal stop releases buffers only after DMA quiet',
        'stuck-DMA stop/open retains buffers; safe retry after quiet'],
    'mdio_scope': 'Delegated API wiring in this PDMA model; actual MDIO C has a separate protocol/concurrency/fault-injection suite.',
    'hardware_tested_ram6': False,
}
(ROOT / 'artifacts/driver-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
