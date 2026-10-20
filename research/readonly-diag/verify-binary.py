#!/usr/bin/env python3
"""Run the built ARM binary against mock UART and read-only flash in Unicorn."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zlib

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import (
    UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
    UC_ARM_REG_R10, UC_ARM_REG_R11,
)

ROOT = Path(__file__).resolve().parent
PAYLOAD = (ROOT / 'c80-readonly-diag.bin').read_bytes()
FLASH = 0x303E0000
UART = 0x11002000
RETURN = 0x41F00000
STACK = 0x41FE0000
PRESERVED = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
             UC_ARM_REG_SP, UC_ARM_REG_LR]


def run_case(name, address, flash, mode):
    assert len(flash) == 0x20000
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.mem_map(address, 4096)
    cpu.mem_write(address, PAYLOAD)
    cpu.mem_protect(address, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(FLASH, len(flash))
    cpu.mem_write(FLASH, flash)
    cpu.mem_protect(FLASH, len(flash), UC_PROT_READ)
    cpu.mem_map(STACK, 4096)
    cpu.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
    output = bytearray()
    reads = 0

    def read_uart(uc, offset, size, data):
        nonlocal reads
        assert offset == 0x14 and size == 4
        reads += 1
        if mode == 'timeout':
            return 0
        return 0x20 if mode == 'ready' or reads % 3 == 0 else 0

    def write_uart(uc, offset, size, value, data):
        assert offset == 0 and size == 4 and value < 256
        output.append(value)

    cpu.mmio_map(UART, 4096, read_uart, None, write_uart, None)
    cpu.reg_write(UC_ARM_REG_CPSR, 0xD3)
    sentinels = {reg: 0x45000000 + index * 0x100 for index, reg in enumerate(PRESERVED)}
    sentinels[UC_ARM_REG_SP] = STACK + 4096
    sentinels[UC_ARM_REG_LR] = RETURN
    for reg, value in sentinels.items():
        cpu.reg_write(reg, value)
    cpu.emu_start(address, RETURN, count=20_000_000)
    assert cpu.reg_read(UC_ARM_REG_PC) == RETURN, 'Did not return'
    for reg, value in sentinels.items():
        assert cpu.reg_read(reg) == value, ('Register changed', reg)
    assert bytes(cpu.mem_read(address, len(PAYLOAD))) == PAYLOAD
    assert bytes(cpu.mem_read(FLASH, len(flash))) == flash
    crc = {'FLASH_TAIL_CRC32': zlib.crc32(flash) & 0xFFFFFFFF,
           'PROFILE_3FE000_CRC32': zlib.crc32(flash[0x1E000:0x1F000]) & 0xFFFFFFFF,
           'RADIO_3FF000_CRC32': zlib.crc32(flash[0x1F000:]) & 0xFFFFFFFF}
    if mode == 'timeout':
        assert not output and reads == 1_000_000
        assert cpu.reg_read(UC_ARM_REG_R0) == 1
    else:
        assert cpu.reg_read(UC_ARM_REG_R0) == 0
        text = output.decode('ascii')
        assert text.startswith('\r\nC80 read-only diagnostics v1\r\n')
        assert text.endswith('DONE\r\n')
        values = dict(re.findall(r'^([A-Z0-9_]+)=([0-9a-f]{8})\r?$', text, re.M))
        expected_fields = {'MIDR', 'MPIDR', 'SCTLR', 'CTR', 'CNTFRQ', 'CPSR'} | set(crc)
        assert set(values) == expected_fields, values
        assert (int(values['MIDR'], 16) >> 4) & 0xFFF == 0xC07
        assert int(values['CPSR'], 16) == 0xD3
        for key, value in crc.items():
            assert int(values[key], 16) == value, (key, values[key], value)
    return {'name': name, 'load_address': hex(address), 'uart_status_reads': reads,
            'uart_bytes_written': len(output), 'return_code': 1 if mode == 'timeout' else 0,
            'crc32_matches_zlib': mode != 'timeout',
            'code_flash_and_preserved_registers_unchanged': True}


parser = argparse.ArgumentParser()
parser.add_argument('--captured-tail', type=Path)
args = parser.parse_args()
cases = [run_case('all-byte-values', 0x40200000, bytes(range(256)) * 512, 'ready'),
         run_case('fresh-address-retry', 0x40210000, bytes(range(256)) * 512, 'ready'),
         run_case('relocated-and-delayed', 0x41000000, bytes(0x20000), 'delayed'),
         run_case('erased-flash', 0x40200000, b'\xff' * 0x20000, 'ready'),
         run_case('bounded-uart-timeout', 0x40200000, bytes(0x20000), 'timeout')]
if args.captured_tail:
    cases.append(run_case('captured-tail', 0x40200000, args.captured_tail.read_bytes(), 'ready'))
report = {'payload_bytes': len(PAYLOAD), 'payload_sha256': hashlib.sha256(PAYLOAD).hexdigest(),
          'scope': 'Actual ARM binary, emulated Cortex-A7, mock UART and read-only flash; diagnostic hardware execution pending',
          'cases': cases}
(ROOT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
