#!/usr/bin/env python3
"""Validate actual handoff instructions and entry registers with Unicorn.

Uses identity section tables to model the observed MMU-on entry and the
transition to MMU-off. Cache operations/operands are checked, but actual dirty
cache data and execution of Linux are not modeled.
"""
from pathlib import Path
import collections
import hashlib
import json
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parent
PAYLOAD = (ROOT / 'artifacts/c80-linux-handoff.bin').read_bytes()
KERNEL = (ROOT / 'build/arch/arm/boot/zImage').read_bytes()
DTB = (ROOT / 'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
        UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC]
RETURN = 0x41F00000
STACK = 0x41FF0000
ENTRY = 0x40800000
FDT = 0x40700000
UART = 0x11002000
TABLE = 0x40400000
SCTLR = 0x00C5187F


def cpread(cpu, op1, crn, crm, op2):
    return cpu.reg_read(UC_ARM_REG_CP_REG, (15, 0, 0, crn, crm, op1, op2))


def run_case(name, address, problem=None):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    for base, data, perms in [(address, PAYLOAD, UC_PROT_READ | UC_PROT_EXEC),
                              (ENTRY, KERNEL[:4096], UC_PROT_READ | UC_PROT_EXEC),
                              (FDT, DTB, UC_PROT_READ)]:
        cpu.mem_map(base, 4096)
        cpu.mem_write(base, data)
        cpu.mem_protect(base, 4096, perms)
    cpu.mem_map(STACK, 4096)
    cpu.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
    if problem == 'kernel':
        cpu.mem_write(ENTRY + 0x24, bytes(4))
    if problem == 'dtb':
        cpu.mem_write(FDT, bytes(4))
    # Identity-map all 1-MiB sections, domain 0, full access, executable.
    cpu.mem_map(TABLE, 16384)
    cpu.mem_write(TABLE, b''.join(struct.pack('<I', (n << 20) | 0xC02) for n in range(4096)))
    for sec in (0, 1):
        for crn, crm, op2, value in [(2, 0, 0, TABLE), (2, 0, 2, 0), (3, 0, 0, 3)]:
            cpu.reg_write(UC_ARM_REG_CP_REG, (15, 0, sec, crn, crm, 0, op2, value))
        cpu.reg_write(UC_ARM_REG_CP_REG, (15, 0, sec, 1, 0, 0, 0, SCTLR))
    cpu.reg_write(UC_ARM_REG_CPSR, 0x600001D3)
    sentinels = {reg: 0x45000000 + n * 0x100 for n, reg in enumerate(REGS[4:13])}
    sentinels[UC_ARM_REG_SP] = STACK + 4096
    sentinels[UC_ARM_REG_LR] = RETURN
    for reg, value in sentinels.items():
        cpu.reg_write(reg, value)
    output = bytearray()
    status_reads = 0
    operations = []
    cleaned = collections.defaultdict(list)
    expected = {}

    def uart_read(uc, offset, size, data):
        nonlocal status_reads
        assert offset == 0x14 and size == 4
        status_reads += 1
        return 0 if problem == 'uart' else 0x20

    def uart_write(uc, offset, size, value, data):
        assert offset == 0 and size == 4 and value < 256
        output.append(value)

    def trace(uc, pc, size, data):
        word = struct.unpack('<I', uc.mem_read(pc, 4))[0]
        if (word & 0x0F000010) != 0x0E000010 or ((word >> 8) & 15) != 15:
            return
        read = (word >> 20) & 1
        op1, crn, crm, op2 = (word >> 21) & 7, (word >> 16) & 15, word & 15, (word >> 5) & 7
        key = (op1, crn, crm, op2)
        if read and key == (1, 0, 0, 0):
            selector = cpread(uc, 2, 0, 0, 0)
            ccsidr = cpread(uc, 1, 0, 0, 0)
            ways = ((ccsidr >> 3) & 0x3FF) + 1
            sets = ((ccsidr >> 13) & 0x7FFF) + 1
            way_shift = 32 - (ways - 1).bit_length() if ways > 1 else 0
            line_shift = (ccsidr & 7) + 4
            expected[selector] = {selector | (s << line_shift) | (w << way_shift)
                                  for s in range(sets) for w in range(ways)}
        if read:
            return
        value = uc.reg_read(REGS[(word >> 12) & 15])
        if key == (0, 7, 14, 2):
            cleaned[value & 14].append(value)
        else:
            operations.append((key, value))

    cpu.mmio_map(UART, 4096, uart_read, None, uart_write, None)
    for offset in range(0, len(PAYLOAD), 4):
        word = struct.unpack_from('<I', PAYLOAD, offset)[0]
        if (word & 0x0F000010) == 0x0E000010 and ((word >> 8) & 15) == 15:
            cpu.hook_add(UC_HOOK_CODE, trace, begin=address + offset, end=address + offset)
    cpu.emu_start(address, RETURN if problem else ENTRY, count=8_000_000)
    if problem:
        assert cpu.reg_read(UC_ARM_REG_PC) == RETURN
        assert cpu.reg_read(UC_ARM_REG_R0) == 1
        assert not cleaned and not operations, 'Changed CPU state on error'
        for reg, value in sentinels.items():
            assert cpu.reg_read(reg) == value, ('ABI register changed', reg)
        assert cpread(cpu, 0, 1, 0, 0) == SCTLR
        if problem == 'uart':
            assert not output and status_reads == 1_000_000
        else:
            assert b'Missing zImage/FDT magic' in output
    else:
        assert cpu.reg_read(UC_ARM_REG_PC) == ENTRY
        assert [cpu.reg_read(reg) for reg in REGS[:3]] == [0, 0xFFFFFFFF, FDT]
        assert cpu.reg_read(UC_ARM_REG_CPSR) & 0xDF == 0xD3
        assert cpread(cpu, 0, 1, 0, 0) == SCTLR & ~0x1805
        assert cpread(cpu, 2, 0, 0, 0) == 0
        assert expected and set(expected) == set(cleaned)
        for level in expected:
            assert set(cleaned[level]) == expected[level]
            assert len(cleaned[level]) == len(expected[level])
        keys = [k for k, value in operations]
        assert keys.index((0, 7, 5, 0)) < keys.index((0, 1, 0, 0))
        assert keys.index((0, 7, 5, 6)) < keys.index((0, 1, 0, 0))
        assert keys.index((0, 1, 0, 0)) < keys.index((0, 8, 7, 0))
        assert b'preparing CPU and starting Linux' in output
    assert bytes(cpu.mem_read(address, len(PAYLOAD))) == PAYLOAD
    return {'name': name, 'address': hex(address), 'result': 'returned safely' if problem else 'reached zImage entry',
            'set_way_operations': {str(k): len(v) for k, v in cleaned.items()},
            'uart_bytes': len(output), 'status': 'pass'}


cases = [run_case('handoff', 0x40600000), run_case('relocated-handoff', 0x40610000),
         run_case('missing-kernel', 0x40600000, 'kernel'),
         run_case('missing-dtb', 0x40600000, 'dtb'),
         run_case('bounded-uart-timeout', 0x40600000, 'uart')]
result = {'scope': __doc__, 'payload_bytes': len(PAYLOAD),
          'payload_sha256': hashlib.sha256(PAYLOAD).hexdigest(), 'cases': cases}
(ROOT / 'artifacts/handoff-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
