#!/usr/bin/env python3
"""Execute the actual A32 payload with emulated UART, not emulated C80 hardware."""
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP,
    UC_ARM_REG_LR, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
    UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10,
    UC_ARM_REG_R11,
)

ROOT = Path(__file__).resolve().parent
PAYLOAD = (ROOT / 'c80-ram-probe.bin').read_bytes()
EXPECTED = b'\r\nC80 RAM probe v1: ARM code executed; returning to U-Boot.\r\n'
UART = 0x11002000
RETURN = 0x41F00000
PRESERVED = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
             UC_ARM_REG_SP, UC_ARM_REG_LR]


def run_case(name, address, mode):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.mem_map(address, 4096)
    cpu.mem_write(address, PAYLOAD)
    cpu.mem_protect(address, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
    output = bytearray()
    reads = 0

    def read_uart(uc, offset, size, data):
        nonlocal reads
        assert offset == 0x14 and size == 4, (offset, size)
        reads += 1
        if mode == 'never-ready':
            return 0
        return 0x20 if mode == 'ready' or reads % 3 == 0 else 0

    def write_uart(uc, offset, size, value, data):
        assert offset == 0 and size == 4 and value < 256
        output.append(value)

    cpu.mmio_map(UART, 4096, read_uart, None, write_uart, None)
    cpu.reg_write(UC_ARM_REG_CPSR, 0xD3)  # ARM supervisor mode, IRQ/FIQ masked.
    sentinels = {reg: 0x45000000 + index * 0x100 for index, reg in enumerate(PRESERVED)}
    sentinels[UC_ARM_REG_SP] = 0x41FF0000  # Intentionally unmapped: no stack use.
    sentinels[UC_ARM_REG_LR] = RETURN
    for reg, value in sentinels.items():
        cpu.reg_write(reg, value)
    cpu.emu_start(address, RETURN, count=8_000_000)
    assert cpu.reg_read(UC_ARM_REG_PC) == RETURN, 'Did not return to caller'
    for reg, value in sentinels.items():
        assert cpu.reg_read(reg) == value, ('Callee-saved register changed', reg)
    assert bytes(cpu.mem_read(address, len(PAYLOAD))) == PAYLOAD
    expected_rc = 1 if mode == 'never-ready' else 0
    assert cpu.reg_read(UC_ARM_REG_R0) == expected_rc
    assert output == (b'' if mode == 'never-ready' else EXPECTED), output
    if mode == 'never-ready':
        assert reads == 1_000_000, reads
    return {'name': name, 'address': hex(address), 'rc': expected_rc,
            'uart_status_reads': reads, 'uart_bytes_written': len(output),
            'preserved_registers_and_code': True}


results = [
    run_case('ready-console', 0x40200000, 'ready'),
    run_case('relocated-delayed-console', 0x41000000, 'delayed'),
    run_case('bounded-timeout', 0x40200000, 'never-ready'),
]
report = {'payload_bytes': len(PAYLOAD), 'sha256': hashlib.sha256(PAYLOAD).hexdigest(),
          'scope': 'ARM instruction emulation with mock UART; hardware not tested',
          'cases': results}
(ROOT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
