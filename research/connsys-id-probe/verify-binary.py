#!/usr/bin/env python3
"""Execute the issued ARM bytes with strict AON/CONNSYS/UART register models.

This proves read scope, refusal paths, UART bounds and ABI preservation, not
MT7626 power/clock behavior, actual cache coherency, bus timing or bus recovery.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct

from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC,
                     UC_HOOK_CODE, UC_HOOK_MEM_WRITE)
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_R0,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

root = Path(__file__).resolve().parent
payload = (root / 'c80-connsys-id-probe.bin').read_bytes()
BASELINE = json.loads((root / 'baseline.json').read_text())
AON = {int(a, 16): int(v, 16) for a, v in BASELINE['registers'].items()}
UART, FE, STACK, RETURN = 0x11002000, 0x1b100000, 0x41fe0000, 0x41f00000
IDS = (0x180b1010, 0x180b101c, 0x18002000, 0x18002004)
GOOD_IDS = (0x10040101, 0, 0x8a00, 0x8a00)
PRESERVED = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
             UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR)
mrc_offsets = [offset for offset in range(0, len(payload), 4)
               if struct.unpack_from('<I', payload, offset)[0] in (0xee100f10, 0xee110f10)]
assert len(payload) < 4096 and len(mrc_offsets) == 2

def run(name, *, address=0x40260000, cpsr=0x600001d3, midr=0x410fc073,
        cfg=0x1410, mask=0, overrides=None, after_overrides=None,
        first=GOOD_IDS, second=None, uart='ready', uart_fail_after=None,
        expected_rc=0, expected_reads=8, expected_guard=0):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.mem_map(address, 4096)
    cpu.mem_write(address, payload)
    cpu.mem_protect(address, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(STACK, 4096)
    cpu.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.reg_write(UC_ARM_REG_CPSR, cpsr)
    saved_cpsr = cpu.reg_read(UC_ARM_REG_CPSR)
    sentinels = {reg: 0x45000000 + index * 0x100 for index, reg in enumerate(PRESERVED)}
    sentinels[UC_ARM_REG_SP] = STACK + 4096
    sentinels[UC_ARM_REG_LR] = RETURN
    for reg, value in sentinels.items(): cpu.reg_write(reg, value)
    aon = deepcopy(AON)
    aon.update(overrides or {})
    output, radio_reads, aon_reads, fe_reads, writes = bytearray(), [], [], [], []
    uart_reads = 0
    second = first if second is None else second
    def read_mmio(uc, offset, size, page):
        nonlocal uart_reads
        absolute = page + offset
        if absolute == UART + 0x14:
            assert size == 4
            uart_reads += 1
            if uart == 'never' or (uart_fail_after is not None and len(output) >= uart_fail_after):
                return 0
            return 0x20 if uart == 'ready' or uart_reads % 3 == 0 else 0
        if absolute in aon:
            assert size == 4
            value = aon[absolute]
            if len(aon_reads) >= 10 and after_overrides:
                value = after_overrides.get(absolute, value)
            aon_reads.append(absolute)
            return value
        if absolute in (FE + 0xa04, FE + 0xa28):
            assert size == 4
            fe_reads.append(absolute)
            return cfg if absolute == FE + 0xa04 else mask
        assert absolute in IDS, ('Out-of-scope MMIO read', hex(absolute), size)
        index = len(radio_reads) % 4
        assert absolute == IDS[index]
        assert size == (4 if index < 2 else 2)
        assert f'READ={absolute:08x}\r\n'.encode() in output
        assert len(aon_reads) >= 10, 'Radio accessed before the AON snapshot'
        assert expected_guard == 0, 'Radio accessed on a failed guard'
        round_values = first if len(radio_reads) < 4 else second
        radio_reads.append((absolute, size))
        return round_values[index] & ((1 << (size * 8)) - 1)
    def write_mmio(uc, offset, size, value, page):
        absolute = page + offset
        assert absolute == UART and size == 4 and 0 <= value < 256, ('Forbidden MMIO write', hex(absolute))
        output.append(value)
    pages = {a & ~0xfff for a in AON} | {UART, FE, *(a & ~0xfff for a in IDS)}
    for page in sorted(pages):
        cpu.mmio_map(page, 4096, read_mmio, page, write_mmio, page)
    def write_memory(uc, access, absolute, size, value, userdata):
        assert STACK <= absolute < STACK + 4096 or absolute == UART, ('Forbidden memory write', hex(absolute))
        writes.append((absolute, size))
    cpu.hook_add(UC_HOOK_MEM_WRITE, write_memory)
    def cp15_read(uc, pc, size, userdata):
        instruction = struct.unpack('<I', uc.mem_read(pc, 4))[0]
        if instruction == 0xee100f10:
            uc.reg_write(UC_ARM_REG_R0, midr)
            uc.reg_write(UC_ARM_REG_PC, pc + 4)
        elif instruction == 0xee110f10:
            uc.reg_write(UC_ARM_REG_R0, 0x00c5187f)
            uc.reg_write(UC_ARM_REG_PC, pc + 4)
    cpu.hook_add(UC_HOOK_CODE, cp15_read, begin=address + min(mrc_offsets), end=address + max(mrc_offsets))
    cpu.emu_start(address, RETURN, timeout=10_000_000, count=12_000_000)
    assert cpu.reg_read(UC_ARM_REG_PC) == RETURN, name
    actual_rc = cpu.reg_read(UC_ARM_REG_R0)
    assert actual_rc == expected_rc, (name, actual_rc, expected_rc, output.decode(errors='replace'))
    assert len(radio_reads) == expected_reads, (name, len(radio_reads), expected_reads)
    for reg, value in sentinels.items(): assert cpu.reg_read(reg) == value, (name, reg)
    assert cpu.reg_read(UC_ARM_REG_CPSR) & 0x3ff == saved_cpsr & 0x3ff
    assert bytes(cpu.mem_read(address, len(payload))) == payload
    if expected_guard == 1 or expected_guard == 2:
        assert not aon_reads and not fe_reads
    if uart == 'never':
        assert uart_reads == 1_000_000 and not output and not aon_reads and not fe_reads
    if uart == 'ready' and uart_fail_after is None:
        text = output.decode('ascii')
        assert f'GUARD_BEFORE={expected_guard:08x}' in text
        assert text.endswith('DONE\r\n')
        if expected_rc == 0:
            assert 'IDS_VALID_BITS=000000ff' in text
            assert 'AON_CHANGED_BITS=00000000' in text
            assert 'PDMA_AFTER_MASK_MATCH_AON_VALID=00001410 00000000 0000000f 00000003' in text
    result = {'name': name, 'address': hex(address), 'return': actual_rc,
              'radio_read_count': len(radio_reads), 'aon_read_count': len(aon_reads),
              'guard_before': expected_guard, 'uart_status_reads': uart_reads,
              'no_peripheral_writes_except_uart': True,
              'code_callee_registers_stack_control_bits_preserved': True}
    return result, bytes(output)

cases = []
def test(name, **kwargs):
    result, output = run(name, **kwargs)
    cases.append(result)
    return output

example = test('observed-C80-baseline')
test('relocated-delayed-uart', address=0x40300000, uart='delayed')
test('wrong-cpsr-abort-mask', cpsr=0x600000d3, expected_rc=1, expected_reads=0, expected_guard=1)
test('wrong-cpsr-irq-mask', cpsr=0x60000153, expected_rc=1, expected_reads=0, expected_guard=1)
test('different-cpu', midr=0x410fc075, expected_rc=2, expected_reads=0, expected_guard=2)
test('pdma-running', cfg=0x1455, expected_rc=3, expected_reads=0, expected_guard=3)
test('pdma-irq-enabled', mask=0x10001, expected_rc=4, expected_reads=0, expected_guard=4)
for reg, bits, guard in ((0x10000220, (2, 8, 15), 5), (0x10000228, (2, 8, 15), 6),
                         (0x10000230, (0, 1, 2), 7), (0x10000238, (0, 1, 2), 8)):
    for bit in bits:
        test(f'protected-{reg:08x}-bit{bit}', overrides={reg: AON[reg] | (1 << bit)},
             expected_rc=guard, expected_reads=0, expected_guard=guard)
test('wrong-emi-window', overrides={0x10000370:0x11050}, expected_rc=9, expected_reads=0, expected_guard=9)
test('spm-control-disabled', overrides={0x10006000:0}, expected_rc=10, expected_reads=0, expected_guard=10)
for bit in (23, 29):
    test(f'spm-mask-missing-bit{bit}', overrides={0x10006608:AON[0x10006608] & ~(1 << bit)},
         expected_rc=11, expected_reads=0, expected_guard=11)
for value in (0x8000, 0x9200):
    test(f'unsafe-reset-{value:04x}', overrides={0x10212018:value},
         expected_rc=12, expected_reads=0, expected_guard=12)
test('power-status-disagrees', overrides={0x10006610:0x0700b646},
     expected_rc=13, expected_reads=0, expected_guard=13)
for bit in (24, 25, 26):
    value = AON[0x1000660c] & ~(1 << bit)
    test(f'inherited-ethernet-power-missing-{bit}', overrides={0x1000660c:value, 0x10006610:value},
         expected_rc=14, expected_reads=0, expected_guard=14)
test('unrelated-aon-bits-allowed', overrides={0x10000220:0x80000000, 0x10212018:0x19000})
for version in (0, 0xffffffff, 0x100400ff, 0x10030101, 0xffff0101):
    test(f'bad-first-version-{version:08x}', first=(version, *GOOD_IDS[1:]), expected_rc=20, expected_reads=1)
test('bad-second-version', second=(0, *GOOD_IDS[1:]), expected_rc=20, expected_reads=5)
test('unstable-version', second=(0x10040200, *GOOD_IDS[1:]), expected_rc=21)
test('different-stable-version', first=(0x10040200, *GOOD_IDS[1:]), expected_rc=22)
test('nonzero-config-low-bits', first=(GOOD_IDS[0], 1, *GOOD_IDS[2:]), expected_rc=22)
test('config-unused-upper-bits', first=(GOOD_IDS[0], 0xabcd0000, *GOOD_IDS[2:]))
test('different-hw-version', first=(*GOOD_IDS[:2], 0x8a01, GOOD_IDS[3]), expected_rc=22)
test('different-fw-version', first=(*GOOD_IDS[:3], 0x8a01), expected_rc=22)
test('hw-register-halfword-width', first=(*GOOD_IDS[:2], 0xfeed8a00, 0xbeef8a00))
test('aon-post-snapshot-critical-change', after_overrides={0x10212018:0x8000}, expected_rc=30)
test('aon-post-snapshot-unrelated-change', after_overrides={0x10000370:0x21040}, expected_rc=31)
test('uart-never-ready', uart='never', expected_rc=40, expected_reads=0)
test('uart-fails-before-first-id', uart_fail_after=example.index(b'READ='), expected_rc=40, expected_reads=0)
test('uart-fails-after-first-id', uart_fail_after=example.index(b'VALUE=') + 8, expected_rc=40, expected_reads=1)
(root / 'example-emulated-output.txt').write_bytes(example)
report = {'scope': __doc__, 'passed': True, 'payload_bytes': len(payload),
          'payload_sha256': hashlib.sha256(payload).hexdigest(), 'cases': cases,
          'hardware_connsys_ids_tested': False,
          'radio_bus_stall_can_be_interrupted_by_this_program': False,
          'cp15_midr_sctlr_read_values_injected_from_observed_C80': True}
(root / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS:', len(cases), 'ARM cases; no peripheral writes except UART; caller state preserved.')
