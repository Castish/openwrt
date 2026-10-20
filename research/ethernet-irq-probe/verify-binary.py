#!/usr/bin/env python3
"""Execute the actual ARM payload with a bounded UART/FE/GIC MMIO model.

This verifies instructions, guards, access scope and restoration, not the
physical MT7626 IRQ wiring or real cache/device timing.
"""
import hashlib
import json
from pathlib import Path
import re

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
    UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
)

ROOT = Path(__file__).resolve().parent
PAYLOAD = (ROOT / 'c80-irq-probe.bin').read_bytes()
UART, FE, GIC = 0x11002000, 0x1B100000, 0x10310000
STACK, RETURN = 0x41FE0000, 0x41F00000
MASKS = [0, 1, 0x10000, 0x10000000, 0x40000000, 4, 0x100, 0]
PRESERVED = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
             UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR]


def run_case(name, *, address=0x40220000, cpsr=0x600001D3, cfg=0x1410,
             initial_mask=0, typer=0xFC68, midr=0x410FC073,
             status=0x50010001, routes=None, routing='level', uart='ready',
             ignore_mask_writes=False, expected_guard=0, bad_final_readback=False):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.mem_map(address, 4096)
    cpu.mem_write(address, PAYLOAD)
    cpu.mem_protect(address, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(STACK, 4096)
    cpu.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.reg_write(UC_ARM_REG_CPSR, cpsr)
    original_cpsr = cpu.reg_read(UC_ARM_REG_CPSR)
    sentinels = {reg: 0x45000000 + i * 0x100 for i, reg in enumerate(PRESERVED)}
    sentinels[UC_ARM_REG_SP] = STACK + 4096
    sentinels[UC_ARM_REG_LR] = RETURN
    for reg, value in sentinels.items():
        cpu.reg_write(reg, value)
    output = bytearray()
    status_reads = 0
    writes = []
    mask_reads = 0
    mask = initial_mask
    # Unrelated pre-existing pending sources must be copied unchanged.
    base_pending = [1 << 27, 0x12, 0, 0, 0, 0, 0, 0, 0]
    sticky_pending = list(base_pending)
    enables = [0x0800FFFF] + [0] * 8
    configs = [0xAAAAAAAA, 0] + [0] * 16
    routes = routes if routes is not None else {1: 255, 0x10000: 256,
                                              0x10000000: 255, 0x40000000: 256}
    fe_values = {0x08: 0x100, 0x0C: 0, 0x10: 0x1234, 0x14: 0,
                 0x20: 0, 0x24: 0, 0xA04: cfg, 0xA20: status,
                 0xA00: 0x202, 0xA0C: 0, 0xA50: 0, 0xA54: 0}

    def active_pending():
        pending = list(base_pending)
        if routing != 'no-route':
            for source, hwirq in routes.items():
                if source & status & mask:
                    pending[hwirq // 32] |= 1 << (hwirq % 32)
        if routing == 'edge-latched':
            for i, value in enumerate(pending):
                sticky_pending[i] |= value
            return list(sticky_pending)
        return pending

    def read_fe(uc, offset, size, data):
        nonlocal mask_reads
        assert size == 4
        if offset == 0xA28:
            mask_reads += 1
            if bad_final_readback and mask_reads == 10:
                return 1
            return mask
        assert offset in fe_values, ('unexpected FE read', hex(offset))
        return fe_values[offset]

    def write_fe(uc, offset, size, value, data):
        nonlocal mask
        assert size == 4 and offset == 0xA28, ('unexpected external write', hex(offset))
        assert value in MASKS and expected_guard in (0, 7)
        assert cpu.reg_read(UC_ARM_REG_CPSR) & 0xFF == 0xD3
        writes.append(value)
        if not ignore_mask_writes:
            mask = value
        active_pending()

    def read_gic(uc, offset, size, data):
        assert size == 4 and offset % 4 == 0
        if offset == 0:
            return 1
        if offset == 4:
            return typer
        if 0x100 <= offset < 0x124:
            return enables[(offset - 0x100) // 4]
        if 0x200 <= offset < 0x224:
            return active_pending()[(offset - 0x200) // 4]
        if 0xC00 <= offset < 0xC48:
            return configs[(offset - 0xC00) // 4]
        raise AssertionError(('unexpected GIC read', hex(offset)))

    def write_gic(uc, offset, size, value, data):
        raise AssertionError(('GIC must be read-only', hex(offset)))

    def read_uart(uc, offset, size, data):
        nonlocal status_reads
        assert offset == 0x14 and size == 4
        assert mask == initial_mask, 'UART started before IRQ mask restoration'
        status_reads += 1
        if uart == 'timeout' or (uart == 'late-timeout' and len(output) >= 100):
            return 0
        if uart == 'delayed':
            return 0x20 if status_reads % 3 == 0 else 0
        return 0x20

    def write_uart(uc, offset, size, value, data):
        assert offset == 0 and size == 4 and value < 256
        assert mask == initial_mask
        output.append(value)

    # Override only the MIDR instruction's result; MMIO and all other ARM
    # instructions execute normally, including CPSR guards and barriers.
    midr_instructions = []
    for off in range(0, len(PAYLOAD), 4):
        if PAYLOAD[off:off+4] == bytes.fromhex('100f10ee'):
            midr_instructions.append(address + off)
    assert len(midr_instructions) == 1

    def read_midr(uc, pc, size, data):
        assert size == 4
        uc.reg_write(UC_ARM_REG_R0, midr)
        uc.reg_write(UC_ARM_REG_PC, pc + 4)

    cpu.hook_add(UC_HOOK_CODE, read_midr,
                 begin=midr_instructions[0], end=midr_instructions[0])
    cpu.mmio_map(UART, 4096, read_uart, None, write_uart, None)
    cpu.mmio_map(FE, 4096, read_fe, None, write_fe, None)
    cpu.mmio_map(GIC, 4096, read_gic, None, write_gic, None)
    cpu.emu_start(address, RETURN, count=12_000_000)
    assert cpu.reg_read(UC_ARM_REG_PC) == RETURN, 'Probe did not return'
    assert mask == initial_mask
    for reg, value in sentinels.items():
        assert cpu.reg_read(reg) == value, ('ABI register changed', reg)
    assert cpu.reg_read(UC_ARM_REG_CPSR) & 0x3FF == original_cpsr & 0x3FF
    assert bytes(cpu.mem_read(address, len(PAYLOAD))) == PAYLOAD
    assert writes == (MASKS[1:] if expected_guard in (0, 7) else []), writes
    expected_rc = 1 if 'timeout' in uart else expected_guard
    assert cpu.reg_read(UC_ARM_REG_R0) == expected_rc
    if uart == 'timeout':
        assert not output and status_reads == 1_000_000
    elif uart == 'late-timeout':
        assert len(output) == 100 and status_reads == 1_000_100
    else:
        text = output.decode('ascii')
        assert text.startswith('\r\nC80 IRQ route probe v1\r\n')
        assert text.endswith('DONE\r\n')
        values = dict(re.findall(r'^([A-Z0-9_]+)=([0-9a-f]{8})\r?$', text, re.M))
        assert len(values) == 20, values
        for key, value in {'CPSR': original_cpsr, 'MIDR': midr, 'GICD_CTLR': 1,
                           'GICD_TYPER': typer, 'PDMA_CFG': cfg,
                           'PDMA_MASK_BEFORE': initial_mask,
                           'PDMA_MASK_AFTER': 1 if bad_final_readback else initial_mask,
                           'PDMA_STATUS_BEFORE': status, 'PDMA_STATUS_AFTER': status,
                           'GUARD_RC': expected_guard}.items():
            assert int(values[key], 16) == value, (key, values[key], value)
        for label, expected in [('GIC_ENABLE', enables), ('GIC_CONFIG', configs)]:
            match = re.search(r'^' + label + r'=(.*?)\r?$', text, re.M)
            assert match and [int(w, 16) for w in match[1].split()] == expected
        samples = re.findall(r'^PHASE_MASK=([0-9a-f]{8}) READBACK=([0-9a-f]{8}) '
                             r'STATUS=([0-9a-f]{8})\r?\nPENDING=(.*?)\r?$', text, re.M)
        expected_masks = [initial_mask] if expected_guard else MASKS
        assert len(samples) == len(expected_masks)
        seen_pending = list(base_pending)
        for (requested, actual, captured_status, raw), expected in zip(samples, expected_masks):
            assert int(requested, 16) == expected
            expected_actual = initial_mask if ignore_mask_writes else expected
            assert int(actual, 16) == expected_actual
            assert int(captured_status, 16) == status
            observed = [int(w, 16) for w in raw.split()]
            predicted = list(base_pending)
            if routing != 'no-route':
                for source, hwirq in routes.items():
                    if source & status & expected_actual:
                        predicted[hwirq // 32] |= 1 << (hwirq % 32)
            if routing == 'edge-latched':
                seen_pending = [a | b for a,b in zip(seen_pending, predicted)]
                predicted = seen_pending
            assert observed == predicted, (name, requested, observed, predicted)
        if name == 'modern-level-routing':
            (ROOT / 'example-emulated-output.txt').write_text(text, newline='')
    return {'name': name, 'address': hex(address), 'return_code': expected_rc,
            'external_non_uart_write_addresses': ['0x1b100a28'] if writes else [],
            'mask_writes': [f'{v:08x}' for v in writes],
            'original_mask_restored_before_uart': True,
            'gic_configuration_and_dma_configuration_read_only': True,
            'abi_and_code_unchanged': True, 'uart_status_reads': status_reads,
            'uart_bytes_written': len(output)}


cases = [
    run_case('modern-level-routing'),
    run_case('relocated-delayed-uart', address=0x40230000, uart='delayed'),
    run_case('legacy-layout-captured-without-assuming-modern', status=0x104,
             routes={4:257, 0x100:255}),
    run_case('no-latched-events', status=0),
    run_case('no-visible-gic-route', routing='no-route'),
    run_case('edge-latched-pending-is-reported', routing='edge-latched'),
    run_case('mask-readback-not-assumed', ignore_mask_writes=True),
    run_case('final-mask-readback-mismatch-detected', bad_final_readback=True, expected_guard=7),
    run_case('cpu-irq-enabled-guard', cpsr=0x13, expected_guard=2),
    run_case('cpu-fiq-enabled-guard', cpsr=0x93, expected_guard=2),
    run_case('active-dma-guard', cfg=0x1455, expected_guard=3),
    run_case('busy-dma-guard', cfg=0x141A, expected_guard=3),
    run_case('nonzero-mask-guard', initial_mask=0x10000, expected_guard=4),
    run_case('different-gic-size-guard', typer=0xFC67, expected_guard=5),
    run_case('wrong-cpu-part-guard', midr=0x410FC090, expected_guard=6),
    run_case('wrong-cpu-implementer-guard', midr=0x420FC073, expected_guard=6),
    run_case('uart-unavailable-mask-already-restored', uart='timeout'),
    run_case('uart-stops-mid-output-mask-already-restored', uart='late-timeout'),
]
report = {'binary_bytes':len(PAYLOAD), 'binary_sha256':hashlib.sha256(PAYLOAD).hexdigest(),
          'scope':'actual ARM binary, Cortex-A7 Unicorn model, mocked FE/GIC/UART; physical IRQ route and device/cache timing unverified',
          'cases_passed':len(cases), 'cases':cases}
(ROOT / 'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'binary_bytes':len(PAYLOAD),
                  'binary_sha256':report['binary_sha256']},indent=2))
