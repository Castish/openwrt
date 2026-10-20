#!/usr/bin/env python3
"""Execute the actual ARM probe with a Clause22/Realtek SMI model.

Checks ABI, relocation, bounded waits, register allowlist, sequencing and
cleanup before UART. Does not model physical MDIO wires/cache timing.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parent
PAYLOAD = (ROOT / 'c80-switch-probe.bin').read_bytes()
FE, UART, STACK, RETURN = 0x1b100000, 0x11002000, 0x41fe0000, 0x41f00000
PRESERVED = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
             UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR]
PORT_REGS = [0x1352 + p for p in [0, 1, 2, 3, 4, 6]]
PORT_VALUES = [0x16, 0, 0, 0, 0, 0x16]


def run_case(name, *, address=0x40240000, cpsr=0x600001d3, midr=0x410fc073,
             cfg=0x1410, mask=0, magic=0, chip_id=0x6367, chip_ver=0xa0,
             initial_busy=False, no_slave=False, ignore_unlock=False,
             ignore_restore=False, inconsistent_id=False, inconsistent_ver=False,
             timeout_at=None, permanent_busy=False, uart='ready',
             changed_cfg=False, changed_mdio_config=False,
             expected_rc=0, expected_cleanup=0, initial_mdio=0, mdio_config=0xc5000100,
             retain_command_bits=True, repeats=1, port_samples=None):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.mem_map(address, 4096)
    cpu.mem_write(address, PAYLOAD)
    cpu.mem_protect(address, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(STACK, 4096)
    cpu.mem_write(STACK, b'\x5a' * 4096)
    cpu.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
    cpu.reg_write(UC_ARM_REG_CPSR, cpsr)
    original_cpsr = cpu.reg_read(UC_ARM_REG_CPSR)
    saved = {reg: 0x45000000 + i * 0x100 for i, reg in enumerate(PRESERVED)}
    saved[UC_ARM_REG_SP] = STACK + 4096
    saved[UC_ARM_REG_LR] = RETURN
    for reg, value in saved.items():
        cpu.reg_write(reg, value)

    state = {'magic': magic, 'mdio': 0x80000000 if initial_busy else initial_mdio,
             'cfg': cfg, 'mask': mask, 'mdio_config': mdio_config,
             'phase': 'idle', 'address': None, 'data': None,
             'read_value': None, 'busy_reads': 0, 'readback': initial_mdio,
             'issued': [], 'logical_writes': [], 'logical_reads': [],
             'writes': [], 'uart_reads': 0, 'uart_seen': False}
    output = bytearray()
    staged_command = None

    def switch_read(reg):
        state['logical_reads'].append(reg)
        if no_slave:
            return 0xffff
        if reg == 0x13c2:
            return state['magic']
        if reg in [0x1300, 0x1301]:
            assert state['magic'] == 0x249, 'ID/version must be read with access key'
            count = state['logical_reads'].count(reg)
            if reg == 0x1300:
                return chip_id ^ (1 if inconsistent_id and count == 2 else 0)
            return chip_ver ^ (1 if inconsistent_ver and count == 2 else 0)
        assert reg in PORT_REGS
        assert chip_id == 0x6367 and chip_ver == 0xa0
        assert state['magic'] == magic, 'Restore key before normal port-status reads'
        return port_values[PORT_REGS.index(reg)]

    def execute_command(command):
        # Independent, literal Clause22 fields from the reviewed BSP protocol.
        assert command & 0x80000000 == 0
        assert (command >> 16) & 3 == 1  # Clause22 ST
        assert (command >> 20) & 31 == 29
        op, reg, value = (command >> 18) & 3, (command >> 25) & 31, command & 0xffff
        assert op in [1, 2]
        if op == 2:
            assert reg == 25 and value == 0 and state['phase'] == 'read-data'
            state['phase'] = 'idle'
            return state['read_value']
        assert reg in [31, 23, 21, 24]
        if reg == 31:
            assert value == 14
            state['phase'] = 'address'
        elif reg == 23:
            assert state['phase'] == 'address'
            assert value in [0x13c2, 0x1300, 0x1301] + PORT_REGS
            state['address'], state['phase'] = value, 'op-or-data'
        elif reg == 24:
            assert state['phase'] == 'op-or-data' and state['address'] == 0x13c2
            assert value in [0x249, magic]
            state['data'], state['phase'] = value, 'write-op'
        elif value == 1:
            assert state['phase'] == 'op-or-data'
            state['read_value'] = switch_read(state['address'])
            state['phase'] = 'read-data'
        else:
            assert value == 3 and state['phase'] == 'write-op'
            assert state['address'] == 0x13c2
            index = len(state['logical_writes'])
            state['logical_writes'].append((state['address'], state['data']))
            if not (ignore_unlock and index == 0 or ignore_restore and index == 1):
                state['magic'] = state['data']
            state['phase'] = 'idle'
        return value

    def read_fe(uc, offset, size, data):
        assert size == 4
        if offset == 0xa04:
            return state['cfg']
        if offset == 0xa28:
            return state['mask']
        if offset == 0x10000:
            return state['mdio_config']
        assert offset == 0x10004, ('unexpected FE read', hex(offset))
        if state['busy_reads']:
            state['busy_reads'] -= 1
            return state['mdio'] | 0x80000000
        if state['issued'] and timeout_at == len(state['issued']) and permanent_busy:
            return state['mdio'] | 0x80000000
        if initial_busy:
            return 0x80000000
        state['mdio'] = state['readback']
        return state['mdio']

    def write_fe(uc, offset, size, value, data):
        nonlocal staged_command
        assert not state['uart_seen'], 'No management work may follow UART output'
        assert size == 4 and offset == 0x10004, ('forbidden FE write', hex(offset))
        assert cpu.reg_read(UC_ARM_REG_CPSR) & 0xff == 0xd3
        assert state['cfg'] == 0x1410 and state['mask'] == 0
        state['writes'].append((FE + offset, value))
        if not value & 0x80000000:
            assert staged_command is None
            staged_command = value
            return
        assert staged_command is not None and value == staged_command | 0x80000000
        command = staged_command
        staged_command = None
        assert not state['busy_reads']
        state['issued'].append(command)
        result = execute_command(command)
        state['readback'] = (command & ~0xffff if retain_command_bits else 0) | result
        state['mdio'] = value
        state['busy_reads'] = 1_000_000 if len(state['issued']) == timeout_at else 2
        if len(state['issued']) == 60:
            if changed_cfg:
                state['cfg'] = 0x1455
            if changed_mdio_config:
                state['mdio_config'] ^= 1

    def assert_before_uart():
        assert staged_command is None
        assert all(a == 0x13c2 for a, v in state['logical_writes'])
        if expected_cleanup & (1 | 4):
            assert state['magic'] == 0x249
        else:
            assert state['magic'] == magic
        if not expected_cleanup & 8:
            assert state['cfg'] == cfg
        assert state['mask'] == mask

    def read_uart(uc, offset, size, data):
        assert offset == 0x14 and size == 4
        assert_before_uart()
        state['uart_seen'] = True
        state['uart_reads'] += 1
        if uart == 'timeout' or uart == 'late-timeout' and len(output) >= 100:
            return 0
        if uart == 'delayed' and state['uart_reads'] < 100:
            return 0
        return 0x20

    def write_uart(uc, offset, size, value, data):
        assert offset == 0 and size == 4 and state['uart_seen']
        output.append(value & 255)

    def inject_midr(uc, pc, size, data):
        uc.reg_write(UC_ARM_REG_R0, midr)
        uc.reg_write(UC_ARM_REG_PC, pc + 4)

    # Only MIDR is injected; actual instruction execution/loops/cleanup remain.
    midr_instructions = [i for i in range(0, len(PAYLOAD) - 3, 4)
                         if struct.unpack_from('<I', PAYLOAD, i)[0] == 0xee100f10]
    assert len(midr_instructions) == 1
    pc = address + midr_instructions[0]
    cpu.hook_add(UC_HOOK_CODE, inject_midr, begin=pc, end=pc)
    cpu.mmio_map(FE, 0x20000, read_fe, None, write_fe, None)
    cpu.mmio_map(UART, 4096, read_uart, None, write_uart, None)
    iterations = []
    for iteration in range(repeats):
        if iteration:
            # Reset audit bookkeeping only. Device registers, SMI phase/data,
            # CPU, caller registers, stack and executable memory are retained.
            for key in ['issued', 'logical_writes', 'logical_reads', 'writes']:
                state[key].clear()
            state['uart_reads'] = 0
            state['uart_seen'] = False
            output.clear()
        entry_mdio = state['readback'] if not initial_busy else 0x80000000
        port_values = port_samples[iteration] if port_samples else PORT_VALUES
        assert len(port_values) == 6
        cpu.emu_start(address, RETURN, count=20_000_000)
        assert cpu.reg_read(UC_ARM_REG_PC) == RETURN, name
        for reg, value in saved.items():
            assert cpu.reg_read(reg) == value, (name, reg)
        assert cpu.reg_read(UC_ARM_REG_CPSR) == original_cpsr
        assert bytes(cpu.mem_read(address, len(PAYLOAD))) == PAYLOAD
        assert bytes(cpu.mem_read(STACK, 3840)) == b'\x5a' * 3840, 'Stack use must stay below 256 bytes'
        expected_return = 1 if 'timeout' in uart else expected_rc
        assert cpu.reg_read(UC_ARM_REG_R0) == expected_return, (name, cpu.reg_read(UC_ARM_REG_R0), expected_return)
        assert_before_uart()
        if 'timeout' in uart:
            assert state['uart_reads'] == 1_000_000 + len(output)
            assert len(output) == (100 if uart == 'late-timeout' else 0)
        else:
            text = output.decode('ascii')
            assert text.startswith('\r\nC80 switch MDIO probe v1\r\n') and text.endswith('DONE\r\n')
            fields = {k: int(v, 16) for k, v in re.findall(r'^([A-Z0-9_]+)=([0-9a-f]{8})\r?$', text, re.M)}
            assert len(fields) == 24
            assert fields['RESULT_RC'] == expected_rc and fields['CLEANUP_ERRORS'] == expected_cleanup
            assert fields['CPSR_BEFORE'] == fields['CPSR_AFTER'] == original_cpsr
            assert fields['PDMA_CFG_BEFORE'] == cfg and fields['PDMA_CFG_AFTER'] == state['cfg']
            assert fields['PDMA_MASK_BEFORE'] == fields['PDMA_MASK_AFTER'] == mask
            assert fields['MDIO_COMMANDS'] == len(state['issued'])
            assert fields['MDIO_BEFORE'] == entry_mdio
            assert fields['MDIO_AFTER'] == state['mdio']
            if expected_rc in [2, 3, 4, 5, 6]:
                assert not state['writes'] and not state['logical_reads']
            if expected_rc == 0:
                assert fields['MAGIC_BEFORE'] == fields['MAGIC_AFTER'] == magic
                assert fields['MAGIC_UNLOCKED'] == 0x249
                assert fields['CHIP_ID_1'] == fields['CHIP_ID_2'] == chip_id
                assert fields['CHIP_VER_1'] == fields['CHIP_VER_2'] == chip_ver
                assert fields['PORTS_VALID'] == 6 and len(state['issued']) == 60
                assert state['logical_writes'] == [(0x13c2, 0x249), (0x13c2, magic)]
                ports = re.search(r'^PORT_STATUS_0_1_2_3_4_6=(.*?)\r?$', text, re.M)
                assert [int(v, 16) for v in ports[1].split()] == port_values
            if name == 'rtl8367s-normal':
                (ROOT / 'example-emulated-output.txt').write_text(text, newline='')
        result = {'name': name, 'status': 'pass', 'load_address': hex(address),
                  'result_rc': expected_rc, 'cleanup_errors': expected_cleanup,
                  'return_code': expected_return, 'mdio_transactions': len(state['issued']),
                  'mdio_mmio_writes': len(state['writes']), 'switch_data_writes': state['logical_writes'],
                  'uart_reads': state['uart_reads'], 'uart_bytes': len(output),
                  'cleanup_verified_before_uart': True, 'abi_cpsr_code_preserved': True,
                  'writes_outside_mdio_command_and_uart': False,
                  'iteration': iteration + 1, 'entry_mdio': hex(entry_mdio),
                  'port_status': [hex(v) for v in port_values]}
        print(name, iteration + 1, 'pass', flush=True)
        iterations.append(result)
    return iterations[0] if repeats == 1 else {
        'name': name, 'status': 'pass', 'successive_invocations': repeats,
        'same_cpu_memory_and_device_state_between_calls': True,
        'iterations': iterations,
    }


if __name__ == '__main__':
    cases = [
        run_case('rtl8367s-normal'),
        run_case('relocated-and-delayed-uart', address=0x40250000, uart='delayed'),
        run_case('preserve-existing-key', magic=0x249),
        run_case('preserve-nzcv', cpsr=0xa00001d3),
        run_case('irq-unmasked-refuse', cpsr=0x60000153, expected_rc=2),
        run_case('fiq-unmasked-refuse', cpsr=0x60000193, expected_rc=2),
        run_case('cpu-implementer-refuse', midr=0x510fc073, expected_rc=3),
        run_case('cpu-part-refuse', midr=0x410fc053, expected_rc=3),
        run_case('active-dma-refuse', cfg=0x1455, expected_rc=4),
        run_case('busy-dma-refuse', cfg=0x141a, expected_rc=4),
        run_case('irq-mask-refuse', mask=0x10001, expected_rc=5),
        run_case('mdio-busy-refuse', initial_busy=True, expected_rc=6),
        run_case('no-slave-refuse-before-unlock', no_slave=True, expected_rc=7),
        run_case('unexpected-key-refuse', magic=0x1234, expected_rc=7),
        run_case('ignored-unlock-cleanup', ignore_unlock=True, expected_rc=9),
        run_case('unstable-chip-id-cleanup', inconsistent_id=True, expected_rc=11),
        run_case('unstable-chip-version-cleanup', inconsistent_ver=True, expected_rc=11),
        run_case('unsupported-chip-no-port-reads', chip_id=0x1234, expected_rc=12),
        run_case('unsupported-revision-no-port-reads', chip_ver=0xb0, expected_rc=12),
        run_case('failed-magic-restore-detected', ignore_restore=True, expected_rc=13, expected_cleanup=4),
        run_case('changed-dma-detected', changed_cfg=True, expected_rc=13, expected_cleanup=8),
        run_case('changed-mdio-config-detected', changed_mdio_config=True, expected_rc=13, expected_cleanup=16),
        run_case('timeout-before-unlock', timeout_at=3, expected_rc=8),
        run_case('timeout-partial-unlock-cleanup', timeout_at=5, expected_rc=8),
        run_case('timeout-unconfirmed-unlock-cleanup', timeout_at=8, expected_rc=8),
        run_case('timeout-id-read-cleanup', timeout_at=16, expected_rc=8),
        run_case('timeout-restore-read-detected', timeout_at=36, expected_rc=13, expected_cleanup=2),
        run_case('timeout-port-read-after-key-restored', timeout_at=40, expected_rc=8),
        run_case('permanent-busy-after-unlock-reported', timeout_at=8, permanent_busy=True, expected_rc=8, expected_cleanup=1),
        run_case('uart-timeout-after-cleanup', uart='timeout'),
        run_case('uart-late-timeout-after-cleanup', uart='late-timeout'),
    ]
    report = {'scope': __doc__, 'binary_bytes': len(PAYLOAD),
              'binary_sha256': hashlib.sha256(PAYLOAD).hexdigest(), 'cases_passed': len(cases),
              'physical_hardware_tested': False, 'cases': cases}
    (ROOT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', len(cases), 'actual ARM cases')
