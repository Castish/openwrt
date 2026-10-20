#!/usr/bin/env python3
"""Execute runner ARM bytes and a real RAM probe with modeled U-Boot callbacks.

Checks the callback ABI/r9, relocated-loader profile, complete preflight,
TFTP size/CRC handling, refusal paths, nested go/return and caller state.
This does not emulate C80 Ethernet, loader networking, MMU/cache coherency or
prove the physical loader's relocation/callback behavior. Those need UART.
"""
import hashlib
import json
import argparse
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--factory-uboot', type=Path,
                    help='Optional private verified factory image; also execute its native do_go bytes')
options = parser.parse_args()
oem = options.factory_uboot.read_bytes() if options.factory_uboot else None
payload = (root / 'c80-script-runner.bin').read_bytes()
probe = (root / 'c80-ram-probe.bin').read_bytes()
profile = json.loads((root / 'loader-profile.json').read_text())
if oem is not None:
    assert hashlib.sha256(oem).hexdigest() == profile['uboot_sha256']
example_script = (root / 'c80-start.txt').read_bytes()
symbols = {name: int(address, 16) for address, _, name in
           (line.split() for line in (root / 'symbols.txt').read_text().splitlines())}
BASE, SCRIPT, UART = 0x40280000, 0x40a00000, 0x11002000
PRESERVED = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
             UC_ARM_REG_SP)

def run(name, *, script=example_script, files=None, loader=0x41f00000,
        address=BASE, caller=None, gd=0x41df0000, stack=0x41dff000,
        corrupt_profile=None, corrupt_table=None, expected_rc=0,
        midr=0x410fc073, cpsr=0x600001d3, setenv_rc=0,
        autostart_readback='no', tftp_error=None, sizes=None,
        env_pointer=None, filesize_text=None, go_rc=None,
        uart_ready=True, mutate_after_go=None, native_go=False):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.mem_map(0x40200000, 0x1e00000)
    cpu.mem_write(address, payload)
    for fp in profile['fingerprints']:
        cpu.mem_write(loader + int(fp['offset'], 16), bytes.fromhex(fp['bytes']))
    for command in profile['commands']:
        off, text, fn = [int(command[k], 16) for k in ('entry_offset', 'name_offset', 'function_offset')]
        cpu.mem_write(loader + off, struct.pack('<5I', loader + text, command['maxargs'],
                      command['repeatable'], loader + fn, 0))
        cpu.mem_write(loader + text, command['name'].encode() + b'\0')
    if native_go:
        assert oem is not None
        cpu.mem_write(loader + 0x271c, oem[0x271c:0x2798])
    if corrupt_profile is not None:
        at = loader + int(profile['fingerprints'][corrupt_profile]['offset'], 16)
        cpu.mem_write(at, bytes([cpu.mem_read(at, 1)[0] ^ 1]))
    if corrupt_table is not None:
        at = loader + int(profile['commands'][corrupt_table]['entry_offset'], 16)
        cpu.mem_write(at + 12, struct.pack('<I', loader + 0x100))
    files = {'c80-ram-probe.bin': probe} if files is None else dict(files)
    transfers = {'c80-start.txt': script, **files}
    sizes = sizes or {}
    environment, calls, go_stack, output, writes = {}, [], [], bytearray(), []
    sentinel = (0x41c03000 if native_go else loader + 0x2774) if caller is None else caller
    nested_return = 0x41c01000
    cpu.reg_write(UC_ARM_REG_CPSR, cpsr)
    saved = {reg: 0x45000000 + i * 0x100 for i, reg in enumerate(PRESERVED)}
    saved[UC_ARM_REG_R9] = gd; saved[UC_ARM_REG_SP] = stack
    for reg, value in saved.items(): cpu.reg_write(reg, value)
    cpu.reg_write(UC_ARM_REG_LR, sentinel)
    cpu.reg_write(UC_ARM_REG_R0, 1)
    cpu.reg_write(UC_ARM_REG_R1, 0x41df1000)
    if native_go:
        cpu.mem_write(0x41df1000, struct.pack('<2I', 0x41df1100, 0x41df1200))
        cpu.mem_write(0x41df1100, b'go\0')
        cpu.mem_write(0x41df1200, f'{address:08x}'.encode() + b'\0')
        cpu.reg_write(UC_ARM_REG_R0, loader + 0x29f58)
        cpu.reg_write(UC_ARM_REG_R1, 0)
        cpu.reg_write(UC_ARM_REG_R2, 2)
        cpu.reg_write(UC_ARM_REG_R3, 0x41df1000)
    uart_reads = 0
    def mmio_read(uc, offset, size, unused):
        nonlocal uart_reads
        assert offset == 0x14 and size == 4
        uart_reads += 1
        return 0x20 if uart_ready else 0
    def mmio_write(uc, offset, size, value, unused):
        assert offset == 0 and size == 4 and value <= 255
        output.append(value)
    cpu.mmio_map(UART, 4096, mmio_read, None, mmio_write, None)
    def cstring(pointer, limit=200):
        data = bytes(cpu.mem_read(pointer, limit))
        assert b'\0' in data, ('unterminated string', hex(pointer))
        return data.split(b'\0', 1)[0].decode('ascii')
    def args_at(pointer, count):
        return [cstring(struct.unpack('<I', cpu.mem_read(pointer + 4 * i, 4))[0]) for i in range(count)]
    def finish(rc):
        cpu.reg_write(UC_ARM_REG_R0, rc & 0xffffffff)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
    def hook(uc, pc, size, unused):
        if native_go and pc == loader + 0x19980:
            assert uc.reg_read(UC_ARM_REG_R1) == 0 and uc.reg_read(UC_ARM_REG_R2) == 16
            finish(int(cstring(uc.reg_read(UC_ARM_REG_R0)), 16)); return
        if native_go and pc == loader + 0x4b7c:
            finish(0); return  # Native go's printf only; console modeled separately.
        if pc == nested_return:
            assert go_stack
            callback_return = go_stack.pop()
            result = uc.reg_read(UC_ARM_REG_R0)
            if mutate_after_go is not None:
                uc.mem_write(mutate_after_go, b'\xff')
            uc.reg_write(UC_ARM_REG_LR, callback_return)
            finish(0 if result == 0 else 1)
            return
        if BASE <= pc < BASE + len(payload):
            instruction = struct.unpack('<I', uc.mem_read(pc, 4))[0]
            if instruction & 0xffff0fff == 0xee100f10:  # MRC MIDR to compiler-selected Rd.
                reg = (instruction >> 12) & 15
                uc.reg_write(UC_ARM_REG_R0 + reg, midr)
                uc.reg_write(UC_ARM_REG_PC, pc + 4)
            return
        if pc not in (loader + 0x41e0, loader + 0x4624, loader + 0x37ec, loader + 0x272c):
            return
        assert uc.reg_read(UC_ARM_REG_R9) == gd, 'U-Boot gd/r9 lost before callback'
        assert uc.reg_read(UC_ARM_REG_SP) % 8 == stack % 8, 'callback ABI stack alignment'
        if pc == loader + 0x4624:
            key = cstring(uc.reg_read(UC_ARM_REG_R0)); calls.append(('getenv', key))
            value = environment.get(key)
            if key == 'autostart': value = autostart_readback
            if key == 'filesize' and filesize_text is not None: value = filesize_text
            if value is None: finish(0); return
            ptr = 0x41df4000
            uc.mem_write(ptr, value.encode() + b'\0')
            finish(ptr if env_pointer is None else env_pointer)
            return
        count, vector = uc.reg_read(UC_ARM_REG_R2), uc.reg_read(UC_ARM_REG_R3)
        args = args_at(vector, count)
        calls.append(tuple(args))
        expected_entry = {0x41e0:0x29ff8, 0x37ec:0x2a020, 0x272c:0x29f58}[pc - loader]
        assert uc.reg_read(UC_ARM_REG_R0) == loader + expected_entry
        assert uc.reg_read(UC_ARM_REG_R1) == 0
        if pc == loader + 0x41e0:
            assert args == ['setenv', 'autostart', 'no']
            environment['autostart'] = 'no'
            finish(setenv_rc)
        elif pc == loader + 0x37ec:
            assert args[0] == 'tftpboot' and count == 3
            assert environment['autostart'] == 'no'
            if args[2] == tftp_error or args[2] not in transfers:
                finish(1); return
            dst = int(args[1], 16)
            data = transfers[args[2]]
            uc.mem_write(dst, data)
            environment['filesize'] = f'{sizes.get(args[2], len(data)):x}'
            finish(0)
        else:
            assert args[0] == 'go' and count == 2
            if native_go: return  # Execute the verified OEM ARM do_go()/do_go_exec().
            if go_rc is not None:
                finish(go_rc); return
            go_stack.append(uc.reg_read(UC_ARM_REG_LR))
            uc.reg_write(UC_ARM_REG_R0, 1)
            uc.reg_write(UC_ARM_REG_R1, vector + 4)
            uc.reg_write(UC_ARM_REG_LR, nested_return)
            uc.reg_write(UC_ARM_REG_PC, int(args[1], 16))
    def write_hook(uc, access, absolute, size, value, unused):
        assert (stack - 0x4000 <= absolute < stack or
                SCRIPT <= absolute < SCRIPT + 4097 or absolute == UART), ('unexpected ARM write', hex(absolute))
        writes.append((absolute, size))
    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    cpu.emu_start(loader + 0x272c if native_go else address, sentinel,
                  timeout=20_000_000, count=20_000_000)
    assert cpu.reg_read(UC_ARM_REG_PC) == sentinel, (name, hex(cpu.reg_read(UC_ARM_REG_PC)), output)
    rc = cpu.reg_read(UC_ARM_REG_R0)
    assert rc == expected_rc, (name, rc, expected_rc, output.decode(errors='replace'))
    for reg, value in saved.items(): assert cpu.reg_read(reg) == value, (name, reg)
    assert cpu.reg_read(UC_ARM_REG_CPSR) & 0x3ff == cpsr & 0x3ff
    assert bytes(cpu.mem_read(address, len(payload))) == payload, 'runner code changed'
    if expected_rc:
        assert not any(call[0] == 'go' for call in calls) or expected_rc == 35 or mutate_after_go is not None
    elif address == BASE:
        assert output.endswith(b'SCRIPT_DONE\r\n')
    if not uart_ready: assert uart_reads == 1000000 and not calls
    result = {'name':name, 'rc':rc, 'loader_base':hex(loader), 'native_oem_go_executed':native_go,
              'calls':[list(call) for call in calls], 'callback_r9_and_caller_state_preserved':True}
    return result, output.decode('ascii')

cases = []
def test(name, **kwargs):
    result, output = run(name, **kwargs)
    cases.append(result)
    return output

example = test('nested-real-probe-return')
test('link-base-loader', loader=0x41e00000)
test('high-relocated-loader', loader=0x41fd0000)
test('wrong-runner-address', address=0x40290000, expected_rc=2)
test('wrong-caller', caller=0x41f02778, expected_rc=4)
test('wrong-gd', gd=0x41000000, expected_rc=4)
test('wrong-stack', stack=0x41000000, expected_rc=4)
test('different-cpu', midr=0x410fc075, expected_rc=3)
test('wrong-cpsr', cpsr=0x600000d3, expected_rc=3)
for index in range(5): test(f'corrupt-function-{index}', corrupt_profile=index, expected_rc=5)
for index in range(3): test(f'corrupt-table-{index}', corrupt_table=index, expected_rc=5)
test('setenv-failure', setenv_rc=1, expected_rc=6)
test('autostart-readback-mismatch', autostart_readback='yes', expected_rc=6)
test('env-pointer-outside-loader-ram', env_pointer=0x30000000, expected_rc=6)
test('script-tftp-failure', tftp_error='c80-start.txt', expected_rc=7)
test('script-empty', script=b'', expected_rc=8)
test('script-oversize', script=b'#' * 4097, expected_rc=8)
test('script-crlf-bom', script=b'\xef\xbb\xbf' + example_script.replace(b'\n', b'\r\n'))
test('comments-and-tabs', script=b'# comment\n\nC80SCRIPT1\n\t# ignored\nend # inline\n')
test('maximum-script-length', script=b'C80SCRIPT1\nend\n#' + b'x' * (4096 - len(b'C80SCRIPT1\nend\n#')))
loads16 = [f'load {0x40270000 + i*4:08x} zero.bin 4 2144df1c' for i in range(16)]
test('maximum-step-count', script=('C80SCRIPT1\n' + '\n'.join(loads16) + '\nend\n').encode(),
     files={'zero.bin':b'\0' * 4})
test('step-count-overflow', script=('C80SCRIPT1\n' + '\n'.join(loads16) + '\ngo 40270000\nend\n').encode(), expected_rc=24)
test('missing-header', script=b'load 40270000 x 1 0\nend\n', expected_rc=22)
test('missing-end', script=b'C80SCRIPT1\n', expected_rc=31)
test('embedded-nul', script=b'C80SCRIPT1\nend\x00\n', expected_rc=20)
test('command-after-end', script=b'C80SCRIPT1\nend\ngo 40270000\n', expected_rc=23)
for command in (b'erase 30000000', b'cp.b 40270000 30000000 10', b'go 30000000', b'load x.bin 1 1 1', b'load 40270000 ../x 1 1', b'load 40270000 x 100000000 1'):
    expected = 29 if command.startswith(b'go ') else 25 if command.startswith(b'load ') else 30
    test('reject-' + command.decode().replace(' ', '_'), script=b'C80SCRIPT1\n' + command + b'\nend\n', expected_rc=expected)
for a, size in ((0x40000000,4),(BASE,4),(BASE-4,8),(SCRIPT,4),(SCRIPT-4,8),
                (0x41c00000,4),(0x40270001,4),(0xfffffffc,16),(0x40270000,0)):
    test(f'bad-range-{a:08x}-{size:x}', script=f'C80SCRIPT1\nload {a:08x} x {size:x} 0\nend\n'.encode(), expected_rc=26)
test('overlap-preflight-before-download', script=b'C80SCRIPT1\nload 40270000 x 100 0\nload 402700fc y 4 0\nend\n', expected_rc=27)
test('later-unknown-command-prevents-load', script=example_script.replace(b'end\n',b'bad\nend\n'), expected_rc=30)
test('payload-tftp-failure', tftp_error='c80-ram-probe.bin', expected_rc=32)
test('payload-short-size', sizes={'c80-ram-probe.bin':139}, expected_rc=33)
test('payload-long-size', sizes={'c80-ram-probe.bin':141}, expected_rc=33)
test('bad-filesize', filesize_text='not-hex', expected_rc=7)
test('oversized-env-number', filesize_text='123456789012345678', expected_rc=7)
test('payload-CRC-mismatch', files={'c80-ram-probe.bin': b'\0' * len(probe)}, expected_rc=34)
test('application-failure', go_rc=1, expected_rc=35)
test('second-go-rechecks-CRC', script=example_script.replace(b'end\n',b'go 40270000\nend\n'), mutate_after_go=0x40270000, expected_rc=34)
test('uart-never-ready', uart_ready=False, expected_rc=40)
if oem is not None:
    test('actual-oem-go-enters-runner-and-nested-probe', loader=0x41e00000, native_go=True)
    test('actual-relocated-oem-go-enters-runner-and-nested-probe', loader=0x41fd0000, native_go=True)

(root / 'example-emulated-output.txt').write_text(example)
report = {'scope':__doc__, 'passed':True, 'payload_bytes':len(payload),
          'payload_sha256':hashlib.sha256(payload).hexdigest(), 'cases':cases,
          'hardware_runner_tested':False, 'native_TFTP_and_cache_operations':'modeled callbacks, not executed',
          'optional_private_verified_oem_go_test_executed':oem is not None}
(root / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'PASS: {len(cases)} ARM scenarios; nested probe, preflight, CRC and ABI/r9 checks.')
