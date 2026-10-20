#!/usr/bin/env python3
"""Execute the built ARM init ELF with mocked Linux syscalls; no kernel boot."""
from pathlib import Path
import hashlib
import json
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parent
ELF = (ROOT / 'build/userspace/init').read_bytes()
header = struct.unpack_from('<16sHHIIIIIHHHHHH', ELF)
assert ELF[:7] == b'\x7fELF\x01\x01\x01' and header[1:3] == (2, 40)
entry, phoff, phsize, phcount = header[4], header[5], header[9], header[10]
segments = [struct.unpack_from('<8I', ELF, phoff + n * phsize) for n in range(phcount)]
assert all(s[0] != 3 for s in segments), 'Unexpected dynamic interpreter'


def run_case(name, commands, proc_error=False, network_error=None):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    pages = set()
    for kind, off, address, physical, filesz, memsz, flags, align in segments:
        if kind == 1:
            pages.update(range(address & ~4095, (address + memsz + 4095) & ~4095, 4096))
    for page in pages:
        cpu.mem_map(page, 4096)
    for kind, off, address, physical, filesz, memsz, flags, align in segments:
        if kind == 1:
            cpu.mem_write(address, ELF[off:off + filesz])
    cpu.mem_map(0x70000000, 65536)
    cpu.mem_write(0x70000000, b'\x5a' * 4096)
    cpu.reg_write(UC_ARM_REG_CPSR, 0x10)
    cpu.reg_write(UC_ARM_REG_SP, 0x70010000)
    incoming = bytearray(commands.encode())
    output = bytearray()
    fake_files = {'/proc/version': b'Linux test version\n', '/proc/cpuinfo': b'ARM test CPU\n',
                  '/proc/meminfo': b'MemTotal: 28000 kB\n', '/proc/interrupts': b'30: 7 arch_timer\n'}
    fake_files.update({'/proc/net/dev': b'eth0: 120 2 0 0 0 0 0 0 120 2 0 0 0 0 0 0\n', '/proc/net/arp': b'192.168.0.3 neighbour\n', '/sys/class/net/eth0/device/ram_state': b'pdma=00001455 irq_mask=00000000\n', '/sys/class/net/eth0/carrier': b'1\n'})
    opened = {}
    network_calls = []
    network_flags = 0x1002
    network_interrupted = False
    next_fd = 3
    read_interrupted = write_interrupted = False
    numbers = set()
    mounts = []

    def string(address):
        value = bytearray()
        for i in range(256):
            c = cpu.mem_read(address + i, 1)[0]
            if c == 0:
                return value.decode()
            value.append(c)
        raise AssertionError('Unterminated path')

    def syscall(uc, interrupt, data):
        nonlocal next_fd, read_interrupted, write_interrupted, network_flags, network_interrupted
        assert interrupt == 2
        nr = uc.reg_read(UC_ARM_REG_R7)
        a, b, c, d, e = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                                  UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4)]
        numbers.add(nr)
        rc = 0
        if nr == 281:
            assert (a, b, c) == (2, 2, 0)
            if network_error == 'socket':
                rc = -97
            else:
                rc = next_fd; next_fd += 1; opened[rc] = ['socket', 0]
        elif nr == 54:
            assert opened[a][0] == 'socket'
            request = bytes(uc.mem_read(c, 32))
            assert request[:16] == b'eth0' + bytes(12)
            if not network_interrupted:
                network_interrupted = True; rc = -4
            elif network_error == 'interface':
                rc = -19
            elif network_error == 'bringup' and b == 0x8914:
                rc = -16
            else:
                network_calls.append(b)
                if b in (0x8916, 0x891c):
                    assert request[16:20] == b'\x02\0\0\0'
                    assert request[20:24] == (b'\xc0\xa8\0\x01' if b == 0x8916 else b'\xff\xff\xff\0')
                elif b == 0x8913:
                    uc.mem_write(c + 16, struct.pack('<H', network_flags))
                elif b == 0x8914:
                    network_flags = struct.unpack_from('<H', request, 16)[0]
                else:
                    raise AssertionError(('Unknown network ioctl', b))
        elif nr == 5:
            path = string(a)
            if path != '/dev/console' and (path not in fake_files or proc_error):
                rc = -2
            else:
                rc = next_fd
                next_fd += 1
                opened[rc] = [path, 0]
        elif nr == 63:
            assert a in opened and b in (0, 1, 2)
            rc = b
        elif nr == 21:
            fs = string(c)
            mounts.append(fs)
            rc = -1 if fs == 'proc' and proc_error else 0
        elif nr == 4:
            assert a == 1
            if not write_interrupted:
                write_interrupted = True
                rc = -4
            else:
                rc = min(c, 7)
                output.extend(uc.mem_read(b, rc))
        elif nr == 3:
            if a == 0:
                if not read_interrupted:
                    read_interrupted = True
                    rc = -4
                elif not incoming:
                    uc.emu_stop()
                else:
                    assert c == 1
                    uc.mem_write(b, bytes(incoming[:1]))
                    del incoming[:1]
                    rc = 1
            else:
                path, position = opened[a]
                chunk = fake_files[path][position:position + min(c, 13)]
                if chunk:
                    uc.mem_write(b, chunk)
                opened[a][1] += len(chunk)
                rc = len(chunk)
        elif nr == 6:
            opened.pop(a, None)
        else:
            raise AssertionError(f'Unexpected syscall {nr}')
        uc.reg_write(UC_ARM_REG_R0, rc & 0xFFFFFFFF)

    cpu.hook_add(UC_HOOK_INTR, syscall)
    cpu.emu_start(entry, 0, count=2_000_000)
    assert not incoming
    assert output.endswith(b'c80-linux> ')
    assert b'C80 Linux RAM userspace ready.' in output
    assert bytes(cpu.mem_read(0x70000000, 4096)) == b'\x5a' * 4096
    assert mounts == ['devtmpfs', 'proc', 'sysfs']
    if proc_error:
        assert b'procfs mount failed' in output and b'Cannot open' in output
    elif name == 'network-commands':
        assert network_calls == [0x8916, 0x891c, 0x8913, 0x8914, 0x8913, 0x8914]
        assert network_flags & 1 == 0
        assert b'interface up.' in output and b'eth0 is down.' in output
        assert b'pdma=00001455' in output and b'192.168.0.3 neighbour' in output
    elif network_error:
        assert b'errno=' in output and b'interface up.' not in output
        assert all(path != 'socket' for path, _ in opened.values())
    elif name == 'commands-and-short-io':
        for contents in [fake_files[n] for n in ('/proc/version', '/proc/cpuinfo', '/proc/meminfo', '/proc/interrupts')]:
            assert contents in output, contents
        assert b'Unknown command' in output
    else:
        assert b'Unknown command' in output and b'Commands: help' in output
    return {'name': name, 'syscalls': sorted(numbers), 'stdout_bytes': len(output), 'status': 'pass'}


result = {'scope': __doc__, 'init_bytes': len(ELF), 'init_sha256': hashlib.sha256(ELF).hexdigest(),
          'cases': [run_case('commands-and-short-io', 'help\nversion\ncpu\nmem\nirq\nunknown\n'),
                    run_case('overlong-command', 'a' * 100 + '\nhelp\n'),
                    run_case('procfs-failure', 'mem\n', True),
                    run_case('network-commands', 'netup\nnet\nnetdown\n'),
                    run_case('network-socket-failure', 'netup\nhelp\n', network_error='socket'),
                    run_case('network-interface-missing', 'netup\nhelp\n', network_error='interface'),
                    run_case('network-bringup-failure', 'netup\nhelp\n', network_error='bringup')]}
(ROOT / 'artifacts/userspace-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
