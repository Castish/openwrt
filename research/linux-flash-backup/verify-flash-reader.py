#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute real ARM init under Unicorn; fake MTD reads, check all backup bytes.

Requires the private 128-KiB backup as --tail; no private data is printed or saved.
This is a syscall model, not hardware validation of the flash mapping.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zlib
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parent
ELF = (ROOT / 'build/userspace/init').read_bytes()
HEADER = struct.unpack_from('<16sHHIIIIIHHHHHH', ELF)
ENTRY, PHOFF, PHSIZE, PHCOUNT = HEADER[4], HEADER[5], HEADER[9], HEADER[10]
SEGMENTS = [struct.unpack_from('<8I', ELF, PHOFF + n * PHSIZE) for n in range(PHCOUNT)]
spec = importlib.util.spec_from_file_location('decode_flash', ROOT / 'decode-flash.py')
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


def run_case(name, flash, command='backup\n', short_io=False, mtd_flags=0,
             mtd_size=0x400000, error_after=None, change_after_scan=False):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    pages = set()
    for kind, off, address, physical, filesz, memsz, flags, align in SEGMENTS:
        if kind == 1:
            pages.update(range(address & ~4095, (address + memsz + 4095) & ~4095, 4096))
    for page in pages:
        cpu.mem_map(page, 4096)
    for kind, off, address, physical, filesz, memsz, flags, align in SEGMENTS:
        if kind == 1:
            cpu.mem_write(address, ELF[off:off + filesz])
    cpu.mem_map(0x70000000, 65536)
    cpu.mem_write(0x70000000, b'\x5a' * 4096)
    cpu.reg_write(UC_ARM_REG_CPSR, 0x10)
    cpu.reg_write(UC_ARM_REG_SP, 0x70010000)
    incoming, output = bytearray(command.encode()), bytearray()
    opened, next_fd, seeks, mtd_reads = {}, 3, 0, 0
    console_levels = []
    interrupted_read = interrupted_write = False

    def string(address):
        chars = bytearray()
        for i in range(256):
            ch = cpu.mem_read(address + i, 1)[0]
            if not ch:
                return chars.decode()
            chars.append(ch)
        raise AssertionError('Unterminated path')

    def syscall(uc, interrupt, data):
        nonlocal next_fd, seeks, mtd_reads, interrupted_read, interrupted_write
        assert interrupt == 2
        nr = uc.reg_read(UC_ARM_REG_R7)
        a, b, c, d, e = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                                       UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4)]
        rc = 0
        if nr == 5:
            path = string(a)
            assert path in ('/dev/console', '/dev/mtd0ro', '/proc/mtd'), path
            assert b == (2 if path == '/dev/console' else 0), 'Flash opened writable'
            rc = next_fd; next_fd += 1; opened[rc] = [path, 0]
        elif nr == 63:
            assert a in opened and b in (0, 1, 2)
            rc = b
        elif nr == 21:
            assert string(c) in ('devtmpfs', 'proc', 'sysfs')
        elif nr == 103:
            assert a == 8 and b == 0 and c in (1, 8)
            console_levels.append(c)
        elif nr == 54:
            assert opened[a][0] == '/dev/mtd0ro' and b == 0x80204d01
            uc.mem_write(c, struct.pack('<B3x5IQ', 2, mtd_flags, mtd_size, 0x400000, 1, 0, 0))
        elif nr == 19:
            assert opened[a][0] == '/dev/mtd0ro' and b == c == 0
            opened[a][1] = 0; seeks += 1
        elif nr == 4:
            assert a == 1, 'Unexpected write destination'
            if short_io and not interrupted_write:
                interrupted_write = True; rc = -4
            else:
                rc = min(c, 19) if short_io else c
                output.extend(uc.mem_read(b, rc))
        elif nr == 3:
            if a == 0:
                if not incoming:
                    uc.emu_stop()
                else:
                    assert c == 1
                    uc.mem_write(b, bytes(incoming[:1])); del incoming[:1]; rc = 1
            else:
                path, position = opened[a]
                if path == '/dev/mtd0ro':
                    mtd_reads += 1
                    if short_io and not interrupted_read:
                        interrupted_read = True; rc = -4
                        uc.reg_write(UC_ARM_REG_R0, rc & 0xffffffff); return
                    if error_after is not None and position >= error_after:
                        rc = -5
                        uc.reg_write(UC_ARM_REG_R0, rc & 0xffffffff); return
                    limit = min(c, 97) if short_io else c
                    chunk = flash[position:position + limit]
                    if change_after_scan and seeks > 1 and position == 0:
                        chunk = bytes([chunk[0] ^ 1]) + chunk[1:]
                else:
                    chunk = b'dev: size erasesize name\nmtd0: 00400000 00400000 "rom"\n'[position:position + c]
                if chunk:
                    uc.mem_write(b, chunk)
                opened[a][1] += len(chunk); rc = len(chunk)
        elif nr == 6:
            opened.pop(a, None)
        else:
            raise AssertionError(f'Unexpected syscall {nr}')
        uc.reg_write(UC_ARM_REG_R0, rc & 0xffffffff)

    cpu.hook_add(UC_HOOK_INTR, syscall)
    cpu.emu_start(ENTRY, 0, count=500_000_000)
    assert not incoming and output.endswith(b'c80-linux> '), 'Did not finish commands'
    assert bytes(cpu.mem_read(0x70000000, 4096)) == b'\x5a' * 4096
    assert console_levels == ([1, 8] if name in ('full-backup', 'changed-between-reads') else [])
    text = output.decode('ascii')
    if name == 'full-backup':
        assert decoder.decode(io.StringIO(text)) == flash
        assert f'FLASH_CRC32={zlib.crc32(flash):08x}' in text
    elif name == 'short-io-and-eintr':
        assert 'Known flash-tail CRCs match.' in text
    else:
        assert 'ERROR:' in text and 'C80FLASH END' not in text
        if name != 'changed-between-reads':
            assert 'C80FLASH BEGIN' not in text
        if name in ('writable-device', 'wrong-size'):
            assert mtd_reads == 0
    result = {'case': name, 'status': 'pass', 'stdout_bytes': len(output),
              'mtd_read_calls': mtd_reads, 'only_readonly_flash_open': True}
    return result, text if name == 'full-backup' else None


def decoder_tests(log, flash):
    lines = log.splitlines(True)
    first = next(i for i, line in enumerate(lines) if line.startswith('F '))
    end = next(i for i, line in enumerate(lines) if line.startswith('C80FLASH END'))
    good = lines[first]
    offset, encoded, crc = good.split()[1:]
    bad_line_crc = good[:-9] + '00000000\n'
    replacements = {
        'missing-line': lines[:first + 1] + lines[first + 2:],
        'repeated-line': lines[:first] + [good] + lines[first:],
        'bad-block-crc': lines[:first] + [bad_line_crc] + lines[first + 1:],
        'bad-base64': lines[:first] + [good[:11] + '!' + good[12:]] + lines[first + 1:],
        'bad-footer-crc': lines[:end] + ['C80FLASH END 00400000 00000000\n'] + lines[end + 1:],
        'truncated-footer': lines[:end],
        'truncated-data': lines[:first + 5],
        'multiple-backups': lines + lines,
    }
    passed = []
    for name, damaged in replacements.items():
        try:
            decoder.decode(iter(damaged))
        except ValueError:
            passed.append(name)
        else:
            raise AssertionError(f'Decoder accepted {name}')
    assert decoder.decode(io.StringIO(log.replace('\n', '\r\n'))) == flash
    passed.append('crlf-log')
    with tempfile.TemporaryDirectory(prefix='c80-backup-test-') as directory:
        path = Path(directory)
        (path / 'uart.log').write_text(log)
        run = subprocess.run([sys.executable, str(ROOT / 'decode-flash.py'), str(path / 'uart.log'), '-o', str(path / 'flash.bin')], capture_output=True)
        assert run.returncode == 0 and (path / 'flash.bin').read_bytes() == flash
        assert (path / 'flash.bin').stat().st_mode & 0o777 == 0o600
        run = subprocess.run([sys.executable, str(ROOT / 'decode-flash.py'), str(path / 'uart.log'), '-o', str(path / 'flash.bin')], capture_output=True)
        assert run.returncode != 0 and (path / 'flash.bin').read_bytes() == flash
        (path / 'damaged.log').write_text(''.join(replacements['missing-line']))
        run = subprocess.run([sys.executable, str(ROOT / 'decode-flash.py'), str(path / 'damaged.log'), '-o', str(path / 'damaged.bin')], capture_output=True)
        assert run.returncode != 0 and not (path / 'damaged.bin').exists()
    return passed + ['cli-private-output', 'cli-no-overwrite', 'cli-no-output-on-corruption']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tail', type=Path, required=True)
    args = parser.parse_args()
    tail = args.tail.read_bytes()
    assert len(tail) == 0x20000 and zlib.crc32(tail) == 0x0fe62f63
    # Synthetic leading bytes, private authentic tail: no test capture is retained.
    flash = (bytes(range(256)) * (0x3e0000 // 256)) + tail
    cases = []
    result, log = run_case('full-backup', flash)
    cases.append(result)
    for name, data, options in [
        ('short-io-and-eintr', flash, {'command': 'flash\n', 'short_io': True}),
        ('writable-device', flash, {'mtd_flags': 0x400}),
        ('wrong-size', flash, {'mtd_size': 0x800000}),
        ('bad-tail-crc', flash[:-1] + bytes([flash[-1] ^ 1]), {}),
        ('read-error', flash, {'error_after': 0x3000}),
        ('changed-between-reads', flash, {'change_after_scan': True}),
    ]:
        result, _ = run_case(name, data, **options)
        cases.append(result)
    result = {'scope': __doc__, 'init_sha256': hashlib.sha256(ELF).hexdigest(),
              'arm_syscall_cases': cases, 'decoder_cases': decoder_tests(log, flash),
              'hardware_mapping_tested': False, 'private_fixture_included': False}
    (ROOT / 'artifacts/flash-reader-verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
