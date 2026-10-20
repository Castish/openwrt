#!/usr/bin/env python3
"""Execute the actual issued C80 zImage FDT memory-selection code on Cortex-A7.

No reimplementation of Linux's selection algorithm: map the issued binary and
call its fdt_check_mem_start(), whose symbol is checked against its build ELF.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_R0, UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_CPSR

base = Path(__file__).resolve().parent
parent = base
previous=base.parent/'openwrt-ram1'
data = (base / 'c80-openwrt-ram24-tx-free-zImage').read_bytes()
assert data==(base/'build/arch/arm/boot/zImage').read_bytes()
symbols = subprocess.check_output([
    str(base.parent / 'ram-probe/tools/usr/bin/arm-none-eabi-nm'), '-n',
    str(parent / 'build/arch/arm/boot/compressed/vmlinux')], text=True)
entry = int(next(line.split()[0] for line in symbols.splitlines()
                 if line.endswith(' T fdt_check_mem_start')), 16)
assert 0 < entry < 0x10000
# Prove that ELF code is the byte-identical code in the issued raw zImage.
elf = (parent / 'build/arch/arm/boot/compressed/vmlinux').read_bytes()
header = struct.unpack_from('<16sHHIIIIIHHHHHH', elf)
segments = [struct.unpack_from('<8I', elf, header[5] + n * header[9])
            for n in range(header[10])]
segment = next(s for s in segments if s[0] == 1)
assert segment[2] == 0 and elf[segment[1]:segment[1] + segment[4]] == data

def run(name, fdt, guessed, expected, pointer=0x40f00000):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.mem_map(0, 0x400000)
    cpu.mem_write(0, data)
    cpu.mem_map(0x40f00000, 0x100000)
    cpu.mem_write(0x40f00000, fdt)
    cpu.mem_map(0x41ff0000, 0x10000)
    sentinel = 0x41ef0000
    cpu.mem_map(sentinel, 0x1000)
    cpu.reg_write(UC_ARM_REG_CPSR, 0xd3)
    cpu.reg_write(UC_ARM_REG_R0, guessed)
    cpu.reg_write(UC_ARM_REG_R1, pointer)
    cpu.reg_write(UC_ARM_REG_SP, 0x41fff000)
    cpu.reg_write(UC_ARM_REG_LR, sentinel)
    returned = False
    def hook(uc, pc, size, userdata):
        nonlocal returned
        if pc == sentinel:
            returned = True
            uc.emu_stop()
    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.emu_start(entry, sentinel + 4, timeout=2_000_000, count=1_000_000)
    actual = cpu.reg_read(UC_ARM_REG_R0)
    assert returned and actual == expected, (name, returned, hex(actual), hex(expected))
    return {'case': name, 'guessed_memory_base': hex(guessed),
            'returned_memory_base': hex(actual), 'kernel_entry': hex(actual + 0x8000)}

old = (previous / 'artifacts/c80-openwrt-ram1.dtb').read_bytes()
new = (base / 'c80-openwrt-ram24-tx-free.dtb').read_bytes()
results = [run('original32MiB', old, 0x40000000, 0x40000000),
           run('C80-EMI-excluded', new, 0x40000000, 0x40200000),
           run('C80-EMI-already-correct', new, 0x40200000, 0x40200000),
           run('C80-wrong-guessed-range', new, 0x42000000, 0x40200000),
           run('null-fdt-fallback', b'\0' * 40, 0x40000000, 0x40000000, pointer=0),
           run('bad-fdt-fallback', b'\0' * 40, 0x40000000, 0x40000000)]
report = {'scope': __doc__, 'passed': True, 'zimage_sha256': hashlib.sha256(data).hexdigest(),
          'fdt_check_mem_start_offset': hex(entry), 'checks': results,
          'full_cpu_cache_behavior_emulated': False}
(base / 'evidence/decompressor-result.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'Actual C80 decompressor code passed {len(results)} memory-selection cases; new kernel entry 0x40208000.')
