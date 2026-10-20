#!/usr/bin/env bash
set -euo pipefail
diag_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
diag_tools=${ARM_BINUTILS_BIN:-"$diag_root/../ram-probe/tools/usr/bin"}
cd -- "$diag_root"
"$diag_tools/arm-none-eabi-as" -mcpu=cortex-a7 -o c80-readonly-diag.o c80-readonly-diag.S
"$diag_tools/arm-none-eabi-ld" --build-id=none -T diag.ld -o c80-readonly-diag.elf c80-readonly-diag.o
"$diag_tools/arm-none-eabi-objcopy" -O binary --only-section=.text c80-readonly-diag.elf c80-readonly-diag.bin
"$diag_tools/arm-none-eabi-objdump" -d c80-readonly-diag.elf > disassembly.txt
"$diag_tools/arm-none-eabi-readelf" -h -A -r c80-readonly-diag.elf > elf-inspection.txt
sha256sum c80-readonly-diag.bin c80-readonly-diag.S diag.ld > SHA256SUMS
wc -c c80-readonly-diag.bin
