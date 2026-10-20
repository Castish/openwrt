#!/usr/bin/env bash
set -euo pipefail
probe_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
probe_tools=${ARM_BINUTILS_BIN:-"$probe_root/../ram-probe/tools/usr/bin"}
cd -- "$probe_root"
test ! -f c80-connsys-id-probe.zip
"$probe_tools/arm-none-eabi-as" -mcpu=cortex-a7 -o c80-connsys-id-probe.o c80-connsys-id-probe.S
"$probe_tools/arm-none-eabi-ld" --build-id=none -T probe.ld -o c80-connsys-id-probe.elf c80-connsys-id-probe.o
"$probe_tools/arm-none-eabi-objcopy" -O binary --only-section=.text c80-connsys-id-probe.elf c80-connsys-id-probe.bin
"$probe_tools/arm-none-eabi-objdump" -d c80-connsys-id-probe.elf > disassembly.txt
"$probe_tools/arm-none-eabi-readelf" -h -A -r c80-connsys-id-probe.elf > elf-inspection.txt
sha256sum c80-connsys-id-probe.bin c80-connsys-id-probe.S uart-print.S probe.ld > SHA256SUMS
wc -c c80-connsys-id-probe.bin
