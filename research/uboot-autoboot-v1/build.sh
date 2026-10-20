#!/usr/bin/env bash
set -euo pipefail
boot_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$boot_root"
test ! -f c80-autoboot-v1.zip
boot_tools="$boot_root/../linux-bringup/tools"
export LD_LIBRARY_PATH="$boot_tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
boot_cross="$boot_tools/usr/bin/arm-linux-gnueabi-"
"${boot_cross}gcc" -mcpu=cortex-a7 -marm -mfloat-abi=soft -Os -ffixed-r9 \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Werror \
    -c boot.c -o boot.o
"${boot_cross}gcc" -mcpu=cortex-a7 -marm -c entry.S -o entry.o
"${boot_cross}ld" --build-id=none -T boot.ld -o c80-autoboot.elf entry.o boot.o
"${boot_cross}objcopy" -O binary --only-section=.text c80-autoboot.elf c80-autoboot.bin
"${boot_cross}objdump" -d c80-autoboot.elf > disassembly.txt
"${boot_cross}readelf" -h -A -r c80-autoboot.elf > elf-inspection.txt
"${boot_cross}nm" -n c80-autoboot.elf > symbols.txt
wc -c c80-autoboot.bin
