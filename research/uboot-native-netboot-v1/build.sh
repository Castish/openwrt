#!/usr/bin/env bash
set -euo pipefail
native_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$native_root"
test ! -f c80-uboot-native-v1.zip
native_tools="$native_root/../linux-bringup/tools"
export LD_LIBRARY_PATH="$native_tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
native_cross="$native_tools/usr/bin/arm-linux-gnueabi-"
"${native_cross}gcc" -mcpu=cortex-a7 -marm -mfloat-abi=soft -Os -ffixed-r9 \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie \
 -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Werror \
 -c netboot.c -o netboot.o
"${native_cross}gcc" -mcpu=cortex-a7 -marm -c entry.S -o entry.o
"${native_cross}ld" --build-id=none -T hook.ld -o netboot.elf entry.o netboot.o
"${native_cross}objcopy" -O binary --only-section=.text netboot.elf netboot-hook.bin
"${native_cross}objdump" -d netboot.elf > disassembly.txt
"${native_cross}readelf" -h -A -r netboot.elf > elf-inspection.txt
"${native_cross}nm" -n netboot.elf > symbols.txt
python3 patch-uboot.py
python3 make-firmware.py
"${native_cross}gcc" -mcpu=cortex-a7 -marm -mfloat-abi=soft -Os -ffixed-r9 \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie \
 -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Werror \
 -c install.c -o install.o
"${native_cross}gcc" -mcpu=cortex-a7 -marm -c install-entry.S -o install-entry.o
"${native_cross}ld" --build-id=none -T install.ld -o install.elf install-entry.o install.o
"${native_cross}objcopy" -O binary --only-section=.text install.elf c80-uboot-install.bin
"${native_cross}objdump" -d install.elf > installer-disassembly.txt
"${native_cross}nm" -n install.elf > installer-symbols.txt
