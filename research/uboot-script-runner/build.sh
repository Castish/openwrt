#!/usr/bin/env bash
set -euo pipefail
runner_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
runner_tools=${ARM_TOOLCHAIN_ROOT:-"$runner_root/../linux-bringup/tools"}
export LD_LIBRARY_PATH="$runner_tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
runner_cross="$runner_tools/usr/bin/arm-linux-gnueabi-"
cd -- "$runner_root"
test ! -f c80-script-runner.zip
"${runner_cross}gcc" -mcpu=cortex-a7 -marm -mfloat-abi=soft -Os -ffixed-r9 \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Werror \
    -c runner.c -o runner.o
"${runner_cross}gcc" -mcpu=cortex-a7 -marm -c entry.S -o entry.o
"${runner_cross}ld" --build-id=none -T runner.ld -o c80-script-runner.elf entry.o runner.o
"${runner_cross}objcopy" -O binary --only-section=.text c80-script-runner.elf c80-script-runner.bin
"${runner_cross}objdump" -d c80-script-runner.elf > disassembly.txt
"${runner_cross}readelf" -h -A -r c80-script-runner.elf > elf-inspection.txt
"${runner_cross}nm" -n c80-script-runner.elf > symbols.txt
"${runner_cross}gcc" --version | head -1
sha256sum c80-script-runner.bin runner.c entry.S runner.ld > SHA256SUMS
wc -c c80-script-runner.bin
