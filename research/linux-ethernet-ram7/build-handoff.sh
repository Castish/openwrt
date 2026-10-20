#!/usr/bin/env bash
set -euo pipefail
handoff_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
handoff_tools=${ARM_BINUTILS_BIN:-"$handoff_root/../ram-probe/tools/usr/bin"}
mkdir -p "$handoff_root/artifacts"
"$handoff_tools/arm-none-eabi-as" -mcpu=cortex-a7 -o "$handoff_root/artifacts/handoff.o" "$handoff_root/handoff.S"
"$handoff_tools/arm-none-eabi-ld" --build-id=none -T "$handoff_root/handoff.ld" \
    -o "$handoff_root/artifacts/handoff.elf" "$handoff_root/artifacts/handoff.o"
"$handoff_tools/arm-none-eabi-objcopy" -O binary --only-section=.text \
    "$handoff_root/artifacts/handoff.elf" "$handoff_root/artifacts/c80-linux-ram7-handoff.bin"
"$handoff_tools/arm-none-eabi-objdump" -d "$handoff_root/artifacts/handoff.elf" > "$handoff_root/artifacts/handoff-disassembly.txt"
"$handoff_tools/arm-none-eabi-readelf" -h -A -r "$handoff_root/artifacts/handoff.elf" > "$handoff_root/artifacts/handoff-elf.txt"
wc -c "$handoff_root/artifacts/c80-linux-ram7-handoff.bin"
