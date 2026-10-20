#!/usr/bin/env bash
set -euo pipefail
bootstrap_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bootstrap_tools=${ARM_TOOLCHAIN_ROOT:-"$bootstrap_root/../linux-bringup/tools"}
export LD_LIBRARY_PATH="$bootstrap_tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
bootstrap_cross="$bootstrap_tools/usr/bin/arm-linux-gnueabi-"
cd -- "$bootstrap_root"
test ! -f c80-connsys-bootstrap.zip
python3 - <<'PY'
import hashlib
from pathlib import Path
for name,digest in [('test_mcu.bin','2ce6788836de35335d5f9cbb6fb86cc8676b788020141b414a25539a18aa429e'),('test_wifi.bin','b1dd35a7c544c162181222bf7770cba3cd225a406eba002181f72b1462b03141')]:
 assert hashlib.sha256((Path('blobs')/name).read_bytes()).hexdigest()==digest,name
PY
"${bootstrap_cross}gcc" -mcpu=cortex-a7 -marm -mfloat-abi=soft -Os -ffixed-r9 \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns \
    -Wall -Wextra -Werror -c bootstrap.c -o bootstrap.o
"${bootstrap_cross}gcc" -mcpu=cortex-a7 -marm -c entry.S -o entry.o
"${bootstrap_cross}gcc" -mcpu=cortex-a7 -marm -c blobs.S -o blobs.o
"${bootstrap_cross}ld" --build-id=none -T bootstrap.ld -o c80-connsys-bootstrap.elf entry.o bootstrap.o blobs.o
"${bootstrap_cross}objcopy" -O binary c80-connsys-bootstrap.elf c80-connsys-bootstrap.bin
"${bootstrap_cross}objdump" -d c80-connsys-bootstrap.elf > disassembly.txt
"${bootstrap_cross}readelf" -h -A -r -S c80-connsys-bootstrap.elf > elf-inspection.txt
"${bootstrap_cross}nm" -n c80-connsys-bootstrap.elf > symbols.txt
sha256sum c80-connsys-bootstrap.bin bootstrap.c entry.S blobs.S bootstrap.ld > SHA256SUMS
wc -c c80-connsys-bootstrap.bin
