#!/usr/bin/env bash
set -euo pipefail
emi_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
emi_parent=${C80_RAM1_ROOT:-"$emi_root/../openwrt-ram1"}
emi_cc=${C80_CPP_CC:-"$emi_parent/tools/usr/bin/arm-linux-gnueabi-gcc"}
emi_dtc=${C80_DTC:-"$emi_parent/build/scripts/dtc/dtc"}
emi_linux=${C80_LINUX_SOURCE:-"$emi_parent/linux-6.12.113"}
emi_output=${1:-"$emi_root/rebuilt-c80-openwrt-ram1-emi.dtb"}
emi_temp=$(mktemp -d "${TMPDIR:-/tmp}/c80-emi-dtb.XXXXXXXX")
trap 'rm -rf -- "$emi_temp"' EXIT
export LD_LIBRARY_PATH="$emi_parent/tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$emi_cc" -E -nostdinc -undef -D__DTS__ -x assembler-with-cpp \
    -I "$emi_linux/include" "$emi_root/mt7626-archer-c80-v1-emi.dts" \
    -o "$emi_temp/source.dts"
"$emi_dtc" -I dts -O dtb -o "$emi_temp/result.dtb" "$emi_temp/source.dts"
python3 - "$emi_temp/result.dtb" "$emi_output" <<'PY'
from pathlib import Path
import hashlib
import sys
data = Path(sys.argv[1]).read_bytes()
assert len(data) == 3364
assert hashlib.sha256(data).hexdigest() == '983672239457797c71451a391e86cb34e7ee83ba705f2fa4218af8d34bc669b2'
with Path(sys.argv[2]).open('xb') as output:
    output.write(data)
print('DTB reproduced byte-for-byte:', sys.argv[2])
PY
