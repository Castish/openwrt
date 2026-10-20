#!/usr/bin/env bash
set -euo pipefail
auth_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$auth_root"
test ! -f c80-ram-auth-v1.zip
source "$auth_root/../../activate.sh"
auth_parent="$auth_root/../openwrt-ram31-scheduler"
auth_dtc="$auth_parent/build/scripts/dtc/dtc"
auth_overlay="$auth_parent/build/scripts/dtc/fdtoverlay"
python3 make-auth.py
"$auth_dtc" -I dts -O dtb -o auth-initrd.dtbo auth-initrd.dtso
"$auth_dtc" -I dts -O dtb -o qemu-bootargs.dtbo qemu-bootargs.dtso
"$auth_overlay" -i "$auth_parent/c80-openwrt-ram31-scheduler.dtb" -o c80-openwrt-ram31-auth.dtb auth-initrd.dtbo
"$auth_overlay" -i "$auth_parent/qemu-emi.dtb" -o qemu-auth.dtb auth-initrd.dtbo qemu-bootargs.dtbo
cp -- "$auth_parent/c80-openwrt-ram31-scheduler-zImage" c80-openwrt-ram31-scheduler-zImage
cp -- "$auth_parent/c80-openwrt-ram31-handoff.bin" c80-openwrt-ram31-handoff.bin
python3 - <<'PY'
from pathlib import Path
import hashlib,json,struct,zlib
r=Path('.')
# Test-only r0=0, r1=-1, r2=DTB, pc=zImage; no MT7626 MMIO.
(r/'qemu-bootshim.bin').write_bytes(struct.pack('<6I',0xe3a00000,0xe3e01000,0xe59f2000,0xe59ff000,0x40f00000,0x41000000))
files=[('41000000','c80-openwrt-ram31-scheduler-zImage'),('40f00000','c80-openwrt-ram31-auth.dtb'),('40e00000','c80-openwrt-ram31-handoff.bin'),('40c00000','c80-auth.cpio')]
lines=['C80SCRIPT1','# Password root/openwrt; per-device stable server identity.']
rows=[]
for addr,name in files:
 b=(r/name).read_bytes();lines.append(f'load {addr} {name} {len(b):08x} {zlib.crc32(b):08x}')
 rows.append({'file':name,'address':addr,'bytes':len(b),'crc32':f'{zlib.crc32(b):08x}','sha256':hashlib.sha256(b).hexdigest()})
lines+=['go 40e00000','end'];(r/'c80-start.txt').write_text('\n'.join(lines)+'\n')
(r/'evidence/boot-inputs.json').write_text(json.dumps({'files':rows,'kernel_and_handoff_unchanged':True,'external_CPIO_changes_only_shadow_and_server_keys':True},indent=2)+'\n')
print(json.dumps(rows,indent=2))
PY
