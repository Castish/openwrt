#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
test ! -f "$r/c80-openwrt-ram38-bmc-profile.zip"
export LD_LIBRARY_PATH="$r/../linux-bringup/tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cross="$r/../linux-bringup/tools/usr/bin/arm-linux-gnueabi-"
export KBUILD_BUILD_TIMESTAMP='Wed Oct 21 18:00:00 UTC 2026'
export KBUILD_BUILD_USER=agent KBUILD_BUILD_HOST=c80-cloud KBUILD_BUILD_VERSION=1
python3 "$r/make-qemu-initramfs.py"
python3 - "$r" <<'PY'
from pathlib import Path
import struct,sys
r=Path(sys.argv[1])
(r/'qemu-bootshim.bin').write_bytes(struct.pack('<6I',0xe3a00000,0xe3e01000,0xe59f2000,0xe59ff000,0x40f00000,0x41000000))
PY
test "$(readlink -- "$r/build-qemu")" = /workspace/.openwrt-onboarding/caches/c80-ram38-build-qemu
mkdir -p /workspace/.openwrt-onboarding/caches/c80-ram38-build-qemu
cp "$r/qemu.config" "$r/build-qemu/.config"
"$r/linux-6.12.113/scripts/config" --file "$r/build-qemu/.config" --set-str INITRAMFS_SOURCE "$r/initramfs-qemu.list"
make -C "$r/linux-6.12.113" O="$r/build-qemu" ARCH=arm CROSS_COMPILE="$cross" olddefconfig
make -C "$r/linux-6.12.113" O="$r/build-qemu" ARCH=arm CROSS_COMPILE="$cross" -j"${C80_BUILD_JOBS:-4}" zImage
dtc="$r/build-qemu/scripts/dtc/dtc"
"$dtc" -@ -I dts -O dtb -o "$r/qemu-emi.dtb" "$r/qemu-emi.dts"
"$dtc" -@ -I dts -O dtb -o "$r/qemu-bootargs.dtbo" "$r/qemu-bootargs.dtso"
"$r/build-qemu/scripts/dtc/fdtoverlay" -i "$r/qemu-emi.dtb" -o "$r/qemu-auth.dtb" "$r/qemu-bootargs.dtbo"
