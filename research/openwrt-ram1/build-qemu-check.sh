#!/usr/bin/env bash
# Only the verification kernel uses QEMU drivers. It is never issued for C80.
set -euo pipefail
c80_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$c80_root/../../activate.sh"
export LD_LIBRARY_PATH="$c80_root/tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
c80_cross="$c80_root/tools/usr/bin/arm-linux-gnueabi-"
c80_source="$c80_root/linux-6.12.113"
c80_output="$c80_root/build-qemu"
if [[ ! -d "$c80_output" ]]; then
    cp -a --reflink=auto "$c80_root/build" "$c80_output"
fi
"$c80_source/scripts/config" --file "$c80_output/.config" \
    --enable ARCH_VIRT --enable SERIAL_AMBA_PL011 --enable SERIAL_AMBA_PL011_CONSOLE \
    --enable VIRTIO_MENU --enable VIRTIO --enable VIRTIO_MMIO --enable VIRTIO_NET \
    --enable COMPAT_32BIT_TIME \
    --disable C80_RAM_ETH --disable MACH_MT7626 \
    --set-str LOCALVERSION '-c80-openwrt-qemu-check'
make -C "$c80_source" O="$c80_output" ARCH=arm CROSS_COMPILE="$c80_cross" olddefconfig
make -C "$c80_source" O="$c80_output" ARCH=arm CROSS_COMPILE="$c80_cross" -j4 zImage
