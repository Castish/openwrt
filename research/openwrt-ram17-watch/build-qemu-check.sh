#!/usr/bin/env bash
# Verification platform only; this kernel must never be issued for the router.
set -euo pipefail
c80_qemu_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$c80_qemu_root/../../activate.sh"
export LD_LIBRARY_PATH="$c80_qemu_root/../linux-bringup/tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export KBUILD_BUILD_TIMESTAMP='Sun Oct 18 13:00:00 UTC 2026'
export KBUILD_BUILD_USER=agent KBUILD_BUILD_HOST=c80-cloud KBUILD_BUILD_VERSION=1
c80_qemu_cross="$c80_qemu_root/../linux-bringup/tools/usr/bin/arm-linux-gnueabi-"
c80_qemu_src="$c80_qemu_root/linux-6.12.113"
c80_qemu_out="$c80_qemu_root/build-qemu"
if [[ ! -d "$c80_qemu_out" ]]; then
    cp -a --reflink=auto "$c80_qemu_root/../openwrt-ram1/build-qemu" "$c80_qemu_out"
fi
"$c80_qemu_src/scripts/config" --file "$c80_qemu_out/.config" \
    --enable ARCH_VIRT --enable SERIAL_AMBA_PL011 --enable SERIAL_AMBA_PL011_CONSOLE \
    --enable VIRTIO_MENU --enable VIRTIO --enable VIRTIO_MMIO --enable VIRTIO_NET \
    --enable COMPAT_32BIT_TIME --disable C80_RAM_ETH --enable MACH_MT7626 \
    --enable C80_MCU_TRANSPORT_TEST --enable POWER_RESET --enable POWER_RESET_C80 --set-str INITRAMFS_SOURCE "$c80_qemu_root/initramfs.list" \
    --set-str LOCALVERSION '-c80-openwrt-ram17-qemu-check'
make -C "$c80_qemu_src" O="$c80_qemu_out" ARCH=arm CROSS_COMPILE="$c80_qemu_cross" olddefconfig
make -C "$c80_qemu_src" O="$c80_qemu_out" ARCH=arm CROSS_COMPILE="$c80_qemu_cross" -j4 zImage
"$c80_qemu_out/scripts/dtc/dtc" -I dts -O dtb \
    -o "$c80_qemu_root/qemu-emi.dtb" "$c80_qemu_root/qemu-emi.dts"
