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
if [[ -L "$c80_qemu_out" ]]; then
    c80_qemu_cache=$(readlink -- "$c80_qemu_out")
    [[ "$c80_qemu_cache" == /tmp/c80-ram*-build-qemu ]]
    mkdir -p -- "$c80_qemu_cache"
else
    mkdir -p -- "$c80_qemu_out"
fi
if [[ ! -f "$c80_qemu_out/.config" ]]; then
    cp -- "$c80_qemu_root/artifacts/qemu-kernel.config" "$c80_qemu_out/.config"
fi
[[ -d "$c80_qemu_src" ]] || python3 "$c80_qemu_root/restore-source.py"
[[ -f "$c80_qemu_root/rootfs/sbin/procd" && -f "$c80_qemu_root/rootfs/bin/busybox" ]] || python3 "$c80_qemu_root/restore-rootfs.py"
python3 "$c80_qemu_root/prepare-kernel.py"
python3 "$c80_qemu_root/make-qemu-initramfs.py"
"$c80_qemu_src/scripts/config" --file "$c80_qemu_out/.config" \
    --enable C80_NET_SELFTEST --enable ARCH_VIRT --enable SERIAL_AMBA_PL011 --enable SERIAL_AMBA_PL011_CONSOLE \
    --enable VIRTIO_MENU --enable VIRTIO --enable VIRTIO_MMIO --enable VIRTIO_NET \
    --enable COMPAT_32BIT_TIME --disable C80_RAM_ETH --enable MACH_MT7626 \
    --enable C80_MCU_TRANSPORT_TEST --enable POWER_RESET --enable POWER_RESET_C80 --set-str INITRAMFS_SOURCE "$c80_qemu_root/initramfs-qemu.list" \
    --set-str LOCALVERSION '-c80-openwrt-ram30-qemu-check'
make -C "$c80_qemu_src" O="$c80_qemu_out" ARCH=arm CROSS_COMPILE="$c80_qemu_cross" olddefconfig
make -C "$c80_qemu_src" O="$c80_qemu_out" ARCH=arm CROSS_COMPILE="$c80_qemu_cross" -j4 zImage
"$c80_qemu_out/scripts/dtc/dtc" -I dts -O dtb \
    -o "$c80_qemu_root/qemu-emi.dtb" "$c80_qemu_root/qemu-emi.dts"
