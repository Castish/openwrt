#!/usr/bin/env bash
set -euo pipefail
auth_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
auth_parent="$auth_root"
auth_qemu="$auth_root/../openwrt-ram1/qemu-tools"
export LD_LIBRARY_PATH="$auth_qemu/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$auth_qemu/usr/bin/qemu-system-arm" \
 -L "$auth_qemu/usr/share/qemu" \
 -machine virt,gic-version=2 -cpu cortex-a7 -smp 1 -m 32M \
 -device loader,file="$auth_parent/build-qemu/arch/arm/boot/zImage",addr=0x41000000,force-raw=on \
 -device loader,file="$auth_root/qemu-auth.dtb",addr=0x40f00000,force-raw=on \
 -device loader,file="$auth_root/qemu-bootshim.bin",addr=0x40e00000,cpu-num=0,force-raw=on \
 -device loader,file="$auth_root/c80-auth.cpio",addr=0x40d00000,force-raw=on \
 -display none -serial stdio -monitor none -no-reboot \
 -device virtio-net-device,netdev=c80test \
 -netdev user,id=c80test,restrict=on,net=192.168.0.0/24,host=192.168.0.3,dns=192.168.0.254,hostfwd=tcp:127.0.0.1:40223-192.168.0.1:22
