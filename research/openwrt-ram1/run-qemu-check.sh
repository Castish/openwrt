#!/usr/bin/env bash
set -euo pipefail
c80_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export LD_LIBRARY_PATH="$c80_root/qemu-tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$c80_root/qemu-tools/usr/bin/qemu-system-arm" \
    -L "$c80_root/qemu-tools/usr/share/qemu" \
    -machine virt,gic-version=2 -cpu cortex-a7 -smp 1 -m 32M \
    -kernel "$c80_root/build-qemu/arch/arm/boot/zImage" \
    -append 'console=ttyAMA0,115200 rdinit=/init panic=0' \
    -display none -serial stdio -monitor none -no-reboot \
    -device virtio-net-device,netdev=c80test \
    -netdev user,id=c80test,restrict=on,net=192.168.0.0/24,host=192.168.0.3,dns=192.168.0.254
