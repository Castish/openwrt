#!/usr/bin/env bash
set -euo pipefail
emi_root=/workspace/.openwrt-onboarding/research/openwrt-ram31-scheduler
emi_parent="$emi_root/../openwrt-ram1"
emi_build="$emi_root/build-qemu"
export LD_LIBRARY_PATH="$emi_parent/qemu-tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$emi_parent/qemu-tools/usr/bin/qemu-system-arm" \
    -L "$emi_parent/qemu-tools/usr/share/qemu" \
    -machine virt,gic-version=2 -cpu cortex-a7 -smp 1 -m 32M \
    -kernel "$emi_build/arch/arm/boot/zImage" \
    -dtb "$emi_root/qemu-emi.dtb" \
    -append 'console=ttyAMA0,115200 rdinit=/init panic=0' \
    -display none -serial stdio -monitor none -no-reboot \
    -device virtio-net-device,netdev=c80test \
    -netdev user,id=c80test,restrict=on,net=192.168.0.0/24,host=192.168.0.3,dns=192.168.0.254,hostfwd=tcp:127.0.0.1:40222-192.168.0.1:22
