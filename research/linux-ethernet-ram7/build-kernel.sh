#!/usr/bin/env bash
set -euo pipefail
bringup_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -r "$bringup_root/../../activate.sh" ]]; then
    source "$bringup_root/../../activate.sh"
fi
export LD_LIBRARY_PATH="$bringup_root/tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
bringup_cross=${CROSS_COMPILE:-"$bringup_root/tools/usr/bin/arm-linux-gnueabi-"}
bringup_jobs=${OPENWRT_BUILD_JOBS:-4}
bringup_source="$bringup_root/linux-6.12.113"
bringup_output="$bringup_root/build"
mkdir -p "$bringup_output"
mkdir -p "$bringup_output/userspace"
python3 "$bringup_root/prepare-kernel.py"
"${bringup_cross}gcc" -Os -marm -march=armv7-a -mfloat-abi=soft -fno-pie \
    -fno-builtin -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -nostdlib -static -no-pie -Wl,--build-id=none,-e,_start \
    -o "$bringup_output/userspace/init" "$bringup_root/init.c"
cat > "$bringup_root/initramfs.list" <<EOF
dir /dev 0755 0 0
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /tmp 1777 0 0
nod /dev/console 0600 0 0 c 5 1
nod /dev/null 0666 0 0 c 1 3
file /init $bringup_output/userspace/init 0755 0 0
EOF
make -C "$bringup_source" O="$bringup_output" ARCH=arm CROSS_COMPILE="$bringup_cross" allnoconfig
KCONFIG_CONFIG="$bringup_output/.config" "$bringup_source/scripts/kconfig/merge_config.sh" \
    -m "$bringup_output/.config" "$bringup_root/minimal.config"
"$bringup_source/scripts/config" --file "$bringup_output/.config" \
    --set-str INITRAMFS_SOURCE "$bringup_root/initramfs.list"
make -C "$bringup_source" O="$bringup_output" ARCH=arm CROSS_COMPILE="$bringup_cross" olddefconfig
python3 - "$bringup_output/.config" <<'CHECK'
from pathlib import Path
import sys
config = Path(sys.argv[1]).read_text()
for name in ('MMU', 'ARCH_MULTIPLATFORM', 'ARCH_MULTI_V7', 'ARCH_MEDIATEK',
             'MACH_MT7626', 'CPU_V7', 'ARM_ARCH_TIMER', 'SERIAL_8250_MT6577',
             'SERIAL_8250_CONSOLE', 'BLK_DEV_INITRD', 'AEABI', 'ARM_ERRATA_814220', 'MTD', 'MTD_ROM', 'MTD_PHYSMAP', 'MTD_PHYSMAP_OF', 'NET', 'INET', 'NETDEVICES', 'C80_RAM_ETH', 'MDIO_DEVICE', 'MDIO_BUS', 'PHYLIB', 'NET_DSA', 'NET_DSA_REALTEK_MDIO', 'NET_DSA_REALTEK_RTL8365MB', 'NET_DSA_TAG_RTL8_4'):
    assert f'CONFIG_{name}=y\n' in config, f'Required option missing: {name}'
for name in ('SMP', 'HIGHMEM', 'ARM_LPAE', 'MTD_CFI', 'MTD_JEDECPROBE', 'MTD_SPI_NOR', 'MTD_RAM', 'SPI', 'NET_MEDIATEK_SOC', 'IPV6', 'WLAN', 'CPU_V7M', 'GPIOLIB'):
    assert f'CONFIG_{name}=y\n' not in config, f'Unexpected option: {name}'
print('Required ARMv7-A/MMU/platform/console/timer configuration verified.')
CHECK
make -C "$bringup_source" O="$bringup_output" ARCH=arm CROSS_COMPILE="$bringup_cross" \
    -j"$bringup_jobs" zImage dtbs
