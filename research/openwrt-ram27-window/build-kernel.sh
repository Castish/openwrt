#!/usr/bin/env bash
set -euo pipefail
c80_mcu_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$c80_mcu_root/../../activate.sh"
export LD_LIBRARY_PATH="$c80_mcu_root/../linux-bringup/tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
c80_mcu_cross="$c80_mcu_root/../linux-bringup/tools/usr/bin/arm-linux-gnueabi-"
c80_mcu_src="$c80_mcu_root/linux-6.12.113"
c80_mcu_out="$c80_mcu_root/build"
test ! -f "$c80_mcu_root/c80-openwrt-ram27-window.zip"
export KBUILD_BUILD_TIMESTAMP='Sun Oct 18 13:00:00 UTC 2026'
export KBUILD_BUILD_USER=agent KBUILD_BUILD_HOST=c80-cloud KBUILD_BUILD_VERSION=1
mkdir -p "$c80_mcu_out"
python3 "$c80_mcu_root/prepare-kernel.py"
python3 "$c80_mcu_root/make-initramfs-list.py"
make -C "$c80_mcu_src" O="$c80_mcu_out" ARCH=arm CROSS_COMPILE="$c80_mcu_cross" allnoconfig
KCONFIG_CONFIG="$c80_mcu_out/.config" "$c80_mcu_src/scripts/kconfig/merge_config.sh" \
    -m "$c80_mcu_out/.config" "$c80_mcu_root/minimal.config"
"$c80_mcu_src/scripts/config" --file "$c80_mcu_out/.config" \
    --set-str INITRAMFS_SOURCE "$c80_mcu_root/initramfs.list"
make -C "$c80_mcu_src" O="$c80_mcu_out" ARCH=arm CROSS_COMPILE="$c80_mcu_cross" olddefconfig
python3 - "$c80_mcu_out/.config" <<'PY'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text()
for n in ('POWER_RESET_C80','C80_MCU_TRANSPORT_TEST','OF_RESERVED_MEM','FW_LOADER','C80_RAM_ETH',
          'MTD_ROM','MTD_PHYSMAP_OF','SERIAL_8250_MT6577','NET_DSA_REALTEK_RTL8365MB'):
 assert f'CONFIG_{n}=y\n' in text,n
for n in ('SMP','ARM_LPAE','HIGHMEM','VFP','NEON','SPI','MTD_SPI_NOR',
          'MTD_CFI','MTD_JEDECPROBE','MTD_RAM','MTD_BLOCK','MODULES','WLAN'):
 assert f'CONFIG_{n}=y\n' not in text,n
PY
make -C "$c80_mcu_src" O="$c80_mcu_out" ARCH=arm CROSS_COMPILE="$c80_mcu_cross" \
    -j"${OPENWRT_BUILD_JOBS:-4}" zImage dtbs
