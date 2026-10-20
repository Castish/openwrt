#!/usr/bin/env bash
set -euo pipefail
c80_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$c80_root/../../activate.sh"
export LD_LIBRARY_PATH="$c80_root/tools/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
c80_cross="$c80_root/tools/usr/bin/arm-linux-gnueabi-"
c80_source="$c80_root/linux-6.12.113"
c80_output="$c80_root/build"
mkdir -p "$c80_output"
python3 "$c80_root/prepare-kernel.py"
python3 "$c80_root/make-initramfs-list.py"
make -C "$c80_source" O="$c80_output" ARCH=arm CROSS_COMPILE="$c80_cross" allnoconfig
KCONFIG_CONFIG="$c80_output/.config" "$c80_source/scripts/kconfig/merge_config.sh" \
    -m "$c80_output/.config" "$c80_root/minimal.config"
"$c80_source/scripts/config" --file "$c80_output/.config" \
    --set-str INITRAMFS_SOURCE "$c80_root/initramfs.list"
make -C "$c80_source" O="$c80_output" ARCH=arm CROSS_COMPILE="$c80_cross" olddefconfig
python3 - "$c80_output/.config" <<'PY'
from pathlib import Path
import sys
config = Path(sys.argv[1]).read_text()
required = ('MMU','AEABI','MACH_MT7626','ARM_ARCH_TIMER','ARM_ERRATA_814220',
            'SERIAL_8250_MT6577','SERIAL_8250_CONSOLE','BLK_DEV_INITRD','TMPFS',
            'PROC_FS','SYSFS','BINFMT_ELF','BINFMT_SCRIPT','FUTEX','EPOLL',
            'EVENTFD','SIGNALFD','TIMERFD','COMPAT_32BIT_TIME','UNIX','PACKET','UNIX98_PTYS',
            'INET','C80_RAM_ETH','NET_DSA_REALTEK_RTL8365MB','NET_DSA_TAG_RTL8_4',
            'MTD','MTD_ROM','MTD_PHYSMAP_OF','SECCOMP','SECCOMP_FILTER','CGROUPS')
for name in required:
    assert f'CONFIG_{name}=y\n' in config, name
for name in ('SMP','HIGHMEM','ARM_LPAE','VFP','NEON','SPI','MTD_SPI_NOR',
             'MTD_CFI','MTD_JEDECPROBE','MTD_RAM','MTD_BLOCK','MODULES','WLAN'):
    assert f'CONFIG_{name}=y\n' not in config, name
print('OpenWrt ABI/event/socket APIs and C80 read-only NOR constraints verified.')
PY
make -C "$c80_source" O="$c80_output" ARCH=arm CROSS_COMPILE="$c80_cross" \
    -j"${OPENWRT_BUILD_JOBS:-4}" zImage dtbs
