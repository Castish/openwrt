# Source and licenses

This experimental bundle combines upstream OpenWrt userspace with a local
Linux C80 board port. Package licenses, origins, versions and upstream URLs
are recorded for all35 packages in openwrt-packages.json.

Linux6.12.113 is GPL-2.0-only, with its normal syscall exception for userspace.
Corresponding pristine source and signature:
https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.113.tar.xz
https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.113.tar.sign
Our complete20-file changes, source files, configuration and build scripts
are included. Local C80 driver changes are GPL-2.0-only.

OpenWrt build/package recipes:
https://git.openwrt.org/openwrt/openwrt/tree/?h=v25.12.5
https://github.com/openwrt/openwrt/tree/v25.12.5
The release feed revisions are in downloads/feeds.buildinfo. Stable package
feeds may have updates beyond those initial release revisions; exact installed
package source versions and origin recipes are in openwrt-packages.json.
OpenWrt upstream source archives are available at https://sources.openwrt.org/.

Key userspace projects include BusyBox (GPL-2.0), musl (MIT), procd, ubus,
netifd, libubox, UCI, ucode, Dropbear and urngd. Their package-specific license
identifiers and source-version commits are retained in the package manifest.
The original notices in included upstream code remain intact.

No proprietary Realtek SDK SerDes initialization code/table or its MCU binary
is redistributed. The switch path uses Linux's existing GPL driver with local
register-control changes and inherits the hardware setup performed by U-Boot.

QEMU/cross compiler binaries are not included. Their Debian package versions
and archive hashes are recorded for verification. Debian source packages:
https://sources.debian.org/src/qemu/
https://sources.debian.org/src/gcc-14/
https://sources.debian.org/src/binutils/

Five unchanged OEM firmware files under rootfs/lib/firmware/c80 come from
the user-supplied Archer C80(RU)_V1_240812.zip. Exact hashes/lengths/origin are
in FIRMWARE-SOURCES.json. They are embedded in the RAM initramfs and keep
the OEM licensing; they are not relicensed as GPL/MIT. This is a private
transformation for the user's own router investigation, not a declaration
of general firmware redistribution rights. No individual calibration, MAC,
password, full TPOS, full flash dump or complete factory U-Boot is bundled.

The unchanged c80-script-runner.bin and its script generator are MIT; see
RUNNER-LICENSE. Corresponding original source bundle is the previously
issued uboot-script-runner/c80-script-runner.zip. Local MCU kernel source,
core, C fault model and Linux source patch are GPL-2.0-only.
