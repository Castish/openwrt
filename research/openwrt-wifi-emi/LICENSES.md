# Sources and licenses

The kernel and embedded OpenWrt userspace are byte-identical to the issued
C80 OpenWrt RAM1 image. This bundle only replaces its separate Device Tree.
The local DTS, kernel/driver changes and handoff source are GPL-2.0-only;
Linux's full license texts and the corresponding pristine source are at
https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.113.tar.xz
(SHA-256 e09b6727e5c521253f0d41694900b9c38fb7604db7d35238a8197aa9f7de2428).

The complete local Linux change is source-ram1/linux-mt7626-bringup.patch;
the new separate DTS and its diff are at the bundle root. The source-ram1
directory also retains the kernel configuration, local drivers, handoff,
build scripts, exact package origins/versions/licenses and release feed pins.
See source-ram1/LICENSES.md and AUTHENTICITY.md for upstream sources and the
verified package distribution chain. The original RAM1 bundle retains the
unchanged userspace bootstrap inputs and signed indexes.

No proprietary MediaTek MCU firmware, vendor driver C files, factory firmware,
individual calibration data, or unredacted hardware UART logs are included.
The Wi-Fi research report and parser expose only non-personal metadata.
