# Source and firmware provenance

The new native entry extension, bounded manifest parser, installer and their
build/verification programs are supplied as source, SPDX MIT. The parser is
adapted from this project's earlier MIT RAM runner; it is now linked inside
normal U-Boot and is not a separate downloaded runner.

The original unmodified portions of the OEM U-Boot retain their original
licensing (U-Boot GPL-2.0+). `patch-uboot.py` records the exact original binary
SHA256, the single changed instruction and the appended code. This is a
binary patch of the user's installed2022 C80 normal U-Boot, not a build of
another model's loader. The cached C88 GPL source was reference material;
it is not asserted to be the exact corresponding C80 source/build.

The OEM TPOS/MiniFS contents retain their original OEM licensing. They are
included only inside the required FIRMWARE partition images for this user's
installation and rollback, unchanged. No original factory loader, full-chip
backup, device PROFILE/RADIO/calibration or private hardware logs are included.

The three OpenWrt RAM31 payloads are byte-identical to the separately issued
RAM31 release. Its source, Linux source archive/signature, build records and
package licenses remain in `../openwrt-ram31-scheduler` in the cloud workspace.
Their frozen package manifest is checked before issuing this bundle.
