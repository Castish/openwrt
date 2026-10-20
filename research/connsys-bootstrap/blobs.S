/* Own layout glue: SPDX-License-Identifier: MIT.
 * Embedded blobs are unchanged files from the user's supplied OEM firmware;
 * this license does not relicense those files. See FIRMWARE-SOURCES.json.
 */
.section .mcu,"a",%progbits
.global firmware_mcu
firmware_mcu:
.incbin "blobs/test_mcu.bin"
.section .wifi,"a",%progbits
.global firmware_wifi
firmware_wifi:
.incbin "blobs/test_wifi.bin"
.section .backup,"aw",%progbits
.global ddr_backup
ddr_backup:
.space 0x200000,0
.section .note.GNU-stack,"",%progbits
