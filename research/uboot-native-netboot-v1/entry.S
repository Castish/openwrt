/* SPDX-License-Identifier: MIT
 * This is appended INSIDE the patched normal U-Boot binary. Its original
 * reset vector branches here before the OEM _start initialises/relocates.
 * The entire stock image remains present. Fallback resumes original _start.
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text.entry,"ax",%progbits
.global c80_netboot_entry
.type c80_netboot_entry,%function
c80_netboot_entry:
    stmdb sp!, {r0-r12,lr}
    mov r0,lr
    add r1,sp,#56
    bl c80_netboot
    ldmia sp!, {r0-r12,lr}
    b 0x41c00044
.size c80_netboot_entry,.-c80_netboot_entry
.section .note.GNU-stack,"",%progbits
