/* SPDX-License-Identifier: MIT */
.syntax unified
.cpu cortex-a7
.arm
.section .text.entry, "ax", %progbits
.global _start
.type _start, %function
_start:
    adr     r12, _start
    ldr     r3, =0x40280000
    cmp     r12, r3
    movne   r0, #2
    bxne    lr
    mov     r2, lr              /* Original do_go() return address. */
    mov     r3, sp
    push    {r4-r12, lr}        /* 40 bytes; retain the caller's alignment. */
    bl      runner_main
    pop     {r4-r12, pc}
.size _start, . - _start
.ltorg
.section .note.GNU-stack, "", %progbits
