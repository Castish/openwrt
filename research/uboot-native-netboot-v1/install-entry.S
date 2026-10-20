/* SPDX-License-Identifier: MIT */
.syntax unified
.cpu cortex-a7
.arm
.section .text.entry,"ax",%progbits
.global _start
_start:
    adr r12,_start
    ldr r3,=0x40290000
    cmp r12,r3
    movne r0,#2
    bxne lr
    mov r2,lr
    mov r3,sp
    push {r4-r12,lr}
    bl install_main
    pop {r4-r12,pc}
.ltorg
.section .note.GNU-stack,"",%progbits
