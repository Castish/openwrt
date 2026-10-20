/* SPDX-License-Identifier: MIT */
.syntax unified
.cpu cortex-a7
.arm
.section .text.entry,"ax",%progbits
.global _start
.type _start,%function
_start:
    adr ip,_start
    ldr r3,=0x41c00000
    cmp ip,r3
    movne r0,#2
    bxne lr
    mov r0,lr
    mov r1,sp
    push {r4-r12,lr}
    bl boot_main
    cmp r0,#1
    pop {r4-r12,lr}
    bxne lr
    ldr ip,=0x40270000
    ldr r0,[ip,#4]
    mov r1,#0
    mov r2,#2
    add r3,ip,#8
    ldr ip,[ip]
    bx ip
.size _start,.-_start
.ltorg
.section .rodata.runner,"a",%progbits
.balign 4
.global runner_begin,runner_end
runner_begin:
.incbin "c80-script-runner.bin"
runner_end:
.section .note.GNU-stack,"",%progbits
