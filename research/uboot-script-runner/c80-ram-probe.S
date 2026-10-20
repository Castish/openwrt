/* SPDX-License-Identifier: MIT
 * Minimal position-independent ARMv7-A program for U-Boot's `go` command.
 * Only hardware write: UART0 THR, using the existing console configuration.
 * The UART map comes from the MT7626/Leopard reference BSP; hardware execution
 * on the user's C80 remains untested. No stack, calls, flash or clock changes.
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text, "ax", %progbits
.balign 4
.global _start
.type _start, %function
_start:
    ldr     r0, =0x11002000       /* BSP UART1 enum = UART0_BASE. */
    adr     r1, .Lmessage
.Lnext:
    ldrb    r2, [r1], #1
    cmp     r2, #0
    beq     .Lsuccess
    movw    r3, #0x4240
    movt    r3, #0x000f          /* 1,000,000 polls per character. */
.Lwait:
    ldr     r12, [r0, #0x14]     /* UART LSR. */
    tst     r12, #0x20           /* Transmit holding register empty. */
    bne     .Lsend
    subs    r3, r3, #1
    bne     .Lwait
    mov     r0, #1               /* No ready indication: return failure. */
    bx      lr
.Lsend:
    str     r2, [r0]             /* UART THR, same 32-bit access as BSP. */
    b       .Lnext
.Lsuccess:
    mov     r0, #0
    bx      lr
.size _start, . - _start
.ltorg
.Lmessage:
    .asciz "\r\nC80 RAM probe v1: ARM code executed; returning to U-Boot.\r\n"
.balign 4
.section .note.GNU-stack, "", %progbits
