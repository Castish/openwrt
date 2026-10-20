/* SPDX-License-Identifier: MIT
 * ARMv7-A U-Boot `go` diagnostic. Reads CP15 identification/control registers
 * and memory-mapped flash. Writes only its stack and the configured UART THR.
 * No flash, clock, MMU, cache, interrupt or serial configuration changes.
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text, "ax", %progbits
.balign 4
.global _start
.type _start, %function

.macro show_cp15 label, op1, crn, crm, op2
    adr     r0, \label
    bl      puts
    mrc     p15, \op1, r0, \crn, \crm, \op2
    bl      hex32
    bl      newline
.endm

.macro show_crc label, address, length
    adr     r0, \label
    bl      puts
    ldr     r0, =\address
    ldr     r1, =\length
    bl      crc32
    bl      hex32
    bl      newline
.endm

_start:
    push    {r4-r8, lr}          /* 24 bytes; preserve 8-byte stack alignment. */
    mrs     r7, cpsr
    ldr     r4, =0x11002000      /* Console base validated by first RAM probe. */
    mov     r8, #0               /* Sticky UART timeout status. */
    adr     r0, .Lbanner
    bl      puts
    show_cp15 .Lmidr, 0, c0, c0, 0
    show_cp15 .Lmpidr, 0, c0, c0, 5
    show_cp15 .Lsctlr, 0, c1, c0, 0
    show_cp15 .Lctr, 0, c0, c0, 1
    show_cp15 .Lcntfrq, 0, c14, c0, 0
    adr     r0, .Lcpsr
    bl      puts
    mov     r0, r7
    bl      hex32
    bl      newline
    show_crc .Ltail, 0x303e0000, 0x20000
    show_crc .Lprofile, 0x303fe000, 0x1000
    show_crc .Lradio, 0x303ff000, 0x1000
    adr     r0, .Ldone
    bl      puts
    mov     r0, r8
    pop     {r4-r8, lr}
    bx      lr
.size _start, . - _start

/* r1=character; r4=UART; r8=sticky status. Clobbers r2/r3 and flags. */
.type putc, %function
putc:
    cmp     r8, #0
    bxne    lr
    movw    r2, #0x4240
    movt    r2, #0x000f
.Lpoll:
    ldr     r3, [r4, #0x14]
    tst     r3, #0x20
    bne     .Lsend
    subs    r2, r2, #1
    bne     .Lpoll
    mov     r8, #1
    bx      lr
.Lsend:
    str     r1, [r4]
    bx      lr
.size putc, . - putc

.type puts, %function
puts:
    push    {r5, lr}
    mov     r5, r0
.Lputs_next:
    ldrb    r1, [r5], #1
    cmp     r1, #0
    beq     .Lputs_done
    bl      putc
    b       .Lputs_next
.Lputs_done:
    pop     {r5, pc}
.size puts, . - puts

/* r0=value; print eight lowercase hexadecimal digits. */
.type hex32, %function
hex32:
    push    {r5-r7, lr}
    mov     r5, r0
    mov     r6, #8
    adr     r7, .Ldigits
.Lhex_next:
    mov     r1, r5, lsr #28
    ldrb    r1, [r7, r1]
    bl      putc
    lsl     r5, r5, #4
    subs    r6, r6, #1
    bne     .Lhex_next
    pop     {r5-r7, pc}
.size hex32, . - hex32

.type newline, %function
newline:
    adr     r0, .Lcrlf
    b       puts
.size newline, . - newline

/* CRC-32/ISO-HDLC: matches Python zlib.crc32 (init/xorout ffffffff).
 * r0=start, r1=length (nonzero at all call sites); result r0.
 */
.type crc32, %function
crc32:
    push    {r5, lr}
    ldr     r5, =0xedb88320
    mvn     r2, #0
.Lcrc_byte:
    ldrb    r3, [r0], #1
    eor     r2, r2, r3
    mov     r3, #8
.Lcrc_bit:
    tst     r2, #1
    lsr     r2, r2, #1
    eorne   r2, r2, r5
    subs    r3, r3, #1
    bne     .Lcrc_bit
    subs    r1, r1, #1
    bne     .Lcrc_byte
    mvn     r0, r2
    pop     {r5, pc}
.size crc32, . - crc32
.ltorg
.balign 4
.Lbanner: .asciz "\r\nC80 read-only diagnostics v1\r\n"
.balign 4
.Lmidr: .asciz "MIDR="
.balign 4
.Lmpidr: .asciz "MPIDR="
.balign 4
.Lsctlr: .asciz "SCTLR="
.balign 4
.Lctr: .asciz "CTR="
.balign 4
.Lcntfrq: .asciz "CNTFRQ="
.balign 4
.Lcpsr: .asciz "CPSR="
.balign 4
.Ltail: .asciz "FLASH_TAIL_CRC32="
.balign 4
.Lprofile: .asciz "PROFILE_3FE000_CRC32="
.balign 4
.Lradio: .asciz "RADIO_3FF000_CRC32="
.balign 4
.Ldone: .asciz "DONE\r\n"
.balign 4
.Lcrlf: .asciz "\r\n"
.balign 4
.Ldigits: .ascii "0123456789abcdef"
.balign 4
.section .note.GNU-stack, "", %progbits
