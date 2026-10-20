/* SPDX-License-Identifier: GPL-2.0-only
 * Experimental ARMv7-A Linux RAM handoff for Archer C80 v1 / MT7626.
 * Uses the standard CLIDR/CCSIDR set/way maintenance algorithm.
 * Entry via U-Boot go at a fresh address, with identity-mapped DDR as in BSP.
 * zImage=0x40800000, FDT=0x40700000. Successful handoff does not return.
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text, "ax", %progbits
.balign 4
.global _start
.type _start, %function
_start:
    push    {r4-r11, r12, lr}
    adr     r0, .Lbanner
    bl      puts
    cmp     r0, #0
    bne     .Lreturn_error
    ldr     r0, =0x40800000
    ldr     r1, [r0, #0x24]
    ldr     r2, =0x016f2818
    cmp     r1, r2
    bne     .Lbad_image
    ldr     r0, =0x40700000
    ldr     r1, [r0]
    ldr     r2, =0xedfe0dd0      /* FDT magic bytes d0 0d fe ed on LE CPU. */
    cmp     r1, r2
    bne     .Lbad_image
    adr     r0, .Lstarting
    bl      puts
    cmp     r0, #0
    bne     .Lreturn_error
    pop     {r4-r11, r12, lr}

    /* From this point no return to U-Boot. Preserve dirty RAM before MMU off. */
    cpsid   if
    dsb     sy
    bl      clean_invalidate_dcache
    mov     r0, #0
    mcr     p15, 0, r0, c7, c5, 0   /* ICIALLU. */
    mcr     p15, 0, r0, c7, c5, 6   /* BPIALL. */
    dsb     sy
    isb     sy
    mrc     p15, 0, r0, c1, c0, 0
    bic     r0, r0, #1             /* MMU off. */
    bic     r0, r0, #4             /* D-cache off. */
    bic     r0, r0, #0x800         /* Branch prediction off. */
    bic     r0, r0, #0x1000        /* I-cache off. */
    mcr     p15, 0, r0, c1, c0, 0
    isb     sy
    mov     r0, #0
    mcr     p15, 0, r0, c8, c7, 0   /* TLBIALL after identity-map transition. */
    dsb     sy
    isb     sy
    mov     r0, #0                 /* Linux boot protocol. */
    mvn     r1, #0                 /* No legacy machine number. */
    ldr     r2, =0x40700000        /* Physical DTB address. */
    ldr     r3, =0x40800000        /* zImage ARM entry. */
    bx      r3
.Lbad_image:
    adr     r0, .Lbad
    bl      puts
.Lreturn_error:
    mov     r0, #1
    pop     {r4-r11, r12, lr}
    bx      lr
.size _start, . - _start

/* UART output with bounded polling, no reconfiguration. */
.type puts, %function
puts:
    mov     r12, r0
    ldr     r3, =0x11002000
.Lnext:
    ldrb    r1, [r12], #1
    cmp     r1, #0
    beq     .Lput_ok
    movw    r2, #0x4240
    movt    r2, #0x000f
.Lwait:
    ldr     r0, [r3, #0x14]
    tst     r0, #0x20
    bne     .Lsend
    subs    r2, r2, #1
    bne     .Lwait
    mov     r0, #1
    bx      lr
.Lsend:
    str     r1, [r3]
    b       .Lnext
.Lput_ok:
    mov     r0, #0
    bx      lr
.size puts, . - puts

/* IRQ/FIQ already disabled. Use all data/unified levels up to LoC.
 * No stack accesses while cleaning; barriers order completion between levels.
 * CSSELR is restored to L1 data/unified before handing control to Linux.
 */
.type clean_invalidate_dcache, %function
clean_invalidate_dcache:
    mrc     p15, 1, r0, c0, c0, 1   /* CLIDR. */
    ands    r3, r0, #0x07000000
    mov     r3, r3, lsr #23
    beq     .Lclean_done
    mov     r10, #0
.Llevel:
    add     r2, r10, r10, lsr #1
    mov     r1, r0, lsr r2
    and     r1, r1, #7
    cmp     r1, #2
    blt     .Lskip_level
    mcr     p15, 2, r10, c0, c0, 0  /* CSSELR. */
    isb     sy
    mrc     p15, 1, r1, c0, c0, 0   /* CCSIDR. */
    and     r2, r1, #7
    add     r2, r2, #4             /* Line size shift. */
    ldr     r4, =0x3ff
    and     r4, r4, r1, lsr #3      /* Associativity minus one. */
    clz     r5, r4
    ldr     r7, =0x7fff
    and     r7, r7, r1, lsr #13     /* Number of sets minus one. */
.Lset:
    mov     r9, r4
.Lway:
    orr     r11, r10, r9, lsl r5
    orr     r11, r11, r7, lsl r2
    mcr     p15, 0, r11, c7, c14, 2 /* DCCISW. */
    subs    r9, r9, #1
    bge     .Lway
    subs    r7, r7, #1
    bge     .Lset
    dsb     sy
.Lskip_level:
    add     r10, r10, #2
    cmp     r10, r3
    blt     .Llevel
.Lclean_done:
    mov     r0, #0
    mcr     p15, 2, r0, c0, c0, 0
    dsb     sy
    isb     sy
    bx      lr
.size clean_invalidate_dcache, . - clean_invalidate_dcache
.ltorg
.balign 4
.Lbanner: .asciz "\r\nC80 Linux RAM handoff v1\r\n"
.balign 4
.Lstarting: .asciz "Images found; preparing CPU and starting Linux...\r\n"
.balign 4
.Lbad: .asciz "Missing zImage/FDT magic; returning to U-Boot.\r\n"
.balign 4
.section .note.GNU-stack, "", %progbits
