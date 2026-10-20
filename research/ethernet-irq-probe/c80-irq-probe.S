/* SPDX-License-Identifier: MIT
 * Position-independent ARM U-Boot `go` diagnostic for the measured C80.
 * External writes: UART THR and, only after guards pass, PDMA IRQ_MASK.
 * DMA remains halted; GIC/IRQ polarity, status, clocks, flash are read-only.
 * Restore IRQ_MASK before any UART output (including the timeout path).
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text, "ax", %progbits
.balign 4
.global _start
.type _start, %function
.equ FRAME_SIZE, 640
.equ ENABLE_OFFSET, 80
.equ CONFIG_OFFSET, 116
.equ SAMPLE_OFFSET, 192
.equ SAMPLE_SIZE, 48

_start:
    push    {r4-r12, lr}
    sub     sp, sp, #FRAME_SIZE
    mov     r10, sp
    ldr     r4, =0x11002000
    ldr     r9, =0x1b100000
    ldr     r11, =0x10310000
    mov     r8, #0
    mrs     r0, cpsr
    str     r0, [r10, #0]
    mrc     p15, 0, r0, c0, c0, 0
    str     r0, [r10, #4]
    ldr     r0, [r11, #0]
    str     r0, [r10, #8]
    ldr     r0, [r11, #4]
    str     r0, [r10, #12]
    ldr     r0, [r9, #0xa04]
    str     r0, [r10, #16]
    ldr     r0, [r9, #0xa20]
    str     r0, [r10, #20]
    ldr     r0, [r9, #0xa28]
    str     r0, [r10, #24]
    mov     r0, #0
    str     r0, [r10, #36]

    /* Read both modern/legacy FE views without assuming their layout. */
    ldr     r0, [r9, #0x08]
    str     r0, [r10, #40]
    ldr     r0, [r9, #0x0c]
    str     r0, [r10, #44]
    ldr     r0, [r9, #0x10]
    str     r0, [r10, #48]
    ldr     r0, [r9, #0x14]
    str     r0, [r10, #52]
    ldr     r0, [r9, #0x20]
    str     r0, [r10, #56]
    ldr     r0, [r9, #0x24]
    str     r0, [r10, #60]
    ldr     r0, [r9, #0xa50]
    str     r0, [r10, #64]
    ldr     r0, [r9, #0xa54]
    str     r0, [r10, #68]
    ldr     r0, [r9, #0xa00]
    str     r0, [r10, #72]
    ldr     r0, [r9, #0xa0c]
    str     r0, [r10, #76]

    add     r0, r10, #ENABLE_OFFSET
    add     r1, r11, #0x100
    mov     r2, #9
    bl      copy_words
    add     r0, r10, #CONFIG_OFFSET
    add     r1, r11, #0xc00
    mov     r2, #18
    bl      copy_words
    add     r0, r10, #SAMPLE_OFFSET
    ldr     r1, [r10, #24]
    bl      snapshot

    /* GUARD_RC: 2 CPU state; 3 DMA; 4 mask; 5 GIC size; 6 CPU part. */
    ldr     r0, [r10]
    and     r0, r0, #0xff
    cmp     r0, #0xd3             /* ARM SVC, both IRQ and FIQ masked. */
    movne   r0, #2
    bne     guard_failed
    ldr     r0, [r10, #16]
    movw    r1, #0x1410
    cmp     r0, r1
    movne   r0, #3
    bne     guard_failed
    ldr     r0, [r10, #24]
    cmp     r0, #0
    movne   r0, #4
    bne     guard_failed
    ldr     r0, [r10, #12]
    and     r0, r0, #31
    cmp     r0, #8                /* Known GIC exposes 9 * 32 IDs. */
    movne   r0, #5
    bne     guard_failed
    ldr     r0, [r10, #4]
    lsr     r0, r0, #4
    movw    r1, #0xfff
    and     r0, r0, r1
    movw    r1, #0xc07
    cmp     r0, r1
    movne   r0, #6
    bne     guard_failed
    ldr     r0, [r10, #4]
    lsr     r0, r0, #24
    cmp     r0, #0x41
    movne   r0, #6
    bne     guard_failed

    adrl    r5, mask_table
    mov     r6, #7
    add     r7, r10, #(SAMPLE_OFFSET + SAMPLE_SIZE)
sample_next:
    ldr     r1, [r5], #4
    str     r1, [r9, #0xa28]      /* The only non-UART external write. */
    dsb     sy
    mov     r2, #4096
settle:
    subs    r2, r2, #1
    bne     settle
    mov     r0, r7
    bl      snapshot
    add     r7, r7, #SAMPLE_SIZE
    subs    r6, r6, #1
    bne     sample_next
    /* Final table entry restores the guarded original value: zero. */
    b       collection_done
guard_failed:
    str     r0, [r10, #36]
collection_done:
    dsb     sy
    ldr     r0, [r9, #0xa20]
    str     r0, [r10, #28]
    ldr     r0, [r9, #0xa28]
    str     r0, [r10, #32]
    ldr     r1, [r10, #24]
    cmp     r0, r1
    movne   r0, #7
    strne   r0, [r10, #36]

    /* No UART polling happens while a test IRQ mask is enabled. */
    adrl    r0, banner
    bl      puts
    mov     r5, r10
    adrl    r6, meta_labels
    mov     r7, #20
meta_next:
    mov     r0, r6
    bl      puts
    ldr     r0, [r5], #4
    bl      hex32
    bl      newline
label_next:
    ldrb    r0, [r6], #1
    cmp     r0, #0
    bne     label_next
    subs    r7, r7, #1
    bne     meta_next

    adrl    r0, enable_label
    bl      puts
    add     r0, r10, #ENABLE_OFFSET
    mov     r1, #9
    bl      print_words
    adrl    r0, config_label
    bl      puts
    add     r0, r10, #CONFIG_OFFSET
    mov     r1, #18
    bl      print_words

    add     r5, r10, #SAMPLE_OFFSET
    ldr     r0, [r10, #36]
    cmp     r0, #0
    moveq   r7, #8
    movne   r7, #1
print_sample:
    adrl    r0, phase_label
    bl      puts
    ldr     r0, [r5]
    bl      hex32
    adrl    r0, readback_label
    bl      puts
    ldr     r0, [r5, #4]
    bl      hex32
    adrl    r0, status_label
    bl      puts
    ldr     r0, [r5, #8]
    bl      hex32
    bl      newline
    adrl    r0, pending_label
    bl      puts
    add     r0, r5, #12
    mov     r1, #9
    bl      print_words
    add     r5, r5, #SAMPLE_SIZE
    subs    r7, r7, #1
    bne     print_sample
    adrl    r0, done_label
    bl      puts
    ldr     r0, [r10, #36]
    cmp     r8, #0
    movne   r0, #1
    add     sp, sp, #FRAME_SIZE
    pop     {r4-r12, lr}
    bx      lr
.size _start, . - _start

/* r0=destination, r1=source MMIO, r2=word count. */
copy_words:
    ldr     r3, [r1], #4
    str     r3, [r0], #4
    subs    r2, r2, #1
    bne     copy_words
    bx      lr

/* r0=48-byte sample destination; r1=requested mask. */
snapshot:
    str     r1, [r0], #4
    ldr     r2, [r9, #0xa28]
    str     r2, [r0], #4
    ldr     r2, [r9, #0xa20]
    str     r2, [r0], #4
    add     r2, r11, #0x200
    mov     r3, #9
snapshot_next:
    ldr     r12, [r2], #4
    str     r12, [r0], #4
    subs    r3, r3, #1
    bne     snapshot_next
    bx      lr

/* UART: bounded 1,000,000 reads; sticky failure suppresses later output. */
putc:
    cmp     r8, #0
    bxne    lr
    movw    r2, #0x4240
    movt    r2, #0x000f
poll_uart:
    ldr     r3, [r4, #0x14]
    tst     r3, #0x20
    bne     send_uart
    subs    r2, r2, #1
    bne     poll_uart
    mov     r8, #1
    bx      lr
send_uart:
    str     r1, [r4]
    bx      lr

puts:
    push    {r5, lr}
    mov     r5, r0
puts_next:
    ldrb    r1, [r5], #1
    cmp     r1, #0
    beq     puts_done
    bl      putc
    b       puts_next
puts_done:
    pop     {r5, pc}

hex32:
    push    {r5-r7, lr}
    mov     r5, r0
    mov     r6, #8
    adrl    r7, digits
hex_next:
    mov     r1, r5, lsr #28
    ldrb    r1, [r7, r1]
    bl      putc
    lsl     r5, r5, #4
    subs    r6, r6, #1
    bne     hex_next
    pop     {r5-r7, pc}

newline:
    adrl    r0, crlf
    b       puts

print_words:
    push    {r5-r7, lr}
    mov     r5, r0
    mov     r6, r1
word_next:
    ldr     r0, [r5], #4
    bl      hex32
    subs    r6, r6, #1
    beq     word_done
    mov     r1, #32
    bl      putc
    b       word_next
word_done:
    bl      newline
    pop     {r5-r7, pc}

.ltorg
.balign 4
mask_table: .word 1, 0x10000, 0x10000000, 0x40000000, 4, 0x100, 0
banner: .asciz "\r\nC80 IRQ route probe v1\r\n"
meta_labels:
    .asciz "CPSR="
    .asciz "MIDR="
    .asciz "GICD_CTLR="
    .asciz "GICD_TYPER="
    .asciz "PDMA_CFG="
    .asciz "PDMA_STATUS_BEFORE="
    .asciz "PDMA_MASK_BEFORE="
    .asciz "PDMA_STATUS_AFTER="
    .asciz "PDMA_MASK_AFTER="
    .asciz "GUARD_RC="
    .asciz "FE_0008="
    .asciz "FE_000C="
    .asciz "FE_0010="
    .asciz "FE_0014="
    .asciz "FE_0020="
    .asciz "FE_0024="
    .asciz "PDMA_GRP_A50="
    .asciz "PDMA_GRP_A54="
    .asciz "PDMA_INFO="
    .asciz "PDMA_DELAY="
.balign 4
enable_label: .asciz "GIC_ENABLE="
config_label: .asciz "GIC_CONFIG="
phase_label: .asciz "PHASE_MASK="
readback_label: .asciz " READBACK="
status_label: .asciz " STATUS="
pending_label: .asciz "PENDING="
done_label: .asciz "DONE\r\n"
crlf: .asciz "\r\n"
digits: .ascii "0123456789abcdef"
.balign 4
.section .note.GNU-stack, "", %progbits
