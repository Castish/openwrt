/* SPDX-License-Identifier: MIT
 * C80 U-Boot diagnostic: CPU IRQ/FIQ stay masked. DMA stays halted.
 * Save/restore SPI targets/enables, GICD_CTLR and FE/PDMA IRQ grouping.
 * Never write GICC, GIC trigger/security/priority/pending, clocks or flash.
 * Restore and verify configuration before the first UART operation.
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text, "ax", %progbits
.balign 4
.global _start
.type _start, %function
.equ FRAME_SIZE, 1152
.equ ENABLE_OFFSET, 144
.equ CONFIG_OFFSET, 180
.equ GROUP_OFFSET, 252
.equ TARGET_OFFSET, 288
.equ SAMPLE_OFFSET, 544
.equ SAMPLE_SIZE, 56

.macro read_fe frame_offset, reg_offset
    ldr r0, [r9, #\reg_offset]
    str r0, [r10, #\frame_offset]
.endm
.macro compare_saved after, before, bit
    ldr r0, [r10, #\after]
    ldr r1, [r10, #\before]
    cmp r0, r1
    orrne r6, r6, #\bit
.endm

_start:
    push {r4-r12, lr}
    mrs r7, cpsr
    sub sp, sp, #FRAME_SIZE
    mov r10, sp
    ldr r4, =0x11002000
    ldr r9, =0x1b100000
    ldr r11, =0x10310000
    mov r8, #0
    mov r0, r10
    mov r1, #0
    mov r2, #36
    bl fill_words
    mov r0, r7
    str r0, [r10]
    mrc p15, 0, r0, c0, c0, 0
    str r0, [r10, #4]
    mrc p15, 0, r0, c0, c0, 5
    str r0, [r10, #8]
    ldr r0, [r11]
    str r0, [r10, #12]
    ldr r0, [r11, #4]
    str r0, [r10, #16]
    ldr r1, =0x10320000
    ldr r0, [r1]
    str r0, [r10, #20]
    ldr r0, [r1, #4]
    str r0, [r10, #24]
    read_fe 28, 0xa04
    read_fe 32, 0xa20
    read_fe 36, 0xa28
    read_fe 40, 0x20
    read_fe 44, 0xa50
    read_fe 48, 0xa54
    add r0, r10, #ENABLE_OFFSET
    add r1, r11, #0x100
    mov r2, #9
    bl copy_words
    add r0, r10, #CONFIG_OFFSET
    add r1, r11, #0xc00
    mov r2, #18
    bl copy_words
    add r0, r10, #GROUP_OFFSET
    add r1, r11, #0x80
    mov r2, #9
    bl copy_words
    add r0, r10, #TARGET_OFFSET
    add r1, r11, #0x820
    mov r2, #64
    bl copy_words

    /* Banked SGI/PPI target registers identify this CPU's target bit. */
    add r0, r11, #0x800
    mov r2, #8
    mov r3, #0
cpu_target_next:
    ldr r1, [r0], #4
    orr r3, r3, r1
    subs r2, r2, #1
    bne cpu_target_next
    orr r3, r3, r3, lsr #16
    orr r3, r3, r3, lsr #8
    and r3, r3, #255
    str r3, [r10, #52]
    orr r3, r3, r3, lsl #8
    orr r3, r3, r3, lsl #16
    str r3, [r10, #136]
    add r0, r10, #SAMPLE_OFFSET
    ldr r1, [r10, #36]
    mov r2, #0
    bl snapshot
    mov r0, #1
    str r0, [r10, #128]
    add r0, r10, #(SAMPLE_OFFSET + SAMPLE_SIZE)
    str r0, [r10, #132]

    ldr r0, [r10]
    and r0, r0, #255
    cmp r0, #0xd3
    movne r0, #2
    bne guard_failed
    ldr r0, [r10, #28]
    movw r1, #0x1410
    cmp r0, r1
    movne r0, #3
    bne guard_failed
    ldr r0, [r10, #36]
    cmp r0, #0
    movne r0, #4
    bne guard_failed
    ldr r0, [r10, #16]
    and r0, r0, #31
    cmp r0, #8
    movne r0, #5
    bne guard_failed
    ldr r0, [r10, #4]
    lsr r0, r0, #4
    movw r1, #0xfff
    and r0, r0, r1
    movw r1, #0xc07
    cmp r0, r1
    movne r0, #6
    bne guard_failed
    ldr r0, [r10, #4]
    lsr r0, r0, #24
    cmp r0, #0x41
    movne r0, #6
    bne guard_failed
    ldr r0, [r10, #12]
    cmp r0, #0
    movne r0, #7
    bne guard_failed
    add r1, r10, #(ENABLE_OFFSET + 4)
    mov r2, #8
check_spi_disabled:
    ldr r0, [r1], #4
    cmp r0, #0
    movne r0, #8
    bne guard_failed
    subs r2, r2, #1
    bne check_spi_disabled
    ldr r0, [r10, #52]
    cmp r0, #0
    moveq r0, #9
    beq guard_failed
    sub r1, r0, #1
    tst r0, r1
    movne r0, #9
    bne guard_failed
    add r0, r10, #(CONFIG_OFFSET + 8)
    ldr r1, =0xaaaaaaaa
    mov r2, #16
check_spi_level:
    ldr r3, [r0], #4
    tst r3, r1
    movne r0, #10
    bne guard_failed
    subs r2, r2, #1
    bne check_spi_level
    ldr r0, [r10, #32]
    ldr r1, =0x10001
    and r0, r0, r1
    cmp r0, r1
    movne r0, #12
    bne guard_failed

    /* All SPI targets -> this CPU while distributor and SPIs are off. */
    add r0, r11, #0x820
    ldr r1, [r10, #136]
    mov r2, #64
    bl fill_words
    dsb sy
    /* Do not enable a source whose target write did not take effect. */
    add r0, r11, #0x820
    ldr r1, [r10, #136]
    mov r2, #64
    bl compare_constant
    str r0, [r10, #120]
    cmp r0, #0
    movne r0, #11
    strne r0, [r10, #56]
    bne cleanup
    add r0, r11, #0x104
    mvn r1, #0
    mov r2, #8
    bl fill_words
    dsb sy
    mov r0, #3                 /* Enable visible groups in either GIC view. */
    str r0, [r11]
    dsb sy
    bl settle
    ldr r0, [r11]
    str r0, [r10, #64]
    add r0, r11, #0x104
    mvn r1, #0
    mov r2, #8
enabled_and:
    ldr r3, [r0], #4
    and r1, r1, r3
    subs r2, r2, #1
    bne enabled_and
    str r1, [r10, #124]
    mov r0, #1
    ldr r1, [r10, #132]
    bl capture_mode
    str r0, [r10, #132]

    /* Linux-v1 grouping pattern, using normal ring0 done sources. */
    ldr r0, =0x21021000
    str r0, [r9, #0x20]
    mov r0, #1
    str r0, [r9, #0xa50]
    mov r0, #0x10000
    str r0, [r9, #0xa54]
    dsb sy
    bl settle
    read_fe 68, 0x20
    read_fe 72, 0xa50
    read_fe 76, 0xa54
    mov r0, #2
    ldr r1, [r10, #132]
    bl capture_mode
    str r0, [r10, #132]

    /* Restore while CPU IRQ/FIQ stay masked; no UART until verified. */
cleanup:
    ldr r0, [r10, #36]
    str r0, [r9, #0xa28]
    dsb sy
    ldr r0, [r10, #12]
    str r0, [r11]
    dsb sy
    add r0, r11, #0x184
    mvn r1, #0
    mov r2, #8
    bl fill_words
    dsb sy
    add r0, r11, #0x820
    add r1, r10, #TARGET_OFFSET
    mov r2, #64
    bl copy_words
    ldr r0, [r10, #40]
    str r0, [r9, #0x20]
    ldr r0, [r10, #44]
    str r0, [r9, #0xa50]
    ldr r0, [r10, #48]
    str r0, [r9, #0xa54]
    dsb sy
    b verify_restoration
guard_failed:
    str r0, [r10, #56]
verify_restoration:
    ldr r0, [r11]
    str r0, [r10, #80]
    read_fe 84, 0xa28
    read_fe 88, 0x20
    read_fe 92, 0xa50
    read_fe 96, 0xa54
    read_fe 100, 0xa20
    read_fe 104, 0xa04
    mov r6, #0
    compare_saved 80, 12, 1
    compare_saved 84, 36, 2
    compare_saved 88, 40, 4
    compare_saved 92, 44, 8
    compare_saved 96, 48, 16
    compare_saved 104, 28, 32
    add r0, r11, #0x820
    add r1, r10, #TARGET_OFFSET
    mov r2, #64
    bl compare_words
    str r0, [r10, #112]
    cmp r0, #0
    orrne r6, r6, #64
    add r0, r11, #0x100
    add r1, r10, #ENABLE_OFFSET
    mov r2, #9
    bl compare_words
    str r0, [r10, #116]
    cmp r0, #0
    orrne r6, r6, #128
    mrs r0, cpsr
    str r0, [r10, #108]
    ldr r1, [r10]
    eor r1, r1, r0
    movw r2, #0x3ff
    tst r1, r2
    orrne r6, r6, #256
    str r6, [r10, #60]
    ldr r0, [r10, #56]
    cmp r0, #0
    bne output
    ldr r0, [r10, #132]
    ldr r1, [r10, #36]
    mov r2, #3
    bl snapshot
    ldr r0, [r10, #128]
    add r0, r0, #1
    str r0, [r10, #128]

output:
    adrl r0, banner
    bl puts
    mov r5, r10
    adrl r6, meta_labels
    mov r7, #32
meta_next:
    mov r0, r6
    bl puts
    ldr r0, [r5], #4
    bl hex32
    bl newline
next_label:
    ldrb r0, [r6], #1
    cmp r0, #0
    bne next_label
    subs r7, r7, #1
    bne meta_next
    adrl r0, enable_label
    bl puts
    add r0, r10, #ENABLE_OFFSET
    mov r1, #9
    bl print_words
    adrl r0, config_label
    bl puts
    add r0, r10, #CONFIG_OFFSET
    mov r1, #18
    bl print_words
    adrl r0, group_label
    bl puts
    add r0, r10, #GROUP_OFFSET
    mov r1, #9
    bl print_words
    add r5, r10, #SAMPLE_OFFSET
    ldr r7, [r10, #128]
print_sample:
    adrl r0, mode_label
    bl puts
    ldr r0, [r5]
    bl hex32
    adrl r0, mask_label
    bl puts
    ldr r0, [r5, #4]
    bl hex32
    adrl r0, readback_label
    bl puts
    ldr r0, [r5, #8]
    bl hex32
    adrl r0, status_label
    bl puts
    ldr r0, [r5, #12]
    bl hex32
    adrl r0, ctlr_label
    bl puts
    ldr r0, [r5, #16]
    bl hex32
    bl newline
    adrl r0, pending_label
    bl puts
    add r0, r5, #20
    mov r1, #9
    bl print_words
    add r5, r5, #SAMPLE_SIZE
    subs r7, r7, #1
    bne print_sample
    adrl r0, done_label
    bl puts
    ldr r0, [r10, #56]
    ldr r1, [r10, #60]
    cmp r1, #0
    movne r0, #64
    cmp r8, #0
    movne r0, #1
    add sp, sp, #FRAME_SIZE
    pop {r4-r12, lr}
    bx lr
.size _start, . - _start

copy_words:
    ldr r3, [r1], #4
    str r3, [r0], #4
    subs r2, r2, #1
    bne copy_words
    bx lr
fill_words:
    str r1, [r0], #4
    subs r2, r2, #1
    bne fill_words
    bx lr
/* Compare r0 MMIO and r1 saved RAM, r2 words. Return mismatch count. */
compare_words:
    mov r12, #0
compare_next:
    ldr r3, [r0], #4
    push {r3, lr}
    ldr lr, [r1], #4
    cmp r3, lr
    addne r12, r12, #1
    pop {r3, lr}
    subs r2, r2, #1
    bne compare_next
    mov r0, r12
    bx lr
/* Compare r0 MMIO against constant r1, r2 words. Return mismatch count. */
compare_constant:
    mov r12, #0
constant_next:
    ldr r3, [r0], #4
    cmp r3, r1
    addne r12, r12, #1
    subs r2, r2, #1
    bne constant_next
    mov r0, r12
    bx lr
settle:
    mov r2, #4096
settle_next:
    subs r2, r2, #1
    bne settle_next
    bx lr
/* r0 destination; r1 requested mask; r2 mode. */
snapshot:
    str r2, [r0], #4
    str r1, [r0], #4
    ldr r3, [r9, #0xa28]
    str r3, [r0], #4
    ldr r3, [r9, #0xa20]
    str r3, [r0], #4
    ldr r3, [r11]
    str r3, [r0], #4
    add r2, r11, #0x200
    mov r3, #9
pending_next:
    ldr r12, [r2], #4
    str r12, [r0], #4
    subs r3, r3, #1
    bne pending_next
    bx lr
/* r0 mode; r1 destination. Return next free sample address in r0. */
capture_mode:
    push {r5-r7, lr}
    sub sp, sp, #8
    mov r5, r0
    mov r6, r1
    adrl r0, mask_table
    str r0, [sp]
    mov r7, #4
capture_next:
    ldr r0, [sp]
    ldr r1, [r0], #4
    str r0, [sp]
    str r1, [r9, #0xa28]
    dsb sy
    bl settle
    mov r0, r6
    mov r2, r5
    bl snapshot
    add r6, r6, #SAMPLE_SIZE
    ldr r0, [r10, #128]
    add r0, r0, #1
    str r0, [r10, #128]
    subs r7, r7, #1
    bne capture_next
    mov r0, r6
    add sp, sp, #8
    pop {r5-r7, pc}

.include "uart-print.S"
.ltorg
.balign 4
mask_table: .word 0, 1, 0x10000, 0
banner: .asciz "\r\nC80 IRQ route probe v2\r\n"
meta_labels:
    .asciz "CPSR_BEFORE="
    .asciz "MIDR="
    .asciz "MPIDR="
    .asciz "GICD_CTLR_BEFORE="
    .asciz "GICD_TYPER="
    .asciz "GICC_CTLR="
    .asciz "GICC_PMR="
    .asciz "PDMA_CFG_BEFORE="
    .asciz "PDMA_STATUS_BEFORE="
    .asciz "PDMA_MASK_BEFORE="
    .asciz "FE_GROUP_BEFORE="
    .asciz "PDMA_GROUP0_BEFORE="
    .asciz "PDMA_GROUP1_BEFORE="
    .asciz "CPU_TARGET_MASK="
    .asciz "GUARD_RC="
    .asciz "RESTORE_ERRORS="
    .asciz "GICD_CTLR_ENABLED="
    .asciz "FE_GROUP_TEST_RB="
    .asciz "PDMA_GROUP0_TEST_RB="
    .asciz "PDMA_GROUP1_TEST_RB="
    .asciz "GICD_CTLR_AFTER="
    .asciz "PDMA_MASK_AFTER="
    .asciz "FE_GROUP_AFTER="
    .asciz "PDMA_GROUP0_AFTER="
    .asciz "PDMA_GROUP1_AFTER="
    .asciz "PDMA_STATUS_AFTER="
    .asciz "PDMA_CFG_AFTER="
    .asciz "CPSR_AFTER="
    .asciz "TARGET_RESTORE_MISMATCHES="
    .asciz "SPI_ENABLE_RESTORE_MISMATCHES="
    .asciz "TARGET_TEST_MISMATCHES="
    .asciz "SPI_ENABLE_TEST_AND="
.balign 4
enable_label: .asciz "ENABLE_BEFORE="
config_label: .asciz "CONFIG_BEFORE="
group_label: .asciz "GROUP_BEFORE="
mode_label: .asciz "MODE="
mask_label: .asciz " MASK="
readback_label: .asciz " READBACK="
status_label: .asciz " STATUS="
ctlr_label: .asciz " GICD="
pending_label: .asciz "PENDING="
done_label: .asciz "DONE\r\n"
crlf: .asciz "\r\n"
digits: .ascii "0123456789abcdef"
.balign 4
.section .note.GNU-stack, "", %progbits
