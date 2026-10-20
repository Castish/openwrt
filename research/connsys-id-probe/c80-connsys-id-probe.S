/* SPDX-License-Identifier: MIT
 * MT7626 CONNSYS identification in U-Boot, with MCU kept in its existing reset.
 * No power/reset/clock/EMI/GIC/PDMA/flash write. Only stack and UART TX writes.
 * Check the observed always-on preconditions before any CONNSYS read.
 * Every radio read has an UART checkpoint. A bus stall is not a software timeout.
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text, "ax", %progbits
.balign 4
.global _start
.type _start, %function
.equ FRAME_SIZE, 176
.equ AON_BEFORE, 48
.equ AON_AFTER, 88
.equ IDS, 128

_start:
    push {r4-r12, lr}
    mrs r7, cpsr
    sub sp, sp, #FRAME_SIZE
    mov r10, sp
    mov r0, #0
    mov r1, r10
    mov r2, #(FRAME_SIZE / 4)
zero_frame:
    str r0, [r1], #4
    subs r2, r2, #1
    bne zero_frame
    mvn r0, #0
    add r1, r10, #AON_BEFORE
    mov r2, #28
unknown_frame:
    str r0, [r1], #4
    subs r2, r2, #1
    bne unknown_frame
    str r7, [r10, #8]
    mrc p15, 0, r0, c0, c0, 0
    str r0, [r10, #12]
    mrc p15, 0, r0, c1, c0, 0
    str r0, [r10, #16]
    ldr r4, =0x11002000
    mov r8, #0
    adrl r0, banner
    bl puts
    cmp r8, #0
    bne uart_failed_early
    ldr r0, [r10, #8]
    movw r1, #0x3ff
    and r0, r0, r1
    movw r2, #0x1d3
    cmp r0, r2
    movne r0, #1
    bne initial_failed
    ldr r0, [r10, #12]
    ldr r1, =0x410fc073
    cmp r0, r1
    movne r0, #2
    bne initial_failed
    ldr r9, =0x1b100000
    ldr r1, [r9, #0xa04]
    str r1, [r10, #20]
    ldr r2, [r9, #0xa28]
    str r2, [r10, #24]
    add r0, r10, #AON_BEFORE
    bl snapshot_aon
    mov r0, #1
    str r0, [r10, #172]
    add r0, r10, #AON_BEFORE
    ldr r1, [r10, #20]
    ldr r2, [r10, #24]
    bl validate_state
    cmp r0, #0
    bne initial_failed
    adrl r0, guard_ok
    bl puts
    mov r5, #0
read_next_id:
    adrl r6, id_addresses
    and r0, r5, #3
    ldr r11, [r6, r0, lsl #2]
    str r11, [r10, #28]
    adrl r0, read_label
    bl puts
    mov r0, r11
    bl hex32
    bl newline
    cmp r8, #0
    bne uart_failed_late
    dsb sy
    and r0, r5, #3
    cmp r0, #2
    ldrlo r0, [r11]
    ldrhhs r0, [r11]
    add r1, r10, #IDS
    str r0, [r1, r5, lsl #2]
    ldr r1, [r10, #36]
    mov r2, #1
    orr r1, r1, r2, lsl r5
    str r1, [r10, #36]
    mov r7, r0
    adrl r0, value_label
    bl puts
    mov r0, r7
    bl hex32
    bl newline
    and r0, r5, #3
    cmp r0, #0
    bne version_valid
    lsr r0, r7, #16
    movw r1, #0x1004
    cmp r0, r1
    bne version_invalid
    uxth r0, r7
    cmp r0, #255
    bls version_invalid
version_valid:
    add r5, r5, #1
    cmp r5, #8
    blo read_next_id
    add r5, r10, #IDS
    mov r6, #4
compare_id_rounds:
    ldr r0, [r5]
    ldr r1, [r5, #16]
    cmp r0, r1
    movne r0, #21
    strne r0, [r10]
    bne final_snapshot
    add r5, r5, #4
    subs r6, r6, #1
    bne compare_id_rounds
    mov r6, #0
    ldr r0, [r10, #IDS]
    ldr r1, =0x10040101
    cmp r0, r1
    orreq r6, r6, #1
    ldr r0, [r10, #(IDS + 4)]
    tst r0, #15
    orreq r6, r6, #2
    ldr r0, [r10, #(IDS + 8)]
    movw r1, #0x8a00
    cmp r0, r1
    orreq r6, r6, #4
    ldr r0, [r10, #(IDS + 12)]
    cmp r0, r1
    orreq r6, r6, #8
    str r6, [r10, #168]
    cmp r6, #15
    movne r0, #22
    strne r0, [r10]
    b final_snapshot
version_invalid:
    mov r0, #20
    str r0, [r10]
    b final_snapshot
uart_failed_late:
    mov r0, #40
    str r0, [r10]
final_snapshot:
    add r0, r10, #AON_AFTER
    bl snapshot_aon
    ldr r0, [r9, #0xa04]
    str r0, [r10, #160]
    ldr r0, [r9, #0xa28]
    str r0, [r10, #164]
    mov r0, #3
    str r0, [r10, #172]
    mov r5, #0
    mov r6, #0
compare_aon:
    add r1, r10, #AON_BEFORE
    ldr r0, [r1, r5, lsl #2]
    add r1, r10, #AON_AFTER
    ldr r1, [r1, r5, lsl #2]
    cmp r0, r1
    mov r2, #1
    orrne r6, r6, r2, lsl r5
    add r5, r5, #1
    cmp r5, #10
    blo compare_aon
    str r6, [r10, #44]
    add r0, r10, #AON_AFTER
    ldr r1, [r10, #160]
    ldr r2, [r10, #164]
    bl validate_state
    str r0, [r10, #32]
    cmp r0, #0
    movne r0, #30
    strne r0, [r10]
    bne output
    cmp r6, #0
    movne r0, #31
    strne r0, [r10]
    b output
initial_failed:
    str r0, [r10, #4]
    str r0, [r10]
    b output
uart_failed_early:
    mov r0, #40
    str r0, [r10]
output:
    mrs r0, cpsr
    str r0, [r10, #40]
    adrl r6, labels
    mov r5, r10
    mov r7, #12
print_meta:
    mov r0, r6
    bl puts
    ldr r0, [r5], #4
    bl hex32
    bl newline
skip_label:
    ldrb r0, [r6], #1
    cmp r0, #0
    bne skip_label
    subs r7, r7, #1
    bne print_meta
    adrl r0, before_label
    bl puts
    add r0, r10, #AON_BEFORE
    mov r1, #10
    bl print_words
    adrl r0, after_label
    bl puts
    add r0, r10, #AON_AFTER
    mov r1, #10
    bl print_words
    adrl r0, ids1_label
    bl puts
    add r0, r10, #IDS
    mov r1, #4
    bl print_words
    adrl r0, ids2_label
    bl puts
    add r0, r10, #(IDS + 16)
    mov r1, #4
    bl print_words
    adrl r0, tail_label
    bl puts
    add r0, r10, #160
    mov r1, #4
    bl print_words
    adrl r0, done_label
    bl puts
    ldr r0, [r10]
    cmp r8, #0
    movne r0, #40
    add sp, sp, #FRAME_SIZE
    pop {r4-r12, lr}
    bx lr
.size _start, . - _start

/* r0 destination. Reads the same ten always-on words supplied by the user. */
snapshot_aon:
    adrl r1, aon_addresses
    mov r2, #10
snapshot_next:
    ldr r3, [r1], #4
    ldr r12, [r3]
    str r12, [r0], #4
    subs r2, r2, #1
    bne snapshot_next
    bx lr

/* r0 AON snapshot, r1 PDMA_CFG, r2 PDMA_MASK. Return guard number or zero. */
validate_state:
    movw r3, #0x1410
    cmp r1, r3
    movne r0, #3
    bxne lr
    cmp r2, #0
    movne r0, #4
    bxne lr
    movw r12, #0x8104
    ldr r3, [r0]
    tst r3, r12
    movne r0, #5
    bxne lr
    ldr r3, [r0, #4]
    tst r3, r12
    movne r0, #6
    bxne lr
    ldr r3, [r0, #8]
    tst r3, #7
    movne r0, #7
    bxne lr
    ldr r3, [r0, #12]
    tst r3, #7
    movne r0, #8
    bxne lr
    ldr r3, [r0, #16]
    movw r12, #0xfff
    and r3, r3, r12
    cmp r3, #0x40
    movne r0, #9
    bxne lr
    ldr r3, [r0, #20]
    tst r3, #1
    moveq r0, #10
    bxeq lr
    ldr r3, [r0, #24]
    ldr r12, =0x20800000
    and r3, r3, r12
    cmp r3, r12
    movne r0, #11
    bxne lr
    ldr r3, [r0, #36]
    movw r12, #0x1200
    and r3, r3, r12
    cmp r3, #0x1000
    movne r0, #12
    bxne lr
    ldr r3, [r0, #28]
    ldr r12, [r0, #32]
    cmp r3, r12
    movne r0, #13
    bxne lr
    and r3, r3, #0x07000000
    cmp r3, #0x07000000
    movne r0, #14
    bxne lr
    mov r0, #0
    bx lr

.include "uart-print.S"
.balign 4
.ltorg
aon_addresses:
    .word 0x10000220, 0x10000228, 0x10000230, 0x10000238, 0x10000370
    .word 0x10006000, 0x10006608, 0x1000660c, 0x10006610, 0x10212018
id_addresses:
    .word 0x180b1010, 0x180b101c, 0x18002000, 0x18002004
banner: .asciz "\r\nC80 CONNSYS ID probe v1 (read-only)\r\n"
guard_ok: .asciz "GUARDS_OK; MCU reset remains asserted; no peripheral writes.\r\n"
read_label: .asciz "READ="
value_label: .asciz "VALUE="
labels:
    .asciz "RESULT_RC="
    .asciz "GUARD_BEFORE="
    .asciz "CPSR_BEFORE="
    .asciz "MIDR="
    .asciz "SCTLR="
    .asciz "PDMA_CFG_BEFORE="
    .asciz "PDMA_MASK_BEFORE="
    .asciz "LAST_READ="
    .asciz "GUARD_AFTER="
    .asciz "IDS_VALID_BITS="
    .asciz "CPSR_AFTER="
    .asciz "AON_CHANGED_BITS="
before_label: .asciz "AON_BEFORE="
after_label: .asciz "AON_AFTER="
ids1_label: .asciz "IDS_ROUND1="
ids2_label: .asciz "IDS_ROUND2="
tail_label: .asciz "PDMA_AFTER_MASK_MATCH_AON_VALID="
done_label: .asciz "DONE\r\n"
digits: .ascii "0123456789abcdef"
crlf: .asciz "\r\n"
.balign 4
.section .note.GNU-stack, "", %progbits
