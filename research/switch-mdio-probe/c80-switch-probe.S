/* SPDX-License-Identifier: GPL-2.0-only
 * MT7626 U-Boot RAM diagnostic. CPU IRQ/FIQ remain masked, DMA halted.
 * MDIO uses the reviewed C80 GPL BSP Clause22/PHY29 SMI protocol.
 * The only switch data write is MAGIC=0249 and restoration of MAGIC.
 * No port/VLAN/init/reset/clock/GIC/flash writes. Code is relocatable.
 */
.syntax unified
.cpu cortex-a7
.arm
.section .text, "ax", %progbits
.balign 4
.global _start
.type _start, %function
.equ FRAME_SIZE, 128
.equ RESULT, 24
.equ ERROR_STAGE, 28
.equ CLEANUP_ERRORS, 32
.equ MAGIC_BEFORE, 36
.equ MAGIC_UNLOCKED, 40
.equ MAGIC_AFTER, 44
.equ PORTS_VALID, 64
.equ COMMANDS, 68
.equ STAGE, 72
.equ DIRTY, 76

_start:
    push {r4-r12, lr}
    mrs r7, cpsr
    sub sp, sp, #FRAME_SIZE
    mov r10, sp
    ldr r4, =0x11002000
    ldr r9, =0x1b110004
    ldr r11, =0x1b100000
    mov r8, #0
    mov r0, #0
    mov r1, r10
    mov r2, #(FRAME_SIZE / 4)
zero_frame:
    str r0, [r1], #4
    subs r2, r2, #1
    bne zero_frame
    mvn r0, #0
    add r1, r10, #MAGIC_BEFORE
    mov r2, #7
unknown_meta:
    str r0, [r1], #4
    subs r2, r2, #1
    bne unknown_meta
    add r1, r10, #96
    mov r2, #6
unknown_ports:
    str r0, [r1], #4
    subs r2, r2, #1
    bne unknown_ports
    str r7, [r10]
    mrc p15, 0, r0, c0, c0, 0
    str r0, [r10, #4]
    ldr r0, [r11, #0xa04]
    str r0, [r10, #8]
    ldr r0, [r11, #0xa28]
    str r0, [r10, #12]
    ldr r0, [r9]
    str r0, [r10, #16]
    ldr r0, [r9, #-4]
    str r0, [r10, #120]

    and r0, r7, #255
    cmp r0, #0xd3
    movne r0, #2
    bne fail
    ldr r0, [r10, #4]
    lsr r1, r0, #24
    cmp r1, #0x41
    movne r0, #3
    bne fail
    lsr r0, r0, #4
    movw r1, #0xfff
    and r0, r0, r1
    movw r1, #0xc07
    cmp r0, r1
    movne r0, #3
    bne fail
    ldr r0, [r10, #8]
    movw r1, #0x1410
    cmp r0, r1
    movne r0, #4
    bne fail
    ldr r0, [r10, #12]
    cmp r0, #0
    movne r0, #5
    bne fail
    ldr r0, [r10, #16]
    tst r0, #0x80000000
    movne r0, #6
    bne fail

    mov r0, #10
    str r0, [r10, #STAGE]
    movw r0, #0x13c2
    bl smi_read
    cmp r1, #0
    bne io_fail
    str r0, [r10, #MAGIC_BEFORE]
    cmp r0, #0
    beq unlock
    movw r1, #0x0249
    cmp r0, r1
    movne r0, #7
    bne fail
unlock:
    /* Mark possibly dirty BEFORE issuing even a partial unlock transaction. */
    mov r0, #1
    str r0, [r10, #DIRTY]
    mov r0, #20
    str r0, [r10, #STAGE]
    movw r0, #0x0249
    bl smi_write_magic
    cmp r1, #0
    bne io_fail
    mov r0, #30
    str r0, [r10, #STAGE]
    movw r0, #0x13c2
    bl smi_read
    cmp r1, #0
    bne io_fail
    str r0, [r10, #MAGIC_UNLOCKED]
    movw r1, #0x0249
    cmp r0, r1
    movne r0, #9
    bne fail

    mov r0, #40
    str r0, [r10, #STAGE]
    movw r0, #0x1300
    bl smi_read
    cmp r1, #0
    bne io_fail
    str r0, [r10, #48]
    movw r0, #0x1301
    bl smi_read
    cmp r1, #0
    bne io_fail
    str r0, [r10, #52]
    mov r0, #50
    str r0, [r10, #STAGE]
    movw r0, #0x1300
    bl smi_read
    cmp r1, #0
    bne io_fail
    str r0, [r10, #56]
    movw r0, #0x1301
    bl smi_read
    cmp r1, #0
    bne io_fail
    str r0, [r10, #60]
    ldr r0, [r10, #48]
    ldr r1, [r10, #56]
    cmp r0, r1
    movne r0, #11
    bne fail
    ldr r0, [r10, #52]
    ldr r1, [r10, #60]
    cmp r0, r1
    movne r0, #11
    bne fail
    /* Restore the management key BEFORE normal port-status reads. */
    bl restore_magic
    ldr r0, [r10, #CLEANUP_ERRORS]
    cmp r0, #0
    bne finalize
    ldr r0, [r10, #48]
    movw r1, #0x6367
    cmp r0, r1
    movne r0, #12
    bne fail
    ldr r0, [r10, #52]
    cmp r0, #0xa0
    movne r0, #12
    bne fail

    mov r0, #70
    str r0, [r10, #STAGE]
    mov r5, #0
read_port:
    adrl r0, port_numbers
    ldr r6, [r0, r5, lsl #2]
    movw r0, #0x1352
    add r0, r0, r6
    bl smi_read
    cmp r1, #0
    bne io_fail
    add r1, r10, #96
    str r0, [r1, r5, lsl #2]
    add r5, r5, #1
    str r5, [r10, #PORTS_VALID]
    cmp r5, #6
    bne read_port
    b finalize
io_fail:
    mov r0, #8
fail:
    str r0, [r10, #RESULT]
    ldr r0, [r10, #STAGE]
    str r0, [r10, #ERROR_STAGE]
finalize:
    bl restore_magic
    ldr r0, [r11, #0xa04]
    str r0, [r10, #80]
    ldr r1, [r10, #8]
    cmp r0, r1
    ldr r2, [r10, #CLEANUP_ERRORS]
    orrne r2, r2, #8
    ldr r0, [r11, #0xa28]
    str r0, [r10, #84]
    ldr r1, [r10, #12]
    cmp r0, r1
    orrne r2, r2, #8
    ldr r0, [r9, #-4]
    str r0, [r10, #124]
    ldr r1, [r10, #120]
    cmp r0, r1
    orrne r2, r2, #16
    str r2, [r10, #CLEANUP_ERRORS]
    cmp r2, #0
    beq return_state
    ldr r0, [r10, #RESULT]
    cmp r0, #0
    moveq r0, #13
    streq r0, [r10, #RESULT]
return_state:
    ldr r0, [r9]
    str r0, [r10, #88]
    msr cpsr_f, r7
    mrs r0, cpsr
    str r0, [r10, #92]
    /* All MDIO work/cleanup must finish before even the first UART read. */
    adrl r0, banner
    bl puts
    mov r5, #24
    mov r6, r10
    adrl r11, meta_labels
print_next:
    mov r0, r11
    bl puts
    ldr r0, [r6], #4
    bl hex32
    bl newline
skip_label:
    ldrb r0, [r11], #1
    cmp r0, #0
    bne skip_label
    subs r5, r5, #1
    bne print_next
    adrl r0, config_label
    bl puts
    ldr r0, [r10, #120]
    bl hex32
    mov r1, #32
    bl putc
    ldr r0, [r10, #124]
    bl hex32
    bl newline
    adrl r0, ports_label
    bl puts
    add r0, r10, #96
    mov r1, #6
    bl print_words
    adrl r0, done_label
    bl puts
    ldr r0, [r10, #RESULT]
    cmp r8, #0
    movne r0, #1
    msr cpsr_f, r7
    add sp, sp, #FRAME_SIZE
    pop {r4-r12, lr}
    bx lr
.size _start, .-_start

/* r0 command without busy; r0 returns data; r1 nonzero on timeout.
 * The initial busy check and both waits are bounded. The BSP requires a
 * pause between sequential writes: 4096 loop iterations provide pacing,
 * without making a claim about a calibrated delay or CPU frequency.
 */
mdio_command:
    push {r5-r7, lr}
    mov r5, r0
    bl mdio_wait
    cmp r1, #0
    bne command_done
    mov r2, #4096
command_pause:
    subs r2, r2, #1
    bne command_pause
    str r5, [r10, #20]
    str r5, [r9]
    dsb sy
    orr r6, r5, #0x80000000
    str r6, [r9]
    dsb sy
    ldr r0, [r10, #COMMANDS]
    add r0, r0, #1
    str r0, [r10, #COMMANDS]
    bl mdio_wait
    uxth r0, r0
command_done:
    pop {r5-r7, pc}
mdio_wait:
    movw r2, #0x4240
    movt r2, #0x000f
mdio_poll:
    ldr r0, [r9]
    tst r0, #0x80000000
    beq mdio_ready
    subs r2, r2, #1
    bne mdio_poll
    mov r1, #1
    bx lr
mdio_ready:
    mov r1, #0
    bx lr
mdio_read:
    lsl r0, r0, #25
    ldr r2, =0x01d90000
    orr r0, r0, r2
    b mdio_command
mdio_write:
    lsl r0, r0, #25
    ldr r2, =0x01d50000
    orr r0, r0, r2
    uxth r1, r1
    orr r0, r0, r1
    b mdio_command

/* Read one switch register using the BSP/Linux PHY29 SMI protocol. */
smi_read:
    push {r5, lr}
    mov r5, r0
    mov r0, #31
    mov r1, #14
    bl mdio_write
    cmp r1, #0
    bne smi_done
    mov r0, #23
    mov r1, r5
    bl mdio_write
    cmp r1, #0
    bne smi_done
    mov r0, #21
    mov r1, #1
    bl mdio_write
    cmp r1, #0
    bne smi_done
    mov r0, #25
    bl mdio_read
smi_done:
    pop {r5, pc}

/* No general switch-write entry: only register 13c2 may receive data. */
smi_write_magic:
    push {r5, lr}
    mov r5, r0
    mov r0, #31
    mov r1, #14
    bl mdio_write
    cmp r1, #0
    bne magic_done
    mov r0, #23
    movw r1, #0x13c2
    bl mdio_write
    cmp r1, #0
    bne magic_done
    mov r0, #24
    mov r1, r5
    bl mdio_write
    cmp r1, #0
    bne magic_done
    mov r0, #21
    mov r1, #3
    bl mdio_write
magic_done:
    pop {r5, pc}

restore_magic:
    push {r5, lr}
    ldr r0, [r10, #DIRTY]
    cmp r0, #0
    beq restore_done
    /* Attempt once. If bus remains busy, report uncertainty; never force it. */
    mov r0, #0
    str r0, [r10, #DIRTY]
    mov r0, #60
    str r0, [r10, #STAGE]
    ldr r0, [r10, #MAGIC_BEFORE]
    bl smi_write_magic
    cmp r1, #0
    movne r0, #1
    bne restore_failed
    movw r0, #0x13c2
    bl smi_read
    cmp r1, #0
    movne r0, #2
    bne restore_failed
    str r0, [r10, #MAGIC_AFTER]
    ldr r1, [r10, #MAGIC_BEFORE]
    cmp r0, r1
    movne r0, #4
    bne restore_failed
    b restore_done
restore_failed:
    ldr r1, [r10, #CLEANUP_ERRORS]
    orr r0, r0, r1
    str r0, [r10, #CLEANUP_ERRORS]
restore_done:
    pop {r5, pc}

.include "uart-print.S"
.ltorg
.balign 4
port_numbers: .word 0,1,2,3,4,6
banner: .asciz "\r\nC80 switch MDIO probe v1\r\n"
meta_labels:
    .asciz "CPSR_BEFORE="
    .asciz "MIDR="
    .asciz "PDMA_CFG_BEFORE="
    .asciz "PDMA_MASK_BEFORE="
    .asciz "MDIO_BEFORE="
    .asciz "MDIO_LAST_COMMAND="
    .asciz "RESULT_RC="
    .asciz "ERROR_STAGE="
    .asciz "CLEANUP_ERRORS="
    .asciz "MAGIC_BEFORE="
    .asciz "MAGIC_UNLOCKED="
    .asciz "MAGIC_AFTER="
    .asciz "CHIP_ID_1="
    .asciz "CHIP_VER_1="
    .asciz "CHIP_ID_2="
    .asciz "CHIP_VER_2="
    .asciz "PORTS_VALID="
    .asciz "MDIO_COMMANDS="
    .asciz "LAST_STAGE="
    .asciz "MAGIC_RESTORE_ATTEMPT_REMAINS="
    .asciz "PDMA_CFG_AFTER="
    .asciz "PDMA_MASK_AFTER="
    .asciz "MDIO_AFTER="
    .asciz "CPSR_AFTER="
config_label: .asciz "MDIO_CONFIG_BEFORE_AFTER="
ports_label: .asciz "PORT_STATUS_0_1_2_3_4_6="
done_label: .asciz "DONE\r\n"
crlf: .asciz "\r\n"
digits: .ascii "0123456789abcdef"
.balign 4
.section .note.GNU-stack, "", %progbits
