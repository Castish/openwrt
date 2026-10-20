/* SPDX-License-Identifier: MIT */
.syntax unified
.cpu cortex-a7
.arm
.section .text.entry, "ax", %progbits
.global _start
.type _start,%function
_start:
    mrs r2,cpsr
    adr r0,_start
    mov r1,#0x41000000
    cmp r0,r1
    bne wrong_position
    movw r1,#0x3ff
    and r0,r2,r1
    movw r1,#0x1d3
    cmp r0,r1
    bne wrong_mode
    mov r0,sp
    ldr r1,=0x41c10000
    cmp r0,r1
    blo wrong_stack
    mov r1,#0x42000000
    cmp r0,r1
    bhs wrong_stack
    tst r0,#7
    bne wrong_stack
    /* Validate physical stack pages without using a stack or changing MMU
     * mappings. r3 temporarily saves the caller's original r12; r12 saves
     * PAR. r0/r1/r2/r3 are ordinary call-clobbered arguments. */
    mov r3,r12
.global entry_midr_op
entry_midr_op:
    mrc p15,0,r0,c0,c0,0
    ldr r1,=0x410fc073
    cmp r0,r1
    bne early_wrong_cpu
.global entry_sctlr_op
entry_sctlr_op:
    mrc p15,0,r0,c1,c0,0
    ldr r1,=0x00c5187f
    cmp r0,r1
    bne early_wrong_mmu
.global entry_ttbcr_op
entry_ttbcr_op:
    mrc p15,0,r0,c2,c0,2
    cmp r0,#0
    bne early_wrong_mmu
.global entry_save_par_op
entry_save_par_op:
    mrc p15,0,r12,c7,c4,0
    sub r0,sp,#0x4000
    lsr r0,r0,#12
    lsl r0,r0,#12
stack_page:
.global entry_translate_read_op
entry_translate_read_op:
    mcr p15,0,r0,c7,c8,0
    isb
.global entry_read_par_op
entry_read_par_op:
    mrc p15,0,r1,c7,c4,0
    tst r1,#1
    bne early_bad_mapping
    eor r1,r1,r0
    lsrs r1,r1,#12
    bne early_bad_mapping
.global entry_translate_write_op
entry_translate_write_op:
    mcr p15,0,r0,c7,c8,1
    isb
.global entry_write_par_op
entry_write_par_op:
    mrc p15,0,r1,c7,c4,0
    tst r1,#1
    bne early_bad_mapping
    eor r1,r1,r0
    lsrs r1,r1,#12
    bne early_bad_mapping
    add r0,r0,#4096
    cmp r0,sp
    blo stack_page
.global entry_restore_par_op
entry_restore_par_op:
    mcr p15,0,r12,c7,c4,0
    isb
    mov r12,r3
    push {r4-r12,lr}
    add r0,sp,#40
    ldr r1,[sp,#36]
    mov r3,r9
    bl bootstrap_main
    pop {r4-r12,pc}
wrong_position:
    mov r0,#2
    bx lr
wrong_mode:
    mov r0,#3
    bx lr
wrong_stack:
    mov r0,#4
    bx lr
early_wrong_cpu:
    mov r12,r3
    mov r0,#3
    bx lr
early_wrong_mmu:
    mov r12,r3
    mov r0,#6
    bx lr
early_bad_mapping:
.global entry_fail_restore_par_op
entry_fail_restore_par_op:
    mcr p15,0,r12,c7,c4,0
    isb
    mov r12,r3
    mov r0,#7
    bx lr
.size _start,.-_start
.ltorg

.section .text.primitives,"ax",%progbits
.global c80_midr,midr_op
c80_midr:
midr_op:
    mrc p15,0,r0,c0,c0,0
    bx lr

.global c80_snapshot
c80_snapshot:
.macro SNAP name,crn,crm,op2,offset
    .global snapshot_\name
snapshot_\name:
    mrc p15,0,r1,\crn,\crm,\op2
    str r1,[r0,#\offset]
.endm
    SNAP midr,c0,c0,0,0
    SNAP sctlr,c1,c0,0,4
    SNAP ctr,c0,c0,1,8
    SNAP ttbr0,c2,c0,0,12
    SNAP ttbr1,c2,c0,1,16
    SNAP ttbcr,c2,c0,2,20
    SNAP vbar,c12,c0,0,24
    SNAP par,c7,c4,0,28
    SNAP cntfrq,c14,c0,0,32
    SNAP mpidr,c0,c0,5,36
    bx lr

.global c80_counter,counter_op
c80_counter:
    isb
counter_op:
    mrrc p15,0,r0,r1,c14
    bx lr

.global c80_translate,translate_read_op,translate_write_op,translate_par_op
c80_translate:
    cmp r1,#0
    bne 1f
translate_read_op:
    mcr p15,0,r0,c7,c8,0
    b 2f
1:
translate_write_op:
    mcr p15,0,r0,c7,c8,1
2:  isb
translate_par_op:
    mrc p15,0,r0,c7,c4,0
    bx lr

.global c80_restore_par,restore_par_op
c80_restore_par:
restore_par_op:
    mcr p15,0,r0,c7,c4,0
    isb
    bx lr

.global c80_clean,clean_op
c80_clean:
    add r3,r0,r1
    sub r12,r2,#1
    bic r0,r0,r12
1:
clean_op:
    mcr p15,0,r0,c7,c10,1
    add r0,r0,r2
    cmp r0,r3
    blo 1b
    dsb sy
    bx lr

.global c80_invalidate,invalidate_op
c80_invalidate:
    add r3,r0,r1
    sub r12,r2,#1
    bic r0,r0,r12
1:
invalidate_op:
    mcr p15,0,r0,c7,c6,1
    add r0,r0,r2
    cmp r0,r3
    blo 1b
    dsb sy
    bx lr
.section .note.GNU-stack,"",%progbits
