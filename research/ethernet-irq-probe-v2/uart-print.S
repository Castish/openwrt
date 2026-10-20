/* SPDX-License-Identifier: MIT */
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

