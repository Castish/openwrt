ENTRY(_start)
SECTIONS { . = 0x40290000; .text : { KEEP(*(.text.entry)) *(.text*) *(.rodata*) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) *(.eh_frame*) } }
