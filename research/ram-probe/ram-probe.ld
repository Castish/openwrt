ENTRY(_start)
SECTIONS
{
    . = 0;
    .text : { *(.text*) *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment) *(.note.GNU-stack) }
}
ASSERT(_start == 0, "Raw payload entry must be byte zero")
ASSERT(SIZEOF(.data) == 0 && SIZEOF(.bss) == 0, "Payload must be self-contained")
ASSERT(SIZEOF(.text) < 512, "Payload must fit in one default TFTP block")
