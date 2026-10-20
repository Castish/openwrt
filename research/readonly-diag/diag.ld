ENTRY(_start)
SECTIONS
{
    . = 0;
    .text : { *(.text*) *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment) *(.note.GNU-stack) }
}
ASSERT(_start == 0, "Raw entry must be byte zero")
ASSERT(SIZEOF(.data) == 0 && SIZEOF(.bss) == 0, "No writable static data")
ASSERT(SIZEOF(.text) < 4096, "Keep diagnostic within one RAM page")
