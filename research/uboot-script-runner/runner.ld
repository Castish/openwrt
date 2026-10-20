ENTRY(_start)
SECTIONS
{
    . = 0x40280000;
    .text : { KEEP(*(.text.entry)) *(.text*) *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(_start == 0x40280000, "Raw entry must be byte zero")
ASSERT(SIZEOF(.data) == 0 && SIZEOF(.bss) == 0, "No writable static data")
ASSERT(SIZEOF(.text) <= 0x10000, "Keep runner inside its reserved 64KiB")
