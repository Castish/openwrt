ENTRY(_start)
SECTIONS
{
    . = 0x41000000;
    .text : { KEEP(*(.text.entry)) *(.text*) *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    .mcu 0x41004000 : { *(.mcu) }
    .wifi 0x41018000 : { *(.wifi) }
    .backup 0x41050000 : { *(.backup) }
    /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(_start == 0x41000000, "Fixed raw entry must be byte zero")
ASSERT(SIZEOF(.text) <= 0x4000, "Code overlaps bootstrap firmware")
ASSERT(SIZEOF(.data) == 0 && SIZEOF(.bss) == 0, "Only backup may be static writable RAM")
ASSERT(SIZEOF(.mcu) == 72096 && SIZEOF(.wifi) == 169240, "Unexpected firmware length")
ASSERT(SIZEOF(.backup) == 0x200000, "Full 2MiB DDR backup required")
