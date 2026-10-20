ENTRY(c80_netboot_entry)
SECTIONS {
  . = 0x41c2f850;
  .text : { KEEP(*(.text.entry)) *(.text*) *(.rodata*) }
  /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) *(.eh_frame*) }
}
