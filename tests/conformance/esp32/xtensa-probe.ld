ENTRY(fixture_entry)
SECTIONS {
  .literal 0x400d1000 : { *(.literal) }
  .text 0x400d1010 : { *(.text) }
}
