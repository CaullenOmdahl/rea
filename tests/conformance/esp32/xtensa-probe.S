    .section .literal,"a",@progbits
    .align 4
    .global fixture_literal
fixture_literal:
    .word fixture_callee
    .section .text,"ax",@progbits
    .align 4
    .global fixture_entry
    .type fixture_entry,@function
fixture_entry:
    entry a1, 32
    call8 fixture_callee
    l32r a8, fixture_literal
    callx8 a8
    retw.n
    .size fixture_entry, .-fixture_entry
    .align 4
    .global fixture_callee
    .type fixture_callee,@function
fixture_callee:
    entry a1, 32
    movi.n a2, 7
    retw.n
    .size fixture_callee, .-fixture_callee
