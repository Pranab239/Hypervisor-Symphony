# User Neo (The One) VM

.globl _start
    .code16
_start:
    xorw %ax, %ax
    
loop1:
    // out %ax, $0x10
    inc %ax
    jmp loop1

