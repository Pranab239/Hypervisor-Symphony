# User Morpheus VM

.globl _start
    .code16
_start:
    xorw %ax, %ax
    
loop1:
    out %ax, $0x11
    dec %ax
    jmp loop1

