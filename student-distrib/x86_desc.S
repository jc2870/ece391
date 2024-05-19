# x86_desc.S - Set up x86 segment descriptors, descriptor tables
# vim:ts=4 noexpandtab

#define ASM     1
#include "x86_desc.h"

.text

.globl ldt_size, tss_size
.globl gdt_desc0, gdt_desc1, ldt_desc, tss_desc
.globl tss, tss_desc_ptr, ldt, ldt_desc_ptr
.globl gdt_ptr
.globl idt_desc_ptr, idt

.align 4


tss_size:
    .long tss_bottom - tss - 1

ldt_size:
    .long ldt_bottom - ldt - 1

    .word 0 # Padding
ldt_desc:
    .word KERNEL_LDT
    .long ldt

    .align 4
tss:
_tss:
    .rept 104
    .byte 0
    .endr
tss_bottom:

    .align  16
gdt_ptr:
_gdt:

    # First GDT entry cannot be used
    .quad 0

    # NULL entry
    .quad 0
    .quad 0x00CF9A000000FFFF # kernel cs 0x00 C F 9 A 00 0000FFFF
    .quad 0x00CF92000000FFFF # kernel ds 0x00 C F 9 2 00 0000FFFF
    .quad 0x00CFFA000000FFFF # user cs   0x00 C F F A 00 0000FFFF
    .quad 0x00CFF2000000FFFF # user ds   0x00 C F F 2 00 0000FFFF
tss_desc_ptr:
    .quad 0x00CFF2000000FFFF # kernel tss
    .quad 0x00CFF2000000FFFF # kernel ldt
    .rept 248
    .quad 0
    .endr
gdt_end:
    # Segmentation will not be used
    # CS and DS both are 0-4GB r/w segments
    #
    # The layout is (from Intel IA-32 reference manual):
    #  31        24 23  22  21  20  19   16 15  14 13 12  11   8 7          0
    # |----------------------------------------------------------------------|
    # |            |   | D |   | A |  Seg  |   |  D  |   |      |            |
    # | Base 31:24 | G | / | 0 | V | Limit | P |  P  | S | Type | Base 23:16 |
    # |            |   | B |   | L | 19:16 |   |  L  |   |      |            |
    # |----------------------------------------------------------------------|
    #
    # |----------------------------------------------------------------------|
    # |                                    |                                 |
    # | Base 15:0                          | Segment Limit 15:0              |
    # |                                    |                                 |
    # |-------------------------------------------------------------------
gdt_desc0:
    .word gdt_end - gdt_ptr - 1
    .long vdr2pdr(gdt_ptr)

gdt_desc1:
    .word gdt_end - gdt_ptr - 1
    .long gdt_ptr

    # Set up one LDT
ldt_desc_ptr:
    .quad 0

gdt_bottom:

    .align 16
ldt:
    .rept 4
    .quad 0
    .endr
ldt_bottom:

.align 4
    .word 0 # Padding
idt_desc_ptr:
    .word idt_bottom - idt - 1
    .long idt


    .align  16
idt:
    .rept NUM_VEC
    .quad 0
    .endr

idt_bottom:
