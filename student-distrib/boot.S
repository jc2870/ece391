# boot.S - start point for the kernel after GRUB gives us control
# vim:ts=4 noexpandtab

#define ASM     1

#include "multiboot.h"
#include "x86_desc.h"

.text

    # Multiboot header (required for GRUB to boot us)
    .long MULTIBOOT_HEADER_MAGIC
    .long MULTIBOOT_HEADER_FLAGS
    .long -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

# Entrypoint to the kernel
.globl start, _start, halt, __kernel_start, __kernel_end, kpgd, kpde
_start = vdr2pdr(entry)

.align 4
.global entry
entry:
    # Make sure interrupts are off
    cli
    jmp     continue

continue:
    # Load the GDT
    lgdt [vdr2pdr(gdt_desc)]

    # Load CS with the new descriptor value
    ljmp    $KERNEL_CS, $vdr2pdr(keep_going)

keep_going:
    # Set up ESP so we can have an initial stack
    movl    $KSTACK_BOTTOM, %esp

    # Set up the rest of the segment selector registers
    movw    $KERNEL_DS, %cx
    movw    %cx, %ss
    movw    %cx, %ds
    movw    %cx, %es
    movw    %cx, %fs
    movw    %cx, %gs

    # Push the parameters that entry() expects (see kernel.c):
    # eax = multiboot magic
    # ebx = address of multiboot info struct
    addl $0xC0000000, %ebx
    pushl   %ebx
    pushl   %eax

    movl %ebx, %ebp # backup multiboot address

    lea  (__kernel_start), %ebx
    lea  (__kernel_end), %ecx
    movl %ebx, %edx     # edx存放线性地址
    shr  $22, %edx       # 右移22位得到pgd中的偏移量
    lea  vdr2pdr(kpgd)(,%edx,4), %edx   # 得到pgd中对应偏移量的地址
    lea  vdr2pdr(kpde1), %eax            # 获取kpde1对应的物理地址
    addl $0x7, %eax # set rw p user
    movl %edx, %edi
    stosl           # set pgd ok. Let's set pde

    lea  (__kernel_start), %ebx
    movl %ebx, %edx          # 当前虚拟地址
    andl $0x3ff000, %ebx # ebx存放pde中的偏移量
    shr $12, %ebx        # 需要右移12位，把低12位清0
    lea 0x400, %ecx     # 1024-ecx, 得到页表中剩余需要填充的数量
    subl %ebx, %ecx

    lea vdr2pdr(kpde1)(, %ebx, 4), %ebx # 得到pde中对应偏移量的地址
    movl %ebx, %edi
    subl $0xC0000000, %edx
    movl %edx, %eax # 获取对应的物理地址
    addl $0x7, %eax
11:
    stosl
    addl $0x1000, %eax
    loop 11b

    # 映射0x400000虚拟地址到0x400000物理地址
    # 临时使用，不然开启paging后无法继续执行。 后续在c中可以撤销此映射
    lea vdr2pdr(kpgd), %edi
    addl $0x4, %edi
    lea vdr2pdr(kpde0), %eax
    addl $0x7, %eax
    stosl
    movl $0x400007, %eax
    lea vdr2pdr(kpde0), %edi
    stosl

    lea vdr2pdr(kpgd), %eax
    movl %eax, %cr3

    # 映射栈,仅映射8KB
    lea pdr2vdr(KSTACK_TOP), %edx
    andl $0x3ff000, %edx
    shr $12, %edx
    lea vdr2pdr(kpde1)(, %edx, 4), %edi
    lea KSTACK_TOP, %eax
    addl $0x7, %eax
    lea 0x2, %ecx
22:
    stosl
    addl $0x1000, %eax
    loop 22b

multiboot:
    # 为multiboot address增加映射
    andl $0xfffff000, %ebp
    movl %ebp, %edx
    shr $22, %edx
    lea vdr2pdr(kpgd)(,%edx,4), %edx
    movl %edx, %edi
    lea vdr2pdr(kpde2), %eax
    addl $0x7, %eax
    stosl
    movl %ebp, %edx
    andl $0x3ff000, %edx
    shr $12, %edx
    lea vdr2pdr(kpde2)(,%edx,4), %edx
    movl %edx, %edi
    subl $0xC0000000, %ebp
    movl %ebp, %eax
    addl $0x7, %eax
    stosl

    # enable paging now
    movl %cr0, %eax
    orl  $0x80000000, %eax
    movl %eax, %cr0

    lea pdr2vdr(KSTACK_BOTTOM), %esp
    subl $0x8, %esp # jmp what we pushed in line 49
    # Jump to the C entrypoint to the kernel.
    call    pdr2vdr(main)

    # We'll never get back here, but we put in a hlt anyway.
halt:
    hlt
    jmp     halt

.align 0x1000
kpgd:
    .rept 1024
    .long 0
    .endr

# 映射multiboot info
kpde2:
    .rept 1024
    .long 0
    .endr

# 映射0xC0400000到0x400000
kpde1:
    .rept 1024
    .long 0
    .endr
# 映射0x400000到0x400000
kpde0:
    .rept 1024
    .long 0
    .endr