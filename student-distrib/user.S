#define ASM
#include "x86_desc.h"

.global user0, user_stk0, kernel_stk0
.global user1, user_stk1, kernel_stk1
.global user2, user_stk2, kernel_stk2
.global init_pgtbl_dir

.align 0x1000
user0:
    mov %ss, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov $65, %eax
    int $0x80
    mov $0xffff, %ecx
1:  loop 1b
    jmp user0

    .fill 128,4,0
user_stk0:

.align 0x1000
user1:
    mov %ss, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov $66, %eax
    int $0x80
    mov $0xffff, %ecx
2:  loop 2b
    jmp user1

    .fill 128,4,0
user_stk1:

.align 0x1000
user2:
    mov %ss, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov $67, %eax
    int $0x80
    mov $0xffff, %ecx
3:  loop 3b
    jmp user2

    .fill 128,4,0
user_stk2: