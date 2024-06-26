#define ASM
#include "x86_desc.h"

.global test_user0, test_user_stk0
.global test_user1, test_user_stk1
.global test_user2, test_user_stk2
.global init_pgtbl_dir

.align 0x1000
test_user0:
    mov %ss, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov $0x4, %eax       # write syscall
    mov $0x1, %ebx       # write to stdout
    mov $user0_str, %ecx # buf: user0_str
    mov $user0_str_end, %edx
    sub %ecx, %edx
    int $0x80

    mov $1, %eax    # exit syscall
    mov $0, %ebx    # exit error 0
    int $0x80
    mov $0xffff, %ecx
1:  loop 1b
    jmp test_user0

user0_str:
    .ascii "test_user0: hello, world\n"
user0_str_end:

    .fill 128,4,0
test_user_stk0:

.align 0x1000
test_user1:
    mov %ss, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov $0x4, %eax      # write syscall
    mov $0x1, %ebx      # write to stdout
    mov $user1_str, %ecx    # buf: user0_str
    mov $user1_str_end, %edx
    sub %ecx, %edx
    int $0x80

    mov $1, %eax    # exit syscall
    mov $0, %ebx    # exit error 0
    int $0x80
    mov $0xffff, %ecx
2:  loop 2b
    jmp test_user1

user1_str:
    .ascii "test_user1: HELLO, world\n"
user1_str_end:

    .fill 128,4,0
test_user_stk1:

.align 0x1000
test_user2:
    mov %ss, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov $0x4, %eax       # write syscall
    mov $0x1, %ebx       # write to stdout
    mov $user2_str, %ecx # buf: user2_str
    mov $user2_str_end, %edx
    sub %ecx, %edx
    int $0x80

    mov $1, %eax    # exit syscall
    mov $0, %ebx    # exit error 0
    int $0x80
    mov $0xffff, %ecx
3:  loop 3b
    jmp test_user2

user2_str:
    .ascii "test_user2: HELLO, WORLD\n"
user2_str_end:

    .fill 128,4,0
test_user_stk2: