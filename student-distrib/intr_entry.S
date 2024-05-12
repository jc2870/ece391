#define ASM

#include "asm.h"
#include "intr.h"
#include "x86_desc.h"

.section .text

.global ignore_intr,intr_num, init_pgtbl_dir, common_iret
.global generic_intr_handler, syscall_entry, timer_interrupt_entry, first_return_to_user

# reference chapter 6.12.1 (Exception- or Interrupt-Handler Procedures) volume 3 intel manual
# After interruption or exception happened, there are 2 circumstances
# 1. No Privilege-Level Change, stack will be
#   EFLAGS
#   CS
#   EIP
#   Error Code    -< ESP
# 2. Privilege-Level Change, stack will be
#   SS
#   ESP
#   EFLAGS
#   CS
#   EIP
#   Error code    -< ESP


common_intr_entry:
    # pusha instruction pushes the contents of the general-purpose registers onto stack.
    popl errno
    pushl errno
    pusha
    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs

    # push %eax
    # movl init_pgtbl_dir, %eax
    # movl %eax, %cr3
    # pop %eax
    # according to https://github.com/hjl-tools/x86-psABI/wiki/intel386-psABI-1.1.pdf and
    #              https://stackoverflow.com/a/37635449/19784965
    # The direction flag DF in the %EFLAGS register must be clear (set to “forward”
    # direction) on function entry and return.
    cld
    pushl %esp
    pushl intr_num
    pushl errno
    call generic_intr_handler
    # The above call instruction will overwrite esp regesiter, so we need restore esp using eax
    movl %eax, %esp

    jmp common_iret

ENTRY(ignore_intr):
    iret

.macro MAKE_INTR_ENTRY_WITHOUT_ERRCODE num
ENTRY(intr\num\()_entry):
    movl $\num, (intr_num)
    pushl $0
    jmp common_intr_entry
.endm

.macro MAKE_INTR_ENTRY_WITH_ERRCODE num
ENTRY(intr\num\()_entry):
    movl $\num, (intr_num)
    jmp common_intr_entry
.endm

# intel predefined
# note: according to 6.4.2 volume3 intel manual,
#       can NOT use INT instruction to produce these predefined intr, for that will damage stack.
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x0
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x1
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x2
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x3
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x4
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x5
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x6
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x7
MAKE_INTR_ENTRY_WITH_ERRCODE    0x8
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x9
MAKE_INTR_ENTRY_WITH_ERRCODE    0xA
MAKE_INTR_ENTRY_WITH_ERRCODE    0xB
MAKE_INTR_ENTRY_WITH_ERRCODE    0xC
MAKE_INTR_ENTRY_WITH_ERRCODE    0xD
MAKE_INTR_ENTRY_WITH_ERRCODE    0xE
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0xF
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x10
MAKE_INTR_ENTRY_WITH_ERRCODE    0x11
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x12
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x13
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x14
MAKE_INTR_ENTRY_WITHOUT_ERRCODE 0x15

MAKE_INTR_ENTRY_WITHOUT_ERRCODE PIC_KEYBOARD_INTR
MAKE_INTR_ENTRY_WITHOUT_ERRCODE PIC_SERIAL2_INTR
MAKE_INTR_ENTRY_WITHOUT_ERRCODE PIC_HARDISK_INTR
MAKE_INTR_ENTRY_WITHOUT_ERRCODE PIC_PRINTER_INTR
MAKE_INTR_ENTRY_WITHOUT_ERRCODE PIC_RTC_INTR
MAKE_INTR_ENTRY_WITHOUT_ERRCODE PIC_MOUSE_INTR

syscall_entry:
    pushl %eax
    pushl %ecx
    pushl %edx
    pushl %ebx
    pushl %esp
    pushl %ebp
    pushl %esi
    pushl %edi

    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs
    cmpl nr_syscalls, %eax
    jge syscall_err
    cld
    pushl %edx
    pushl %ecx
    pushl %ebx
    call *syscall_table(,%eax,4)
    popl %ebx
    popl %ecx
    popl %edx

    jmp syscall_iret
syscall_err:
    mov $-1, %eax
    jmp syscall_iret

syscall_iret:
    popl %gs
    popl %fs
    popl %es
    popl %ds

    # cannot use popa here, cause we need eax to pass retval to user
    popl %edi
    popl %esi
    popl %ebp
    popl %esp
    popl %ebx
    popl %edx
    popl %ecx

    addl $4, %esp # skip eax

    iret

timer_interrupt_entry:
    pushl $0
    pusha
    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs

    call timer_handler
    jmp common_iret


common_iret:
    popl %gs
    popl %fs
    popl %es
    popl %ds
    popa

    popl errno

    iret


# get eip and esp from stack, eip and esp have been pushed into stack in init_task()
first_return_to_user:
    movl -4(%esp), %eax # user stack
    movl -8(%esp), %ebx # user eip
    pushl $USER_DS
    pushl %eax
    pushfl
    push $USER_CS
    pushl %ebx
    movl $0, %eax
    movl $0, %ebx
    iret


.data
    intr_num: .long 0
    errno   : .long 0