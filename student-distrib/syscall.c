#include "i8259.h"
#include "lib.h"

/* system call: SYSCALL_INTR */
unsigned long syscall_handler(unsigned long c, unsigned long esp)
{
    printf("%c", c);

    return esp;
}
