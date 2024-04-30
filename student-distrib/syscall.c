#include "i8259.h"
#include "lib.h"
#include "syscall.h"
#include "types.h"
#include "errno.h"

/* syscall abi for i386:
 * arg1: ebx arg2: ecx arg3: edx arg4: esi arg5: edi arg6: ebp
 */
ssize_t syscall_handler(u32 n, u32 a1, u32 a2, u32 a3, u32 esp)
{
    if (n >= __NR_max) {
        return -EINVAL;
    }

    return esp;
}