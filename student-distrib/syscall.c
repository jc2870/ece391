#include "i8259.h"
#include "lib.h"
#include "syscall.h"
#include "types.h"
#include "errno.h"

/* syscall abi for i386:
 * arg1: ebx arg2: ecx arg3: edx arg4: esi arg5: edi arg6: ebp
 */