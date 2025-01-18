#include "ece391sysnum.h"

/* 
 * Rather than create a case for each number of arguments, we simplify
 * and use one macro for up to three arguments; the system calls should
 * ignore the other registers, and they're caller-saved anyway.
 */
#define DO_CALL(name,number)   \
.GLOBL name                   ;\
name:   PUSHL	%EBX          ;\
	MOVL	$number,%EAX  ;\
	MOVL	8(%ESP),%EBX  ;\
	MOVL	12(%ESP),%ECX ;\
	MOVL	16(%ESP),%EDX ;\
	INT	$0x80         ;\
	POPL	%EBX          ;\
	RET

/* the system call library wrappers */
DO_CALL(ece391_setup,SYS_setup)
DO_CALL(ece391_exit,SYS_exit)
DO_CALL(ece391_fork,SYS_fork)
DO_CALL(ece391_read,SYS_read)
DO_CALL(ece391_write,SYS_write)
DO_CALL(ece391_open,SYS_open)
DO_CALL(ece391_close,SYS_close)
DO_CALL(ece391_waitpid,SYS_waitpid)
DO_CALL(ece391_create,SYS_creat)
DO_CALL(ece391_link,SYS_link)
DO_CALL(ece391_unlink,SYS_unlink)
DO_CALL(ece391_execve,SYS_execve)


/* Call the main() function, then halt with its return value. */

.GLOBAL _start
_start:
	CALL	main
    PUSHL   $0
    PUSHL   $0
	PUSHL	%EAX
	CALL	ece391_exit

