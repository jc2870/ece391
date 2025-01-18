#include <stdint.h>

#include "ece391support.h"
#include "ece391syscall.h"

#define BUFSIZE 1024
#define NULL 0

static int ece391_execute(uint8_t *buf)
{
	return ece391_execve(buf, NULL, NULL);
}

int main ()
{
    int32_t cnt, rval;
    uint8_t buf[BUFSIZE];
    ece391_fdputs (1, (uint8_t*)"Starting 391 Shell\n");
	int32_t pid;

    while (1) {
        ece391_fdputs (1, (uint8_t*)"391OS> ");
		if (-1 == (cnt = ece391_read (0, buf, BUFSIZE-1))) {
			ece391_fdputs (1, (uint8_t*)"read from keyboard failed\n");
			return 3;
		}
		if (cnt > 0 && ('\n' == buf[cnt - 1] || '\r' == buf[cnt-1]))
			cnt--;
		buf[cnt] = '\0';
		if (0 == ece391_strcmp (buf, (uint8_t*)"exit"))
			return 0;
		if ('\0' == buf[0])
			continue;
		pid = ece391_fork();
		if (pid > 0) {
			// parent process
			ece391_waitpid(pid);
		} else if (pid == 0) {
			// child process
			rval = ece391_execute(buf);
			
			if (-1 == rval)
				ece391_fdputs (1, (uint8_t*)"no such command\n");
			else if (256 == rval)
				ece391_fdputs (1, (uint8_t*)"program terminated by exception\n");
			else if (rval < 0) {
				char fbuf[BUFSIZE] = {0};
				int ret = 0;
				
				ret = ece391_atoi(rval, fbuf, sizeof(fbuf));
				fbuf[ret++] = '\n';
				fbuf[ret] = '\0';
				
				ece391_fdputs(1, (uint8_t*)fbuf) ;
				ece391_fdputs (1, (uint8_t*)"program terminated abnormally\n");
			}
			ece391_exit(rval);
		} else 
			ece391_fdputs(1, (uint8_t*)"fork failed\n");
	}
}

