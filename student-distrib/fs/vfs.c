#include "errno.h"
#include "tasks.h"

static int aaaaaqaa()
{
    // struct task_struct *task = current();
    return -EOPNOTSUPP;
}

// If add this function, init rd will panic. may be because bootimg over 140k? but why?
// int initrd_error(const char *path)
// {
//     int fd = -1;

//     return fd;
// }

int sys_read(int fd, void *buf, size_t count)
{
    return -EOPNOTSUPP;
}

int sys_write(int fd, void *buf, size_t count)
{
    return -EOPNOTSUPP;
}