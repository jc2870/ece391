#include "errno.h"
#include "tasks.h"

static int get_fd()
{
    struct task_struct *task = current();
    return -EOPNOTSUPP;
}

int initrd_error(const char *path)
{
    int fd = get_fd();

    return fd;
}

int sys_read(int fd, void *buf, size_t count)
{
    return -EOPNOTSUPP;
}

int sys_write(int fd, void *buf, size_t count)
{
    return -EOPNOTSUPP;
}