#include "errno.h"
#include "fs.h"

int sys_read(int fd, void *buf, size_t count)
{
    return -EOPNOTSUPP;
}

int sys_write(int fd, void *buf, size_t count)
{
    return -EOPNOTSUPP;
}