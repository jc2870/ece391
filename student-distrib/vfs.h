#ifndef _VFS_H_
#define _VFS_H_
#include "types.h"


struct file_operations {
    int (*open) (struct inode *, struct file *);
    int (*release) (struct inode *, struct file *);
    ssize_t (*read) (struct file *, char __user *, size_t size, u32 *offset);
	ssize_t (*write) (struct file *, const char __user *, size_t size, u32 *offset);
};

#endif