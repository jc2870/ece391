#ifndef _VFS_H
#define _VFS_H
#include "types.h"

struct file_operations {
    int (*open) (struct initrd_inode_t *, struct file *);
    int (*release) (struct initrd_inode_t *, struct file *);
    ssize_t (*read) (struct file *, char __user *, size_t size, u32 *offset);
	ssize_t (*write) (struct file *, const char __user *, size_t size, u32 *offset);
};

struct file {
    struct file_operations *f_ops;
};


struct initrd_inode_t {

};

#endif