#ifndef _VFS_H
#define _VFS_H
#include "mm.h"
#include "types.h"

#define DEFAULT_MAX_FD 32
#define BLOCK_SIZE 4096

struct file;
struct inode;

struct fs_struct {
    struct inode *pwd;
    struct inode *root;
};

struct file_struct {
    struct file *fd_array;
    u32 nr_openfd;
    u32 max_fd;
    u32 *fd_bitmap;
};

struct inode_operations {

};

struct inode {
    u64 i_mode;
    u64 i_ctime;
    u64 i_mtime;
    u32 size; /* size in bytes */

    struct inode_operations *i_ops;

    pfn_t *pages;
    u32 nr_pages;
};

struct file {
    struct file_operations *f_ops;
};

struct file_operations {
    int (*open) (struct inode *inode, struct file *file);
    int (*release) (struct inode *inode, struct file *file);
    ssize_t (*read) (struct file *file, char __user *buf, size_t size, u32 *offset);
	ssize_t (*write) (struct file *file, const char __user *buf, size_t size, u32 *offset);
};

#endif