#ifndef _VFS_H
#define _VFS_H
#include "mm.h"
#include "tasks.h"
#include "types.h"
#include "mutex.h"

#define DEFAULT_MAX_FD 32
#define BLOCK_SIZE 4096

#define STD_IN  0
#define STD_OUT 1
#define STD_ERR 2

struct file;
struct inode;

struct fs_struct {
    struct inode *pwd;
    struct inode *root;
};

struct files_struct {
    struct file **fd_array;
    u32 nr_openfd;
    u32 max_fd;
    u32 *fd_bitmap;
    struct mutex mutex;
};

struct inode_operations {

};

struct file {
    struct file_operations *f_ops;
    u32 f_fd;
    char *f_path;
    struct inode *f_inode;
};

struct file_operations {
    int (*open) (struct inode *inode, struct file *file);
    int (*release) (struct inode *inode, struct file *file);
    ssize_t (*read) (struct file *file, char __user *buf, size_t size, u32 *offset);
	ssize_t (*write) (struct file *file, const char __user *buf, size_t size, u32 *offset);
};

struct inode {
    u64 i_mode;
    u64 i_ctime;
    u64 i_mtime;
    u32 size; /* size in bytes */

    struct inode_operations *i_ops;
    struct file_operations  *i_fops;

    pfn_t *pages;
    u32 nr_pages;
    u32 i_no;
};

extern void alloc_files_struct(struct task_struct *task);
extern void destroy_files_struct(struct task_struct *task);

extern void clear_opened_files(struct task_struct *task);
#endif