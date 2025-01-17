#ifndef _INIT_RD_H_
#define _INIT_RD_H_
#include "types.h"
#include "multiboot.h"
#include "lib.h"

#define DENTRY_LEN 32
#define BLOCK_SIZE 4096
#define ALL_FILE 0xffffffff

struct fs_stat {
    u32 nr_dentries;
    u32 nr_inodes;
    u32 nr_blocks;

    char reserved[52];
};

#define D_TYPE_RTC 0
#define D_TYPE_DIR 1
#define D_TYPE_REG 2

typedef struct initrd_dentry {
    char name[DENTRY_LEN];
    u32 type;
    u32 inode;

    char reserved[24];
} initrd_dentry_t ;

struct initrd_inode_t {
    u32 size; /* size in bytes */
    u32 data_blocks[BLOCK_SIZE/4-1];
};

struct boot_block {
    struct fs_stat stat;
    struct initrd_dentry dentries[BLOCK_SIZE/64-1];
};

struct data_block {
    char data [BLOCK_SIZE];
};

struct initrd_fs_mod {
    struct boot_block *boot_block;
    struct initrd_inode_t *inodes;
    struct data_block *blocks;
};


extern void initrd_init(multiboot_info_t *mbi);
extern void display_initrd_file_name(void);

extern s32 __must_check read_dentry_by_name(const char* fname, initrd_dentry_t* dentry);
extern s32 __must_check read_dentry_by_ino(u32 index, initrd_dentry_t* dentry);
extern s32 __must_check read_data_by_ino(u32 inode, u32 offset, char *buf, u32 len);
extern s32 __must_check read_data_by_name(const char *fname, u32 offset, char *buf, u32 len);

#endif