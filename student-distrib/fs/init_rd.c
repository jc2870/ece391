#include "init_rd.h"
#include "errno.h"
#include "liballoc.h"
#include "lib.h"
#include "mm.h"
#include "vfs.h"
#include "elf.h"
#include "x86_desc.h"

#define INITRD_FS_MOD "/filesys_img"

static struct initrd_fs_mod *fs = NULL;
static struct file_operations initrd_file_operations;
static struct file_operations initrd_dir_operations;
static struct inode_operations initrd_dir_inode_ops;

module_t *get_fs_mod(multiboot_info_t *mbi)
{
    if (CHECK_FLAG(mbi->flags, 3)) {
        int mod_count = 0;
        module_t* mod = (module_t*)pdr2vdr(mbi->mods_addr);
        mod->string = pdr2vdr(mod->string);
        mod->mod_start = pdr2vdr(mod->mod_start);
        mod->mod_end = pdr2vdr(mod->mod_end);
        while (mod_count < mbi->mods_count) {
            if (!memcmp((void*)mod->string, INITRD_FS_MOD, sizeof(INITRD_FS_MOD))) {
                return mod;
            }
            mod_count++;
            mod++;
        }
    }

    return NULL;
}

void initrd_init(multiboot_info_t *mbi)
{
    fs = kmalloc(sizeof(struct initrd_fs_mod));
    module_t *module = get_fs_mod(mbi);
    int i = 0;
    struct inode *root = kmalloc(sizeof(struct inode));
    struct task_struct *cur = current();

    panic_on(!fs, "alloc fs failed\n");
    panic_on(!module, "cannot find fs module %s\n", INITRD_FS_MOD);
    panic_on(!root, "alloc root failed\n");

    fs->boot_block = (void*)module->mod_start;
    fs->inodes = (void*)(fs->boot_block + 1);
    fs->blocks = (void*)(fs->boot_block->stat.nr_inodes*4096 + (char*)fs->inodes);
    root->i_no = ROOTINO;
    root->i_ops = &initrd_dir_inode_ops;
    root->i_mode = S_IFDIR;
    cur->fs->root = root;
    cur->fs->pwd = root;

    panic_on(module->mod_end != (u32)(fs->blocks + fs->boot_block->stat.nr_blocks),
            "unexpected here");

    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        fs->boot_block->dentries[i].name[DENTRY_LEN - 1] = '\0';
    }
}

void display_initrd_file_name()
{
    int i = 0;
    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        printf("file: %s\n", fs->boot_block->dentries[i].name);
    }
}

/* @param: fname in
 *         dentry out
 */
s32 read_dentry_by_name(const char* fname, initrd_dentry_t* dentry)
{
    int len = strlen(fname);
    int i = 0;

    len = len < DENTRY_LEN-1 ? len : DENTRY_LEN-1;
    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        struct initrd_dentry *d = &fs->boot_block->dentries[i];
        if (!strncmp(fname, d->name, len)) {
            strcpy(dentry->name, d->name);
            dentry->inode = d->inode;
            dentry->type = d->type;

            return 0;
        }
    }

    return -ENOENT;
}

/* @param: index in
 *         dentry out
 */
s32 read_dentry_by_ino(u32 index, initrd_dentry_t* dentry)
{
    int i = 0;

    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        struct initrd_dentry *d = &fs->boot_block->dentries[i];
        if (d->inode == index) {
            strcpy(dentry->name, d->name);
            dentry->inode = d->inode;
            dentry->type = d->type;

            return 0;
        }
    }

    return -1;
}

s32 __read_data_by_ino(u32 ino, u32 offset, char *buf, u32 len)
{
    struct initrd_inode_t *inode = NULL;
    int nr_blocks;
    int nr_bytes;
    int i, oft = 0;
    int block = 0;

    inode = &fs->inodes[ino];
    len = len < inode->size ? len : inode->size;
    nr_blocks = len/BLOCK_SIZE;
    nr_bytes  = len%BLOCK_SIZE;

    for (i = 0; i < nr_blocks; ++i) {
        block = inode->data_blocks[i];
        memcpy(buf + oft, fs->blocks[block].data, BLOCK_SIZE);

        oft += BLOCK_SIZE;
    }

    if (nr_bytes) {
        block = inode->data_blocks[i];
        memcpy(buf + oft, fs->blocks[block].data, nr_bytes);
    }

    return len;
}

s32 read_data(u32 ino, u32 offset, char *buf, u32 len)
{
    struct initrd_dentry d;
    int err;

    panic_on(offset, "current offset only support 0\n");
    err = read_dentry_by_ino(ino, &d);
    panic_on(err == -1, "error inode number %d\n", ino);

    if (d.type != D_TYPE_REG) {
        return -1;
    }

    return __read_data_by_ino(ino, offset, buf, len);
}

s32 read_data_by_name(const char *fname, u32 offset, char *buf, u32 len)
{
    struct initrd_dentry d;
    int ret;

    panic_on(offset, "current offset only support 0\n");
    if ((ret = read_dentry_by_name(fname, &d)))
	return ret;
    return __read_data_by_ino(d.inode, offset, buf, len);
}

int initrd_open(struct inode *inode, struct file *file)
{
    return 0;
}

int initrd_release(struct inode *inode, struct file *file)
{
    file->f_ops = NULL;
    return 0;
}

ssize_t initrd_read(struct file *file, char __user *buf, size_t size, u32 *offset)
{
    return read_data(file->f_inode->i_no, *offset, (char*)buf, size);
}

ssize_t initrd_write(struct file *file, const char __user *buf, size_t size, u32 *offset)
{
    /* initrd is read only */
    return -EOPNOTSUPP;
}

static ssize_t initrd_lookup(const char *path)
{
	struct initrd_dentry d;
	return read_dentry_by_name(path, &d);
}

static struct file_operations initrd_file_operations = {
    .open    = initrd_open,
    .release = initrd_release,
    .read    = initrd_read,
    .write   = initrd_write,
};

static struct inode_operations initrd_dir_inode_ops = {
	.lookup = initrd_lookup,
};