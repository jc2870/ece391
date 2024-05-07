#include "fs.h"
#include "liballoc.h"
#include "lib.h"

#define FS_MOD "filesys_img"

static struct fs_mod *fs = NULL;

module_t *get_fs_mod(multiboot_info_t *mbi)
{
    module_t *fs_mod = NULL;
    if (CHECK_FLAG(mbi->flags, 3)) {
        int mod_count = 0;
        module_t* mod = (module_t*)mbi->mods_addr;
        while (mod_count < mbi->mods_count) {
            if (memcmp((void*)mod->string, FS_MOD, sizeof(FS_MOD))) {
                fs_mod = mod;
                break;
            }
            mod_count++;
            mod++;
        }
    }

    return fs_mod;
}

void init_fs(multiboot_info_t *mbi)
{
    fs = kmalloc(sizeof(struct fs_mod));
    module_t *module = get_fs_mod(mbi);
    int i = 0;
    panic_on(!fs, "alloc fs failed\n");

    fs->boot_block = (void*)module->mod_start;
    fs->inodes = (void*)(fs->boot_block + 1);
    fs->blocks = (void*)(fs->boot_block->stat.nr_inodes*4096 + (char*)fs->inodes);

    panic_on(module->mod_end != (u32)(fs->blocks + fs->boot_block->stat.nr_blocks),
            "unexpected here");

    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        fs->boot_block->dentries[i].name[DENTRY_LEN - 1] = '\0';
    }
}

void display_file_name()
{
    int i = 0;
    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        printf("file: %s\n", fs->boot_block->dentries[i].name);
    }
}

/* @param: fname in
 *         dentry out
 */
s32 read_dentry_by_name(const char* fname, dentry_t* dentry)
{
    int len = strlen(fname);
    int i = 0;

    len = len < DENTRY_LEN-1 ? len : DENTRY_LEN-1;
    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        struct dentry *d = &fs->boot_block->dentries[i];
        if (!strncmp(fname, d->name, len)) {
            strcpy(dentry->name, d->name);
            dentry->inode = d->inode;
            dentry->type = d->type;

            return 0;
        }
    }

    return -1;
}

/* @param: index in
 *         dentry out
 */
s32 read_dentry_by_ino(u32 index, dentry_t* dentry)
{
    int i = 0;

    for (i = 0; i < fs->boot_block->stat.nr_dentries; ++i) {
        struct dentry *d = &fs->boot_block->dentries[i];
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
    struct inode *inode = NULL;
    int nr_blocks;
    int nr_bytes;
    int i, oft = 0;
    int block = 0;

    inode = &fs->inodes[ino];
    nr_blocks = inode->size/BLOCK_SIZE;
    nr_bytes  = inode->size % BLOCK_SIZE;
    len = len < inode->size ? len : inode->size;

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
    struct dentry d;
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
    struct dentry d;

    panic_on(offset, "current offset only support 0\n");
    read_dentry_by_name(fname, &d);
    return __read_data_by_ino(d.inode, offset, buf, len);
}