#include "errno.h"
#include "fs/vfs.h"
#include "lib.h"
#include "liballoc.h"
#include "mutex.h"
#include "tasks.h"
#include "types.h"

static int dummy_open(struct inode *inode, struct file* f)
{
    return -EOPNOTSUPP;
}

static int dummy_release(struct inode *inode, struct file* f)
{
    return -EOPNOTSUPP;
}

ssize_t dummy_read(struct file *file, char __user *buf, size_t size, u32 *offset)
{
    return -EOPNOTSUPP;
}

ssize_t dummy_write(struct file *file, const char __user *buf, size_t size, u32 *offset)
{
    return -EOPNOTSUPP;
}

struct file_operations dummy_file_operations = {
    .open    = dummy_open,
    .release = dummy_release,
    .read = dummy_read,
    .write = dummy_write,
};

struct files_struct * alloc_files_struct()
{
    struct files_struct *files = kmalloc(sizeof(struct files_struct));
    if (!files) {
        return NULL;
    }

    files->max_fd = DEFAULT_MAX_FD;
    files->fd_array = kmalloc(sizeof(void*) * files->max_fd);
    files->fd_bitmap = kmalloc(files->max_fd/8);
    files->nr_openfd = 0;
    mutex_init(&files->mutex);

    if (!files->fd_bitmap || !files->fd_array) {
        kfree(files->fd_array);
        kfree(files->fd_bitmap);
        kfree(files);
        return NULL;
    }

    return files;
}

static struct file* alloc_file()
{
    struct file *f = kmalloc(sizeof(struct file));
    panic_on(!f, "alloc file failed\n");
    f->f_ops = &dummy_file_operations;

    return f;
}

static void destroy_file(struct file *f)
{
    kfree(f);
}

static int get_fd()
{
    struct files_struct *cur_files = current()->files;
    struct file *f;
    int fd;
    int bitmap;

    mutex_lock(&cur_files->mutex);

    bitmap = cur_files->fd_bitmap[0];
    if (bitmap == 0xffffffff) {
        fd = -ENOSPC;
        goto out;
    }

    fd = find_first_free_bit(bitmap);
    panic_on(fd == 0xff, "unexpected here, bitmap is 0x%lx\n", bitmap);
    set_bit(&bitmap, fd);
    cur_files->fd_bitmap[0] = bitmap;
    cur_files->nr_openfd++;

    f = cur_files->fd_array[fd];
    panic_on(f, "try to alloc already alloced file\n");
    f = alloc_file();
    cur_files->fd_array[fd] = f;

out:
    mutex_unlock(&cur_files->mutex);
    return fd;
}

static void put_fd(int fd)
{
    int bitmap;
    struct files_struct *cur_files = current()->files;
    struct file *f;

    mutex_lock(&cur_files->mutex);

    bitmap = cur_files->fd_bitmap[0];
    if (get_bits(bitmap, fd, fd) == 0) {
        panic("try to free a fd already free\n");
    }

    f = cur_files->fd_array[fd];
    panic_on(!f, "try to free a file already free\n");
    destroy_file(f);

    clear_bit(&bitmap, fd);
    cur_files->fd_bitmap[0] = bitmap;

    mutex_unlock(&cur_files->mutex);
}

int sys_open(const char *path)
{
    int fd = get_fd();

    return fd;
}

int sys_close(int fd)
{
    put_fd(fd);
    return 0;
}

static int check_fd(int fd)
{
    struct file *f = NULL;
    int bitmap = 0;
    struct files_struct *cur_files = current()->files;

    mutex_lock(&cur_files->mutex);
    f = cur_files->fd_array[fd];
    bitmap = cur_files->fd_bitmap[0];
    mutex_unlock(&cur_files->mutex);

    if (f == NULL && get_bits(bitmap, fd, fd) == 0) {
        return -EBADF;
    }
    if (f == NULL || get_bits(bitmap, fd, fd) == 0) {
        panic("unexpected here, f: 0x%lx bitmap: 0x%x\n", f, bitmap);
    }

    return 0;
}

ssize_t sys_read(int fd, char __user *buf, size_t count)
{
    struct file *f = NULL;
    ssize_t ret = check_fd(fd);

    if (ret) {
        goto out;
    }

    ret = f->f_ops->read(f, buf, count, 0);

out:
    return ret;
}

int sys_write(int fd, const char __user *buf, size_t count)
{
    struct file *f = NULL;
    ssize_t ret = check_fd(fd);

    if (ret) {
        goto out;
    }

    ret = f->f_ops->write(f, buf, count, 0);

out:
    return ret;
}