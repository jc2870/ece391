#include "errno.h"
#include "vfs.h"
#include "lib.h"
#include "liballoc.h"
#include "mutex.h"
#include "tasks.h"
#include "types.h"

static int get_fd(struct task_struct *task, const char *path);
static void put_fd(struct task_struct *task, int fd);
extern struct file_operations serial_file_operations;

static int dummy_open(struct inode *inode, struct file* f)
{
    printf("unsupported syscall %s\n", __func__);
    return -EOPNOTSUPP;
}

static int dummy_release(struct inode *inode, struct file* f)
{
    printf("unsupported syscall %s\n", __func__);
    return -EOPNOTSUPP;
}

ssize_t dummy_read(struct file *file, char __user *buf, size_t size, u32 *offset)
{
    printf("unsupported syscall %s\n", __func__);
    return -EOPNOTSUPP;
}

ssize_t dummy_write(struct file *file, const char __user *buf, size_t size, u32 *offset)
{
    printf("unsupported syscall %s\n", __func__);
    return -EOPNOTSUPP;
}

ssize_t generic_write(struct file *file, const char __user *buf, size_t size, u32 *offset)
{
    if (file->f_fd != 1) {
        printf("unsupported write to fd %d\n", file->f_fd);
        return -EOPNOTSUPP;
    }

    return printf("%s", buf);
}

struct file_operations dummy_file_operations = {
    .open    = dummy_open,
    .release = dummy_release,
    .read = dummy_read,
    .write = dummy_write,
};

struct file_operations generic_file_operations = {
    .open    = dummy_open,
    .release = dummy_release,
    .read = dummy_read,
    .write = generic_write,
};

void set_builtin_fd(struct task_struct *task)
{
    int fd;
    struct files_struct *files = task->files;

    fd = get_fd(task, "stdin");
    panic_on(fd != 0, "fd should be 0, but %d\n", fd);
    fd = get_fd(task, "stdout");
    panic_on(fd != 1, "fd should be 1, but %d\n", fd);
    fd = get_fd(task, "stderr");
    panic_on(fd != 2, "fd should be 2, but %d\n", fd);

    panic_on(files->fd_bitmap[0] != 0x7, "set builtin fd error\n");
}

void alloc_files_struct(struct task_struct *task)
{
    struct files_struct *files = kmalloc(sizeof(struct files_struct));
    panic_on(!files, "alloc files failed\n");

    files->max_fd = DEFAULT_MAX_FD;
    files->fd_array = kmalloc(sizeof(void*) * files->max_fd);
    files->fd_bitmap = kmalloc(files->max_fd/8);
    files->nr_openfd = 0;
    files->fd_bitmap[0] = 0;
    memset(files->fd_array, 0, sizeof(void*)*files->max_fd);
    mutex_init(&files->mutex);
    task->files = files;

    if (!files->fd_bitmap || !files->fd_array) {
        kfree(files->fd_array);
        kfree(files->fd_bitmap);
        kfree(files);
    }
    set_builtin_fd(task);
}

void clear_opened_files(struct task_struct *task)
{
    int fd;

    while (1) {
        fd = find_first_set_bit(task->files->fd_bitmap[0]);
        if (fd == 0xff) {
            break;
        }
        put_fd(task, fd);
    }
}

void destroy_files_struct(struct task_struct *task)
{
    kfree(task->files->fd_array);
    kfree(task->files->fd_bitmap);
    kfree(task->files);
    task->files = NULL;
}

struct inode* get_inode_from_path(const char *path)
{
    return NULL;
}

static struct file* alloc_file(const char *path)
{
    struct file *f = kmalloc(sizeof(struct file));
    panic_on(!f, "alloc file failed\n");
    f->f_ops = &serial_file_operations;
    f->f_path = kstrdup(path);
    f->f_inode = get_inode_from_path(path);
    // f->f_ops = f->f_inode->i_fops;

    return f;
}

static void destroy_file(struct file *f)
{
    kfree(f->f_path);
    kfree(f);
}

static int get_fd(struct task_struct *task, const char *path)
{
    struct files_struct *cur_files = task->files;
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
    panic_on(fd >= DEFAULT_MAX_FD, "invalid fd:%d\n", fd);
    set_bit(&bitmap, fd);
    cur_files->fd_bitmap[0] = bitmap;
    cur_files->nr_openfd++;

    f = cur_files->fd_array[fd];
    panic_on(f, "try to alloc already alloced file\n");
    f = alloc_file(path);
    f->f_fd = fd;
    cur_files->fd_array[fd] = f;

out:
    mutex_unlock(&cur_files->mutex);
    return fd;
}

static void put_fd(struct task_struct *task, int fd)
{
    int bitmap;
    struct files_struct *cur_files = task->files;
    struct file *f;

    panic_on(fd >= DEFAULT_MAX_FD, "invalid fd:%d\n", fd);
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

struct file* get_file(int fd, struct files_struct *files)
{
    struct file *f = NULL;

    mutex_lock(&files->mutex);
    f = files->fd_array[fd];
    mutex_unlock(&files->mutex);

    return f;
}

int sys_open(const char *path)
{
    struct file *f = NULL;
    int fd = get_fd(current(), path);
    f = get_file(fd, current()->files);
    if (f->f_inode) {
        f->f_inode->i_fops->open(f->f_inode, f);
    }

    return fd;
}

int sys_close(int fd)
{
    put_fd(current(), fd);
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
    struct files_struct *files = current()->files;
    mutex_lock(&files->mutex);
    f = current()->files->fd_array[fd];
    mutex_unlock(&files->mutex);

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
    struct files_struct *files = current()->files;
    mutex_lock(&files->mutex);
    f = current()->files->fd_array[fd];
    mutex_unlock(&files->mutex);

    if (ret) {
        goto out;
    }

    ret = f->f_ops->write(f, buf, count, 0);

out:
    return ret;
}

int sys_creat()
{
    return -1;
}

int sys_link()
{
    return -1;
}

int sys_unlink()
{
    return -1;
}