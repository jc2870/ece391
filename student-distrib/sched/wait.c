#include "container_of.h"
#include "lib.h"
#include "list.h"
#include "timer.h"
#include "types.h"
#include <wait.h>
#include <tasks.h>
#include <errno.h>

void init_wait_queue_head(wait_queue_head_t *head)
{
    spinlock_init(&head->lock);
    INIT_LIST(&head->head);
}

void init_wait_queue_entry(wait_queue_entry_t *wait_entry, void *private, wait_queue_func_t func)
{
    wait_entry->func = func;
    INIT_LIST(&wait_entry->entry);
    wait_entry->private = private;
    wait_entry->flags = 0;
}

void finish_wait(wait_queue_entry_t *entry)
{
    list_del(&entry->entry);
}

void prepare_to_wait(wait_queue_head_t *head, wait_queue_entry_t *entry, int state)
{
    current()->state = state;
    list_add_tail(&head->head, &entry->entry);
}

int default_wakeup(wait_queue_entry_t *entry, void *key)
{
    int flags;
    struct task_struct *task = entry->private;

    cli_and_save(flags);
    task->state = TASK_RUNNABLE;
    list_del(&task->task_list);
    list_add_tail(&runnable_tasks, &task->task_list);
    sti_and_restore(flags);

    return 0;
}

static bool pid_child_should_wake(struct wait_ops *ops, struct task_struct *task)
{
    if (ops->pid == -1 || task->pid == ops->pid) {
        return true;
    }

    return false;
}

static int child_wait_callback(wait_queue_entry_t *entry, void *key)
{
    struct wait_ops *ops = container_of(entry, struct wait_ops, entry);
    struct task_struct *task = (struct task_struct*)key;

    if (pid_child_should_wake(ops, task)) {
        default_wakeup(entry, key);
    }

    return 0;
}

int do_waitpid(pid_t pid, int *status, int __unused options)
{
    struct task_struct *cur = current();
    struct wait_ops ops;

    ops.pid = pid;
    init_wait_queue_entry(&ops.entry, cur, child_wait_callback);
    prepare_to_wait(&cur->wait_child_exit, &ops.entry, TASK_INTERRUPTIBLE);

    schedule();
    finish_wait(&ops.entry);

    return 0;
}


int sys_waitpid(pid_t pid, int *status, int options)
{
    /* Don't support these cases yet. */
    if (pid < -1 || pid == 0 || options != 0) {
        return -ENOTSUPP;
    }

    return do_waitpid(pid, status, options);
}