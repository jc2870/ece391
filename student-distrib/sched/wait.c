#include <wait.h>

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

void prepare_to_wait(wait_queue_head_t *head, wait_queue_entry_t *entry)
{
    list_add_tail(&head->head, &entry->entry);
}