#ifndef _LIST_H
#define _LIST_H

#include "rwonce.h"
#include "list_def.h"
#include "container_of.h"
#include "lib.h"

static inline void INIT_LIST(struct list *list)
{
    WRITE_ONCE(list->prev, list);
    WRITE_ONCE(list->next, list);
}

#define entry_list(ptr, type, member_name)  \
    container_of(ptr, type, member_name)

static inline bool list_empty(struct list *head)
{
    return READ_ONCE(head->next) == head;
}

/* Insert a list between first and second */
static inline void __list_add(struct list *first, struct list *second, struct list *v)
{
    if (first->next != second || second->prev != first)
        panic("bad list\n");
    WRITE_ONCE(first->next, v);
    WRITE_ONCE(v->prev, first);
    WRITE_ONCE(v->next, second);
    WRITE_ONCE(second->prev, v);
}

static inline void list_add_tail(struct list *head, struct list *v)
{
    __list_add(head->prev, head, v);
}

static inline void list_add_head(struct list *head, struct list *v)
{
    __list_add(head, head->next, v);
}

static inline void list_del(struct list *v)
{
    WRITE_ONCE(v->prev->next, v->next);
    WRITE_ONCE(v->next->prev, v->prev);
    v->prev = NULL;
    v->next = NULL;
}

static inline int list_is_head(struct list *l1, struct list *l2)
{
    return l1 == l2;
}

#define list_for_each(cur, head) \
    for(cur = (head)->next; !list_is_head(cur, (head)); cur = cur->next)

#define list_entry(ptr, type, member)\
    container_of(ptr, type, member)

#endif
