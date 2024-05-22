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

static inline bool list_empty(const struct list *head)
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

static inline void __list_del(struct list * prev, struct list * next)
{
	next->prev = prev;
	WRITE_ONCE(prev->next, next);
}

static inline void list_del(struct list *v)
{
    __list_del(v->prev, v->next);
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

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_entry_is_head(pos, head, member)				\
	(&pos->member == (head))

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))


#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_next_entry(n, member))

#define list_for_each_entry_safe_from_head(pos, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_first_entry(head, typeof(*pos), member))

static inline void __list_splice(const struct list *list,
				 struct list *prev,
				 struct list *next)
{
	struct list *first = list->next;
	struct list *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void list_splice(const struct list *list,
				struct list *head)
{
	if (!list_empty(list))
		__list_splice(list, head, head->next);
}

#endif
