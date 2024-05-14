#ifndef _WAIT_H
#define _WAIT_H

#include "spinlock.h"
#include "list.h"

typedef struct wait_queue_entry wait_queue_entry_t;
typedef int (*wait_queue_func_t)(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key);

struct wait_queue_entry {
	unsigned int		flags;
	void			*private;
	wait_queue_func_t	func;
	struct list entry;
};

struct wait_queue_head {
	spinlock_t		lock;
	struct list	head;
};
typedef struct wait_queue_head wait_queue_head_t;

void init_wait_queue_head(wait_queue_head_t *);
void init_wait_queue_entry(wait_queue_entry_t *wait_entry, void *private, wait_queue_func_t func);


#endif