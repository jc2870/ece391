#ifndef _WAIT_H
#define _WAIT_H

#include "spinlock.h"
#include "list.h"

typedef struct wait_queue_entry wait_queue_entry_t;
typedef struct wait_queue_head wait_queue_head_t;
typedef int (*wait_queue_func_t)(struct wait_queue_entry *wq_entry, void *key);

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

struct wait_ops {
	pid_t pid;
	wait_queue_entry_t entry;
};

extern void init_wait_queue_head(wait_queue_head_t *);
extern void init_wait_queue_entry(wait_queue_entry_t *wait_entry, void *private, wait_queue_func_t func);
extern void prepare_to_wait(wait_queue_head_t *head, wait_queue_entry_t *entry, int state);
extern int default_wakeup(wait_queue_entry_t *entry, void *key);
extern void finish_wait(wait_queue_entry_t *entry);
extern int do_waitpid(pid_t pid, int *status, int __unused options);

#endif