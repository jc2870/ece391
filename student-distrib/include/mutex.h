#ifndef _MUTEX_H
#define _MUTEX_H

#include "list.h"
#include "list_def.h"
#include "atomic.h"

struct mutex {
    struct atomic owner;
    struct list wait_list;
};

extern void mutex_init(struct mutex *mutex);
extern void mutex_lock(struct mutex *mutex);
extern void mutex_unlock(struct mutex *mutex);

#endif