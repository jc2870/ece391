#include "mutex.h"
#include "atomic.h"
#include "list.h"

void mutex_init(struct mutex *mutex)
{
    atomic_set(&mutex->owner, 0);
    INIT_LIST(&mutex->wait_list);
}

void mutex_lock(struct mutex *mutex)
{

}

void mutex_unlock(struct mutex *mutex)
{

}