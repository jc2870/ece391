#ifndef _SPIN_LOCK_H
#define _SPIN_LOCK_H

typedef struct spin_lock {

} spinlock_t;

void spinlock_init();
void spinlock_lock();
void spinlock_unlock();

#endif