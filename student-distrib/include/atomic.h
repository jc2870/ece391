#ifndef _ATOMIC_H
#define _ATOMIC_H
#include "types.h"

struct atomic{
    volatile int count;
};

static inline int atomic_read(struct atomic *ptr) {
    int ret = 0;
    asm volatile ("movl %1, %0"
                  :"=r"(ret)
                  :"m"(ptr->count)
    );

    return ret;
}

#define atomic_inc(ptr) do {    \
    asm volatile ("lock; incl %0;"  \
                  :"+m"(ptr->count) \
                  :                 \
                  :"memory"         \
    );                              \
} while(0)

#define atomic_dec(ptr) do {    \
    asm volatile ("lock; decl %0"  \
                  :"+m"(ptr->count) \
                  :                 \
                  :"memory"         \
    );                              \
} while(0)


#define atomic_set(ptr, i) do {     \
    asm volatile ("mov %1, %0"  \
                  :"=m"((ptr)->count) \
                  :"r"(i)  \
                  :"memory"         \
    );                              \
} while(0)

#define atomic_add(t, i)    do  {   \
    asm volatile ("lock; addl %1, %0;"  \
                  :"=m"((t)->count)     \
                  :"r"(i)               \
                  :"memory");           \
} while(0)

#define atomic_sub(t, i)    do  {   \
    asm volatile ("lock; subl %1, %0;"  \
                  :"=m"((t)->count)     \
                  :"r"(i)               \
                  :"memory");           \
} while(0)

#endif