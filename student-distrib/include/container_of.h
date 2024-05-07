#ifndef _CONTAINER_OF_H
#define _CONTAINER_OF_H

#include "types.h"

#define offsetof(type, member_name) \
    (size_t) &(((type*)0)->member_name)

#define container_of(ptr, type, member_name) \
    (type*)((char*)ptr - offsetof(type, member_name))

#endif
