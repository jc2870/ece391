#ifndef _RWONCE_H
#define _RWONCE_H

#define WRITE_ONCE(x, val)  \
do {                        \
    *(volatile typeof(x) *)&x = (val);  \
} while(0)

#define READ_ONCE(v)    \
    *((const volatile typeof(v)*)&(v))

#endif
