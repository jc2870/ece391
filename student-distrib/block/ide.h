#ifndef _HD_H
#define _HD_H
#include "../types.h"

extern void ide_init();
extern void test_ide_read();
extern void test_ide_write();
extern void ide_write(u32 block, char *buf, u32 cnt);
extern void ide_read(u32 block, char *buf, u32 cnt);

static inline void
insl(int port, void *addr, int cnt)
{
  asm volatile("cld; rep insl" :
               "=D" (addr), "=c" (cnt) :
               "d" (port), "0" (addr), "1" (cnt) :
               "memory", "cc");
}

static inline void
outsl(int port, const void *addr, int cnt)
{
  asm volatile("cld; rep outsl" :
               "=S" (addr), "=c" (cnt) :
               "d" (port), "0" (addr), "1" (cnt) :
               "cc");
}


#endif