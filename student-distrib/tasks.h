#ifndef _SCHED_H
#define _SCHED_H
#include "mm.h"
#include "types.h"
#include "x86_desc.h"

#define STACK_SIZE (2*PAGE_SIZE)

struct regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;

    uint32_t gs;
    uint32_t fs;
    uint32_t es;
    uint32_t ds;

    uint32_t eip;
    uint32_t cs;
    uint32_t eflags;
    uint32_t esp;   /* user level stack */
    uint32_t ss;
    uint32_t esp0;  /* kernel level stack */

    // uint32_t error;
} __attribute__ ((packed));

typedef enum task_state {
    TASK_RUNNING = 0,
    TASK_RUNNABLE = 1,
    TASK_INTERRUPTIBLE = 2,
    TASK_UNINTERRUPTIBLE = 3,
    TASK_ZOMBIE = 4,
    TASK_STOPPED = 8,
} task_state;

typedef unsigned long pid_t;

struct task_struct {
    union {
        char stack[STACK_SIZE];
        struct {
            volatile task_state state;
            pid_t pid;
            struct task_struct *parent;
            struct list task_list;
            char comm[16];
            struct mm mm;

            struct regs cpu_state;
        };
    };
} __attribute__ ((aligned(STACK_SIZE)));

static inline struct task_struct* current()
{
    int i = 0;
    return (struct task_struct*)(((unsigned long)&i) & ~(STACK_SIZE-1));
}

extern void test_tasks();
extern void init_test_tasks();
extern void init_tasks();

extern struct list running_tasks;
extern struct list runnable_tasks;  // waiting for time slice
extern struct list waiting_tasks;   // waiing for io or lock or something

#endif
