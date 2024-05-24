#ifndef _SCHED_H
#define _SCHED_H
#include "elf.h"
#include "mm.h"
#include "types.h"
#include "x86_desc.h"
#include "wait.h"

#define STACK_SIZE (2*PAGE_SIZE)
#define USER_STACK 0x09000000

struct intr_regs {
    /* pushed in syscall_entry */
    uint32_t gs;
    uint32_t fs;
    uint32_t es;
    uint32_t ds;

    /* pushed by syscall_entry */
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp_unused;   /* user level stack */
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;

    /* pushed by hardware automatically */
    uint32_t eip;
    uint32_t cs;
    uint32_t eflags;
    uint32_t esp;   /* user level stack */
    uint32_t ss;
} __attribute__ ((packed));

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

struct task_struct {
    union {
        char stack[STACK_SIZE];
        struct {
            volatile task_state state;
            pid_t pid;
            struct task_struct *parent;
            struct list task_list;
            struct list children;
            struct list sibling;
            char comm[16];
            struct mm mm;
            struct files_struct *files;
            struct fs_struct *fs;
            wait_queue_head_t wait_child_exit;

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
extern void tasks_init();
extern void init_user_task(Elf32_Ehdr *header, const char *name);

extern struct list running_tasks;
extern struct list runnable_tasks;  // waiting for time slice
extern struct list waiting_tasks;   // waiing for io or lock or something

#endif
