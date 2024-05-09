#include "timer.h"
#include "i8259.h"
#include "intr.h"
#include "list.h"
#include "multiboot.h"
#include "tasks.h"
#include "x86_desc.h"

#define update_tss(task) tss.esp0 = (unsigned long)(((char*)task)+STACK_SIZE)

#define switch_to(cur,new) \
do  {   \
    asm volatile ("pusha;"           \
         "pushl %%ds;"       \
         "pushl %%es;"       \
         "pushl %%fs;"       \
         "pushl %%gs;"       \
         "movl %4, %%cr3;"   \
         "sti;"              \
         "movl %%esp, %0;" /* save esp */     \
         "movl %2, %%esp;" /* restore esp */  \
         "movl $1f, %1;"  /* save eip */    \
         "jmp %3;"      /* restore eip */   \
         /* "pushl %3"
            "jmp __switch_to;"
            We cannot jmp __switch_to function, because the 'push %ebp; movl %esp %ebp' instrutions in function header
            will corrupt the new task's stack.
            So we use jmp directly
          */ \
         "1: popl %%gs;"    \
         "popl %%fs;"        \
         "popl %%es;"        \
         "popl %%ds;"        \
         "popa;"            \
        :"=m"(cur->cpu_state.esp0), "=m"(cur->cpu_state.eip)     \
        :"m"((new)->cpu_state.esp0), "m"((new)->cpu_state.eip), "r"((new)->mm.pgdir) \
    );  \
} while(0)

void schedule()
{
    struct task_struct *cur = current();
    struct task_struct *next = NULL;
    if (list_empty(&runnable_tasks)) {
        return;
    }

    cli();
    next = list_entry(runnable_tasks.next, struct task_struct, task_list);

    list_del(&cur->task_list);
    if (!cur->exited) {
        list_add_tail(&runnable_tasks, &cur->task_list);
        cur->state = TASK_RUNNABLE;
    }
    list_del(&next->task_list);
    list_add_tail(&running_tasks, &next->task_list);
    next->state = TASK_RUNNING;

    update_tss(next);
    switch_to(cur, next);
    /*
     * Stack has changed, cur & next also changed, so we can't use cur/next any more
     * asm volatile ("movl %0, %%cr3;" : :"r"(next->mm.pgdir));
     */
}

void timer_handler(struct regs *cpu_state)
{
    send_eoi(PIC_TIMER_INTR);
    schedule();
}

int init_timer()
{
    /* @TODO: support local APIC timer */
    return 0;
}