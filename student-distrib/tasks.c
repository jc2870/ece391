#include "tasks.h"
#include "errno.h"
#include "fs/vfs.h"
#include "lib.h"
#include "liballoc.h"
#include "list.h"
#include "timer.h"
#include "types.h"
#include "x86_desc.h"
#include "mm.h"

extern void user0();
extern void *user_stk0;
extern void user1();
extern void *user_stk1;
extern void user2();
extern void *user_stk2;
extern void first_return_to_user();
struct task_struct *task0;
struct task_struct *task1;
struct task_struct *task2;

struct list running_tasks;
struct list runnable_tasks;  // waiting for time slice
struct list waiting_tasks;   // waiing for io or lock or something

void __init_task(struct task_struct *task, unsigned long eip, unsigned long user_stack, unsigned long kernel_stack)
{
    memset(task, 0, sizeof(struct task_struct));

    INIT_LIST(&task->task_list);
    task->cpu_state.cs = USER_CS;
    task->cpu_state.ds = USER_DS;
    task->cpu_state.es = USER_DS;
    task->cpu_state.es = USER_DS;
    task->cpu_state.fs = USER_DS;
    task->cpu_state.gs = USER_DS;
    task->cpu_state.eip = eip;
    task->cpu_state.esp = user_stack;
    task->cpu_state.esp0 = kernel_stack;
    task->state = TASK_RUNNABLE;
    task->parent = NULL;
    task->mm.pgdir = alloc_page();
    task->fs = kmalloc(sizeof(struct fs_struct));
    task->files = alloc_files_struct();
    panic_on(!task->mm.pgdir || !task->fs || !task->files, "alloc page failed");
    /* map to kernel space */
    page_table_init(task->mm.pgdir);
}

void init_task(struct task_struct *task, unsigned long eip, unsigned long user_stack, unsigned long kernel_stack)
{
    unsigned long *kernel_stk = (unsigned long*)kernel_stack;

    memset(task, 0, sizeof(*task));

    /*
     * 这里可能不太容易看的懂，结合doc/sched.md一起看
     * 大概解释如下:因为是新进程，内核栈是空的。所以我们在switch_to时，不能走到lable 1处(因为lable 1的逻辑需要内核栈已经预先push了寄存器)。
     * 在这里，我们把eip设置为first_return_to_user，然后预先往内核栈中放入iret所需要的eip, esp。
     * 我们通过switch_to切换task时，通过jmp指令直接跳转到 first_return_to_user处，然后拿出预先放好的esp和eip，进行iret到用户态
     */
    __init_task(task, (unsigned long)first_return_to_user, user_stack, (unsigned long)kernel_stack);
    kernel_stk -= 2;
    /* push eip/esp that iret needed, see first_return_to_user */
    kernel_stk[0] = eip;
    kernel_stk[1] = user_stack;
    list_add_tail(&runnable_tasks, &task->task_list);
}

static struct task_struct* alloc_task()
{
    struct task_struct *task = NULL;
    void* p = alloc_pages(1);
    panic_on((((unsigned long)p) % STACK_SIZE !=0), "struct task_struct must stack_size aligned\n");

    task = p;
    return task;
}

void init_tasks()
{
    INIT_LIST(&runnable_tasks);
    INIT_LIST(&waiting_tasks);
    INIT_LIST(&running_tasks);
}

void init_test_tasks()
{
    /* Construct a TSS entry in the GDT */
    seg_desc_t the_tss_desc = {0};
    // struct task_struct *task0 = NULL;
    // struct task_struct *task1 = NULL;
    // struct task_struct *task2 = NULL;

    the_tss_desc.granularity   = 0x0;
    the_tss_desc.opsize        = 0x0;
    the_tss_desc.reserved      = 0x0;
    the_tss_desc.avail         = 0x0;
    the_tss_desc.seg_lim_19_16 = 0xF;
    the_tss_desc.present       = 0x1;
    the_tss_desc.dpl           = 0x0;
    the_tss_desc.sys           = 0x0;
    the_tss_desc.type          = 0x9;
    the_tss_desc.seg_lim_15_00 = 0xFFFF;

    SET_TSS_PARAMS(the_tss_desc, &tss, tss_size);
    tss_desc_ptr = the_tss_desc;

    task0 = alloc_task();
    task1 = alloc_task();
    task2 = alloc_task();
    if (!task0 || !task1 || !task2) {
        panic("alloc task failed\n");
    }

    tss.esp0 = (unsigned long)(((char*)task0) + STACK_SIZE);  // stack top
    tss.ss0 = KERNEL_DS;
    tss.cs = KERNEL_CS;
    ltr(KERNEL_TSS);
    init_task(task0, (unsigned long)user0, (unsigned long)&user_stk0, (unsigned long)(((char*)task0) + STACK_SIZE));
    init_task(task1, (unsigned long)user1, (unsigned long)&user_stk1, (unsigned long)(((char*)task1) + STACK_SIZE));
    init_task(task2, (unsigned long)user2, (unsigned long)&user_stk2, (unsigned long)(((char*)task2) + STACK_SIZE));

    strcpy(task0->comm, "user0");
    strcpy(task1->comm, "user1");
    strcpy(task2->comm, "user2");
    // uadd_page_mapping((uint32_t)user0 & ~PAGE_MASK, (uint32_t)user0 & ~PAGE_MASK, task0->mm.pgdir);
    // uadd_page_mapping((uint32_t)user1 & ~PAGE_MASK, (uint32_t)user1 & ~PAGE_MASK, task1->mm.pgdir);
    // uadd_page_mapping((uint32_t)user2 & ~PAGE_MASK, (uint32_t)user2 & ~PAGE_MASK, task2->mm.pgdir);

    tss.cr3 = (unsigned long)init_pgtbl_dir;
    // list_add_tail(&running_tasks, &task0->task_list);
}

void test_tasks()
{
    panic_on(!task0->mm.pgdir, "unexpected task0 pgdir\n");
    panic_on(!task1->mm.pgdir, "unexpected task1 pgdir\n");
    panic_on(!task2->mm.pgdir, "unexpected task2 pgdir\n");

    sti();
}


void new_kthread(unsigned long addr)
{
    struct task_struct *task = NULL;
    if (!task) {
        panic("failed to malloc memory\n");
        return;
    }

    task->cpu_state.ds = KERNEL_DS;
    task->cpu_state.fs = KERNEL_DS;
    task->cpu_state.gs = KERNEL_DS;
    task->cpu_state.es = KERNEL_DS;

    task->cpu_state.cs = KERNEL_CS;
    task->cpu_state.eip = addr;
    task->cpu_state.ss = KERNEL_DS;
    task->cpu_state.esp = (unsigned long)task + STACK_SIZE;

    task->cpu_state.eax = 0;
    task->cpu_state.ebx = 0;
    task->cpu_state.ecx = 0;
    task->cpu_state.edx = 0;
    task->cpu_state.esi = 0;
    task->cpu_state.edi = 0;
    task->cpu_state.ebp = 0;
}

int sys_fork()
{
    return -EOPNOTSUPP;
}

int sys_exit(int err)
{
    return -EOPNOTSUPP;
}