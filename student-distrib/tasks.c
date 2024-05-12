#include "tasks.h"
#include "atomic.h"
#include "elf.h"
#include "errno.h"
#include "vfs.h"
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

static struct atomic next_pid;

struct list running_tasks;
struct list runnable_tasks;  // waiting for time slice
struct list waiting_tasks;   // waiing for io or lock or something

static pid_t get_next_pid();

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
    task->exited = false;
    task->pid = get_next_pid();
    alloc_files_struct(task);
    panic_on(!task->mm.pgdir || !task->fs || !task->files, "alloc page failed");
    /* map to kernel space */
    upgtbl_init(task->mm.pgdir);
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
}

static struct task_struct* alloc_task()
{
    struct task_struct *task = NULL;
    void* p = alloc_pages(1);
    panic_on((((unsigned long)p) % STACK_SIZE !=0), "struct task_struct must stack_size aligned\n");

    task = p;
    return task;
}

/* @fixme: the function is not atomic */
static pid_t get_next_pid()
{
    pid_t ret = atomic_read(&next_pid);
    atomic_inc(&next_pid);

    return ret;
}

void init_tasks()
{
    struct task_struct *init_task = (struct task_struct*)INIT_TASK;
    seg_desc_t the_tss_desc = {0};

    atomic_set(&next_pid, 0);

    strcpy(init_task->comm, "init");
    init_task->mm.pgdir = init_pgtbl_dir;
    init_task->pid = get_next_pid();
    panic_on(init_task->pid != 0, "unexpected here\n");

    init_task->cpu_state.esp0 = STACK_BOTTOM;
    INIT_LIST(&init_task->task_list);
    /* Construct a TSS entry in the GDT */

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

    tss.esp0 = (unsigned long)STACK_BOTTOM;  // stack top
    tss.ss0 = KERNEL_DS;
    tss.cs = KERNEL_CS;
    ltr(KERNEL_TSS);
    tss.cr3 = (unsigned long)init_pgtbl_dir;

    INIT_LIST(&runnable_tasks);
    INIT_LIST(&waiting_tasks);
    INIT_LIST(&running_tasks);
}

void init_test_tasks()
{
    task0 = alloc_task();
    task1 = alloc_task();
    task2 = alloc_task();

    if (!task0 || !task1 || !task2) {
        panic("alloc task failed\n");
    }
    init_task(task0, (unsigned long)user0, (unsigned long)&user_stk0, (unsigned long)(((char*)task0) + STACK_SIZE));
    init_task(task1, (unsigned long)user1, (unsigned long)&user_stk1, (unsigned long)(((char*)task1) + STACK_SIZE));
    init_task(task2, (unsigned long)user2, (unsigned long)&user_stk2, (unsigned long)(((char*)task2) + STACK_SIZE));

    strcpy(task0->comm, "user0");
    strcpy(task1->comm, "user1");
    strcpy(task2->comm, "user2");
}

static __always_inline void init_user_task_finish(struct task_struct *task)
{
    list_add_tail(&runnable_tasks, &task->task_list);
}

void init_user_task(Elf32_Ehdr *header, const char *name)
{
    struct task_struct *task = NULL;

    task = alloc_task();
    if (!task) {
        panic("alloc task failed\n");
    }
    init_task(task, (unsigned long)header->e_entry, USER_STACK, (unsigned long)(((char*)task) + STACK_SIZE));

    strcpy(task->comm, name);
    init_task_mm(task, header);
    init_user_task_finish(task);
}

void test_tasks()
{
    panic_on(!task0->mm.pgdir, "unexpected task0 pgdir\n");
    panic_on(!task1->mm.pgdir, "unexpected task1 pgdir\n");
    panic_on(!task2->mm.pgdir, "unexpected task2 pgdir\n");

    init_user_task_finish(task0);
    init_user_task_finish(task1);
    init_user_task_finish(task2);
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

int sys_fork(__unused u32 ebx, __unused u32 ecx, __unused u32 edx, struct intr_regs regs)
{
    struct task_struct *task = NULL;
    struct task_struct *cur = current();

    task = alloc_task();
    if (!task) {
        panic("alloc task failed\n");
    }

    printf("user esp is 0x%x\n", regs.esp);
    init_task(task, (unsigned long)regs.eip, regs.esp, (unsigned long)(((char*)task) + STACK_SIZE));
    strcpy(task->comm, cur->comm);
    copy_task_mm(task, cur);
    task->parent = cur;
    init_user_task_finish(task);

    return 0;
}

int sys_exit(int err)
{
    cli();
    struct task_struct *cur = current();
    cur->exited = true;
    sti();
    clear_opened_files(cur);
    destroy_files_struct(cur);
    schedule();

    return 0;
}