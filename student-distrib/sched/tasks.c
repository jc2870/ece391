#include "tasks.h"
#include "mm.h"
#include "types.h"
#include "wait.h"
#include "atomic.h"
#include "errno.h"
#include "init_rd.h"
#include "vfs.h"
#include "lib.h"
#include "liballoc.h"
#include "list.h"
#include "timer.h"
#include "x86_desc.h"

extern void test_user0();
extern void *test_user_stk0;
extern void test_user1();
extern void *test_user_stk1;
extern void test_user2();
extern void *test_user_stk2;
extern void first_return_to_user();
struct task_struct *test_task0;
struct task_struct *test_task1;
struct task_struct *test_task2;

static struct atomic next_pid;

struct list running_tasks;
struct list runnable_tasks;  // waiting for time slice
struct list waiting_tasks;   // waiing for io or lock or something

static pid_t get_next_pid();

void __init_task(struct task_struct *task, unsigned long eip, unsigned long user_stack)
{
    memset(task, 0, sizeof(struct task_struct));

    INIT_LIST(&task->task_list);
    INIT_LIST(&task->children);
    INIT_LIST(&task->sibling);
    task->cpu_state.cs = USER_CS;
    task->cpu_state.ds = USER_DS;
    task->cpu_state.es = USER_DS;
    task->cpu_state.es = USER_DS;
    task->cpu_state.fs = USER_DS;
    task->cpu_state.gs = USER_DS;
    task->cpu_state.eip = eip;
    task->cpu_state.esp = user_stack;
    task->cpu_state.esp0 = (usl_t)((char*)task + STACK_SIZE);
    task->state = TASK_RUNNABLE;
    task->parent = NULL;
    task->mm.pgdir = alloc_pgdir();
    task->fs = kmalloc(sizeof(struct fs_struct));
    task->pid = get_next_pid();
    init_wait_queue_head(&task->wait_child_exit);
    alloc_files_struct(task);
    panic_on(!task->mm.pgdir || !task->fs || !task->files, "alloc page failed");
    /* map to kernel space */
    upgtbl_init(task);
}

void init_task(struct task_struct *task, unsigned long eip, unsigned long user_stack)
{
    unsigned long *kernel_stk = (unsigned long*)((char*)task + STACK_SIZE);

    memset(task, 0, sizeof(*task));

    /*
     * 这里可能不太容易看的懂，结合doc/sched.md一起看
     * 大概解释如下:因为是新进程，内核栈是空的。所以我们在switch_to时，不能走到lable 1处(因为lable 1的逻辑需要内核栈已经预先push了寄存器)。
     * 在这里，我们把eip设置为first_return_to_user，然后预先往内核栈中放入iret所需要的eip, esp。
     * 我们通过switch_to切换task时，通过jmp指令直接跳转到 first_return_to_user处，然后拿出预先放好的esp和eip，进行iret到用户态
     */
    __init_task(task, (unsigned long)first_return_to_user, user_stack);
    kernel_stk -= 2;
    /* push eip/esp that iret needed, see first_return_to_user */
    kernel_stk[0] = eip;
    kernel_stk[1] = user_stack;
}

static struct task_struct* alloc_task()
{
    struct task_struct *task = NULL;
    struct page* p = get_free_pages(1);
    panic_on((page_vdr(p) % STACK_SIZE !=0), "struct task_struct must stack_size aligned\n");

    task = (struct task_struct*)page_vdr(p);
    return task;
}

/* @fixme: the function is not atomic */
static pid_t get_next_pid()
{
    pid_t ret = atomic_read(&next_pid);
    atomic_inc(&next_pid);

    return ret;
}

void tasks_init()
{
    struct task_struct *init_task = (struct task_struct*)pdr2vdr(INIT_TASK);
    seg_desc_t the_tss_desc = {0};

    atomic_set(&next_pid, 0);

    strcpy(init_task->comm, "init");
    init_task->mm.pgdir = &kpgd;
    init_task->pid = get_next_pid();
    panic_on(init_task->pid != 0, "unexpected here\n");

    init_task->cpu_state.esp0 = pdr2vdr(KSTACK_BOTTOM);
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

    tss.esp0 = pdr2vdr(KSTACK_BOTTOM);  // stack top
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
    test_task0 = alloc_task();
    test_task1 = alloc_task();
    test_task2 = alloc_task();

    if (!test_task0 || !test_task1 || !test_task2) {
        panic("alloc task failed\n");
    }
    init_task(test_task0, (unsigned long)test_user0, (unsigned long)&test_user_stk0);
    init_task(test_task1, (unsigned long)test_user1, (unsigned long)&test_user_stk1);
    init_task(test_task2, (unsigned long)test_user2, (unsigned long)&test_user_stk2);

    strcpy(test_task0->comm, "test_user0");
    strcpy(test_task1->comm, "test_user1");
    strcpy(test_task2->comm, "test_user2");
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
    init_task(task, (unsigned long)header->e_entry, USER_STACK);

    strcpy(task->comm, name);
    init_task_mm(task, header);
    init_user_task_finish(task);
}

void test_tasks()
{
    panic_on(!test_task0->mm.pgdir, "unexpected test_task0 pgdir\n");
    panic_on(!test_task1->mm.pgdir, "unexpected test_task1 pgdir\n");
    panic_on(!test_task2->mm.pgdir, "unexpected test_task2 pgdir\n");

    init_user_task_finish(test_task0);
    init_user_task_finish(test_task1);
    init_user_task_finish(test_task2);
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

/* @note: only support initrd yet */
int do_sys_execve(struct task_struct *cur, const char* path, char *const argv[], char *const envp[])
{
    struct page *page = get_free_pages(1);
    char *buf = (char*)page_vdr(page);
    Elf32_Ehdr *header;
    char *_path = kstrdup(path);
    panic_on(!page, "alloc failed\n");

    str_trim(_path);
    read_data_by_name(_path, 0, buf, PAGE_SIZE*2);
    header = (Elf32_Ehdr*)buf;
    panic_on(elf_invalid(header), "should never happen for initrd, cannot find file:%s\n", path);
    /* @fixme: destroy all page mapped by cur */
    init_task(cur, (unsigned long)header->e_entry, USER_STACK);

    kfree(cur->comm);
    strcpy(cur->comm, path);
    init_task_mm(cur, header);

    kfree(_path);

    return 0;
}

/* @note: only support initrd yet */
int sys_execve(const char* path, char *const argv[], char *const envp[])
{
    do_sys_execve(current(), path, argv, envp);
    return 0;
}

int sys_fork(__unused u32 ebx, __unused u32 ecx, __unused u32 edx, struct intr_regs regs)
{
    struct task_struct *child = NULL;
    struct task_struct *cur = current();

    child = alloc_task();
    if (!child) {
        panic("alloc task failed\n");
    }

    init_task(child, (unsigned long)regs.eip, regs.esp);
    strcpy(child->comm, cur->comm);
    copy_task_mm(child, cur);
#define ECE391_SYSCALL
#ifdef ECE391_SYSCALL
    do_sys_execve(child, (void*)ebx, (void*)ecx, (void*)edx);
#endif
    child->parent = cur;
    list_add_tail(&cur->children, &child->sibling);
    init_user_task_finish(child);
    schedule();

#define ECE391_SYSCALL
#ifdef ECE391_SYSCALL
    do_waitpid(child->pid, NULL, 0);
#endif

    return 0;
}

static void exit_notify(struct task_struct *task)
{
    struct task_struct *parent = task->parent;
    wait_queue_entry_t *entry;

    list_for_each_entry(entry, &parent->wait_child_exit.head, entry) {
        entry->func(entry, task);
    }
}

/* @fixme: should free all pages. */
int sys_exit(int err)
{
    struct task_struct *cur = current();

    cli();
    cur->state = TASK_STOPPED;
    sti();

    exit_notify(cur);

    clear_opened_files(cur);
    destroy_files_struct(cur);
    schedule();

    return 0;
}