/* kernel.c - the C part of the kernel
 * vim:ts=4 noexpandtab
 */

#include "intr.h"
#include "mouse.h"
#include "multiboot.h"
#include "x86_desc.h"
#include "lib.h"
#include "i8259.h"
#include "debug.h"
#include "tests.h"
#include "vga.h"
#include "intr_def.h"
#include "keyboard.h"
#include "mm.h"
#include "tasks.h"
#include "init_rd.h"
#include "block/hd.h"
#include "serial.h"

#define RUN_TESTS

extern void timer_handler();

#define APIC_LOCAL_TIMER_ONESHOT_MODE  (0)
#define APIC_LOCAL_TIMER_PERIODIC_MODE (1 << 17)
#define APIC_LOCAL_TIMER_TSCDDL_MODE   (2 << 17)
#define APIC_LOCAL_TIMER_DELIVERT_IDLE (0)
#define APIC_LOCAL_TIMER_DELIVERT_PENDING (1 << 11)

#define LOCAL_APIC_TIMER 0xbf

static bool detect_apic()
{
        uint32_t regs[4] = {0};

        cpuid(1, regs);

        if (CHECK_FLAG(regs[3], 9)) {
            KERN_INFO("APIC present\n");
            return true;
        } else {
            KERN_INFO("WARNING APIC absent\n");
            return false;
        }
}

static uint8_t get_apic_id()
{
        uint32_t regs[4] = {0};

        cpuid(1, regs);

        if (CHECK_FLAG(regs[3], 9)) {
            KERN_INFO("APIC present\n");
            return true;
        } else {
            KERN_INFO("WARNING APIC absent\n");
            return false;
        }

        return (regs[3] >> 24);
}

static __attribute__((unused)) void self_test()
{
    asm volatile ("int $0x3");
}

void entry(unsigned long magic, unsigned long addr)
{
    console_init();
    /*
     * Check if MAGIC is valid and print the Multiboot information structure
     * pointed by ADDR.
     */
    multiboot_info(magic, addr);

    get_apic_id();

    {
        char vendor[12];
        uint32_t regs[4];

        cpuid(0, regs);
        ((unsigned *)vendor)[0] = regs[1]; // EBX
        ((unsigned *)vendor)[1] = regs[3]; // EDX
        ((unsigned *)vendor)[2] = regs[2]; // ECX

        cpuid(1, regs);
        unsigned logical = (regs[1] >> 16) & 0xff;
        KERN_INFO("there are %u logical cores\n", logical);
        cpuid(4, regs);
        uint32_t cores = ((regs[0] >> 26) & 0x3f) + 1;
        KERN_INFO("there are %u physical cores\n", cores);
    }

    if (detect_apic() == false)
        return;
    /* Init the PIC */
    cli();
    i8259_init();
    sti();
    if (init_timer()) {
        panic("timer init failed\n");
        return;
    }
    early_setup_idt();
    if (keyboard_init()) {
        panic("keyboard init failed\n");
        return;
    }
    init_serial();
    clear();
    if (init_paging(addr)) {
        panic("paging init failed\n");
        return;
    }
    {
        struct task_struct *task = (struct task_struct*)INIT_TASK;
        strcpy(task->comm, "init");
        task->mm.pgdir = init_pgtbl_dir;
        task->pid = 0;

        task->cpu_state.esp0 = STACK_BOTTOM;
    }

    if (launch_tests() == false)
        panic("test failed\n");

    enable_paging();
    init_tasks();
    enable_irq(PIC_TIMER_INTR);
#ifdef TEST_TASKS
    init_test_tasks();
    test_tasks();
#endif
    init_fs((void*)addr);
    display_file_name();
#define TEST_FS
#ifdef TEST_FS
    {
        char *data = alloc_page();

        clear();
        read_data_by_name("frame0.txt", 0, data, BLOCK_SIZE);
        printf("%s\n", data);
        read_data_by_name("frame1.txt", 0, data, BLOCK_SIZE);
        printf("%s\n", data);
    }
    clear();
#endif

    // sti();
    hd_init();
    hd_test();

    /* Enable paging */
    while (1) ;

    /* Initialize devices, memory, filesystem, enable device interrupts on the
     * PIC, any other initialization stuff... */

    /* Enable interrupts */
    /* Do not enable the following until after you have set up your
     * IDT correctly otherwise QEMU will triple fault and simple close
     * without showing you any output */
    /*KERN_INFO("Enabling Interrupts\n");
    sti();*/

/* #ifdef RUN_TESTS
    Run tests
    launch_tests();
#endif */
    /* Execute the first program ("shell") ... */

    /* Spin (nicely, so we don't chew up cycles) */
    // asm volatile (".1: hlt; jmp .1;");
}
