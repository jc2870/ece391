/* kernel.c - the C part of the kernel
 * vim:ts=4 noexpandtab
 */

#include "intr.h"
#include "list.h"
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
            return true;
        } else {
            return false;
        }
}

static __unused uint8_t get_apic_id()
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

static __unused void self_test()
{
    asm volatile ("int $0x3");
}

void main(unsigned long magic, unsigned long addr)
{
    if (detect_apic() == false)
        return;
    console_init();
    printf("console_init finished\n");
    i8259_init();
    printf("i8259_init finished\n");
    early_setup_idt();
    printf("early_setup_idt finished\n");
    serial_init();
    printf("serial_init finished\n");
    sti();
    /*
     * Check if MAGIC is valid and print the Multiboot information structure
     * pointed by ADDR.
     */
    multiboot_info(magic, addr);

    /* Init the PIC */
    tasks_init();
    timer_init();
    keyboard_init();
    mm_init(addr);
    // launch_tests();

    enable_irq(PIC_TIMER_INTR);
// #define TEST_TASKS
#ifdef TEST_TASKS
    init_test_tasks();
    test_tasks();
#endif
    initrd_init((void*)addr);
    display_initrd_file_name();
#define TEST_FS
#ifdef TEST_FS
    {
        char *data = (char*)page_vdr(get_free_pages(1));
        const char *shell = "shell";

        clear();
        read_data_by_name("frame0.txt", 0, data, ALL_FILE);
        printf("%s\n", data);
        read_data_by_name("frame1.txt", 0, data, ALL_FILE);
        printf("%s\n", data);
        read_data_by_name(shell, 0, data, ALL_FILE);
        init_user_task((void*)data, shell);
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


int sys_setup()
{
    return 0;
}