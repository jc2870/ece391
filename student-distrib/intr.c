#include "intr.h"
#include "intr_def.h"
#include "types.h"
#include "x86_desc.h"
#include "i8259.h"
#include "lib.h"

struct intr_entry intr_entry[256];

static void _set_gate(idt_desc_t *gate, int type, int dpl, void *addr)
{
    gate->dpl = dpl;
    gate->present = 1;
    gate->type = type;
    gate->seg_selector = KERNEL_CS;
    SET_IDT_ENTRY(*gate, addr);
}

static void set_trap_gate(unsigned int n, void *addr)
{
    _set_gate(&idt[n], TRAP_GATE, KERNEL_RPL, addr);
}

static void set_intr_gate(unsigned int n, void *addr)
{
    _set_gate(&idt[n], INTR_GATE, KERNEL_RPL, addr);
}

// If procedure is going to be executed at a numerically lower privilege level, a stack switch occurs
static void set_system_gate(unsigned int n, void *addr)
{
    _set_gate(&idt[n], SYSTEM_GATE, USER_RPL, addr);
}

/* devide error */
static void intr0x0_handler(unsigned long errno)
{
    KERN_INFO("devide error occured\n");
}

/* debug exception */
static void intr0x1_handler(unsigned long errno)
{
    KERN_INFO("debug exception occured\n");
}

/* none maskable interrupt */
static void intr0x2_handler(unsigned long errno)
{
    KERN_INFO("nmi interrupt occured\n");
}

/* break point */
static void intr0x3_handler(unsigned long errno)
{
    KERN_INFO("break point occured\n");
}

/* overflow */
static void intr0x4_handler(unsigned long errno)
{
    KERN_INFO("overflow occured\n");
}

/* bound range exceeded */
static void intr0x5_handler(unsigned long errno)
{
    KERN_INFO("bound range exceed occured\n");
}

/* undefined opcode */
static void intr0x6_handler(unsigned long errno)
{
    KERN_INFO("undefined opcode occured\n");
}

/* device not available(no math coprocessor) */
static void intr0x7_handler(unsigned long errno)
{

    KERN_INFO("device not available occured\n");
}

/* double fault, with error code(zero) */
static void intr0x8_handler(unsigned long errno)
{
    KERN_INFO("double fault occured\n");
}

/* coprocessor segment overrun */
static void intr0x9_handler(unsigned long errno)
{
    KERN_INFO("coprocessor segment overrun occured\n");

}
/* invalid tss, with error code  */
static void intr0xA_handler(unsigned long errno)
{
    KERN_INFO("invalid tss occured\n");
}

/* segment not present, with error code */
static void intr0xB_handler(unsigned long errno)
{
    KERN_INFO("segment not present occured\n");
}

/* stack segment fault, with error code */
static void intr0xC_handler(unsigned long errno)
{
    KERN_INFO("stack segment fault occured\n");
}

/* general protection, with error code  */
static void intr0xD_handler(unsigned long errno)
{
    KERN_INFO("general protection occured\n");
}

/* x87 fpu floating-point error(Math fault) */
static void intr0x10_handler(unsigned long errno)
{
    KERN_INFO("fpu floating-point error occured\n");
}

/* alignment check, with error code(zero) */
static void intr0x11_handler(unsigned long errno)
{
    KERN_INFO("alignment check occured\n");
}

/* machine check */
static void intr0x12_handler(unsigned long errno)
{
    KERN_INFO("machine check occured\n");
}

/* SIMD floating-point exception */
void intr0x13_handler(unsigned long errno)
{
    KERN_INFO("SIML floating-point exception occured\n");
}

/* Virtualization Exception */
static void intr0x14_handler(unsigned long errno)
{
    KERN_INFO("Virtualization Exception occured\n");
}

/*  Control Protection Exception, with error code  */
static void intr0x15_handler(unsigned long errno)
{
    KERN_INFO("Control Protection Exception occured\n");
}

/* APIC_MASTER_FIRST_INTR +3 */
static void intr0x33_handler(unsigned long errno)
{
    KERN_INFO("serial2 interrupt occured\n");
}

/* APIC_SLAVE_FIRST_INTR */
static void intr0x38_handler(unsigned long errno)
{
    KERN_INFO("real time counter occured\n");
}

/* APIC_SLAVE_FIRST_INTR +5 */
static void intr0x3D_handler(unsigned long errno)
{
    KERN_INFO("math cooperation occured\n");
}

void setup_intr_handler()
{
    memset(&intr_entry, 0, sizeof(intr_entry));

    SET_STATIC_INTR_HANDLER(0x0);
    SET_STATIC_INTR_HANDLER(0x1);
    SET_STATIC_INTR_HANDLER(0x2);
    SET_STATIC_INTR_HANDLER(0x3);
    SET_STATIC_INTR_HANDLER(0x4);
    SET_STATIC_INTR_HANDLER(0x5);
    SET_STATIC_INTR_HANDLER(0x6);
    SET_STATIC_INTR_HANDLER(0x7);
    SET_STATIC_INTR_HANDLER(0x8);
    SET_STATIC_INTR_HANDLER(0x9);
    SET_STATIC_INTR_HANDLER(0xA);
    SET_STATIC_INTR_HANDLER(0xB);
    SET_STATIC_INTR_HANDLER(0xC);
    SET_STATIC_INTR_HANDLER(0xD);
    SET_EXTERN_INTR_HANDLER(0xE);
    // 0xF was reserved
    SET_STATIC_INTR_HANDLER(0x10);
    SET_STATIC_INTR_HANDLER(0x11);
    SET_STATIC_INTR_HANDLER(0x12);
    SET_STATIC_INTR_HANDLER(0x13);
    SET_STATIC_INTR_HANDLER(0x14);
    SET_STATIC_INTR_HANDLER(0x15);
    SET_EXTERN_INTR_HANDLER(0x31);
    SET_EXTERN_INTR_HANDLER(0x3C);
    SET_EXTERN_INTR_HANDLER(0x3E);
    SET_EXTERN_INTR_HANDLER(0x34);
}

void early_setup_idt()
{
    struct x86_desc idt_desc =
    {
        .size = sizeof(idt)-1,
        .addr = (u32)&idt,
    };

    for (int i = 0; i < 256; ++i) {
        set_intr_gate(i, ignore_intr);
    }

    set_intr_gate(0x1, intr0x1_entry);
    set_intr_gate(0x2, intr0x2_entry);
    set_intr_gate(0x3, intr0x3_entry);
    set_intr_gate(0x4, intr0x4_entry);
    set_intr_gate(0x5, intr0x5_entry);
    set_intr_gate(0x6, intr0x6_entry);
    set_intr_gate(0x7, intr0x7_entry);
    set_intr_gate(0x8, intr0x8_entry);
    set_intr_gate(0x9, intr0x9_entry);
    set_intr_gate(0xA, intr0xA_entry);
    set_intr_gate(0xB, intr0xB_entry);
    set_intr_gate(0xC, intr0xC_entry);
    set_intr_gate(0xD, intr0xD_entry);
    set_intr_gate(0xE, intr0xE_entry);
    set_intr_gate(0xF, intr0xF_entry);
    set_intr_gate(0x11, intr0x11_entry);
    set_intr_gate(0x12, intr0x12_entry);
    set_intr_gate(0x13, intr0x13_entry);
    set_intr_gate(0x14, intr0x14_entry);
    set_intr_gate(0x15, intr0x15_entry);

    set_system_gate(SYSCALL_INTR, syscall_entry);
    set_intr_gate(PIC_TIMER_INTR, timer_interrupt_entry);
    set_intr_gate(PIC_HARDISK_INTR, intr0x3E_entry);

    set_intr_gate(PIC_KEYBOARD_INTR, intr0x31_entry);
    set_intr_gate(PIC_SERIAL2_INTR, intr0x34_entry);
    set_intr_gate(PIC_MOUSE_INTR, intr0x3C_entry);
    asm volatile ("lidt %0" ::"m"(idt_desc));

    setup_intr_handler();
}

unsigned long generic_intr_handler(unsigned long errno, unsigned long intr_num, unsigned long esp)
{
    if (intr_entry[intr_num].intr_handler)
        intr_entry[intr_num].intr_handler(errno);
    else
        KERN_INFO("unsupported intr 0x%x\n", intr_num);
    if (intr_num >= PIC_MASTER_FIRST_INTR)
        send_eoi(intr_num);

    return esp;
}