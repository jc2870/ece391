/* i8259.c - Functions to interact with the 8259 interrupt controller
 * vim:ts=4 noexpandtab
 */

#include "i8259.h"
#include "lib.h"
#include "intr.h"

/* Interrupt masks to determine which interrupts are enabled and disabled */
uint8_t master_mask; /* IRQs 0-7  */
uint8_t slave_mask;  /* IRQs 8-15 */

#define PIC_MASTER 0x20
#define PIC_SLAVE  0xA0
#define PIC_MASTER_CMD PIC_MASTER
#define PIC_MASTER_DATA 0x21
#define PIC_SLAVE_CMD  PIC_SLAVE
#define PIC_SLAVE_DATA 0xA1

#define ICW1_ICW4	0x01		    /* Indicates that ICW4 will be present */
#define ICW1_SINGLE  (0x1 << 1)		/* Single mode */
#define ICW1_CASCADE (0x0 << 1)		/* Cascade mode */
#define ICW1_INTERVAL4	(0x1 << 2)	/* Call address interval 4 (8), not used in x86 */
#define ICW1_LEVEL	(0x1 << 3)		/* Level triggered mode */
#define ICW1_EDGE   (0x0 << 3)      /* Edge triggered mode */
#define ICW1_INIT	0x10		    /* Initialization - required! */

#define ICW3_IRQ2 (0x1 << 2)

#define ICW4_8086	0x01		/* 8086/88 (MCS-80/85) mode */
#define ICW4_AUTO	0x02		/* Auto (normal) EOI */
#define ICW4_BUF_SLAVE	0x08	/* Buffered mode/slave */
#define ICW4_BUF_MASTER	0x0C    /* Buffered mode/master */
#define ICW4_SFNM	0x10		/* Special fully nested (not) */

uint8_t master_mask = 0xff & ~(1 << 0x2); /* IRQs 0-7  */
uint8_t slave_mask = 0xff;  /* IRQs 8-15 */

/*
 * @reference:  https://wiki.osdev.org/8259_PIC
 *              http://jpk.pku.edu.cn/course/wjyl/script/chapter18.pdf
 *              https://elixir.bootlin.com/linux/v5.13/source/arch/x86/kernel/i8259.c#L327
 */
void i8259_init(void)
{
    /* mask all interrupts in master and slave chips */
    outb_d(0xff, PIC_MASTER_DATA);

    /* ICW1, start initialization  */
    outb_d(ICW1_INIT|ICW1_ICW4|ICW1_CASCADE|ICW1_EDGE, PIC_MASTER_CMD);
    outb_d(ICW1_INIT|ICW1_ICW4|ICW1_CASCADE|ICW1_EDGE, PIC_SLAVE_CMD);

    /*
     * ICW2: Because conflict of intr vector of 8259A and intr vector of cpu, we should
     * do remapping of intr vector of 8259A
     */
    outb_d(PIC_MASTER_FIRST_INTR, PIC_MASTER_DATA);
    outb_d(PIC_SLAVE_FIRST_INTR, PIC_SLAVE_DATA);

    /* ICW3: tell Master PIC that there is a slave PIC at IRQ2 (0000 0100) */
    outb_d(ICW3_IRQ2, PIC_MASTER_DATA);
    outb_d(0x2, PIC_SLAVE_DATA);

    /* ICW4: 8086mode, normal EOI, non buffer, fully nested mode */
    outb_d(ICW4_8086, PIC_MASTER_DATA);
    outb_d(ICW4_8086, PIC_SLAVE_DATA);

    outb_d(master_mask, PIC_MASTER_DATA);
    outb_d(slave_mask, PIC_SLAVE_DATA);
}

/* Disable (mask) the specified IRQ */
void disable_irq(uint32_t irq) {
    uint16_t port;
    uint8_t value;

    irq -= PIC_MASTER_FIRST_INTR;
    if (irq & 8) {
        // slave
        port = PIC_SLAVE;
        irq -= 8;
    } else {
        // master
        port = PIC_MASTER;
    }
    value = inb(port) | (1 << irq);
    outb(value, port);
}

/* Enable (unmask) the specified IRQ */
void enable_irq(uint32_t irq_num) {
    uint16_t port;
    uint32_t value;

    irq_num -= PIC_MASTER_FIRST_INTR;

    if (irq_num & 8) {
        // slave
        port = PIC_SLAVE_DATA;
        irq_num -= 8;
    } else {
        // master
        port = PIC_MASTER_DATA;
    }
    value = inb(port);
    value = value & ~(1 << irq_num);
    outb(value, port);
}

/* Send end-of-interrupt signal for the specified IRQ */
void send_eoi(uint32_t irq_num) {
    panic_on(irq_num < PIC_MASTER_FIRST_INTR || irq_num > PIC_SLAVE_FIRST_INTR + 8, "error irq num %u\n", irq_num);
    irq_num -= PIC_MASTER_FIRST_INTR;
    if (irq_num & 8) {
        outb(0x20, PIC_SLAVE_CMD);
    } else {
        outb(0x20, PIC_MASTER_CMD);
    }
}