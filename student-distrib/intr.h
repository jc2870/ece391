#ifndef _INTR_H
#define _INTR_H

#define PIC_MASTER_FIRST_INTR 0x30 // first intr vector in 8259 master
#define PIC_SLAVE_FIRST_INTR  (PIC_MASTER_FIRST_INTR + 8) // first intr vector in 8259 slave
#define PIC_MAX_INTR  (PIC_SLAVE_FIRST_INTR + 8)

#define PIC_TIMER_INTR    0x30
#define PIC_KEYBOARD_INTR 0x31
#define PIC_SERIAL1_INTR  0x33  /* COMS2/COMS4 */
#define PIC_SERIAL2_INTR  0x34  /* COMS1/COMS3 */
#define PIC_SOFTDISK_INTR 0x36
#define PIC_PRINTER_INTR  0x37
#define PIC_RTC_INTR      0x38
#define PIC_MOUSE_INTR    0x3C
#define PIC_HARDISK_INTR  0x3E

#define SYSCALL_INTR 0x80

/*
 * The only difference between trap and interrupt is that
 * interrupt gate will disable interrupt auto and trap gate will not.
 */
#define TRAP_GATE 15
#define INTR_GATE 14
#define SYSTEM_GATE TRAP_GATE

#define KERNEL_RPL 0
#define USER_RPL   3
#endif