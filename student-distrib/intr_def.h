#ifndef _INTR_DEF_H
#define _INTR_DEF_H
#include "types.h"
#include "intr.h"
#include "keyboard.h"
#include "mouse.h"
#include "timer.h"


typedef void (*intr_handler_t)(unsigned long);

struct intr_entry {
    intr_handler_t intr_handler;
};

extern struct intr_entry intr_entry[256];

#define SET_EXTERN_INTR_HANDLER(intr_num) \
    extern void intr ## intr_num ## _handler(); \
    intr_entry[intr_num].intr_handler = intr ## intr_num ## _handler;

#define SET_STATIC_INTR_HANDLER(intr_num) \
    intr_entry[intr_num].intr_handler = intr ## intr_num ## _handler;

extern void early_setup_idt();
extern void ignore_intr();
extern void intr0x1_entry();
extern void intr0x2_entry();
extern void intr0x3_entry();
extern void intr0x4_entry();
extern void intr0x5_entry();
extern void intr0x6_entry();
extern void intr0x7_entry();
extern void intr0x8_entry();
extern void intr0x9_entry();
extern void intr0xA_entry();
extern void intr0xB_entry();
extern void intr0xC_entry();
extern void intr0xD_entry();
extern void intr0xE_entry();
extern void intr0xF_entry();
extern void intr0x10_entry();
extern void intr0x11_entry();
extern void intr0x12_entry();
extern void intr0x13_entry();
extern void intr0x14_entry();
extern void intr0x15_entry();

extern void intr0x30_entry();
extern void intr0x31_entry();
extern void intr0x3C_entry();
extern void intr0x3E_entry();
extern void intr0x34_entry();
extern void syscall_entry();
extern void timer_interrupt_entry();

#endif
