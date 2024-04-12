#ifndef _MOUSE_H
#define _MOUSE_H

extern void intr0x3C_handler(unsigned long errno);
extern int mouse_init();

#define intr_mouse_handler intr0x3C_handler

#endif