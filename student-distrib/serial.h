#ifndef _SERIAL_H
#define _SERIAL_H

/* Ref: https://wiki.osdev.org/Serial_Ports */
#define COMS1 0x3F8
#define COMS2 0x2F8

void init_serial();
void uartputc();
#endif