#include "serial.h"
#include "lib.h"

void init_serial() {
    outb(0x00, COMS1 + 1);    // Disable all interrupts
    outb(0x80, COMS1 + 3);    // Enable DLAB (set baud rate divisor)
    outb(0x03, COMS1 + 0);    // Set divisor to 3 (lo byte) 38400 baud
    outb(0x00, COMS1 + 1);    //                  (hi byte)
    outb(0x03, COMS1 + 3);    // 8 bits, no parity, one stop bit
    outb(0xC7, COMS1 + 2);    // Enable FIFO, clear them, with 14-byte threshold
    outb(0x0B, COMS1 + 4);    // IRQs enabled, RTS/DSR set
    outb(0x1E, COMS1 + 4);    // Set in loopback mode, test the serial chip
    outb(0xAE, COMS1 + 0);    // Test serial chip (send byte 0xAE and check if serial returns same byte)

    // Check if serial is faulty (i.e: not same byte as sent)
    if(inb(COMS1 + 0) != 0xAE) {
       panic("serial is faulty\n");
    }

    // If serial is not faulty set it in normal operation mode
    // (not-loopback with IRQs enabled and OUT#1 and OUT#2 bits enabled)
    outb(0x0F, COMS1 + 4);
}

int serial_received() {
   return inb(COMS1 + 5) & 1;
}

char read_serial() {
   while (serial_received() == 0);

   return inb(COMS1);
}

int is_transmit_empty() {
   return inb(COMS1 + 5) & 0x20;
}

void write_serial(char c) {
   while (is_transmit_empty() == 0);

   outb(c, COMS1);
}

void intr0x34_handler()
{

}