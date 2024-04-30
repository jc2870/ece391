#include "serial.h"
#include "lib.h"
#include "i8259.h"
#include "intr.h"

static int uart = 0;
void uartputc(int c);
static int uartgetc(void);

void init_serial() {
    char *p;

    // Turn off the FIFO
    outb(0, COMS1+2);

    // 9600 baud, 8 data bits, 1 stop bit, parity off.
    outb(0x80, COMS1+3);    // Unlock divisor
    outb(115200/9600, COMS1+0);
    outb(0x00, COMS1+1);
    outb(0x03, COMS1+3);    // Lock divisor, 8 data bits.
    outb(0x00, COMS1+4);
    outb(0x01, COMS1+1);    // Enable receive interrupts.

    // If status is 0xFF, no serial port.
    if(inb(COMS1+5) == 0xFF)
       return;
    uart = 1;

    // Acknowledge pre-existing interrupt conditions;
    // enable interrupts.
    inb(COMS1+2);
    inb(COMS1+0);
    enable_irq(PIC_SERIAL2_INTR);

    uartputc('\n');
    for (char *p = "ece391...\n"; *p; ++p) {
        uartputc(*p);
    }
}

static void mdelay()
{

}

void uartputc(int c)
{
    int i;

    if(!uart)
        return;
    for(i = 0; i < 128 && !(inb(COMS1+5) & 0x20); i++)
        mdelay();
    outb(c, COMS1+0);
}

int uartgetc(void)
{
  if(!uart)
    return -1;
  if(!(inb(COMS1+5) & 0x01))
    return -1;
  return inb(COMS1+0);
}

void intr0x34_handler()
{
    char c = uartgetc();
    switch (c) {
    case '\r':
        uartputc('\n');
        break;
    case 0x7f: // backspace
        uartputc('\b');
        uartputc(' ');
        uartputc('\b');
        break;
    default:
        printf("%c", c);
    }
}