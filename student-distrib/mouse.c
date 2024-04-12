#include "lib.h"
#include "vga.h"
/* TODO: complete mouse driver, it doesn't work yet */

#define DATA_PORT   0x60
#define STATUS_PORT 0x64  /* for read */
#define CMD_PORT    0x64  /* for write */

static u8 buf[3];
static u8 offset = 0;
static char x, y;

int mouse_init()
{
    int v = 0;

    outb(0xa8, CMD_PORT);
    outb(0x20, CMD_PORT);
    v = (inb(DATA_PORT) | 2);
    outb(0x60, CMD_PORT);
    outb(v, DATA_PORT);

    outb(0xD4, CMD_PORT);
    outb(0xF4, DATA_PORT);
    inb(DATA_PORT);

    return 0;
}

/* mouse interrupt handler */
void intr0x3C_handler(unsigned long errno)
{
    u8 status = inb(CMD_PORT);
    if (!(status & 0x20))
        return;

    buf[offset] = inb(DATA_PORT);
    offset = (offset+1) % 3;

    if (offset == 0) {
        x += buf[1];
        y -= buf[2];
    }

    set_cursor(x, y);

    KERN_INFO("mouse interrupt occured\n");
}
