#include "serial.h"
#include "lib.h"
#include "i8259.h"
#include "intr.h"
#include "errno.h"
#include "vfs.h"

static int uart = 0;
void uartputc(int c);
static int uartgetc(void);

static char serial_buf[128] = {0};
static u8 serial_idx = 0;

void serial_init() {
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
    char c;

    if(!uart)
        return -1;

    while (1) {
        if (inb(COMS1+5) & 0x01) {
            break;
        }
    }

    c = inb(COMS1+0);
    cli();
    serial_buf[serial_idx++] = c;
    sti();

    return c;
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

int uartgets(char __user *buf, size_t size)
{
    int c;
    int ret = 0;
    while (1) {
        c = uartgetc();
        buf[ret] = c;
        ret++;

        if (c == '\n' || c == '\r') {
            break;
        }

        if (ret == size) {
            break;
        }
    }

    return ret;
}

ssize_t serial_read(struct file *file, char __user *buf, size_t size, u32 *offset)
{
    char c;
    int ret;
    while (1) {
        cli();
        c = serial_buf[serial_idx - 1];
        if (c == '\n' || c == '\r') {
            memcpy(buf, serial_buf, serial_idx);
            memset(serial_buf, 0 , sizeof(serial_buf));
            ret = serial_idx;
            serial_idx = 0;
            break;
        }
        sti();
    }

    sti();
    return ret;
}

ssize_t serial_write(struct file *file, const char __user *buf, size_t size, u32 *offset)
{
    if (file->f_fd != 1) {
        printf("unsupported write to fd %d\n", file->f_fd);
        return -EOPNOTSUPP;
    }

    return printf("%s", buf);
}

struct file_operations serial_file_operations = {
    .open    = NULL,
    .release = NULL,
    .read = serial_read,
    .write = serial_write,
};