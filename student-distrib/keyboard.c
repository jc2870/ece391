#include "lib.h"
#include "vga.h"

#define DATA_PORT   0x60
#define STATUS_PORT 0x64  /* for read */
#define CMD_PORT    0x64  /* for write */

/* reference:   https://wiki.osdev.org/%228042%22_PS/2_Controller
                https://github.com/Stichting-MINIX-Research-Foundation/minix/blob/master/minix/drivers/hid/pckbd/pckbd.c#L254
*/

// function keys map, 0x80 to 0xFF, unassigned have 0xFF
#define DO_GUI    0xFF
#define DO_APPS   0xFF
#define DO_F1     0x81
#define DO_F2     0x82
#define DO_F3     0x83
#define DO_F4     0x84
#define DO_F5     0x85
#define DO_F6     0x86
#define DO_F7     0x87
#define DO_F8     0x88
#define DO_F9     0x89
#define DO_F10    0x8A
#define DO_F11    0x8B
#define DO_F12    0x8C
#define DO_INSERT 0x92
#define DO_DELETE 0x93
#define DO_PGUP   0x95
#define DO_PGDN   0x96
#define SCAN_UARROW     0xA0
#define RELEASE_UARROW  0xA1
#define SCAN_DARROW     0xA2
#define RELEASE_DARROW  0xA3
#define SCAN_RARROW     0xA4
#define RELEASE_RARROW  0xA5
#define SCAN_LARROW     0xA6
#define RELEASE_LARROW  0xA7
#define DO_HOME   0xB0
#define DO_END    0xB1
#define SCAN_LSHFT      0xB2
#define RELEASE_LSHFT   0xB3
#define SCAN_RSHFT      0xB4
#define RELEASE_RSHFT   0xB5
#define SCAN_CTRL       0xB6
#define RELEASE_CTRL    0xB7
#define SCAN_ALT        0xB8
#define RELEASE_ALT     0xB9

static unsigned char scancode_map[256] = {
    // left column is the pressed code, right column is the released code
    [0x1E]='a',[0x9E]='A',
    [0x30]='b',[0xB0]='B',
    [0x2E]='c',[0xAE]='C',
    [0x20]='d',[0xA0]='D',
    [0x12]='e',[0x92]='E',
    [0x21]='f',[0xA1]='F',
    [0x22]='g',[0xA2]='G',
    [0x23]='h',[0xA3]='H',
    [0x17]='i',[0x97]='I',
    [0x24]='j',[0xA4]='J',
    [0x25]='k',[0xA5]='K',
    [0x26]='l',[0xA6]='L',
    [0x32]='m',[0xB2]='M',
    [0x31]='n',[0xB1]='N',
    [0x18]='o',[0x98]='O',
    [0x19]='p',[0x99]='P',
    [0x10]='q',[0x90]='Q',
    [0x13]='r',[0x93]='R',
    [0x1F]='s',[0x9F]='S',
    [0x14]='t',[0x94]='T',
    [0x16]='u',[0x96]='U',
    [0x2F]='v',[0xAF]='V',
    [0x11]='w',[0x91]='W',
    [0x2D]='x',[0xAD]='X',
    [0x15]='y',[0x95]='Y',
    [0x2C]='z',[0xAC]='Z',
    [0x0B]='0',[0x8B]=')',
    [0x02]='1',[0x82]='!',
    [0x03]='2',[0x83]='@',
    [0x04]='3',[0x84]='#',
    [0x05]='4',[0x85]='$',
    [0x06]='5',[0x86]='%',
    [0x07]='6',[0x87]='^',
    [0x08]='7',[0x88]='&',
    [0x09]='8',[0x89]='*',
    [0x0A]='9',[0x8A]='(',
    [0x29]='`',[0xA9]='~',
    [0x0C]='-',[0x8C]='_',
    [0x0D]='=',[0x8D]='+',
    [0x2B]='\\',[0xAB]='|',
    [0x39]=' ',[0xB9]=' ',
    [0x0F]='\t',[0x8F]='\t',
    [0x1C]='\n',[0x9C]='\n', // enter
    [0x1A]='[',[0x9A]='{',
    [0x1B]=']',[0x9B]='}',
    [0x27]=';',[0xA7]=':',
    [0x28]='\'',[0xA8]='"',
    [0x33]=',',[0xB3]='<',
    [0x34]='.',[0xB4]='>',
    [0x35]='/',[0xB5]='?',
    [0x0E]='\b',[0x8E]='\b', // function key
    [0x2A]=SCAN_LSHFT,[0xAA]=RELEASE_LSHFT,
    [0x5B]=DO_GUI,[0xDB]=DO_GUI,
    [0x5C]=DO_GUI,[0xDC]=DO_GUI,
    [0x5D]=DO_APPS,[0xDD]=DO_APPS,
    [0x01]='\33',[0x81]='\33',
    [0x3B]=DO_F1,[0xBB]=DO_F1,
    [0x3C]=DO_F2,[0xBC]=DO_F2,
    [0x3D]=DO_F3,[0xBD]=DO_F3,
    [0x3E]=DO_F4,[0xBE]=DO_F4,
    [0x3F]=DO_F5,[0xBF]=DO_F5,
    [0x40]=DO_F6,[0xC0]=DO_F6,
    [0x41]=DO_F7,[0xC1]=DO_F7,
    [0x42]=DO_F8,[0xC2]=DO_F8,
    [0x43]=DO_F9,[0xC3]=DO_F9,
    [0x44]=DO_F10,[0xC4]=DO_F10,
    [0x57]=DO_F11,[0xD7]=DO_F11,
    [0x58]=DO_F12,[0xD8]=DO_F12,
    [0x52]=DO_INSERT,[0xD2]=DO_INSERT,
    [0x47]=DO_HOME,[0x97]=DO_HOME,
    [0x49]=DO_PGUP,[0xC9]=DO_PGUP,
    [0x53]=DO_DELETE,[0xD3]=DO_DELETE,
    [0x4F]=DO_END,[0xCF]=DO_END,
    [0x51]=DO_PGDN,[0xD1]=DO_PGDN,
    [0x48]=SCAN_UARROW,[0xC8]=RELEASE_UARROW,
    [0x4B]=SCAN_LARROW,[0xCB]=RELEASE_LARROW,
    [0x50]=SCAN_DARROW,[0xD0]=RELEASE_DARROW,
    [0x4D]=SCAN_RARROW,[0xCD]=RELEASE_RARROW,
    [0x1D]=SCAN_CTRL ,[0x9D]=RELEASE_CTRL,
    [0x38]=SCAN_ALT ,[0xB8]=RELEASE_ALT,
};

int keyboard_init()
{
    int v = 0;

    while ((v = inb(CMD_PORT) & 0x1))
        v = inb(DATA_PORT);

    outb(0xae, CMD_PORT);
    outb(0x20, CMD_PORT);
    v = (inb(DATA_PORT) | 1) & ~0x10;
    outb(0x60, CMD_PORT);
    outb(v, DATA_PORT);

    outb(0xf4, DATA_PORT);

    return 0;

    /* Disable devices */
    outb(0xad, CMD_PORT);
    outb(0xa7, CMD_PORT);

    /* Flush The Output Buffer */
    inb(DATA_PORT);

    /* Set the Controller Configuration Byte */
    outb(0x20, CMD_PORT);
    v = inb(DATA_PORT);
    if (!(v & (1 << 5))) {
        KERN_INFO("PS/2 port disabled\n");
    }
    v |= 3;
    v &= ~0x10;
    // v &= ~(1 << 6);
    outb(0x60, CMD_PORT);
    outb(v, CMD_PORT);

    /* Perform controller self test */
    outb(0xaa, CMD_PORT);
    v = inb(DATA_PORT);
    if (v != 0x55) {
        KERN_INFO("PS/2 controller self test failed\n");
    }

    /* Determine if there are 2 channels */
    outb(0xa8, CMD_PORT);
    v = inb(STATUS_PORT);
    if (v & (1 << 5)) {
        KERN_INFO("not a dual channel controller\n");
        return -1;
    }
    outb(0xa7, CMD_PORT);

    /* Perform interface tests */
    outb(0xAB, CMD_PORT);
    v = inb(DATA_PORT);
    if (v) {
        KERN_INFO("The test of first PS/2 port failed\n");
        return -1;
    }
    outb(0xA9, CMD_PORT);
    v = inb(DATA_PORT);
    if (v) {
        KERN_INFO("The test of second PS/2 port failed\n");
        return -1;
    }

    /* Enable devices */
    outb(0xa8, CMD_PORT);
    outb(0xae, CMD_PORT);
    outb(0xf4, DATA_PORT);

    return 0;
}

void intr0x31_handler(unsigned long errno)
{
    u8 v = inb(0x60);
    u16 x, y;
    static bool with_shift = false;
    static bool with_ctrl = false;
    static bool with_alt = false;

    get_cursor(&x, &y);
    if (scancode_map[v] == SCAN_LSHFT) {
        with_shift = true;
        return;
    } else if (scancode_map[v] == RELEASE_LSHFT) {
        with_shift = false;
        return;
    }

    if (scancode_map[v] == SCAN_CTRL) {
        with_ctrl = true;
        return;
    } else if (scancode_map[v] == RELEASE_CTRL) {
        with_ctrl = false;
        return;
    }

    if (scancode_map[v] == SCAN_ALT) {
        with_alt = true;
        return;
    } else if (scancode_map[v] == RELEASE_ALT) {
        with_alt = false;
        return;
    }

    // printf("0x%x\n", v);

    if (v == 0x45) { return; /* ignore */ }      /* number lock pressed */
    else if (v == 0x3A) { return; /* ignore */ } /* caps lock pressed */
    else if (v == 0x46) { return; /* ignore */ } /* scroll lock pressed */

    /* Handle cursor */
    if (scancode_map[v] == SCAN_UARROW)      { set_cursor(x, y-1); return; }
    else if (scancode_map[v] == SCAN_DARROW) { set_cursor(x, y+1); return; }
    else if (scancode_map[v] == SCAN_LARROW) { set_cursor(x-1, y); return; }
    else if (scancode_map[v] == SCAN_RARROW) { set_cursor(x+1, y); return; }

    if (!with_shift && with_ctrl && scancode_map[v] == 'l') {
        clear();
        return;
    }

    /* Just ignore released code */
    if (v < 0x80) {
        if (with_shift)
            printf("%c", scancode_map[v+0x80]);
        else
            printf("%c", scancode_map[v]);
    }
}