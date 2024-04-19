#include "lib.h"
#include "hd.h"
#include "mm.h"

char *data_buf = NULL;
static int havedisk1 = 0;

/* Ref: https://vtda.org/books/Computing/Hardware/SCSI/The_SCSI_Bus_and_IDE_Interface_2nd_Ed.pdf
 *      http://www.gaby.de/gide/IDE-TCJ.pdf
 */

#define REG_DATA      0x1f0
#define REG_ERROR     0x1f1 /* for read.If the ERR bit in the status register is set, then thjs register contains the enor code
                               of the last executed command.  */
#define REG_FEATURE   0x1f1 /* for write. not used. */
#define REG_SEC_CNT   0x1f2 /* for rw. contains the number of sectors to be read or written */
#define REG_SEC_NUM   0x1f3 /* for rw. contains the number of the first sector to be transferred. */
#define REG_CYL_LOW   0x1f4 /* for rw. low bytes of cylinder numwer */
#define REG_CYL_HIGH  0x1f5 /* for rw. high bytes of cylinder number */
#define REG_DRIVE     0x1f6 /* for rw. contains the drive number, head number and addressing mode.  */
#define REG_STATUS    0x1f7 /* for read. contains the status of the disk drive as of the last command. */
#define REG_CMD       0x1f7 /* for write. receives the commands that are sent to the controller. */
#define REG_CTL       0x3f6 /* for write. 0 for enable interruprt */

/* Below errors were read from REG_ERROR register */
#define ERR_BBK       (1 << 7) /* bad block detected */
#define ERR_UNC       (1 << 6) /* uncorrectable data error */
#define ERR_MC        (1 << 5) /* media change */
#define ERR_IDNF      (1 << 4) /* id not found */
#define ERR_MCR       (1 << 3) /* media change requested */
#define ERR_ABRT      (1 << 2) /* aborted command */
#define ERR_TKONF     (1 << 1) /* track not found */
#define ERR_AMNF      (1 << 0) /* address mark not found */

#define SECTOR_SIZE   512
/* Below status were read from REG_STATUS register */
#define STATUS_BSY    (1 << 7)  /* If BSY is set, no other bits in the status register are valid */
#define STATUS_DRDY   (1 << 6)  /* Indicates that the drive is ready to accept a command */
#define STATUS_DF     (1 << 5)  /* Indicates an error on the drive. */
#define STATUS_DSC    (1 << 4)   /* Indicates that the heads are positioned over the desired cylinder.  */
#define STATUS_DRQ    (1 << 3)  /* This bit is set when the drive wants to exchange a byte with
                                   the host via the data register */
#define STATUS_CORR   (1 << 2)  /* This bit is set if a correctable read error has occurred. */
#define STATUS_ERR    (1 << 0)  /* Indicates an error has occurred.The error register contains further information */

#define CMD_READ_BUF      0xE4
#define CMD_READ_DMA      0xC8  /* C8h with retry. C9h without retry */
#define CMD_READ_SEC      0x20  /* 20 with retry. 21 without retry */
#define CMD_INENTIFY      0xEC  /* identify device */
#define CMD_WRITE_BUF     0xE8
#define CMD_WRITE_DMA     0xCA  /* CA with retry. CB without retry */
#define CMD_WRITE_SEC     0x30  /* 30 with retry. 31 without retry */

#define GET_CUR_DISK() (!!(inb(REG_DRIVE) & (1 << 4)))

#define SET_CUR_DISK(n) do {              \
  int _v = inb(REG_DRIVE);                \
  panic_on(n!=0 && n!=1, "error value;"); \
  _v = (n == 0 ? (_v & ~(1<<4)) : (_v | (1 << 4)));  \
  outb(_v, REG_DRIVE);                    \
} while(0);

static int
idewait(int checkerr)
{
  int r;

  while(((r = inb(REG_STATUS)) & (STATUS_BSY|STATUS_DRDY)) != STATUS_DRDY)
    ;
  if(checkerr && (r & (STATUS_DF|STATUS_ERR)) != 0)
    return -1;
  return 0;
}

void ideinit()
{
    int i = 0;
    int disk = -1;
    int sectors = 0;

    outb(0, REG_CTL);
    idewait(0);
    disk = GET_CUR_DISK();
    outb(0xe0 | (1<<4), REG_DRIVE);
    disk = GET_CUR_DISK();

    for (i=0; i < 1000; i++) {
        if (inb(0x1f7) != 0) {
            havedisk1 = 1;
            break;
        }
    }
    SET_CUR_DISK(0);
}

void test_hd_read()
{
    data_buf = alloc_page();
    panic_on(!data_buf, "alloc buf failed\n");
    memset(data_buf, 0, PAGE_SIZE);

    outb(1, REG_SEC_CNT);
    outb(0, REG_SEC_NUM);
    outb(0, REG_CYL_LOW);
    outb(0, REG_CYL_HIGH);
    outb(CMD_READ_SEC, REG_CMD);

    idewait(0);

    insl(REG_DATA, data_buf, 512/4);
}
void test_hd_write()
{
    panic_on(!havedisk1, "disk1 doesn't exist\n");
    SET_CUR_DISK(1);

    memset(data_buf, 'a', 512);
    outb(1, REG_SEC_CNT);
    outb(0, REG_SEC_NUM);
    outb(0, REG_CYL_LOW);
    outb(0, REG_CYL_HIGH);
    outb(CMD_WRITE_SEC, REG_CMD);

    outsl(REG_DATA, data_buf, 512/4);
    idewait(0);
}

void hd_intr_handler()
{
    printf("hard disk interruption\n");
}

void intr0x3E_handler(int errno)
{
    return hd_intr_handler();
}