#include "../lib.h"
#include "ide.h"
#include "../mm.h"
#include "hd.h"

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

/*
 * set logical block addressing mode
 * LBA = (CylinderNumber * HeadCount + HeadNumber) *  SectorCount + SectorNumber - 1
 */
#define SET_LBA_MODE() do {              \
    int _v = inb(REG_DRIVE);             \
    _v = _v | (1 << 6);                  \
    outb(_v, REG_DRIVE);                 \
} while(0);

/* set cylinder head sector addressing mode */
#define SET_CHS_MODE() do {              \
    int _v = inb(REG_DRIVE);             \
    _v = _v & ~(1 << 6);                  \
    outb(_v, REG_DRIVE);                 \
} while(0);

/*
 * In LBA mode, REG_SEC_NUM contains byte 0 of the logical block number
 *              REG_CYL_LOW, REG_CYL_HIGH holds bytes 1 and 2 of the logical block number
 *              REG_DRIVE 0-3 bits holds low four bits of byte 3 of the logical block address.
*/
#define LBA_SET_BLOCK(n) do {               \
    int _v = inb(REG_DRIVE);                   \
    outb(block & 0xff, REG_SEC_NUM);          \
    outb((block >> 8) & 0xff, REG_CYL_LOW);   \
    outb((block >> 16) & 0xff, REG_CYL_HIGH); \
    outb(((block >> 20) & 0xf) | _v, REG_DRIVE); \
} while(0)

/* 2^28 */
#define LBA_MAX_BLOCK   268435456

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

void ide_init()
{
    int i = 0;
    int disk = -1;

    idewait(0);
    SET_LBA_MODE();
    outb(0, REG_CTL);
    disk = GET_CUR_DISK();
    panic_on(disk != 0, "unexpected disk:%d, expected 0", disk);

    SET_CUR_DISK(1);
    idewait(0);
    disk = GET_CUR_DISK();
    panic_on(disk != 1, "unexpected disk:%d, expected 1", disk);
    SET_LBA_MODE();
    outb(0, REG_CTL);

    for (i=0; i < 1000; i++) {
        if (inb(0x1f7) != 0) {
            havedisk1 = 1;
            break;
        }
    }
    SET_CUR_DISK(0);
    data_buf = alloc_page();
    panic_on(!data_buf, "alloc buf failed\n");
}

/* @note: caller must set current disk via SET_CUR_DISK */
void ide_read(u32 block, char *buf, u32 cnt)
{
    panic_on(block >= LBA_MAX_BLOCK, "invalid block: %u", block);
    panic_on((block + cnt) >= LBA_MAX_BLOCK, "invalid block: %u, cnt: %u", block, cnt);

    outb(cnt, REG_SEC_CNT);
    LBA_SET_BLOCK(block);
    outb(CMD_READ_SEC, REG_CMD);

    idewait(0);

    insl(REG_DATA, data_buf, cnt*512/4);
}

/* @note: caller must set current disk via SET_CUR_DISK */
void ide_write(u32 block, char *buf, u32 cnt)
{
    panic_on(block >= LBA_MAX_BLOCK, "invalid block: %u", block);
    panic_on((block + cnt) >= LBA_MAX_BLOCK, "invalid block: %u, cnt: %u", block, cnt);

    outb(cnt, REG_SEC_CNT);
    LBA_SET_BLOCK(block);
    outb(CMD_WRITE_SEC, REG_CMD);

    outsl(REG_DATA, data_buf, cnt*512/4);
    idewait(0);
}

void test_ide_read()
{
    SET_CUR_DISK(0);
    memset(data_buf, 0, PAGE_SIZE);
    ide_read(15, data_buf, 1);
    panic_on(memcmp(data_buf+0x104, "ext2fs", 6), "read error\n");
}

void test_ide_write()
{
    panic_on(!havedisk1, "disk1 doesn't exist\n");
    SET_CUR_DISK(1);
    memset(data_buf, 'b', 512);
    ide_write(1, data_buf, 1);

    SET_CUR_DISK(1);
    memset(data_buf, 0, 512);
    ide_read(1, data_buf, 1);
    memset(data_buf+512, 'b', 512);
    panic_on(memcmp(data_buf, data_buf+512, 512), "write or read error\n");
}

void hd_intr_handler()
{
    printf("hard disk interruption\n");
}

void intr0x3E_handler(int errno)
{
    return hd_intr_handler();
}