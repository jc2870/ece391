#include "lib.h"
#include "ide.h"
#include "mm.h"
#include "hd.h"

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
#define REG_STATUS    0x1f7 /* for read. contains the status of the disk drive as of the last command.
                                         @note: read access to this register clears pending interrupt requests */
#define REG_CMD       0x1f7 /* for write. receives the commands that are sent to the controller. */
#define REG_ALT_STS   0x3f6 /* for read. alternate status register. read from this register has no effect on pending interrupt requests*/
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

#define CMD_READ_BUF        0xE4
#define CMD_READ_DMA        0xC8  /* C8h with retry. C9h without retry */
#define CMD_READ_SEC        0x20  /* 20 with retry. 21 without retry */
#define CMD_READ_MUL_SEC    0xC4
#define CMD_INENTIFY        0xEC  /* identify device */
#define CMD_WRITE_BUF       0xE8
#define CMD_WRITE_DMA       0xCA  /* CA with retry. CB without retry */
#define CMD_WRITE_SEC       0x30  /* 30 with retry. 31 without retry */
#define CMD_WRITE_MUL_SEC   0xC5

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
#define MAX_SECTOR_CNT  256

static int
idewait_clear_intr(int checkerr)
{
    int r;

    while(((r = inb(REG_STATUS)) & (STATUS_BSY|STATUS_DRDY)) != STATUS_DRDY)
        ;
    if(checkerr && (r & (STATUS_DF|STATUS_ERR)) != 0)
        return -1;
    return 0;
}

static int
idewait(int checkerr)
{
    int r;

    while(((r = inb(REG_ALT_STS)) & (STATUS_BSY|STATUS_DRDY)) != STATUS_DRDY)
        ;
    if(checkerr && (r & (STATUS_DF|STATUS_ERR)) != 0)
        panic("io error\n");
    return 0;
}

void ide_init()
{
    int i = 0;
    int disk = -1;

    INIT_LIST(&hd_ide_driver.list);
    idewait_clear_intr(0);
    SET_LBA_MODE();
    outb(0, REG_CTL);
    disk = GET_CUR_DISK();
    panic_on(disk != 0, "unexpected disk:%d, expected 0", disk);

    SET_CUR_DISK(1);
    idewait_clear_intr(0);
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
}

/* @note: caller must set current disk via SET_CUR_DISK */
int ide_read(u32 block, char *buf, u32 cnt)
{
    panic_on(block >= LBA_MAX_BLOCK, "invalid block: %u", block);
    panic_on(cnt > MAX_SECTOR_CNT, "invalid cnt: %u", cnt);
    int cmd = cnt == 1 ? CMD_READ_SEC : CMD_READ_MUL_SEC;

    /* 0 means 256 sectors */
    if (cnt == MAX_SECTOR_CNT) cnt = 0;

    outb(0, REG_CTL);
    outb(cnt, REG_SEC_CNT);
    LBA_SET_BLOCK(block);
    outb(cmd, REG_CMD);

    idewait(1);

    insl(REG_DATA, buf, cnt*512/4);

    return cnt;
}

/* @note: caller must set current disk via SET_CUR_DISK */
int ide_write(u32 block, char *buf, u32 cnt)
{
    panic_on(block >= LBA_MAX_BLOCK, "invalid block: %u", block);
    panic_on(cnt > MAX_SECTOR_CNT, "invalid cnt: %u", cnt);
    int cmd = cnt == 1 ? CMD_WRITE_SEC : CMD_WRITE_MUL_SEC;

    /* 0 means 256 sectors */
    if (cnt == MAX_SECTOR_CNT) cnt = 0;

    idewait(0);
    outb(0, REG_CTL);
    outb(cnt, REG_SEC_CNT);
    LBA_SET_BLOCK(block);
    outb(cmd, REG_CMD);

    outsl(REG_DATA, buf, cnt*512/4);
    idewait(1);

    return cnt;
}

void ide_test_read()
{
    char *data_buf = alloc_page();
    panic_on(!data_buf, "alloc page failed\n");
    SET_CUR_DISK(0);
    memset(data_buf, 0, PAGE_SIZE);
    ide_read(15, data_buf, 1);
    panic_on(memcmp(data_buf+0x104, "ext2fs", 6), "read error\n");
    free_page(data_buf);
}

void ide_test_write()
{
    char *data_buf = alloc_page();

    panic_on(!data_buf, "alloc page failed\n");
    panic_on(!havedisk1, "disk1 doesn't exist\n");

    SET_CUR_DISK(1);
    memset(data_buf, 'b', 1024);
    ide_write(1, data_buf, 1);

    memset(data_buf, 0, 512);
    ide_read(1, data_buf, 1);
    panic_on(memcmp(data_buf, data_buf+512, 512), "write or read error\n");

    free_page(data_buf);
}

static void ide_intr_handler()
{

}


static struct hd_driver_operations hd_ide_ops = {
    .init           = ide_init,
    .read           = ide_read,
    .write          = ide_write,
    .test_read      = ide_test_read,
    .test_write     = ide_test_write,
    .intr_handler   = ide_intr_handler,
};

struct hd_driver hd_ide_driver = {
    .name = "ide",
    .ops = &hd_ide_ops,
};


