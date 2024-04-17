#include "lib.h"
#include "hd.h"

#define SECTOR_SIZE   512
#define IDE_BSY       0x80
#define IDE_DRDY      0x40
#define IDE_DF        0x20
#define IDE_ERR       0x01

/* Ref: https://vtda.org/books/Computing/Hardware/SCSI/The_SCSI_Bus_and_IDE_Interface_2nd_Ed.pdf
 *      http://www.gaby.de/gide/IDE-TCJ.pdf
 */

static int
idewait(int checkerr)
{
  int r;

  while(((r = inb(0x1f7)) & (IDE_BSY|IDE_DRDY)) != IDE_DRDY)
    ;
  if(checkerr && (r & (IDE_DF|IDE_ERR)) != 0)
    return -1;
  return 0;
}

void ideinit()
{
    int i = 0;
    int havedisk1 = 0;

    idewait(0);
    outb(0xe0 | (1<<4), 0x1f6);

    for (i=0; i < 1000; i++) {
        if (inb(0x1f7) != 0) {
            havedisk1 = 1;
            break;
        }
    }
}