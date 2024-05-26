#ifndef _PCI_DEV_H
#define _PCI_DEV_H
#include <types.h>
#include <list.h>

struct pci_dev {
    u8 bus;
    u8 dev;
    u8 fn;
    u16 vendor_id;
    u16 device_id;
    u16 class;
    u8 interrupt;
    u8 reg;

    struct list list;
};

extern struct list pci_dev_lists;

#endif