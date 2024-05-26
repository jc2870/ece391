#include "lib.h"
#include "list.h"
#include "pci_regs.h"
#include <pci.h>
#include <types.h>
#include <errno.h>
#include <pci_ids.h>
#include <pci_dev.h>
#include <mm.h>

static const u32 addr_reg = 0xCF8;
static const u32 data_reg = 0xCFC;
#define INVALID_VENDOR 0xFFFF

/* The format of addr reg is showed as followed:
 * 31  30-24    23-16  15-11 10-8  7-0
 * |-|-------|--------|-----|---|--------|
 * bit 31:    enable bit 0x80000000
 * bit 30-24: reserved
 * bit 23-16: bus number
 * bit 15-11: device numver
 * bit 10-8:  function number
 * bit 7-0:   register offset (bits1:0 is always 0)
 */


#define PCI_CONF1_ADDRESS(bus, devfn, reg) \
	(0x80000000 | ((reg & 0xF00) << 16) | (bus << 16) \
	| (devfn << 8) | (reg & 0xFC))

static int pci_conf1_read(u32 bus, u32 devfn, int reg, int len, u32 *value)
{
	usl_t flags;

	if ((bus > 255) || (devfn > 255) || (reg > 4095)) {
		*value = -1;
		return -EINVAL;
	}

	cli_and_save(flags);

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), addr_reg);

	switch (len) {
	case 1:
		*value = inb(data_reg + (reg & 3));
		break;
	case 2:
		*value = inw(data_reg + (reg & 2));
		break;
	case 4:
		*value = inl(data_reg);
		break;
	}

	sti_and_restore(flags);

	return 0;
}

static int pci_conf1_write(u32 seg, u32 bus, u32 devfn, int reg, int len, u32 value)
{
	usl_t flags;

	if (seg || (bus > 255) || (devfn > 255) || (reg > 4095))
		return -EINVAL;

	cli_and_save(flags);

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), addr_reg);

	switch (len) {
	case 1:
		outb((u8)value, data_reg + (reg & 3));
		break;
	case 2:
		outw((u16)value, data_reg + (reg & 2));
		break;
	case 4:
		outl((u32)value, data_reg);
		break;
	}

	sti_and_restore(flags);

	return 0;
}

static int pci_check_type1(void)
{
	usl_t flags;
	u32 tmp;
	int works = 0;

	cli_and_save(flags);

	outb(0x01, 0xCFB);
	tmp = inl(addr_reg);
	outl(0x80000000, addr_reg);
	if (inl(addr_reg) == 0x80000000) {
		works = 1;
	}
	outl(tmp, addr_reg);
	sti_and_restore(flags);

	return works;
}

static void pci_scan()
{
    int bus = 0;

    for (bus = 0; bus < 8; ++bus) {
        int dev = 0;

        for (dev = 0; dev < 32; ++dev) {
            u32 functions;
            u32 devfn = PCI_DEVFN(dev, 0);
            u32 func = 0;
            u32 hdr_type;

            if (pci_conf1_read(bus, devfn, PCI_HEADER_TYPE, 1, &hdr_type)) {
                continue;
            }

            functions = (hdr_type & PCI_HEADER_TYPE_MFD) ? 8 : 1;
            for (func = 0; func < functions; ++func) {
                u32 vendor_id;
                u32 dev_id;
                u32 class_id;
                u32 reg;
                u32 interrupt;
                struct pci_dev *pci_dev;
                char *dev_type;
                u32 bar;
                int i = 0;
                u32 pci_bar = PCI_BASE_ADDRESS_0;

                devfn = PCI_DEVFN(dev, func);
                pci_conf1_read(bus, devfn, PCI_VENDOR_ID, 2 , &vendor_id);
                if (vendor_id == INVALID_VENDOR) {
                    break;
                }

                hdr_type &= PCI_HEADER_TYPE_MASK;
                if (hdr_type == PCI_HEADER_TYPE_NORMAL) {
                    dev_type = "normal device";
                } else if (hdr_type == PCI_HEADER_TYPE_BRIDGE) {
                    dev_type = "pci-to-pci bridge";
                } else if (hdr_type == PCI_HEADER_TYPE_CARDBUS) {
                    dev_type = "pci-to-cardbus bridge";
                } else {
                    dev_type = "unknown device";
                }

                pci_conf1_read(bus, devfn, PCI_DEVICE_ID, 2, &dev_id);
                pci_conf1_read(bus, devfn, PCI_CLASS_DEVICE, 2, &class_id);
                pci_conf1_read(bus, devfn, PCI_CLASS_PROG, 1, &reg);
                pci_conf1_read(bus, devfn, PCI_INTERRUPT_LINE, 1, &interrupt);

                printf("bus:0x%x dev:0x%x func:0x%x vendor_id:0x%x dev_type:%s dev_id:0x%x class_id:0x%x reg:0x%x intr:0x%x\n",
                    bus, PCI_SLOT(devfn), PCI_FUNC(devfn), vendor_id, dev_type, dev_id, class_id, reg, interrupt);
                while (i < 6) {
                    pci_conf1_read(bus, devfn, pci_bar, 4, &bar);

                    if ((bar & 0x1) == PCI_BASE_ADDRESS_SPACE_IO) {
                        printf("\t bar%d is io space, base address is 0x%x\n", i, bar & PCI_BASE_ADDRESS_IO_MASK);
                    } else {
                        printf("\t bar%d is memory space, base address is 0x%x\n", i, bar & PCI_BASE_ADDRESS_MEM_MASK);
                    }

                    pci_bar += 0x4;
                    i++;
                }

                pci_dev = kmalloc(sizeof(*pci_dev));
                pci_dev->bus = bus;
                pci_dev->dev = PCI_SLOT(devfn);
                pci_dev->fn  = PCI_FUNC(devfn);
                pci_dev->vendor_id = vendor_id;
                pci_dev->device_id = dev_id;
                pci_dev->class = class_id;
                pci_dev->reg = reg;
                pci_dev->interrupt = interrupt;
                INIT_LIST(&pci_dev->list);
                list_add_tail(&pci_dev_lists, &pci_dev->list);
            }

        }
    }
}

void pci_init()
{
    if (pci_check_type1() == 0) {
        panic("configuration type 2 is not supported\n");
    }
    INIT_LIST(&pci_dev_lists);

    pci_scan();
}