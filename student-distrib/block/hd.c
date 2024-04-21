#include "hd.h"
#include "ide.h"

struct list hd_divers_list;
struct hd_driver *dft_driver;

void set_default_driver()
{
    dft_driver = &hd_ide_driver;
}

void hd_init()
{
    INIT_LIST(&hd_divers_list);

    hd_ide_driver.ops->init();
    list_add_tail(&hd_divers_list, &hd_ide_driver.list);

    set_default_driver();
}

void hd_test()
{
    struct list *cur;
    list_for_each(cur, &hd_divers_list) {
        struct hd_driver *driver = entry_list(cur, struct hd_driver, list);
        driver->ops->test_read();
        driver->ops->test_write();
    }
}

int hd_read(u32 block, char *buf, u32 cnt)
{
    return dft_driver->ops->read(block, buf, cnt);
}

int hd_write(u32 block, char *buf, u32 cnt)
{
    return dft_driver->ops->write(block, buf, cnt);
}

void hd_intr_handler()
{
    printf("hard disk interruption\n");
    dft_driver->ops->intr_handler();
}

void intr0x3E_handler(int errno)
{
    return hd_intr_handler();
}

