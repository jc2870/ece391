#ifndef _HD_H
#define _HD_H
#include "../types.h"
#include "../list.h"

#define MAX_DRIVER_NAME_LEN 8

struct hd_driver_operations {
    void(*init)();
    int(*read)(u32 block, char *buf, u32 cnt);
    int(*write)(u32 block, char *buf, u32 cnt);
    void(*test_read)();
    void(*test_write)();
};

struct hd_driver {
    struct list list;           /* list all drivers */
    char name[MAX_DRIVER_NAME_LEN];
    struct hd_driver_operations *ops;
};

extern void hd_init();
extern void hd_test();

#endif