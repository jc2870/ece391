#ifndef _BIO_H
#define _BIO_H
#include "types.h"

typedef void(*end_io_t)();

struct request {
    char *buf;
    u32 flags;
    bool rw:1;


};

struct bio {
    char * data_buf;
    size_t data_size;
    bool rw:1;
};

void submit_bio(struct bio* bio);

#endif