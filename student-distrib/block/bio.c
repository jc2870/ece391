#include "bio.h"
#include "lib.h"

void submit_bio(struct bio* bio)
{
    panic_on(bio->data_size % 512, "invalid data size %u\n", bio->data_size);
}