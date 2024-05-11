#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include "murmur.h"
#include "dablooms.h"
#include "mem_util.h"

int main(int argc, char const *argv[])
{
    int i;
    struct dabm_mem_stat mstat = {};

    char *ptr = (char *)dabm_malloc(100, &mstat);
    assert(ptr != NULL);

    assert(mstat.blocks == 1);
    assert(mstat.bytes == 100 + dabm_get_mem_hdr_size());
    dabm_free(ptr, &mstat);
    assert(mstat.blocks == 0);
    assert(mstat.bytes == 0);

    int *iptr = (int *)dabm_calloc(100, sizeof(int), &mstat);
    assert(iptr != NULL);
    for (i = 0; i < 100; i++)
    {
        assert(iptr[i] == 0);
    }
    assert(mstat.blocks == 1);
    assert(mstat.bytes == 100 + dabm_get_mem_hdr_size());
    dabm_free(iptr, &mstat);

    ptr = dabm_realloc(NULL, 100, &mstat);
    assert(ptr != NULL);

    assert(mstat.blocks == 1);
    assert(mstat.bytes == 100 + dabm_get_mem_hdr_size());
    memset(ptr, 0xAA, 100);

    unsigned char *uptr = (unsigned char *)dabm_realloc(ptr, 1000, &mstat);
    for (i = 0; i < 100; i++)
    {
        assert(uptr[i] == 0xAA);
    }
    assert(mstat.blocks == 1);
    assert(mstat.bytes == 100 + dabm_get_mem_hdr_size());

    dabm_free(uptr, &mstat);
    assert(mstat.blocks == 0);
    assert(mstat.bytes == 0);

    printf("test mem util success!\n");
    return 0;
}
