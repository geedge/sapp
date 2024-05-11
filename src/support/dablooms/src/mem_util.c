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
#include <time.h>
#include <pthread.h>
#include "murmur.h"
#include "dablooms.h"
#include "mem_util.h"

struct dabm_mem_hdr{
    size_t size;
    char *user_ptr;
};

void *dabm_malloc(size_t user_size, struct dabm_mem_stat *mstat)
{
    size_t real_size = user_size + sizeof(struct dabm_mem_hdr);
    char *real_ptr = (char *)malloc(real_size);
    if (real_ptr)
    {
        struct dabm_mem_hdr *stat = (struct dabm_mem_hdr *)real_ptr;
        stat->size = real_size;
        stat->user_ptr = real_ptr + sizeof(struct dabm_mem_hdr);
        mstat->blocks++;
        mstat->bytes += real_size;
        return stat->user_ptr;
    }
    return NULL;
}

void *dabm_calloc(size_t nmemb, size_t user_size, struct dabm_mem_stat *mstat)
{
    size_t real_size = nmemb * user_size + sizeof(struct dabm_mem_hdr);
    char *real_ptr = (char *)calloc(1, real_size);
    if (real_ptr)
    {
        struct dabm_mem_hdr *stat = (struct dabm_mem_hdr *)real_ptr;
        stat->size = real_size;
        stat->user_ptr = real_ptr + sizeof(struct dabm_mem_hdr);
        mstat->blocks++;
        mstat->bytes += real_size;
        return stat->user_ptr;
    }
    return NULL;
}

void dabm_free(void *user_ptr, struct dabm_mem_stat *mstat)
{
    if (user_ptr)
    {
        struct dabm_mem_hdr *stat = (struct dabm_mem_hdr *)((char *)user_ptr - sizeof(struct dabm_mem_hdr));
        mstat->blocks--;
        mstat->bytes -= stat->size;
        free(stat);
    }
}

void *dabm_realloc(void *user_ptr, size_t new_size, struct dabm_mem_stat *mstat)
{
    char *old_real_ptr;
    struct dabm_mem_hdr *stat;

    if (user_ptr)
    {
        stat = (struct dabm_mem_hdr *)((char *)user_ptr - sizeof(struct dabm_mem_hdr));
        old_real_ptr = (char *)stat;
        mstat->bytes -= stat->size;
    }
    else
    {
        old_real_ptr = NULL;
        mstat->blocks++; // no memory alloc before
    }

    size_t real_size = new_size + sizeof(struct dabm_mem_hdr);
    char *new_real_ptr = (char *)realloc(old_real_ptr, real_size);
    if (new_real_ptr)
    {
        mstat->bytes += real_size;
        stat = (struct dabm_mem_hdr *)new_real_ptr;
        stat->size = real_size;
        stat->user_ptr = new_real_ptr + sizeof(struct dabm_mem_hdr);
        return stat->user_ptr;
    }

    return NULL;
}

int dabm_get_mem_hdr_size(void)
{
    return sizeof(struct dabm_mem_hdr);
}

