/* Copyright @2012 by Justin Hines at Bitly under a very liberal license. See LICENSE in the source distribution. */

#ifndef __BLOOM_H__
#define __BLOOM_H__
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus 
extern "C" { 
#endif 

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

const char *dablooms_version(void);

typedef struct {
    size_t bytes;
    char  *array;
} bitmap_t;


// bitmap_t *bitmap_resize(bitmap_t *bitmap, size_t old_size, size_t new_size);
// bitmap_t *new_bitmap(size_t bytes);

// int bitmap_increment(bitmap_t *bitmap, unsigned int index, long offset);
int bitmap_decrement(bitmap_t *bitmap, unsigned int index, long offset);
// int bitmap_check(bitmap_t *bitmap, unsigned int index, long offset);
int bitmap_flush(bitmap_t *bitmap);

// void free_bitmap(bitmap_t *bitmap);

typedef struct {
    uint64_t id;
    uint32_t count;
    uint32_t _pad;
} counting_bloom_header_t;

struct DA_bloom_stat{
    size_t expand_num_acc;
    double expand_size_ratio_rt; //current bitmap size / defalut bitmap size  * 100
    size_t slice_num_rt;
};
typedef struct {
    counting_bloom_header_t *header;
    unsigned int capacity;
    long offset;
    unsigned int counts_per_func;
    uint32_t *hashes;
    size_t nfuncs;
    size_t size;
    size_t num_bytes;
    double error_rate;
    bitmap_t *bitmap;
} counting_bloom_t;

// int free_counting_bloom(counting_bloom_t *bloom);
// counting_bloom_t *new_counting_bloom(unsigned int capacity, double error_rate);
// int counting_bloom_add(counting_bloom_t *bloom, const char *s, size_t len);
int counting_bloom_remove(counting_bloom_t *bloom, const char *s, size_t len);
// int counting_bloom_check(counting_bloom_t *bloom, const char *s, size_t len);

typedef struct {
    uint64_t max_id;
    uint64_t mem_seqnum;
    uint64_t disk_seqnum;
} scaling_bloom_header_t;

typedef struct {
    scaling_bloom_header_t *header;
    unsigned int capacity;
    unsigned int num_blooms;
    size_t num_bytes;
    double error_rate;
    counting_bloom_t **blooms;
    bitmap_t *bitmap;
    struct DA_bloom_stat stat;
} scaling_bloom_t;

// scaling_bloom_t *new_scaling_bloom(unsigned int capacity, double error_rate);
// int free_scaling_bloom(scaling_bloom_t *bloom);
// int scaling_bloom_add(scaling_bloom_t *bloom, const char *s, size_t len, uint64_t id);
int scaling_bloom_remove(scaling_bloom_t *bloom, const char *s, size_t len, uint64_t id);
// int scaling_bloom_check(scaling_bloom_t *bloom, const char *s, size_t len);
int scaling_bloom_flush(scaling_bloom_t *bloom);
uint64_t scaling_bloom_mem_seqnum(scaling_bloom_t *bloom);
uint64_t scaling_bloom_disk_seqnum(scaling_bloom_t *bloom);

struct expiry_dablooms_handle;
enum expiry_dablooms_errno{
    EXPIRY_DABLOOMS_ERRNO_BLOOM_NULL = -1,
    EXPIRY_DABLOOMS_ERRNO_NEW_BLOOM_FAIL = -2,
};
char* expiry_dablooms_errno_trans(enum expiry_dablooms_errno _errno);
void expiry_dablooms_destroy(struct expiry_dablooms_handle *handle);
struct expiry_dablooms_handle* expiry_dablooms_init(int partition_num, unsigned int capacity, double error_rate, long cur_time_ms, long expiry_time_ms, long transition_time_ms);
int expiry_dablooms_element_count_get(struct expiry_dablooms_handle *handle, uint64_t *count);
int expiry_dablooms_add(struct expiry_dablooms_handle *handle, const char *key, size_t len,  time_t cur_time);
int expiry_dablooms_search(struct expiry_dablooms_handle *handle, const char *key, size_t len,  time_t cur_time);
int expiry_dablooms_get_mem_stat(struct expiry_dablooms_handle *handle, long long *blocks, long long *bytes);
size_t DA_bloom_stat_get_slice_new_num(const struct expiry_dablooms_handle *bloom);
size_t DA_bloom_stat_get_slice_free_num(const struct expiry_dablooms_handle *bloom);
size_t DA_bloom_stat_get_hash_num(const struct expiry_dablooms_handle *bloom);
size_t DA_bloom_stat_get_expand_num(const struct expiry_dablooms_handle *bloom);
size_t DA_bloom_stat_get_cur_slice_num(const struct expiry_dablooms_handle *bloom);
size_t DA_bloom_stat_get_resize_ratio(const struct expiry_dablooms_handle *bloom);
#ifdef __cplusplus 
}
#endif 

#endif
