/* Copyright @2012 by Justin Hines at Bitly under a very liberal license. See LICENSE in the source distribution. */

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
#include <assert.h>
#include "murmur.h"
#include "dablooms.h"
#include "mem_util.h"

#define DABLOOMS_VERSION "1.0.2"

#define ERROR_TIGHTENING_RATIO 0.5
#define SALT_CONSTANT 0x97c29b3a


#define ALLOC(type, number, mstat) ((type *)dabm_calloc(number, sizeof(type), mstat))
#define	FREE(p, mstat)	dabm_free(p, mstat)
#define REALLOC(p, size, mstat) dabm_realloc(p, size, mstat)

const char *dablooms_version(void)
{
    return DABLOOMS_VERSION;
}

static void free_bitmap(bitmap_t *bitmap, struct dabm_mem_stat *mstat)
{
#if 0
    if ((munmap(bitmap->array, bitmap->bytes)) < 0) {
        perror("Error, unmapping memory");
    }
#else
    FREE(bitmap->array, mstat);
#endif
    FREE(bitmap, mstat);
}

static bitmap_t *bitmap_resize(bitmap_t *bitmap, size_t old_size, size_t new_size, struct dabm_mem_stat *mstat)
{   

#if 0
    /* resize if mmap exists and possible on this os, else new mmap */
    if (bitmap->array != NULL) {
#if __linux
        bitmap->array = mremap(bitmap->array, old_size, new_size, MREMAP_MAYMOVE);
        if (bitmap->array == MAP_FAILED) {
            perror("Error resizing mmap");
            free_bitmap(bitmap);
            return NULL;
        }
#else
        if (munmap(bitmap->array, bitmap->bytes) < 0) {
            perror("Error unmapping memory");
            free_bitmap(bitmap);
            return NULL;
        }
        bitmap->array = NULL;
#endif
    }
    if (bitmap->array == NULL) {
        bitmap->array = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (bitmap->array == MAP_FAILED) {
            perror("Error init mmap");
            free_bitmap(bitmap);
            return NULL;
        }
    }
#else
    if (bitmap->array != NULL)
    {
        bitmap->array = (char *)REALLOC(bitmap->array, new_size, mstat);
        assert(bitmap->array);
        // if (bitmap->array == NULL)
        // {
        //     perror("Error resizing memory");
        //     free_bitmap(bitmap, mstat);
        //     return NULL;
        // }
        memset(bitmap->array + old_size, 0, new_size - old_size);
        //printf("bitmap_resize(), %p, new:%d, old:%d\n", bitmap,(int)new_size, (int)old_size);
    }   
    else 
    {
        bitmap->array = ALLOC(char, new_size, mstat);
    }
#endif
    bitmap->bytes = new_size;
    return bitmap;
}

/* Create a new bitmap, not full featured, simple to give
 * us a means of interacting with the 4 bit counters */
static bitmap_t *new_bitmap(size_t bytes, struct dabm_mem_stat *mstat)
{
    bitmap_t *bitmap;
    

    bitmap = ALLOC(bitmap_t, 1, mstat); 
    bitmap->bytes = bytes;
    
    if ((bitmap = bitmap_resize(bitmap, 0, bytes, mstat)) == NULL) {
        return NULL;
    }
    
    return bitmap;
}

static inline int bitmap_increment(bitmap_t *bitmap, unsigned int index, long offset)
{
    long access = index / 2 + offset;
    uint8_t temp;
    __builtin_prefetch(&(bitmap->array[access]), 0, 1);
    uint8_t n = bitmap->array[access];
    if (index % 2 != 0) {
        temp = (n & 0x0f);
        n = (n & 0xf0) + ((n & 0x0f) + 0x01);
    } else {
        temp = (n & 0xf0) >> 4;
        n = (n & 0x0f) + ((n & 0xf0) + 0x10);
    }
    
    if (temp == 0x0f) {
        //fprintf(stderr, "Error, 4 bit int Overflow\n");
        return -1;
    }
    
    __builtin_prefetch(&(bitmap->array[access]), 1, 1);
    bitmap->array[access] = n;
    return 0;
}

/* increments the four bit counter */
int bitmap_decrement(bitmap_t *bitmap, unsigned int index, long offset)
{
    long access = index / 2 + offset;
    uint8_t temp;
    uint8_t n = bitmap->array[access];
    
    if (index % 2 != 0) {
        temp = (n & 0x0f);
        n = (n & 0xf0) + ((n & 0x0f) - 0x01);
    } else {
        temp = (n & 0xf0) >> 4;
        n = (n & 0x0f) + ((n & 0xf0) - 0x10);
    }
    
    if (temp == 0x00) {
        //fprintf(stderr, "Error, Decrementing zero\n");
        return -1;
    }
    
    bitmap->array[access] = n;
    return 0;
}

/* decrements the four bit counter */
static inline int bitmap_check(const bitmap_t *bitmap, unsigned int index, long offset)
{
    long access = index / 2 + offset;
    if (index % 2 != 0 ) {
        return bitmap->array[access] & 0x0f;
    } else {
        return bitmap->array[access] & 0xf0;
    }
}

// int bitmap_flush(bitmap_t *bitmap)
// {
// #if 0
//     if ((msync(bitmap->array, bitmap->bytes, MS_SYNC) < 0)) {
//         perror("Error, flushing bitmap to disk");
//         return -1;
//     } else {
//         return 0;
//     }
// #else
//     return 0;
// #endif
// }

/*
 * Perform the actual hashing for `key`
 *
 * Only call the hash once to get a pair of initial values (h1 and
 * h2). Use these values to generate all hashes in a quick loop.
 *
 * See paper by Kirsch, Mitzenmacher [2006]
 * http://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
 */
static inline void hash_func(uint32_t *hashes, const uint32_t checksum[4], size_t nfuncs, uint32_t counts_per_func)
{
    // uint32_t checksum[4];
    // MurmurHash3_x64_128(key, key_len, SALT_CONSTANT, checksum);
    uint32_t h1 = checksum[0];
    uint32_t h2 = checksum[1];
    for (size_t i = 0; i < nfuncs; i++) {
        hashes[i] = (h1 + i * h2) % counts_per_func;
    }
}

// int free_counting_bloom(counting_bloom_t *bloom)
// {
//     if (bloom != NULL) {
//         FREE(bloom->hashes);
//         bloom->hashes = NULL;
//         free_bitmap(bloom->bitmap);
//         FREE(bloom);
//         bloom = NULL;
//     }
//     return 0;
// }

counting_bloom_t *counting_bloom_init(unsigned int capacity, double error_rate, long offset, struct dabm_mem_stat *mstat)
{
    counting_bloom_t *bloom;
    
    bloom = ALLOC(counting_bloom_t, 1, mstat);
    bloom->bitmap = NULL;
    bloom->capacity = capacity;
    bloom->error_rate = error_rate;
    bloom->offset = offset + sizeof(counting_bloom_header_t);
    bloom->nfuncs = (int) ceil(log(1 / error_rate) / log(2));
    bloom->counts_per_func = (int) ceil(capacity * fabs(log(error_rate)) / (bloom->nfuncs * pow(log(2), 2)));
    bloom->size = bloom->nfuncs * bloom->counts_per_func;
    /* rounding-up integer divide by 2 of bloom->size */
    bloom->num_bytes = ((bloom->size + 1) / 2) + sizeof(counting_bloom_header_t);
    bloom->hashes = ALLOC(uint32_t, bloom->nfuncs, mstat);
    
    return bloom;
}

static counting_bloom_t *new_counting_bloom(unsigned int capacity, double error_rate, struct dabm_mem_stat *mstat)
{
    counting_bloom_t *cur_bloom;
    
    cur_bloom = counting_bloom_init(capacity, error_rate, 0, mstat);
    cur_bloom->bitmap = new_bitmap(cur_bloom->num_bytes, mstat);
    cur_bloom->header = (counting_bloom_header_t *)(cur_bloom->bitmap->array);
    return cur_bloom;
}

static int counting_bloom_add(counting_bloom_t *bloom, const uint32_t checksum[4])
{
    unsigned int index, i, offset;
    unsigned int *hashes = bloom->hashes;
    size_t nfuncs = bloom->nfuncs;
    uint32_t counts_per_func = bloom->counts_per_func;

    hash_func(hashes, checksum, nfuncs, counts_per_func);
    
    for (i = 0; i < nfuncs; i++) {
        offset = i * counts_per_func;
        index = hashes[i] + offset;
        bitmap_increment(bloom->bitmap, index, bloom->offset);
    }
    bloom->header->count++;
    
    return 0;
}

// int counting_bloom_remove(counting_bloom_t *bloom, const char *s, size_t len)
// {
//     unsigned int index, i, offset;
//     unsigned int *hashes = bloom->hashes;
    
//     hash_func(bloom, s, len, hashes);
    
//     for (i = 0; i < bloom->nfuncs; i++) {
//         offset = i * bloom->counts_per_func;
//         index = hashes[i] + offset;
//         bitmap_decrement(bloom->bitmap, index, bloom->offset);
//     }
//     bloom->header->count--;
    
//     return 0;
// }

static int counting_bloom_check(const counting_bloom_t *bloom, const uint32_t checksum[4])
{
    unsigned int index, i, offset;
    unsigned int *hashes = bloom->hashes;
    size_t nfuncs = bloom->nfuncs;
    uint32_t counts_per_func = bloom->counts_per_func;

    hash_func(hashes, checksum, nfuncs, counts_per_func);
    
    for (i = 0; i < nfuncs; i++) {
        offset = i * counts_per_func;
        index = hashes[i] + offset;
        if (!(bitmap_check(bloom->bitmap, index, bloom->offset))) {
            return 0;
        }
    }
    return 1;
}

static int free_scaling_bloom(scaling_bloom_t *bloom, struct dabm_mem_stat *mstat)
{
    int i;
    for (i = bloom->num_blooms - 1; i >= 0; i--) {
        FREE(bloom->blooms[i]->hashes, mstat);
        bloom->blooms[i]->hashes = NULL;
        FREE(bloom->blooms[i], mstat);
        bloom->blooms[i] = NULL;
    }
    FREE(bloom->blooms, mstat);
    free_bitmap(bloom->bitmap, mstat);
    FREE(bloom, mstat);
    return 0;
}

/* creates a new counting bloom filter from a given scaling bloom filter, with count and id */
counting_bloom_t *new_counting_bloom_from_scale(scaling_bloom_t *bloom, struct dabm_mem_stat *mstat)
{
    long offset;
    double error_rate;
    counting_bloom_t *cur_bloom;
    
    error_rate = bloom->error_rate * (pow(ERROR_TIGHTENING_RATIO, bloom->num_blooms + 1));
    bloom->blooms = (counting_bloom_t **)REALLOC(bloom->blooms, (bloom->num_blooms + 1) * sizeof(counting_bloom_t *), mstat);
    assert(bloom->blooms);
    // if (unlikely(bloom->blooms == NULL)) {
    //     fprintf(stderr, "Error, could not realloc a new bloom filter\n");
    //     return NULL;
    // }
    
    cur_bloom = counting_bloom_init(bloom->capacity, error_rate, bloom->num_bytes ,mstat);
    bloom->blooms[bloom->num_blooms] = cur_bloom;
    
    bloom->bitmap = bitmap_resize(bloom->bitmap, bloom->num_bytes, bloom->num_bytes + cur_bloom->num_bytes, mstat);

    if(bloom->num_bytes > sizeof(scaling_bloom_header_t)){
        bloom->stat.expand_num_acc++;
        bloom->stat.expand_size_ratio_rt *= (double)(bloom->num_bytes + cur_bloom->num_bytes) / bloom->num_bytes;
    }
    
    /* reset header pointer, as mmap may have moved */
    bloom->header = (scaling_bloom_header_t *) bloom->bitmap->array;
    
    /* Set the pointers for these header structs to the right location since mmap may have moved */
    bloom->num_blooms++;
    bloom->stat.slice_num_rt = bloom->num_blooms;
    for (unsigned int i = 0; i < bloom->num_blooms; i++) {
        offset = bloom->blooms[i]->offset - sizeof(counting_bloom_header_t);
        bloom->blooms[i]->header = (counting_bloom_header_t *) (bloom->bitmap->array + offset);
    }
    
    bloom->num_bytes += cur_bloom->num_bytes;
    cur_bloom->bitmap = bloom->bitmap;
    
    return cur_bloom;
}


uint64_t scaling_bloom_clear_seqnums(scaling_bloom_t *bloom)
{
    uint64_t seqnum;
    
    // if (bloom->header->disk_seqnum != 0) {
    //     // disk_seqnum cleared on disk before any other changes
    //     bloom->header->disk_seqnum = 0;
    //     // bitmap_flush(bloom->bitmap);
    // }
    bloom->header->disk_seqnum = 0;
    seqnum = bloom->header->mem_seqnum;
    bloom->header->mem_seqnum = 0;
    return seqnum;
}

static int scaling_bloom_add(scaling_bloom_t *bloom, const uint32_t checksum[4], uint64_t id, struct dabm_mem_stat *mstat)
{
    int i;
    uint64_t seqnum;
    
    counting_bloom_t *cur_bloom = NULL;
    for (i = bloom->num_blooms - 1; i >= 0; i--) {
        cur_bloom = bloom->blooms[i];
        if (id >= cur_bloom->header->id) {
            break;
        }
    }
    
    seqnum = scaling_bloom_clear_seqnums(bloom);
    
    if ((id > bloom->header->max_id) && (cur_bloom->header->count >= cur_bloom->capacity - 1)) {
        cur_bloom = new_counting_bloom_from_scale(bloom, mstat);
        cur_bloom->header->count = 0;
        cur_bloom->header->id = bloom->header->max_id + 1;
    }
    if (bloom->header->max_id < id) {
        bloom->header->max_id = id;
    }
    counting_bloom_add(cur_bloom, checksum);
    
    bloom->header->mem_seqnum = seqnum + 1;
    
    return 1;
}

// int scaling_bloom_remove(scaling_bloom_t *bloom, const char *s, size_t len, uint64_t id)
// {
//     counting_bloom_t *cur_bloom;
//     int i;
//     uint64_t seqnum;
    
//     for (i = bloom->num_blooms - 1; i >= 0; i--) {
//         cur_bloom = bloom->blooms[i];
//         if (id >= cur_bloom->header->id) {
//             seqnum = scaling_bloom_clear_seqnums(bloom);
            
//             counting_bloom_remove(cur_bloom, s, len);
            
//             bloom->header->mem_seqnum = seqnum + 1;
//             return 1;
//         }
//     }
//     return 0;
// }

static int scaling_bloom_check(scaling_bloom_t *bloom, const uint32_t checksum[4])
{
    int i;
    counting_bloom_t *cur_bloom;
    for (i = bloom->num_blooms - 1; i >= 0; i--) {
        cur_bloom = bloom->blooms[i];
        if (counting_bloom_check(cur_bloom, checksum)) {
            return 1;
        }
    }
    return 0;
}

// int scaling_bloom_flush(scaling_bloom_t *bloom)
// {
//     if (bitmap_flush(bloom->bitmap) != 0) {
//         return -1;
//     }
//     // all changes written to disk before disk_seqnum set
//     if (bloom->header->disk_seqnum == 0) {
//         bloom->header->disk_seqnum = bloom->header->mem_seqnum;
//         return bitmap_flush(bloom->bitmap);
//     }
//     return 0;
// }

// uint64_t scaling_bloom_mem_seqnum(scaling_bloom_t *bloom)
// {
//     return bloom->header->mem_seqnum;
// }

// uint64_t scaling_bloom_disk_seqnum(scaling_bloom_t *bloom)
// {
//     return bloom->header->disk_seqnum;
// }

scaling_bloom_t *scaling_bloom_init(unsigned int capacity, double error_rate,struct dabm_mem_stat *mstat)
{
    scaling_bloom_t *bloom;
    
    bloom = ALLOC(scaling_bloom_t, 1, mstat);
    if ((bloom->bitmap = new_bitmap(sizeof(scaling_bloom_header_t), mstat)) == NULL) {
        fprintf(stderr, "Error, Could not create bitmap with file\n");
        free_scaling_bloom(bloom, mstat);
        return NULL;
    }
    
    bloom->header = (scaling_bloom_header_t *) bloom->bitmap->array;
    bloom->capacity = capacity;
    bloom->error_rate = error_rate;
    bloom->num_blooms = 0;
    bloom->num_bytes = sizeof(scaling_bloom_header_t);
    bloom->blooms = NULL;
    
    return bloom;
}

static scaling_bloom_t *new_scaling_bloom(unsigned int capacity, double error_rate, struct dabm_mem_stat *mstat)
{
    scaling_bloom_t *bloom;
    counting_bloom_t *cur_bloom;
    
    bloom = scaling_bloom_init(capacity, error_rate, mstat);
    cur_bloom = new_counting_bloom_from_scale(bloom, mstat);
    // if (!()) {
    //     fprintf(stderr, "Error, Could not create counting bloom\n");
    //     free_scaling_bloom(bloom, mstat);
    //     return NULL;
    // }
    assert(cur_bloom);
    cur_bloom->header->count = 0;
    cur_bloom->header->id = 0;
    
    bloom->header->mem_seqnum = 1;
    bloom->stat.expand_size_ratio_rt = 1.0;
    return bloom;
}

struct expiry_dablooms_handle_entity{
    scaling_bloom_t *cur_bloom;
    scaling_bloom_t *next_bloom;
    long cur_bloom_start_ms;
    long next_bloom_start_ms;
    long last_bloom_check_ms;
    uint64_t cur_bloom_inc_id;
    uint64_t next_bloom_inc_id;
    unsigned int capacity;
    long expiry_time_ms;
    long cur_time_ms;
    long transition_time_ms;
    double error_rate;
    struct dabm_mem_stat mstat;
    size_t bloom_new_num;
    size_t bloom_free_num;
};

/* 24.05, split bloomfilter into multiple partition to avoid blocking caused by memset large memory */
struct expiry_dablooms_handle{
    struct expiry_dablooms_handle_entity **bm_handle;
    int bm_partition_num;
};


char* expiry_dablooms_errno_trans(enum expiry_dablooms_errno _errno){
	switch(_errno){
		case EXPIRY_DABLOOMS_ERRNO_BLOOM_NULL:
			return (char*)"scaling_bloom_null";
		case EXPIRY_DABLOOMS_ERRNO_NEW_BLOOM_FAIL:
			return (char*)"new_scaling_bloom_fail";
		default:
			return (char*)"unknown";
	}
}

static void expiry_dablooms_destroy_entity(struct expiry_dablooms_handle_entity *handle){
    if(handle != NULL){
        if(handle->cur_bloom != NULL){
            free_scaling_bloom(handle->cur_bloom, &handle->mstat);
        }
        if(handle->next_bloom != NULL){
            free_scaling_bloom(handle->next_bloom, &handle->mstat);
        }
        free(handle);
    }   
}

void expiry_dablooms_destroy(struct expiry_dablooms_handle *handle){
    for (size_t i = 0; i < handle->bm_partition_num; i++)
    {
        expiry_dablooms_destroy_entity(handle->bm_handle[i]);
    }
}


static struct expiry_dablooms_handle_entity* expiry_dablooms_init_entity(unsigned int capacity, double error_rate, long cur_time_ms, long expiry_time_ms, long transition_time_ms){
    struct expiry_dablooms_handle_entity *handle = (struct expiry_dablooms_handle_entity *)calloc(1, sizeof(struct expiry_dablooms_handle_entity));
    scaling_bloom_t *cur_bloom = new_scaling_bloom(capacity, error_rate, &handle->mstat);
    if(cur_bloom == NULL){
        goto error_out;
    }
    handle->cur_bloom = cur_bloom; 
    handle->cur_bloom_inc_id = 0;
    handle->cur_bloom_start_ms=cur_time_ms;
    handle->capacity = capacity;
    handle->error_rate = error_rate;
    handle->expiry_time_ms = expiry_time_ms;
    handle->cur_time_ms = cur_time_ms;
    handle->transition_time_ms = transition_time_ms; 
    handle->bloom_new_num++;
    return handle;
    
error_out:
    expiry_dablooms_destroy_entity(handle);
    return NULL;
}

struct expiry_dablooms_handle* expiry_dablooms_init(int partition_num, unsigned int capacity, double error_rate, long cur_time_ms, long expiry_time_ms, long transition_time_ms)
{
    struct expiry_dablooms_handle *handle = (struct expiry_dablooms_handle *)calloc(1, sizeof(struct expiry_dablooms_handle));
    handle->bm_partition_num = partition_num;
    handle->bm_handle = (struct expiry_dablooms_handle_entity **)calloc(partition_num, sizeof(struct expiry_dablooms_handle_entity *));

    long spread_expire_timeout;
    srand(time(NULL));
    int polarity = 1;
    for (size_t i = 0; i < partition_num; i++)
    {
        spread_expire_timeout = expiry_time_ms + (random() % 1000) * polarity; // spread out expire time
        if(spread_expire_timeout <= 0){
            spread_expire_timeout = expiry_time_ms;
        }
        polarity *= -1;
        handle->bm_handle[i] = expiry_dablooms_init_entity(capacity, error_rate, cur_time_ms, spread_expire_timeout, transition_time_ms);
        if(handle->bm_handle[i] == NULL){
            goto error_out;
        }
    }
    return handle;

error_out:
    expiry_dablooms_destroy(handle);
    return NULL;
}

int expiry_dablooms_element_count_get(struct expiry_dablooms_handle *handle, uint64_t *count){
    uint64_t tot_count = 0;
    if(handle == NULL || handle->bm_handle == NULL){
        return EXPIRY_DABLOOMS_ERRNO_BLOOM_NULL;
    }   
    for (int i = 0; i < handle->bm_partition_num; i++)
    {
        tot_count += handle->bm_handle[i]->cur_bloom_inc_id;
    }
    *count = tot_count;
    return 0;
}

static inline int bloom_in_transition_period(const struct expiry_dablooms_handle_entity *handle, long cur_time_ms)
{
    if((cur_time_ms - handle->cur_bloom_start_ms) + handle->transition_time_ms < handle->expiry_time_ms){
        return 0;
    }
    return 1;
}

static int bloom_expired_check(struct expiry_dablooms_handle_entity *handle, long cur_time_ms, struct dabm_mem_stat *mstat){
    // if(unlikely(handle == NULL || handle->cur_bloom == NULL)){
    //     return EXPIRY_DABLOOMS_ERRNO_BLOOM_NULL;
    // }
    if(likely(cur_time_ms <= handle->last_bloom_check_ms + 1000)){
        return 0;
    }
    long delta_time_ms = cur_time_ms - handle->cur_bloom_start_ms;
    handle->cur_time_ms=cur_time_ms;
    if(unlikely(delta_time_ms >= handle->expiry_time_ms)){
        free_scaling_bloom(handle->cur_bloom, mstat);
        handle->bloom_free_num++;
        if(handle->next_bloom != NULL){
            handle->cur_bloom = handle->next_bloom;
            handle->cur_bloom_start_ms = handle->next_bloom_start_ms;
            handle->cur_bloom_inc_id = handle->next_bloom_inc_id;
            handle->next_bloom = NULL;
            handle->last_bloom_check_ms=0;
        }
        else{
            scaling_bloom_t *cur_bloom = new_scaling_bloom(handle->capacity, handle->error_rate, mstat);
            if(unlikely(cur_bloom == NULL)){
                return EXPIRY_DABLOOMS_ERRNO_NEW_BLOOM_FAIL;
            }
            handle->bloom_new_num++;
            handle->cur_bloom = cur_bloom;
            handle->cur_bloom_inc_id = 0;
            handle->cur_bloom_start_ms=cur_time_ms;
            handle->last_bloom_check_ms=0;
        }
    }
    else 
    {
        handle->last_bloom_check_ms=cur_time_ms;
    }
    return 0;
}

static int expiry_dablooms_add_entity(struct expiry_dablooms_handle_entity *handle, const char *key, size_t len,  long cur_time_ms){
    assert(!(key==NULL || len ==0 || handle == NULL));
    int ret = bloom_expired_check(handle, cur_time_ms, &handle->mstat);
    if(unlikely(ret < 0))
    {
        return ret;
    }
    uint32_t checksum[4];
    MurmurHash3_x64_128(key, len, SALT_CONSTANT, checksum);

    long delta_time_ms = cur_time_ms - handle->cur_bloom_start_ms;
    handle->cur_time_ms=cur_time_ms;

    int is_transition = bloom_in_transition_period(handle, cur_time_ms);
    if(unlikely(is_transition != 0)){ 
        if(unlikely(handle->next_bloom == NULL)){
            scaling_bloom_t *next_bloom = new_scaling_bloom(handle->capacity, handle->error_rate, &handle->mstat);
            if(next_bloom == NULL){
                return EXPIRY_DABLOOMS_ERRNO_NEW_BLOOM_FAIL;
            }
            handle->bloom_new_num++;
            handle->next_bloom = next_bloom;
            handle->next_bloom_inc_id = 0;
            handle->next_bloom_start_ms=cur_time_ms;
        }
        scaling_bloom_add(handle->next_bloom, checksum, handle->next_bloom_inc_id, &handle->mstat);
        handle->next_bloom_inc_id++;
    }else{
        scaling_bloom_add(handle->cur_bloom, checksum, handle->cur_bloom_inc_id, &handle->mstat);
        handle->cur_bloom_inc_id++;
    }

    return 0;
}

/* Keep It Simple Stupid */
static inline unsigned int bloom_parttion_kiss_hash(const unsigned char *key, size_t key_len)
{
	unsigned int hash = 127;
	for(size_t i = 0; i < key_len; i++){
		hash += (unsigned int )key[i];
	}
	return (hash & 0x7ffffff);
}

int expiry_dablooms_add(struct expiry_dablooms_handle *handle, const char *key, size_t len,  long cur_time_ms){
    __builtin_prefetch(key, 0, 0);
    int index = (int)bloom_parttion_kiss_hash((unsigned char *)key, len) % handle->bm_partition_num;
    return expiry_dablooms_add_entity(handle->bm_handle[index], key, len, cur_time_ms);
}

static int expiry_dablooms_search_entity(struct expiry_dablooms_handle_entity *handle, const char *key, size_t len,  long cur_time_ms){
    assert(!(key==NULL || len ==0 || handle == NULL));
    int ret = bloom_expired_check(handle, cur_time_ms, &handle->mstat);
    if(unlikely(ret < 0))
    {
        return ret;
    }

    uint32_t checksum[4];
    MurmurHash3_x64_128(key, len, SALT_CONSTANT, checksum);

    int bloom_hit_cur = 0;
    int bloom_hit_next = 0;
    int is_transition = bloom_in_transition_period(handle, cur_time_ms);

    if(unlikely(is_transition != 0) && (handle->next_bloom != NULL)){
        bloom_hit_next = scaling_bloom_check(handle->next_bloom, checksum);
    }

    if(likely(0 == bloom_hit_next)){
        bloom_hit_cur = scaling_bloom_check(handle->cur_bloom, checksum);
    }

    return bloom_hit_cur || bloom_hit_next;
}

int expiry_dablooms_search(struct expiry_dablooms_handle *handle, const char *key, size_t len,  long cur_time_ms){
    __builtin_prefetch(key, 0, 0);
    int index = (int)bloom_parttion_kiss_hash((unsigned char *)key, len) % handle->bm_partition_num;
    return expiry_dablooms_search_entity(handle->bm_handle[index], key, len, cur_time_ms);
}

int expiry_dablooms_get_mem_stat(struct expiry_dablooms_handle *handle, long long *blocks, long long *bytes)
{
    long long tot_blocks = 0;
    long long tot_bytes = 0;
    for (int i = 0; i < handle->bm_partition_num; i++)
    {
        tot_blocks += handle->bm_handle[i]->mstat.blocks;
        tot_bytes += handle->bm_handle[i]->mstat.bytes;
    }
    *blocks = tot_blocks;
    *bytes = tot_bytes;
    return 0;
}

size_t DA_bloom_stat_get_slice_new_num(const struct expiry_dablooms_handle *bloom)
{
    size_t tot_num = 0;
    for(int i = 0; i < bloom->bm_partition_num; i++){
        const struct expiry_dablooms_handle_entity *bm_entity = bloom->bm_handle[i];
        tot_num += bm_entity->bloom_new_num;
    }
    return tot_num;
}

size_t DA_bloom_stat_get_slice_free_num(const struct expiry_dablooms_handle *bloom)
{
    size_t tot_num = 0;
    for(int i = 0; i < bloom->bm_partition_num; i++){
        const struct expiry_dablooms_handle_entity *bm_entity = bloom->bm_handle[i];
        tot_num += bm_entity->bloom_free_num;
    }
    return tot_num;
}

size_t DA_bloom_stat_get_hash_num(const struct expiry_dablooms_handle *bloom)
{
    if(bloom->bm_handle != NULL && bloom->bm_handle[0] != NULL){
        const struct expiry_dablooms_handle_entity *bm_entity = bloom->bm_handle[0];
        return ceil(log(1 / bm_entity->error_rate ) / log(2));
    }
    return 0;
}
size_t DA_bloom_stat_get_expand_num(const struct expiry_dablooms_handle *bloom)
{
    size_t tot_num = 0;
    for(int i = 0; i < bloom->bm_partition_num; i++){
        const struct expiry_dablooms_handle_entity *bm_entity = bloom->bm_handle[i];
        if(bm_entity->cur_bloom){
            tot_num += bm_entity->cur_bloom->stat.expand_num_acc;
        }
        if(bm_entity->next_bloom){
            tot_num += bm_entity->next_bloom->stat.expand_num_acc;
        }
    }
    return tot_num;
}
size_t DA_bloom_stat_get_cur_slice_num(const struct expiry_dablooms_handle *bloom)
{
    size_t tot_num = 0;
    for(int i = 0; i < bloom->bm_partition_num; i++){
        const struct expiry_dablooms_handle_entity *bm_entity = bloom->bm_handle[i];
        if(bm_entity->cur_bloom){
            tot_num += bm_entity->cur_bloom->stat.slice_num_rt;
        }
        if(bm_entity->next_bloom){
            tot_num += bm_entity->next_bloom->stat.slice_num_rt;
        }
    }
    return tot_num;
}
size_t DA_bloom_stat_get_resize_ratio(const struct expiry_dablooms_handle *bloom)
{
    double max_ratio = 1.000;
    for(int i = 0; i < bloom->bm_partition_num; i++){
        const struct expiry_dablooms_handle_entity *bm_entity = bloom->bm_handle[i];
        if(bm_entity->cur_bloom){
            if(bm_entity->cur_bloom->stat.expand_size_ratio_rt > max_ratio){
                max_ratio = bm_entity->cur_bloom->stat.expand_size_ratio_rt;
            }
        }
        if(bm_entity->next_bloom){
            if(bm_entity->next_bloom->stat.expand_size_ratio_rt > max_ratio){
                max_ratio = bm_entity->next_bloom->stat.expand_size_ratio_rt;
            }
        }
    }
    return (size_t)(max_ratio * 100.0);
}