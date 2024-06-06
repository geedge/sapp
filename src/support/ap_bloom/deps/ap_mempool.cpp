#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include "ap_mempool.h"

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

struct apbm_block_info{
    void *block_memory_head; 
    void *block_memory_tail;
    void **block_heads;
    int *block_inused_flags;
    unsigned int block_size;
    unsigned int block_num;
    int ues_hugepage;
    int to_flush_block_num;
};
struct apbm_mempool{
    struct apbm_block_info large;
    struct apbm_block_info small;
};
enum mempool_flag{
    MEMPOOL_USABLE = 0,
    MEMPOOL_INUSED = 1,
};  

static int apbm_mempool_block_init(struct apbm_block_info *block, size_t block_size, int block_num)
{
    block->block_size = block_size;
    block->block_num = block_num;
#if USE_HUGE_PAGE
    block->block_memory_head = mmap(NULL, block_num * block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if(MAP_FAILED == block->block_memory_head){
        perror("dabm_mempool_init() mmap huge-page error, use glibc: ");
        posix_memalign((void **)&block->block_memory_head, 64, block->block_num * block->block_size);
        block->ues_hugepage = 0;
    }else{
        block->ues_hugepage = 1;
    }
#else
    posix_memalign((void **)&block->block_memory_head, MEM_ALIGN_SIZE(), block->block_num * block->block_size);
#endif
    block->block_memory_tail = (char *)block->block_memory_head + block->block_num * block->block_size;
    memset(block->block_memory_head, 0, block->block_num * block->block_size);
    block->block_heads = (void **)calloc(block->block_num, sizeof(void *));
    block->block_inused_flags = (int *)calloc(block->block_num, sizeof(int));
    for(int i=0; i<block->block_num; i++)
    {
        block->block_heads[i] = (char *)block->block_memory_head + i * block->block_size;
        block->block_inused_flags[i] = 0;
    }
    return 0;
}
static void apbm_mp_block_free(struct apbm_block_info *block, void *p)
{
    for (int i = 0; i < block->block_num; i++)
    {
        if((block->block_heads[i] == p) 
        && (block->block_inused_flags[i] == MEMPOOL_INUSED)){          
            memset(p, 0, block->block_size); //memset in free()
            block->block_inused_flags[i] = MEMPOOL_USABLE;     
            return;
        }
    }
    assert(0);
}
static void apbm_mp_block_destroy(struct apbm_block_info *block)
{
    if(block->block_memory_head){
        if(block->ues_hugepage){
            munmap(block->block_memory_head, block->block_num * block->block_size);
        }else{
            free(block->block_memory_head);
        }
        block->block_memory_head = NULL;
    }
    if(block->block_heads){
        free(block->block_heads);
        block->block_heads = NULL;
    }
    if(block->block_inused_flags){
        free(block->block_inused_flags);
        block->block_inused_flags = NULL;
    }
    block->block_num = 0;
    block->block_size = 0;
}
static void *apbm_mp_block_alloc(struct apbm_block_info *block, int size)
{
    for (int i = 0; i < block->block_num; i++){
        if(block->block_inused_flags[i] == MEMPOOL_USABLE){
            block->block_inused_flags[i] = MEMPOOL_INUSED;
            return block->block_heads[i];
        }
    }
    return NULL;
}

#ifdef __cplusplus
extern "C"
{
#endif
void *apbm_mempool_alloc(struct apbm_mempool *mp, int size)
{
    void *res = NULL;
    if(size <= mp->small.block_size){
        res = apbm_mp_block_alloc(&mp->small, size);
    }else if(size <= mp->large.block_size){
        res = apbm_mp_block_alloc(&mp->large, size);
    }
    if(NULL == res){
        //mempool full or size unmatch, alloc use glibc
        res = calloc(size, sizeof(char));
    }
    return res;
}
void apbm_mempool_free(struct apbm_mempool *mp, void *p)
{
    if((unsigned long long)p >= (unsigned long long)mp->small.block_memory_head 
    && (unsigned long long)p <= (unsigned long long)mp->small.block_memory_tail){
        return apbm_mp_block_free(&mp->small, p);
    }
    if((unsigned long long)p >= (unsigned long long)mp->large.block_memory_head 
    && (unsigned long long)p <= (unsigned long long)mp->large.block_memory_tail){
        return apbm_mp_block_free(&mp->large, p);
    }
    //not allocated from mempool
    free(p);
}
struct apbm_mempool *apbm_mempool_new(size_t large_block_size, int large_block_num, size_t small_block_size, int small_block_num)
{
    struct apbm_mempool *mp = (struct apbm_mempool *)calloc(1, sizeof(struct apbm_mempool));
    memset(mp, 0, sizeof(struct apbm_mempool));
    apbm_mempool_block_init(&mp->large, large_block_size, large_block_num);
    apbm_mempool_block_init(&mp->small, small_block_size, small_block_num);
    return mp;
}
void apbm_mempool_destroy(struct apbm_mempool *mp)
{
    apbm_mp_block_destroy(&mp->large);
    apbm_mp_block_destroy(&mp->small);
    free(mp);
}
#ifdef __cplusplus
}
#endif