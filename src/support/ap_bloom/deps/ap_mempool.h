#ifndef _AP_MEMPOOL_H_
#define _AP_MEMPOOL_H_ 1
#include <stdint.h>
#include <unistd.h>
#ifdef __cplusplus
extern "C"
{
#endif
#define USE_HUGE_PAGE   (0) //precondition : sysctl -w vm.nr_hugepages=128,256,512... or other number by your needs
#define MEM_POOL_INIT_BLOCK_NUM (24) 
#define MEM_ALIGN_SIZE()  (getpagesize() > 4096 ? 4096: getpagesize())
struct apbm_mempool;
/*
 * FYI: 
 *      if error_rate set to 0.000001, slice num is 20 
 *      if capacity set to 1000000,  slice size is 180344
 *      if capacity set to 5000000,  slice size is 901688
 *      if capacity set to 10000000, slice size is 1803376    
 */
struct apbm_mempool *apbm_mempool_new(size_t large_block_size, int large_block_num, size_t small_block_size, int small_block_num);
void apbm_mempool_destroy(struct apbm_mempool *mp);
void *apbm_mempool_alloc(struct apbm_mempool *mp, int size);
void apbm_mempool_free(struct apbm_mempool *mp, void *p);
#ifdef __cplusplus
}
#endif

#endif