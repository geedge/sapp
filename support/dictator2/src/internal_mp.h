#ifndef	__INTERNAL_MEM_POOL_H_INCLUDE_
#define	__INTERNAL_MEM_POOL_H_INCLUDE_
typedef struct 
{
}IMP_t;
void* mmap_alloc(size_t size);
void mmap_free(void*p);
void* block_alloc(size_t size,IMP_t *imp);
void block_free(void*p,IMP_t* imp);
#endif	//end of __INTERNAL_MEM_POOL_H_INCLUDE_

