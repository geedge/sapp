#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* 申请大页内存函数 
 * @note: 不要在数据面频繁使用！！
 */
int marsio_is_hugepage_available(void);
void * marsio_hugepage_malloc(size_t size, int seq);
void * marsio_hugepage_calloc(size_t num, size_t size, int seq);
void * marsio_hugepage_realloc(void * ptr, size_t size);

/* 释放大页内存函数 */
void marsio_hugepage_free(void * mem);

#ifdef __cplusplus
}
#endif