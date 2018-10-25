/* DICATATOR Memory Manager
*	Version 20141115
*	zhengchao@iie.ac.cn
*/
#ifndef _DICTATOR2_H_
#define _DICTATOR2_H_

#ifdef __cplusplus
extern "C"{
#endif

void *__wrap_malloc(size_t size);
void __wrap_free(void *p);
void *__wrap_realloc(void *ptr, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);

void *__dictator_malloc(int t_seq,size_t size);
void __dictator_free(int t_seq,void*p);
void *__dictator_realloc(int t_seq,void *ptr, size_t size);
void *__dictator_calloc(int t_seq,size_t nmemb, size_t size);

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *calloc(size_t nmemb, size_t size);
void free(void *p);

#ifdef __cplusplus
}
#endif// end extern "C"

#endif
