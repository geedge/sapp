#ifndef _DABM_MEM_UTIL_H_
#define _DABM_MEM_UTIL_H_ 1

#ifdef __cplusplus
extern "C"
{
#endif
    struct dabm_mem_stat
    {
        long blocks;
        long bytes;
    };

    void *dabm_malloc(size_t size, struct dabm_mem_stat *mstat);
    void *dabm_calloc(size_t nmemb, size_t size, struct dabm_mem_stat *mstat);
    void dabm_free(void *user_ptr, struct dabm_mem_stat *mstat);
    void *dabm_realloc(void *ptr, size_t new_size, struct dabm_mem_stat *mstat);
    int dabm_get_mem_hdr_size(void);
#ifdef __cplusplus
}
#endif
#endif