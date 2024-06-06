#pragma once

#include <stdlib.h>	//calloc
#include <sys/time.h>//gettimeofday
#include <stdint.h>	//uint64_t

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(p); p=NULL;}

#define APBM_USE_MEMPOOL 1
#if APBM_USE_MEMPOOL
#define APMOOL_ALLOC(mp, type, number) ((type *)apbm_mempool_alloc(mp, sizeof(type)*(number)))
#define APMOOL_FREE(mp, p)  {apbm_mempool_free(mp, p); p=NULL;}
#else
#define APMOOL_ALLOC(mp, type, number) ALLOC(type, number)
#define APMOOL_FREE(mp, p) FREE(p)
#endif

#define	TRUE	1
#define	FALSE	0

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			 \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif
#define timeval_delta_ms(start, end) (((end).tv_sec-(start).tv_sec)*1000 + ((end).tv_usec-(start).tv_usec)/1000)
#define timeval_delta_us(start, end) (((end).tv_sec-(start).tv_sec)*1000*1000 + ((end).tv_usec-(start).tv_usec))
#define	timeval_to_ms(t)	((t).tv_sec*1000+(t).tv_usec/1000)
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


#ifdef __cplusplus
extern "C"
{
#endif

// Double hashing for fast hashing, 
// reference: Kirsch, Adam, and Michael Mitzenmacher. "Less hashing, same performance: Building a better bloom filter." 
// Algorithms¨CESA 2006: 14th Annual European Symposium, Zurich, Switzerland, September 11-13, 2006. Proceedings 14. Springer Berlin Heidelberg, 2006.
// https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf 
struct double_hash
{
    uint64_t a;
    uint64_t b;
};
// void double_hash_init(struct double_hash *rv, const void *buffer, size_t len);
// int double_hash_generate(const struct double_hash *rv, int i, int m);
#define double_hash_init(rv, buffer, len)                                        \
        XXH128_hash_t xxh128b = XXH3_128bits_withSeed(buffer, len, 0x9747b28c); \
        rv.a = xxh128b.high64;                                                  \
        rv.b = xxh128b.low64;
        
static inline unsigned int double_hash_generate(const struct double_hash *rv, unsigned int i, unsigned int m)
{
    return (rv->a + i * rv->b) % m;
}

#define TIME_MEASURE 0 //to observe delay jitter
#if TIME_MEASURE
#define MAX_DELAY (100000) //ns
#define TIME_RECORD()  struct timespec _start_time, _end_time; long long time_diff_ns;  clock_gettime(CLOCK_REALTIME, &_start_time)
#define TIME_DIFF()  \
    do {             \
        clock_gettime(CLOCK_REALTIME, &_end_time); \
        if (likely(_end_time.tv_sec == _start_time.tv_sec))\
        {\
            time_diff_ns = (_end_time.tv_nsec - _start_time.tv_nsec);\
        }else{\
            time_diff_ns = ((long long)_end_time.tv_sec * 1000 * 1000 * 1000 + _end_time.tv_nsec) - ((long long)_start_time.tv_sec * 1000 * 1000 * 1000 + _start_time.tv_nsec);\
        }\
        if(unlikely(time_diff_ns > MAX_DELAY)){\
            fprintf(stderr, "%s:%d, timestamp:%lld.%lld, time diff:%ld ns\n", __FILE__, __LINE__, (long long)_start_time.tv_sec, (long long)_start_time.tv_nsec, time_diff_ns);\
        }\
    }while (0)
#else
#define TIME_RECORD()   
#define TIME_DIFF()  
#endif

#ifdef __cplusplus
}
#endif