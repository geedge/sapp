#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h> /* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include "dablooms.h"
#include "sapp_global_val.h"

#ifdef __cplusplus
extern "C"
{
#endif
    void bloom_free_partition(void *bloom_filter, const sapp_dup_pkt_t *dup_conf);
    void *bloom_new_partition(const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms);
    int bloom_check_partition(void *bloom_filter, const char *key, int key_len, const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms);
    void bloom_add_partition(void *bloom_filter, const char *key, int key_len, const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms);
#ifdef __cplusplus
}
#endif

static const unsigned int BM_CAPACITY = 200000;
static const double BM_ERROR_RATE = 0.000001;
static const int BM_TIMEOUT = 10 * 1000; // ms
static const int BM_PARTITION_NUM = 64;
static const long BM_TRANSITION_TIME = 2 * 1000;

static const int MAX_ITEM_NUM = 10000000;
static const int ITEM_BATCH_NUM = 1000;
#define TUPLE4_ADDR_LEN (12 + 1) // sizeof(tuple4) add begin char 'Y' or 'N'
#define BM_TEST_MAX_THREAD (1)
static pthread_t bm_test_thread_id[BM_TEST_MAX_THREAD];
static pthread_t timer_thread_id;
static volatile struct timespec g_current_time_sp = {};
static volatile long long g_current_time_in_ms = 0;
static struct timeval g_current_time_tv;
static volatile int timer_thread_run = 1;

static const unsigned int INIT_SIP = 0x12345678;
static const unsigned int INIT_DIP = 0x87654321;
static const unsigned short INIT_SPORT = 0x1234;
static const unsigned short INIT_DPORT = 0x4321;

static inline void bm_update_key(char *tuple4_buf, unsigned int index)
{
    unsigned int *p_sip = (unsigned int *)&tuple4_buf[1];
    unsigned int *p_dip = (unsigned int *)&tuple4_buf[5];
    unsigned short *p_sport = (unsigned short *)&tuple4_buf[9];
    unsigned short *p_dport = (unsigned short *)&tuple4_buf[11];

    *p_sip = INIT_SIP + index;
    *p_dip = INIT_DIP + index;
    *p_sport = INIT_SPORT + index;
    *p_dport = INIT_DPORT + index;
}

static unsigned long long max_add_time = 0;      // us
static unsigned long long total_add_time = 0;    // us
static unsigned long long max_search_time = 0;   // us
static unsigned long long total_search_time = 0; // us

// for test, only support one thread
static struct timespec start_time, end_time;

// return us
static inline unsigned long long bm_time_diff(const struct timespec *start_time, const struct timespec *end_time)
{
    if (start_time->tv_sec == end_time->tv_sec)
    {
        return (unsigned long long)(end_time->tv_nsec - start_time->tv_nsec) / 1000;
    }
    return ((unsigned long long)end_time->tv_sec * 1000000 + end_time->tv_nsec / 1000) - ((unsigned long long)start_time->tv_sec * 1000000 + start_time->tv_nsec / 1000);
}

static void bm_add_item(void *bloom_filter, char *tuple4_buf, unsigned int index, const sapp_dup_pkt_t *dup_conf)
{
    bm_update_key(tuple4_buf, index);
    clock_gettime(CLOCK_REALTIME, &start_time);
    g_current_time_tv.tv_sec = g_current_time_sp.tv_sec;
    g_current_time_tv.tv_usec = g_current_time_sp.tv_nsec / 1000;
    bloom_add_partition(bloom_filter, tuple4_buf, TUPLE4_ADDR_LEN, dup_conf, g_current_time_tv, g_current_time_in_ms);
    clock_gettime(CLOCK_REALTIME, &end_time);

    unsigned long long time_diff = bm_time_diff(&start_time, &end_time);
    if (time_diff > max_add_time)
    {
        max_add_time = time_diff;
    }
    total_add_time += (unsigned long long)time_diff;
}

static int bm_search_item(void *bloom_filter, char *tuple4_buf, unsigned int index, const sapp_dup_pkt_t *dup_conf)
{
    bm_update_key(tuple4_buf, index);
    clock_gettime(CLOCK_REALTIME, &start_time);
    g_current_time_tv.tv_sec = g_current_time_sp.tv_sec;
    g_current_time_tv.tv_usec = g_current_time_sp.tv_nsec / 1000;
    int ret = bloom_check_partition(bloom_filter, tuple4_buf, TUPLE4_ADDR_LEN, dup_conf, g_current_time_tv, g_current_time_in_ms);
    clock_gettime(CLOCK_REALTIME, &end_time);
    long long time_diff = bm_time_diff(&start_time, &end_time);
    if (time_diff > max_search_time)
    {
        max_search_time = time_diff;
    }
    total_search_time += (unsigned long long)time_diff;
    return ret;
}

static int bm_test(int bloom)
{
    sapp_dup_pkt_t dup_conf = {};
    dup_conf.bloom_capacity = BM_CAPACITY;
    dup_conf.bloom_error_rate = BM_ERROR_RATE;
    dup_conf.bloom_timeout_ms = BM_TIMEOUT;
    dup_conf.bloom_library = (enum bloom_library)bloom;
    dup_conf.kickout_udp_stream_enabled = 1;
    dup_conf.dup_pkt_distinguish_all_inject = 1;
    dup_conf.dup_pkt_distinguish_ipv4_tcp = 1;
    dup_conf.dup_pkt_distinguish_ipv4_udp = 1;
    dup_conf.bloom_partition_num = BM_PARTITION_NUM;
    dup_conf.transition_time_ms = BM_TRANSITION_TIME;

    void *dabm_handle = bloom_new_partition(&dup_conf, g_current_time_tv, g_current_time_in_ms);
    assert(dabm_handle);
    char tuple4_buf[1024] = {};
    long long search_y_error_num = 0;
    long long search_n_error_num = 0;
    time_t cur_time = time(NULL);
    long long tot_collision_num = 0;

    tuple4_buf[0] = 'Y';
    bm_update_key(tuple4_buf, 0);

    bloom_add_partition(dabm_handle, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
    int hit = bloom_check_partition(dabm_handle, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
    if (hit <= 0)
    {
        fprintf(stderr, "not found tuple4!\n");
        bloom_free_partition(dabm_handle, &dup_conf);
        return -1;
    }

    printf("starting test, capacity:%u, timeout:%dms, partition:%d, batch_num:%d, max-items:%d\n",
           BM_CAPACITY, BM_TIMEOUT, BM_PARTITION_NUM, ITEM_BATCH_NUM, MAX_ITEM_NUM);
    int ret;
    int add_index = 0, search_index_y = 0, search_index_n = 0;
    while (add_index < MAX_ITEM_NUM || search_index_y < MAX_ITEM_NUM || search_index_n < MAX_ITEM_NUM)
    {
        tuple4_buf[0] = 'Y';
        for (int b = 0; b < ITEM_BATCH_NUM && add_index < MAX_ITEM_NUM; b++, add_index++)
        {
            bm_add_item(dabm_handle, tuple4_buf, add_index, &dup_conf);
        }

        tuple4_buf[0] = 'Y';
        for (int b = 0; b < ITEM_BATCH_NUM && search_index_y < MAX_ITEM_NUM; b++, search_index_y++)
        {
            ret = bm_search_item(dabm_handle, tuple4_buf, search_index_y, &dup_conf);
            if (ret <= 0) // expect exist
            {
                search_y_error_num++;
            }
        }

        tuple4_buf[0] = 'N';
        for (int b = 0; b < ITEM_BATCH_NUM && search_index_n < MAX_ITEM_NUM; b++, search_index_n++)
        {
            ret = bm_search_item(dabm_handle, tuple4_buf, search_index_n, &dup_conf);
            if (ret > 0) // expect not exist
            {
                search_n_error_num++;
            }
        }
    }

    printf("add %lld items success, avg-time:%.3fus, max:%lluus\n",
           (long long)MAX_ITEM_NUM, (double)total_add_time / (double)MAX_ITEM_NUM, max_add_time);

    printf("search %lld items , avg-time:%.3fus, max:%lluus\n",
           (long long)MAX_ITEM_NUM, (double)total_search_time / (double)MAX_ITEM_NUM, max_search_time);

    double err_rate = (double)search_n_error_num / (double)MAX_ITEM_NUM;
    printf("search_y_error_num:%lld \nsearch_n_error_num:%lld, errer-rate:%f\n",
           search_y_error_num, search_n_error_num, err_rate);

    bloom_free_partition(dabm_handle, &dup_conf);

    return search_y_error_num + (err_rate > (double)BM_ERROR_RATE);
}

static void *bm_test_thread(void *arg)
{
    int bloom = (int)(long)arg;
    if (bm_test(bloom) != 0)
    {
        return (void *)"error";
    }
    return (void *)"success";
}

static inline long long get_curtime_in_us(void)
{
    struct timespec curts;
    clock_gettime(CLOCK_MONOTONIC, &curts);
    return curts.tv_sec * 1000000 + curts.tv_nsec / 1000;
}

static inline void nssleep(long ns)
{
    struct timespec req = {0, ns};
    nanosleep(&req, NULL);
}

static void *timer_thread(void *arg)
{
    while (timer_thread_run)
    {
        clock_gettime(CLOCK_REALTIME, (struct timespec *)&g_current_time_sp);
        g_current_time_in_ms = g_current_time_sp.tv_sec * 1000 + g_current_time_sp.tv_nsec / 1000000;
        nssleep(10);
    }
    return NULL;
}

int sapp_bloom_filter_test_run(int bloom)
{
    int ret = 0;
    pthread_create(&timer_thread_id, NULL, timer_thread, NULL);

    for (int i = 0; i < BM_TEST_MAX_THREAD; i++)
    {
        pthread_create(&bm_test_thread_id[i], NULL, bm_test_thread, (void *)(long)bloom);
    }

    void *thread_result;
    for (int i = 0; i < BM_TEST_MAX_THREAD; i++)
    {
        pthread_join(bm_test_thread_id[i], &thread_result);
        if (thread_result != "success")
        {
            printf("thread %d test failed\n", i);
            ret = -1;
        }
    }
    timer_thread_run = 0;
    pthread_cancel(timer_thread_id);
    pthread_join(timer_thread_id, NULL);

    return ret;
}
