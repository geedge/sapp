#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
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
#include "ap_bloom.h"
#include "sapp_global_val.h"
#include "fieldstat/fieldstat_easy.h"
#ifdef __cplusplus
extern "C"
{
#endif
    void bloom_free(void *bloom_filter, const sapp_dup_pkt_t *dup_conf);
    void *bloom_new(const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms);
    int bloom_check(void *bloom_filter, const char *key, int key_len, const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms);
    void bloom_add(void *bloom_filter, const char *key, int key_len, const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms);
    int DA_bloomfilter_get_stat(const struct expiry_dablooms_handle *bloom, sapp_sys_stat_type_t type, long long *count);
    int AP_bloomfilter_get_stat(const struct AP_bloom *bloom, sapp_sys_stat_type_t type, long long *count);
#ifdef __cplusplus
}
#endif

static int BM_LIBRARY = BLOOM_LIBRARY_DABLOOM;
static unsigned int BM_CAPACITY = 10000000;
static double BM_ERROR_RATE = 0.000001;
static int BM_TIMEOUT = 10 * 1000; // ms
static int BM_PARTITION_NUM = 1;
static long BM_TRANSITION_TIME = 2 * 1000;
static int MAX_ITEM_NUM = 10000000;
static int ITEM_BATCH_NUM = 1000;
static int APBM_SLICE_NUM = 0;
#define TUPLE4_ADDR_LEN (12 + 1) // sizeof(tuple4) add begin char 'Y' or 'N'
#define BM_TEST_MAX_THREAD (1)
static pthread_t bm_test_thread_id[BM_TEST_MAX_THREAD];
static pthread_t timer_thread_id;
static volatile long long g_current_time_in_ms = 0;
static struct timeval g_current_time_tv;

static const unsigned int INIT_SIP = 0x12345678;
static const unsigned int INIT_DIP = 0x87654321;
static const unsigned short INIT_SPORT = 0x1234;
static const unsigned short INIT_DPORT = 0x4321;

static struct fieldstat_easy *fs4_instance;
static struct field FS4_HISGRAM_TAG = {"bm_test", FIELD_VALUE_INTEGER , 0};
static int fs4_add_metric_id, fs4_check_true_metric_id, fs4_check_false_metric_id;
static int fs4_expand_num_metric_id, fs4_slice_new_metric_id, fs4_slice_free_metric_id;

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

static unsigned long long max_add_time = 0;      // ns
static unsigned long long total_add_time = 0;    // ns
static unsigned long long max_search_time = 0;   // ns
static unsigned long long total_search_time = 0; // ns

// for test, only support one thread
static struct timespec start_time, end_time;
unsigned long long time_diff; //ns

#define TIME_UPDATE()                                      \
    clock_gettime(CLOCK_REALTIME, &start_time);            \
    g_current_time_tv.tv_sec = start_time.tv_sec;          \
    g_current_time_tv.tv_usec = start_time.tv_nsec / 1000; \
    g_current_time_in_ms = start_time.tv_sec * 1000 + start_time.tv_nsec / 1000000;

#define TIME_DIFF()  \
    do {             \
        clock_gettime(CLOCK_REALTIME, &end_time); \
        if (likely(end_time.tv_sec == start_time.tv_sec))\
        {\
            time_diff = (end_time.tv_nsec - start_time.tv_nsec);\
        }else{\
            time_diff = ((unsigned long long)end_time.tv_sec * 1000 * 1000 * 1000 + end_time.tv_nsec) - ((unsigned long long)start_time.tv_sec * 1000 * 1000 * 1000 + start_time.tv_nsec);\
        }\
    }while (0)

static void bm_add_item(void *bloom_filter, char *tuple4_buf, unsigned int index, const sapp_dup_pkt_t *dup_conf)
{
    bm_update_key(tuple4_buf, index);
    TIME_UPDATE();
    bloom_add(bloom_filter, tuple4_buf, TUPLE4_ADDR_LEN, dup_conf, g_current_time_tv, g_current_time_in_ms);
    clock_gettime(CLOCK_REALTIME, &end_time);
    TIME_DIFF();
    if(time_diff > max_add_time){
        max_add_time = (unsigned long long)time_diff;
    }
    total_add_time += (unsigned long long)time_diff;
    fieldstat_easy_histogram_record(fs4_instance, 0, fs4_add_metric_id, &FS4_HISGRAM_TAG, 1, time_diff);
}

static int bm_search_item(void *bloom_filter, char *tuple4_buf, unsigned int index, const sapp_dup_pkt_t *dup_conf, int fs4_metric_id)
{
    bm_update_key(tuple4_buf, index);
    TIME_UPDATE();
    int ret = bloom_check(bloom_filter, tuple4_buf, TUPLE4_ADDR_LEN, dup_conf, g_current_time_tv, g_current_time_in_ms);
    TIME_DIFF();
    if(time_diff > max_search_time){
        max_search_time = (unsigned long long)time_diff;
    }    
    total_search_time += (unsigned long long)time_diff;
    fieldstat_easy_histogram_record(fs4_instance, 0, fs4_metric_id, &FS4_HISGRAM_TAG, 1, time_diff);
    return ret;
}

static void fieldstat_update(void *bm_handle)
{
    static long long history_expand_num = 0, history_slice_new_num = 0, history_slice_free_num = 0;
    long long expand_num = 0, slice_new_num = 0, slice_free_num = 0;
    if(BM_LIBRARY == BLOOM_LIBRARY_DABLOOM){
        DA_bloomfilter_get_stat((const expiry_dablooms_handle *)bm_handle, SAPP_STAT_BM_EXPAND_NUM, &expand_num);
        DA_bloomfilter_get_stat((const expiry_dablooms_handle *)bm_handle, SAPP_STAT_BM_SLICE_NUM_NEW, &slice_new_num);
        DA_bloomfilter_get_stat((const expiry_dablooms_handle *)bm_handle, SAPP_STAT_BM_SLICE_NUM_FREE, &slice_free_num);
        
    }else{
        AP_bloomfilter_get_stat((const AP_bloom*)bm_handle, SAPP_STAT_BM_EXPAND_NUM, &expand_num);
        AP_bloomfilter_get_stat((const AP_bloom *)bm_handle, SAPP_STAT_BM_SLICE_NUM_NEW, &slice_new_num);
        AP_bloomfilter_get_stat((const AP_bloom *)bm_handle, SAPP_STAT_BM_SLICE_NUM_FREE, &slice_free_num);   
    }
    fieldstat_easy_counter_incrby(fs4_instance, 0, fs4_expand_num_metric_id, &FS4_HISGRAM_TAG, 1, expand_num-history_expand_num); 
    fieldstat_easy_counter_incrby(fs4_instance, 0, fs4_slice_new_metric_id,  &FS4_HISGRAM_TAG, 1, slice_new_num-history_slice_new_num);
    fieldstat_easy_counter_incrby(fs4_instance, 0, fs4_slice_free_metric_id, &FS4_HISGRAM_TAG, 1, slice_free_num-history_slice_free_num);
    history_expand_num = expand_num;
    history_slice_new_num = slice_new_num;
    history_slice_free_num = slice_free_num;
}

static int bm_test()
{
    sapp_dup_pkt_t dup_conf = {};
    dup_conf.bloom_capacity = BM_CAPACITY;
    dup_conf.bloom_error_rate = BM_ERROR_RATE;
    dup_conf.bloom_timeout_ms = BM_TIMEOUT;
    dup_conf.bloom_library = (enum bloom_library)BM_LIBRARY;
    dup_conf.kickout_udp_stream_enabled = 1;
    dup_conf.dup_pkt_distinguish_all_inject = 1;
    dup_conf.dup_pkt_distinguish_ipv4_tcp = 1;
    dup_conf.dup_pkt_distinguish_ipv4_udp = 1;
    dup_conf.bloom_partition_num = BM_PARTITION_NUM;
    dup_conf.transition_time_ms = BM_TRANSITION_TIME;
    dup_conf.bloom_slice_num = APBM_SLICE_NUM;

    fs4_instance = fieldstat_easy_new(1, "bm-test", NULL, 0);
    fieldstat_easy_enable_auto_output(fs4_instance, "./bm_gtest_fs4.json", 1);
    // fieldstat_easy_enable_delta_in_active_output(fs4_instance);
    fs4_add_metric_id = fieldstat_easy_register_histogram(fs4_instance, "add", 1, 99999999, 5);
    fs4_check_true_metric_id = fieldstat_easy_register_histogram(fs4_instance, "chk_true", 1, 99999999, 5);
    fs4_check_false_metric_id = fieldstat_easy_register_histogram(fs4_instance, "chk_false", 1, 99999999, 5);
    fs4_expand_num_metric_id = fieldstat_easy_register_counter(fs4_instance, "bm_expand_num");
    fs4_slice_new_metric_id = fieldstat_easy_register_counter(fs4_instance, "bm_slice_new");
    fs4_slice_free_metric_id = fieldstat_easy_register_counter(fs4_instance, "bm_slice_free");

    clock_gettime(CLOCK_REALTIME, &start_time);
    g_current_time_tv.tv_sec = start_time.tv_sec;
    g_current_time_tv.tv_usec = start_time.tv_nsec / 1000;
    g_current_time_in_ms = start_time.tv_sec * 1000 + start_time.tv_nsec / 1000000;

    void *dabm_handle = bloom_new(&dup_conf, g_current_time_tv, g_current_time_in_ms);
    assert(dabm_handle);
    char tuple4_buf[1024] = {};
    long long search_y_error_num = 0;
    long long search_n_error_num = 0;
    time_t cur_time = time(NULL);
    long long tot_collision_num = 0;

    tuple4_buf[0] = 'Y';
    bm_update_key(tuple4_buf, 0);

    bloom_add(dabm_handle, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
    int hit = bloom_check(dabm_handle, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
    if (hit <= 0)
    {
        fprintf(stderr, "not found tuple4!\n");
        bloom_free(dabm_handle, &dup_conf);
        return -1;
    }

    printf("starting test, capacity:%u, timeout:%dms, partition:%d, slice_num:%d, batch_num:%d, max-items:%d\n",
           BM_CAPACITY, BM_TIMEOUT, BM_PARTITION_NUM, APBM_SLICE_NUM, ITEM_BATCH_NUM, MAX_ITEM_NUM);
    int ret;
    int add_index = 0, search_index_y = 0, search_index_n = 0;
    while (add_index < MAX_ITEM_NUM || search_index_y < MAX_ITEM_NUM  || search_index_n < MAX_ITEM_NUM )
    {
        tuple4_buf[0] = 'Y';
        for (int b = 0; b < ITEM_BATCH_NUM && add_index < MAX_ITEM_NUM; b++, add_index++)
        {
            bm_add_item(dabm_handle, tuple4_buf, add_index, &dup_conf);
        }

        tuple4_buf[0] = 'Y';
        for (int b = 0; b < ITEM_BATCH_NUM && search_index_y < MAX_ITEM_NUM; b++, search_index_y++)
        {
            ret = bm_search_item(dabm_handle, tuple4_buf, search_index_y, &dup_conf, fs4_check_true_metric_id);
            if (ret <= 0) // expect exist
            {
                search_y_error_num++;
            }
        }

        tuple4_buf[0] = 'N';
        for (int b = 0; b < ITEM_BATCH_NUM && search_index_n < MAX_ITEM_NUM; b++, search_index_n++)
        {
            ret = bm_search_item(dabm_handle, tuple4_buf, search_index_n, &dup_conf, fs4_check_false_metric_id);
            if (ret > 0) // expect not exist
            {
                search_n_error_num++;
            }
        }

        fieldstat_update(dabm_handle);
    }

    printf("add %lld items success, avg-time:%.3fns, max:%lluns\n",
           (long long)MAX_ITEM_NUM, (double)total_add_time / (double)MAX_ITEM_NUM, max_add_time);

    printf("search %lld items , avg-time:%.3fns, max:%lluns\n",
           (long long)MAX_ITEM_NUM, (double)total_search_time / (double)MAX_ITEM_NUM, max_search_time);

    double err_rate = (double)search_n_error_num / (double)MAX_ITEM_NUM;
    printf("search_y_error_num:%lld \nsearch_n_error_num:%lld, errer-rate:%f\n",
           search_y_error_num, search_n_error_num, err_rate);

    bloom_free(dabm_handle, &dup_conf);
    sleep(2); //wait fs4 output
    fieldstat_easy_free(fs4_instance);

    return search_y_error_num + (err_rate > (double)BM_ERROR_RATE);
}

static void *bm_test_thread(void *arg)
{
    if (bm_test() != 0)
    {
        return (void *)"error";
    }
    return (void *)"success";
}

static inline void nssleep(long ns)
{
    struct timespec req = {0, ns};
    nanosleep(&req, NULL);
}

static void bm_test_usage(void)
{
    printf("BM test usage:\n");
    printf("\tlibrary=[dabloom,apbloom]\n");
    printf("\tcapacity=2500000\n");
    printf("\terror_rate=0.000001\n");
    printf("\ttimeout=10000\n");
    printf("\tmax_item_num=10000000\n");
    printf("\titem_batch_num=1000\n");
    printf("\tpartition=1\n");
    printf("\tslice_num=1\n");
    printf("\texample: ./gtest_sapp -f=apbloom.simple -u=\"capacity=100000,error_rate=0.000001,partition=1,timeout=10000,slice_num=3,max_item_num=100000,item_batch_num=1000\"\n");
    printf("\n");
}

static int convert_user_args(const char *user_args)
{
    if (user_args == NULL)
    {
        return 0;
    }
    if(strstr(user_args, "-h") ){
        bm_test_usage();
        exit(0);
    }
    if(strstr(user_args, "--help") ){
        bm_test_usage();
        exit(0);
    }
    
    char *tmp_args = strdup(user_args);
    char *saveptr = NULL;
    char *token = strtok_r(tmp_args, ",", &saveptr);
    while (token)
    {
        char *key = strtok(token, "=");
        char *value = strtok(NULL, "=");
        if (key && value)
        {
            if (strcmp(key, "capacity") == 0)
            {
                BM_CAPACITY = (unsigned int )strtoull(value, NULL, 10);
            } 
            else if (strcmp(key, "error_rate") == 0)
            {
                BM_ERROR_RATE = strtod(value, NULL);
            }
            else if (strcmp(key, "partition") == 0)
            {
                BM_PARTITION_NUM = atoi(value);
            }
            else if (strcmp(key, "timeout") == 0)
            {
                BM_TIMEOUT = atoi(value);
            }
            else if (strcmp(key, "max_item_num") == 0)
            {
                MAX_ITEM_NUM = (unsigned int )strtoull(value, NULL, 10);
            }
            else if (strcmp(key, "item_batch_num") == 0)
            {
                ITEM_BATCH_NUM = atoi(value);
            }
            else if (strcmp(key, "slice_num") == 0)
            {
                APBM_SLICE_NUM = atoi(value);
            }
            else{
                fprintf(stderr, "unknown args: %s=%s\n", key, value);
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(tmp_args);

    return 0;
}

int sapp_bloom_filter_test_run(int bm_liarary, const char *user_define_args)
{
    int ret = 0;

    BM_LIBRARY = bm_liarary;
    convert_user_args(user_define_args);

    for (int i = 0; i < BM_TEST_MAX_THREAD; i++)
    {
        pthread_create(&bm_test_thread_id[i], NULL, bm_test_thread, NULL);
    }

    void *thread_result;
    for (int i = 0; i < BM_TEST_MAX_THREAD; i++)
    {
        pthread_join(bm_test_thread_id[i], &thread_result);
        if (strcmp((char *)thread_result, "success") != 0)
        {
            printf("thread %d test failed\n", i);
            ret = -1;
        }
    }

    return ret;
}

int sapp_apbloom_merge_test_run(void)
{
    int ret = 0;
    const int max_item_num = 100000;
    sapp_dup_pkt_t dup_conf = {};
    dup_conf.bloom_capacity = 1000000;
    dup_conf.bloom_error_rate = 0.000001;
    dup_conf.bloom_timeout_ms = 30*1000;
    dup_conf.bloom_library = (enum bloom_library)BLOOM_LIBRARY_APBLOOM;
    dup_conf.kickout_udp_stream_enabled = 1;
    dup_conf.dup_pkt_distinguish_all_inject = 1;
    dup_conf.dup_pkt_distinguish_ipv4_tcp = 1;
    dup_conf.dup_pkt_distinguish_ipv4_udp = 1;
    dup_conf.bloom_slice_num = 1;

    TIME_UPDATE();

    struct AP_bloom *apbma = (struct AP_bloom *)bloom_new(&dup_conf, g_current_time_tv, g_current_time_in_ms);
    assert(apbma);
    char tuple4_buf[1024] = {};

    tuple4_buf[0] = 'A';
    for(int i = 0; i < max_item_num; i++){
        bm_update_key(tuple4_buf, i);
        bloom_add(apbma, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
    }

    struct AP_bloom *apbmb = (struct AP_bloom *)bloom_new(&dup_conf, g_current_time_tv, g_current_time_in_ms);
    assert(apbmb);
    
    tuple4_buf[0] = 'B';
    for(int i = 0; i < max_item_num; i++){
        TIME_UPDATE(); 
        bm_update_key(tuple4_buf, i);
        bloom_add(apbmb, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
    }

    tuple4_buf[0] = 'B';
    for(int i = 0; i < max_item_num; i++){
        TIME_UPDATE();   
        bm_update_key(tuple4_buf, i);
        ret = bloom_check(apbma, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
        if(ret > 0){
            fprintf(stderr, "found tuple4 with B apbma before merge!\n");
            return -1;
        }  
    }

    AP_bloom_merge(apbma, apbmb);

    for(int i = 0; i < max_item_num; i++){
        TIME_UPDATE();   

        tuple4_buf[0] = 'A';
        bm_update_key(tuple4_buf, i);
        ret = bloom_check(apbma, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
        if(ret <= 0){
            fprintf(stderr, "not found tuple4 with A!\n");
            return -1;
        }
        tuple4_buf[0] = 'B';
        bm_update_key(tuple4_buf, i);
        ret = bloom_check(apbma, tuple4_buf, TUPLE4_ADDR_LEN, &dup_conf, g_current_time_tv, g_current_time_in_ms);
        if(ret <= 0){
            fprintf(stderr, "not found tuple4 with B!\n");
            return -1;
        }        
    }
    AP_bloom_free(apbma);
    AP_bloom_free(apbmb);
    return 0;
}
