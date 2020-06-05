#include "sapp_api.h"
#include "sapp_private_api.h"

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

static int MRTUNNAT_THREAD_NUM = 1;
static int  MAX_SEND_THREAD = 1;
static int send_payload_len = 22;

typedef struct{
	long long value1;
	long long value2;
	long long value3;
	long long value4;
	long long value5;
	long long value6;
	long long value7;
	long long value8;
}cache_align_t;

#if IOMODE_MARSIO

static cache_align_t fake_rand_num[256];

static void test_send_udp_by_vlink(int thread_seq)
{
	SAPP_TLV_T option[32];
	int opt_num = 0, ret;
	struct streaminfo  tmp_streaminfo;
	const char *udp_payload = "test MESA_fakepacket_send_udp_options by vlink id()";
	char udp_paylaod_long[1450]; //负载22字节整体包长是64,  1472整体包长是1514.

	tmp_streaminfo.threadnum = thread_seq;

	option[0].type = SAPP_SEND_OPT_VIRTUAL_LINK_ID;
	option[0].length = sizeof(long long);
	option[0].long_value = 0;
	opt_num++;

	option[1].type = SAPP_SEND_OPT_REHASH_INDEX;
	option[1].length = sizeof(long long);
	option[1].long_value = fake_rand_num[thread_seq].value1 % MRTUNNAT_THREAD_NUM;
	fake_rand_num[thread_seq].value1++;
	opt_num++;
	

#if 0
	ret = MESA_fakepacket_send_udp_options(&tmp_streaminfo, 0xC0A83294, 0xC0A86405, 0x1111, 0x5555, 
											udp_payload, strlen(udp_payload), 0,
											option, opt_num);
#else
ret = MESA_fakepacket_send_udp_options(&tmp_streaminfo, 0xC0A83295, 0xC0A86405, 0x1111, 0x5555, 
										udp_paylaod_long, send_payload_len, 0,
										option, opt_num);

#endif
	if(ret < 0){
		printf("MESA_fakepacket_send_udp_options error!\n");
	}
}

static void *sendpacket_perf_thread(void *arg)
{
	int tid, ret, opt_len;

	opt_len = sizeof(int);
	ret = sapp_get_platform_opt(SPO_INDEPENDENT_THREAD_ID,  &tid,  &opt_len);
	if(ret < 0){
		printf("houyi_plug: get SPO_INDEPENDENT_THREAD_ID error!\n");
		return NULL;
	}

#if 0 //加上修改线程名之后, marsio会发包错误, 原因不明
	char thread_name[32];
	snprintf(thread_name, sizeof(thread_name), "%s_%d", "sapp_snd", tid);
	pthread_setname_np(pthread_self(), thread_name);
#endif

	packet_io_send_only_thread_init();

	while(1){
			test_send_udp_by_vlink(tid);
	}

	return NULL;
}


int CHAR_INIT()
{
	pthread_t pid[256];
	int  i;

	int ret = MESA_load_profile_int_def((char *)"etc/test_sendpacket_perf.conf", (char *)"main", (char *)"thread_num",  &MAX_SEND_THREAD, 1);
	if(ret < 0){
		printf("can't get thread_num from: %s\n", "etc/test_sendpacket_perf.conf");
		return -1;
	}
	ret = MESA_load_profile_int_def((char *)"etc/test_sendpacket_perf.conf", (char *)"main", (char *)"mrtunnat_thread_num",  &MRTUNNAT_THREAD_NUM, 1);
	if(ret < 0){
		printf("can't get mrtunnat_thread_num from: %s\n", "etc/test_sendpacket_perf.conf");
		return -1;
	}	
	ret = MESA_load_profile_int_def((char *)"etc/test_sendpacket_perf.conf", (char *)"main", (char *)"send_payload_len",  &send_payload_len, 22);
	if(ret < 0){
		printf("can't get send_payload_len from: %s\n", "etc/test_sendpacket_perf.conf");
		return -1;
	}	
	for(i = 0; i < MAX_SEND_THREAD; i++){
		pthread_create(&pid[i], NULL, sendpacket_perf_thread, NULL);
	}
	
	return 1;
}

void CHAR_DESTROY(void)
{

}
#else
int CHAR_INIT()
{
	printf("##### error! test_sendpacket_performance plug must compile and run in marsio mode!\n");
	return -1;
}

#endif

#ifdef __cplusplus
}
#endif


