#ifndef _SAPP_BCHMK_INNER_H_
#define _SAPP_BCHMK_INNER_H_  1
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include "wrap_cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif

#define CONFIG_MAX_LEN	(64)

#define TAP_DEV_NAME_MAX_LEN	(32)
#define MD5_STRING_MAX_LEN	(33)
#define SAPP_BCHMK_MTU		(2000)
#define ERROR_MSG_MAX_LEN	(2048)
#define SAPP_BCHMK_RECV_WAIT_TIMEOUT (3)
#define MAX_DUP_NAME_ITEM_NUM   (10)

#define SAPP_DEFAULT_MAIN_CONFIG_FILE "./etc/sapp.toml"

#define SAPP_TAP_DEVICE_UP_NAME  	"sapp_bch_tap_up"
#define SAPP_TAP_DEVICE_DOWN_NAME  	"sapp_bch_tap_down"

#define SAPP_START_PRE_CMD_NAME		"start_pre_command"
#define SAPP_STOP_PORT_CMD_NAME		"stop_post_command"


#define SAPP_BCHMK_TEST_JSON_DIR		"./TEST_PROFILE"

#define TSHARK_TOOLS_PATH "/usr/bin/tshark"

#define SAPP_BCHMK_OUTPUT_PCAP_FILE  "/tmp/.sapp_benchmark_output.pcap"

#define SAPP_BCHMK_TEMP_PCAP_FILE  "/tmp/.sapp_benchmark.pcap"
#define SAPP_BCHMK_TSHARK_STD_JSON_FILE  "/tmp/.sapp_benchmark.tshark.json"
#define SAPP_BCHMK_TSHARK_PLUG_JSON_FILE "/tmp/.sapp_benchmark.plug.json"

#define SAPP_BCHMK_DEFAULT_CFG_FILE_DIR "sapp_default_config"

#include "MESA_handle_logger.h"
extern void * __g_sapp_benchmark_log_handle;
#define sapp_bchmk_log(h, log_level, format, args...)  do{if(((benchmark_engine_t *)h)->plug_opt.MESA_log_handle) {MESA_handle_runtime_log(((benchmark_engine_t *)h)->plug_opt.MESA_log_handle, log_level, "sapp_benchmark", format, ##args);} }while(0)

/* �ڴ����index��0��ʼ, ����Ϊ�˷����wireshark�Աȷ���, ���������ļ���index����1��ʼ, ��Ҫ��һ��ת�� */
#define ADJUST_ARRAY_INDEX_to_WIRESHARK(n) do{ n = n + 1;}while(0)
#define ADJUST_WIRESHARK_INDEX_to_ARRAY(n) do{ n = n + 1;}while(0)



typedef struct{
	
}layer_detail_t;

typedef struct{
	int payload_len;
	char *payload_content;
	char *payload_md5sum;
}payload_detail_t;

typedef struct{
	int compare_base_index;
	int is_same_dir;
	int layer_detail_number;
	layer_detail_t *layer_detail;
	
	payload_detail_t payload_detail;
}inject_benchmark_t;


typedef struct{
	int pkt_len; /* pcapÿ��eth���ĳ��� */
	const struct ethhdr *pkt_data; /* �洢pcap�����ݵ�ָ������ */
	//char md5sum_with_timestamp[MD5_STRING_MAX_LEN]; /* ��Ϊ�ظ������ش���md5������ȫ��һ����, Ҫ����ʱ��� */
}pcap_pkt_detail_t;


typedef struct{
	int pkt_num; /* ���pcap����һ�����ٸ����ݰ� */
	pcap_pkt_detail_t *pkt_array;
}pcap_pkt_image_t;

#include "stream.h"

typedef struct{
	enum sapp_deploment_mode_t sapp_deploy_mode;
	int tap_internal_fd;
	int tap_external_fd;
	int last_replay_fd; /* ��¼�Ǵ��ĸ���������ȥ��, ֻ��˫��ģʽ������, inline��mirror�϶�����tap_up */
}pkt_process_engine_t;


typedef struct{
	long plug_set_opt_flags;
	void *MESA_log_handle;
	sapp_benchmark_result_t no_plug_defalut_result;
	sapp_benchmark_result_t plug_process_result;
	const char *json_file_name;
	const char *json_mem_cont;
}plug_opt_t;


/* ����debug, ԭʼ��ע���, �ִ������յ������ݰ�, (������Э��ջ�Զ������Ĺ㲥���鲥��),
   ������forward��, �����ǲ����ע���, Ҳ����һ����û��, ����DROP��! 
*/
typedef struct{
	int pkt_index;
	FILE *fp;
}benchmark_output_t;

typedef struct{
	volatile long running_flag;
	cJSON *benchmark_json_struct; 
	pthread_t replay_pkt_thread_pid;
	pkt_process_engine_t *process_engine;
	pcap_pkt_image_t *pcap_pkt_image;
	inject_benchmark_t *inject_benchmark_array;
	pthread_t timer_thread_pid;
	plug_opt_t plug_opt;
	benchmark_output_t output_pkt;
}benchmark_engine_t;


typedef struct  {
	unsigned int magic;
	unsigned short version_major;
	unsigned short version_minor;
	unsigned int thiszone;	/* gmt to local correction */
	unsigned int sigfigs;	/* accuracy of timestamps */
	unsigned int snaplen;	/* max length saved portion of each pkt */
	unsigned int linktype;	/* data link type (LINKTYPE_*) */
}pcap_file_hdr_t;

typedef struct {
	unsigned int tv_sec;	/* time stamp */
	unsigned int tv_usec;	/* time stamp */
	unsigned int caplen;	/* length of portion present */
	unsigned int len;	/* length this packet (off wire) */
}pcap_pkt_hdr_t;


char *sapp_bchmk_strdup(const char *raw_s);

const cJSON *sapp_bchmk_get_object_from_json(const cJSON *root, const char *expect_object_name);
const char *sapp_bchmk_get_value_from_json(const cJSON *root, const char *expect_father_item, const char *expect_item, char *result, int *result_max_len);
char *sapp_benchmark_load_json_from_file(const char *json_file_name);

const char *sapp_bchmk_md5sum(const void *data, int data_len);
int sapp_bchmk_create_process_engine(benchmark_engine_t *bch_engine);

int sapp_bchmk_md5_checksum(const char *filename, const char *expect_md5sum);
/*
	ע��:
		�˺���ʵ�ʷ��ص���TRUE��FALSE,
		0��ʾ��һ��, 1��ʾһ��!!
*/
cJSON_bool sapp_bchmk_json_file_compare(benchmark_engine_t *, const char *json_file1, const char *json_file2, cJSON_Compare_Opt_t opt);

int sapp_bchmk_gen_pcap_header(benchmark_engine_t *bchmk_engine, const char *pcap_filename);
int sapp_bchmk_append_pcap_pkt(benchmark_engine_t *bchmk_engine, const pcap_pkt_detail_t *pkt_detail, int pkt_num, const char *pcap_filename);
int sapp_bchmk_gen_pcap_file(benchmark_engine_t *,const pcap_pkt_detail_t *pkt_detail, int pkt_num, const char *pcap_filename);
int sapp_bchmk_gen_tshark_json(benchmark_engine_t *,const pcap_pkt_detail_t *pkt_detail, int pkt_num, const char *tshark_json_filename);
int sapp_bchmk_need_drop_cur_pkt(benchmark_engine_t *bchmk_engine, int pkt_index);
const char *sapp_bchmk_need_check_forward_pkt(benchmark_engine_t *bchmk_engine, int pkt_index);
const cJSON *sapp_bchmk_need_check_inject_pkt(benchmark_engine_t *bchmk_engine, int pkt_index);
const cJSON *sapp_bchmk_need_process_control(benchmark_engine_t *bchmk_engine, int carray_pkt_index);

unsigned long sapp_bchmk_get_file_len(const char *file_name);
sapp_benchmark_result_t sapp_benchmark_by_json_string(const char *benchmark_json_str, void *logger_handle);
sapp_benchmark_result_t sapp_benchmark_by_json_file(const char *benchmark_json_filename, void *logger_handle);
const char *sapp_benchmark_payload_to_hex(const void *data, int data_len);
void sapp_bchmk_set_default_config(void);
const char *sapp_bchmk_ippkt_ntop(const unsigned char *iphdr, char *res_buf, int buf_len);




#ifdef __cplusplus
}
#endif

#endif

