#ifdef __cplusplus
extern "C" {
#endif

/*
	marsio模式的pag接口, 采用中心标准规范设计, 和之前专用网卡的不一致.
	所以和之前普通pag模式区别开.
*/

#include <unistd.h>
#include <pthread.h>
#include "packet_io.h"
#include "packet_io_internal.h"
#include "stream_internal.h"
#include "mesa_net.h"
#include "libpag.h"
#include "MESA_sleep.h"
#include <assert.h>

typedef struct{
	int thread_num; 
	UINT8 pag_send_buf[SENDPACKET_BUF_LEN];
}pag_send_handle;

int g_pag_marsio_version_VERSION_20170407;
int g_pag_marsio_version_VERSION = 20170407;
static PACKET_IO_CB_T g_pag_work_fun;
static int g_pag_work_thread_num = 1;
static int g_pag_cap_level = CAP_LEVEL_MAC;
static int g_pag_topology_mode = NET_CONN_PARALLEL;
static int pag_work_thread_seq[MAX_THREAD_NUM];
static pthread_t pag_work_tid[MAX_THREAD_NUM];
extern int g_use_MESA_sleep_sw;
extern void bind_thread_to_cpuid(int thread_id);


int dl_io_set_cap_level(int cap_level)
{
	g_pag_cap_level = cap_level;
	
	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode; /* pag模式无需设置 */
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_pag_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{
	 /* pag模式捕包网卡在pag.conf中设置 */
	(void)cap_dev;

	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	 /* pag模式捕包网卡在pag.conf中设置 */
	(void)up_dev;
	(void)down_dev;

	return -1;
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule; /* pag模式不支持过滤规则 */
	return 0;
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* pag模式无缓冲队列 */
	return 0;
}
	
int dl_io_set_work_thread_num(int thread_num_max)
{
	g_pag_work_thread_num = thread_num_max;
	return 0;
}


long dl_io_get_app_drop_num(int thread_num)
{
	/* pag模式查看丢包有专用工具, 程序目前不提供此功能 */
	(void)thread_num;
	return 0;
}

long dl_io_get_lib_drop_num(void)
{
	/* pag模式查看丢包有专用工具, 程序目前不提供此功能 */
	return 0;
}


unsigned char *dl_io_get_sendbuf(void *phandle, int thread_num)
{
	pag_send_handle *send_handle = (pag_send_handle *)phandle;
	
	return send_handle->pag_send_buf;
}

void dl_io_free_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	
	/* PCAP模式无需释放 */
	return;
}

int dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num)
{
	//TODO:

	printf("TODO: pag send not support yet\n");
	assert(0);
	return -1;
}

void *dl_io_get_send_handle(int thread_num)
{
	pag_send_handle *send_handle = (pag_send_handle *)calloc(1, sizeof(pag_send_handle));

	send_handle->thread_num = thread_num;

	return send_handle;
}


int dl_io_get_version(void)
{
	return g_pag_marsio_version_VERSION;
}

int dl_io_init(int argc, char *argv[])
{
	if(pag_open()<0) {
		fprintf(stderr,"%s\n","pag open err!\n");
		return -1;
	}

	return 0;
}


#if USE_PAG_GET_FRAME
static void *packet_io_pag_get(raw_pkt_t *raw_pkt, int tid)
{
	raw_pkt->raw_pkt_data = pag_get_frame(tid);
	raw_pkt->raw_pkt_len = pag_get_frame_length(tid);
	if((raw_pkt->raw_pkt_len <= 34/* 最小的IPv4包长 */) || (raw_pkt->raw_pkt_len > 65535)){
		return NULL;
	}
	raw_pkt->low_layer_type = (enum addr_type_t)CAP_LEVEL_MAC;
	raw_pkt->raw_pkt_ts.tv_sec = 0;
	raw_pkt->raw_pkt_ts.tv_usec = 0;
	raw_pkt->magic_num = RAW_PKT_MAGIC_NUM; /* 2014-12-11 lijia add */
	
	return (void *)raw_pkt->raw_pkt_data;
}
#else
static int __pag_get_raw_pkt_len(const raw_pkt_t *raw_pkt)
{
	int raw_pkt_len = 0;
	
	if(CAP_LEVEL_IPV4 == (enum cap_level_t)raw_pkt->low_layer_type){
		struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)raw_pkt->raw_pkt_data;
		raw_pkt_len = ntohs(ip4hdr->ip_len);
	}if(CAP_LEVEL_IPV6 == (enum cap_level_t)raw_pkt->low_layer_type){
		struct mesa_ip6_hdr *ip6hdr = (struct mesa_ip6_hdr *)raw_pkt->raw_pkt_data;
		raw_pkt_len = ntohs(ip6hdr->ip6_payload_len) + sizeof(struct mesa_ip6_hdr);	
	}else{
		//TODO
	}

	return raw_pkt_len;
}

/* 2014-12-12 lijia add, 网卡不支持pag_get_frame(), 只能猜猜看了 */
static int __guess_ipv4_or_ipv6(const char *data)
{
	if(0x40 == (data[0] & 0xF0)){
		return CAP_LEVEL_IPV4;
	}else if(0x60 == (data[0] & 0xF0)){
		return CAP_LEVEL_IPV6;
	}
	return __CAP_LEVEL_UNKNOW;
}

static void *packet_io_pag_get(raw_pkt_t *raw_pkt, int tid)
{
	void *data;

	data = pag_get(tid);
	if(NULL == data){
		return NULL;
	}
	
	raw_pkt->low_layer_type = (enum addr_type_t )__guess_ipv4_or_ipv6((const char *)data);
	if((int)raw_pkt->low_layer_type != (int)CAP_LEVEL_IPV4){ //2015-10-27 lijia add
		return NULL;  /* pag_get()只处理ipv4包 */
	}	
	raw_pkt->raw_pkt_data = (const void *)data;
	raw_pkt->raw_pkt_len = __pag_get_raw_pkt_len(raw_pkt);
	raw_pkt->raw_pkt_ts.tv_sec = 0;
	raw_pkt->raw_pkt_ts.tv_usec = 0;
	raw_pkt->magic_num = RAW_PKT_MAGIC_NUM; /* 2014-12-11 lijia add */

	return data;
}
#endif

static void *pag_worker(void *arg)
{
	int tid = *((int *)arg);
	void *data;
	raw_pkt_t raw_pkt;
	
	//bind_thread_to_cpuid(tid);

	memset(&raw_pkt, 0, sizeof(raw_pkt_t));

	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	raw_pkt.offset_to_raw_pkt_hdr = 0;
	
	while(1){
		data = packet_io_pag_get(&raw_pkt, tid);
		if(unlikely(NULL == data)){
			if(0 == g_use_MESA_sleep_sw){
				usleep(1);
			}else{
				MESA_sleep();
			}	
			continue;			
		}

		(*g_pag_work_fun)((const raw_pkt_t *)&raw_pkt, 0, tid);

		//pag_free(tid, data); /* 新的pag规范里无需再调用pag_free() */
	}

	return NULL;
}


void dl_io_run(void)
{
	int i=0;
	
	for(i = 0; i < g_pag_work_thread_num; i++)
	{
		pag_work_thread_seq[i] = i;
		pthread_create(&(pag_work_tid[i]), NULL, pag_worker, (void *) &(pag_work_thread_seq[i]));
	}
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_pag_work_fun = fun;
	return 0;
}


#ifdef __cplusplus
}
#endif


