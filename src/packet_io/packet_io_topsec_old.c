#ifdef __cplusplus
extern "C" {
#endif
/*
	2015-09-29 lijia add, 
	for trojan detect, get packet from TOPSEC library.
*/
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "tos_mc_api.h"

typedef struct{
	int thread_num; 
	UINT8 topsec_send_buf[SENDPACKET_BUF_LEN];
}topsec_send_handle;

int g_topsec_version_VERSION_20150929;
int g_topsec_version_VERSION = 20150929;
static PACKET_IO_CB_T g_topsec_work_fun;
static int g_topsec_work_thread_num = 1;
static int g_topsec_cap_level = CAP_LEVEL_IPV4;
static int g_topsec_topology_mode = NET_CONN_PARALLEL;
static int topsec_work_thread_seq[MAX_THREAD_NUM];
static pthread_t topsec_work_tid[MAX_THREAD_NUM];
static void *g_topsec_handle;


int dl_io_set_cap_level(int cap_level)
{
	g_topsec_cap_level = cap_level;
	
	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode; /* topsec模式无需设置 */
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_topsec_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{
	(void)cap_dev;

	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	(void)up_dev;
	(void)down_dev;

	return -1;
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule; /* topsec模式不支持过滤规则 */
	return 0;
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* topsec模式无缓冲队列 */
	return 0;
}
	
int dl_io_set_work_thread_num(int thread_num_max)
{
	g_topsec_work_thread_num = thread_num_max;

	if(g_topsec_work_thread_num != 1){
		printf("topsec lib not support multiple thread!\n");
		assert(0);
	}
	
	return 0;
}


long dl_io_get_app_drop_num(int thread_num)
{
	/* 目前不提供此功能 */
	(void)thread_num;
	return 0;
}

long dl_io_get_lib_drop_num(void)
{
	/* topsec目前不提供此功能 */
	return 0;
}


unsigned char *dl_io_get_sendbuf(void *phandle, int thread_num)
{
	topsec_send_handle *send_handle = (topsec_send_handle *)phandle;
	
	return send_handle->topsec_send_buf;
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
	//TODO 1:
	printf("TODO: topsec send not support yet\n");
	assert(0);
	return -1;
}

void *dl_io_get_send_handle(int thread_num)
{
	topsec_send_handle *send_handle = (topsec_send_handle *)calloc(1, sizeof(topsec_send_handle));

	send_handle->thread_num = thread_num;

	return send_handle;
}


int dl_io_get_version(void)
{
	return g_topsec_version_VERSION;
}

int dl_io_init(int argc, char *argv[])
{
	g_topsec_handle = tos_get_handle(getpid());
	if(NULL == g_topsec_handle) {
		fprintf(stderr,"%s\n","tos_get_handle error!\n");
		return -1;
	}

	return 0;
}


static int packet_io_topsec_get(raw_pkt_t *raw_pkt, int tid)
{
	struct mc_desc *pkt_desc;
	int ret;

	ret = tos_tr_packet_recv(&pkt_desc, g_topsec_handle);
	if(ret < 0){
		return -1;
	}
	
	raw_pkt->low_layer_type = (enum addr_type_t )CAP_LEVEL_IPV4; /* topsec暂时只支持ipv4 */
	raw_pkt->raw_pkt_data = (const void *)pkt_desc->buffer;
	raw_pkt->raw_pkt_len = pkt_desc->tot_len;

	return 0;
}


static void *topsec_worker(void *arg)
{
	int tid = *((int *)arg);
	int ret;
	raw_pkt_t raw_pkt;

	memset(&raw_pkt, 0, sizeof(raw_pkt_t));

	raw_pkt.raw_pkt_ts.tv_sec = 0;
	raw_pkt.raw_pkt_ts.tv_usec = 0;
	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM; /* 2014-12-11 lijia add */
	
	while(1){
		ret = packet_io_topsec_get(&raw_pkt, tid);
		if(ret < 0){
			//sapp_usleep(1);
			MESA_sleep();
			continue;			
		}

		(*g_topsec_work_fun)((const raw_pkt_t *)&raw_pkt, 0, tid);
	}

	return NULL;
}


void dl_io_run(void)
{
	int i=0;
	
	for(i = 0; i < g_topsec_work_thread_num; i++)
	{
		topsec_work_thread_seq[i] = i;
		pthread_create(&(topsec_work_tid[i]), NULL, topsec_worker, (void *) &(topsec_work_thread_seq[i]));
	}
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_topsec_work_fun = fun;
	return 0;
}


#ifdef __cplusplus
}
#endif


