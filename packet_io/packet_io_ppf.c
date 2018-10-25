#ifdef __cplusplus
extern "C" {
#endif

#include <pcap/pcap.h>
#include <unistd.h>
#include <pthread.h>
#include "packet_io.h"
#include "packet_io_internal.h"
#include "mesa_net.h"
#include "libppf.h"
#include "MESA_sleep.h"

int g_ppf_version_VERSION = 20151216;
int g_ppf_version_VERSION_20151216;
static PACKET_IO_CB_T g_ppf_work_fun;
static int g_ppf_work_thread_num = 1;
static int g_ppf_cap_level = CAP_LEVEL_IPV4;
static int g_ppf_topology_mode = NET_CONN_PARALLEL;
static int ppf_work_thread_seq[MAX_THREAD_NUM];
static pthread_t ppf_work_tid[MAX_THREAD_NUM];


int dl_io_set_cap_level(int cap_level)
{
	g_ppf_cap_level = cap_level;
	
	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode; /* ppf模式无需设置 */
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_ppf_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{
	 /* ppf模式捕包网卡在conf中设置 */
	(void)cap_dev;

	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	 /* ppf模式捕包网卡在conf中设置 */
	(void)up_dev;
	(void)down_dev;

	return 0;
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule; /* ppf模式不支持过滤规则 */
	return 0;
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* ppf模式无缓冲队列 */
	return 0;
}
	
int dl_io_set_work_thread_num(int thread_num_max)
{
	g_ppf_work_thread_num = thread_num_max;
	return 0;
}


long dl_io_get_app_drop_num(int thread_num)
{
	/* ppf模式查看丢包有专用工具, 程序目前不提供此功能 */
	(void)thread_num;
	return 0;
}

long dl_io_get_lib_drop_num(void)
{
	/* ppf模式查看丢包有专用工具, 程序目前不提供此功能 */
	return 0;
}

int dl_io_get_version(void)
{
	return g_ppf_version_VERSION;
}

int dl_io_init(int argc, char *argv[])
{
	if(ppf_open() <0){
		fprintf(stderr,"%s\n","ppf open err!\n");
		return -1;
	}

	if(ppf_setStreamNum(g_ppf_work_thread_num) < 0){
		fprintf(stderr,"%s\n","ppf_setStreamNum err!!");
		return -1;
	}

	return 0;
}

static int __ppf_get_raw_pkt_len(const char *raw_pkt)
{
	int raw_pkt_len = 0;
	
	if(__ADDR_TYPE_IP_PAIR_V4 == g_ppf_cap_level){
		struct mesa_ip4_hdr *iphdr = (struct mesa_ip4_hdr *)raw_pkt;
		raw_pkt_len = ntohs(iphdr->ip_len);
	}else{
		// to do :
		// how to get ???
	}

	return raw_pkt_len;
}

static void *ppf_worker(void *arg)
{
	int tid = *((int *)arg);
	int len;
	void *pkt, *iph;
	raw_pkt_t raw_pkt;

	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM; /* 2014-12-11 lijia add */
	raw_pkt.raw_pkt_ts.tv_sec = 0;
	raw_pkt.raw_pkt_ts.tv_usec = 0;
		
	while(1){
		//pkt = ppf_recvDataBlock(tid);
		pkt = ppf_getDataBlock_no_Lock(tid);
		if(NULL == pkt) 
		{
			usleep(100);
			//MESA_sleep();
			continue;
		}
		iph = ppf_getIPPacket(pkt);
		len = ppf_getPktLength(pkt);

		raw_pkt.low_layer_type = (enum addr_type_t)g_ppf_cap_level;
		raw_pkt.raw_pkt_data = (const void *)iph;
		raw_pkt.raw_pkt_len = len;
		
		(*g_ppf_work_fun)((const raw_pkt_t *)&raw_pkt, 0, tid);

		ppf_freeDataBlock(pkt);
	}

	return NULL;
void dl_io_free_sendbuf(void *phandle, int thread_num)
{
	}

unsigned char *dl_io_get_sendbuf(void *phandle, int thread_num)
{
	return NULL;
}
void *dl_io_get_send_handle(int thread_num)
{
	void *p = malloc(100);
	return p;
}


void dl_io_run(void)
{
	int i=0;
	
	for(i = 0; i < g_ppf_work_thread_num; i++)
	{
		ppf_work_thread_seq[i] = i;
		pthread_create(&(ppf_work_tid[i]), NULL, ppf_worker, (void *) &(ppf_work_thread_seq[i]));
	}
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_ppf_work_fun = fun;
	return 0;
}


#ifdef __cplusplus
}
#endif


