#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "marsio.h"

#define USE_MARSIO_API			(0)

int g_dpdk_version_VERSION_20160929;
int g_dpdk_version_VERSION = 20160929;
static PACKET_IO_CB_T g_dpdk_work_fun;
static int g_dpdk_work_thread_num = 1;
static int g_dpdk_cap_level = CAP_LEVEL_MAC;
static int g_dpdk_topology_mode = NET_CONN_PARA_NOSEND;

typedef struct{
	struct mesa_ethernet_hdr *dpdk_raw_pkt_hdr; /* 记录原始包头指针, 用于发包获取MAC地址用 */
	unsigned char dpdk_raw_pkt_route_dir; /* 记录原始包方向, 用于发送数据包 */
	raw_pkt_t raw_pkt;
	char __cache_align[56];
}dpdk_low_level_io_para_t;

static dpdk_low_level_io_para_t dpdk_low_level_io_para[MAX_THREAD_NUM];

typedef struct{
	int thread_num; 
	UINT8 dpdk_send_buf[SENDPACKET_BUF_LEN];
}dpdk_send_handle;

extern void idle_polling_call(int thread_seq);
void dpdk_empty_call(int thread_seq)
{
	idle_polling_call(thread_seq);
}

#if USE_MARSIO_API
int dpdk_hand(const char * data, int datalen, int thread_num, mr_pkt_desc_t * desc, void * arg)
#else
int dpdk_hand(const unsigned char *data, int datalen, int dir, int thread_num)
#endif
{
	int ret;
	dpdk_low_level_io_para_t *io_para = &dpdk_low_level_io_para[thread_num];
	raw_pkt_t *raw_pkt = &io_para->raw_pkt;
	
#if USE_MARSIO_API
	unsigned char dir = desc->in_dest;
#endif

	io_para->dpdk_raw_pkt_route_dir = dir;
	io_para->dpdk_raw_pkt_hdr = (struct mesa_ethernet_hdr *)data;

	raw_pkt->low_layer_type = (enum addr_type_t)g_dpdk_cap_level;
	raw_pkt->__lib_raw_pkt_data = (const void *)data;
	raw_pkt->__lib_raw_pkt_len = datalen;
	raw_pkt->raw_pkt_data = (const void *)data;
	raw_pkt->raw_pkt_len = datalen;
	//io_para->raw_pkt.raw_pkt_ts.tv_sec = 0;
	//io_para->raw_pkt.raw_pkt_ts.tv_usec = 0;
	//io_para->raw_pkt.magic_num = RAW_PKT_MAGIC_NUM; /* 2014-12-11 lijia add */

#if USE_MARSIO_API	
	raw_pkt->hd_hash = desc->in_hash;
#endif	
	ret =  (*g_dpdk_work_fun)((const raw_pkt_t *)raw_pkt, dir, thread_num);

	/* DPDK靠返回值判断是否转发包, 所以在并联模式下, 固定返回DROP */
	if(likely(g_dpdk_topology_mode & __NET_CONN_PARALLEL)){
		ret = DROP;
	}

	return ret;
}

int dl_io_set_cap_level(int cap_level)
{
	g_dpdk_cap_level = cap_level;
	
	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode; /* dpdk模式无需设置 */
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_dpdk_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{
	 /* dpdk模式捕包网卡在命令行参数中设置 */
	(void)cap_dev;

	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	 /* dpdk模式捕包网卡在命令行参数中设置 */
	(void)up_dev;
	(void)down_dev;

	return 0;
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule; /* dpdk模式不支持过滤规则 */
	return 0;
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* dpdk模式无缓冲队列 */
	return 0;
}
	
int dl_io_set_work_thread_num(int thread_num_max)
{
	g_dpdk_work_thread_num = thread_num_max;
	return 0;
}


long dl_io_get_app_drop_num(int thread_num)
{
	/* dpdk模式查看丢包有专用工具, 程序目前不提供此功能 */
	(void)thread_num;
	return 0;
}

long dl_io_get_lib_drop_num(void)
{
	/* dpdk模式查看丢包有专用工具, 程序目前不提供此功能 */
	return 0;
}

int dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num)
{
	int dir_reverse = 0, ret;

	(void)phandle;

	if(dir != dpdk_low_level_io_para[thread_num].dpdk_raw_pkt_route_dir){
		dir_reverse = 1;
	}else{
		dir_reverse = 0;
	}
	
	net_common_build_send_mac(data, dpdk_low_level_io_para[thread_num].dpdk_raw_pkt_hdr, 
							  eth_carry_layer_addr_type, dir_reverse, g_dpdk_topology_mode);
	/* delete by lijia 2014-12-10, datalen已经包含了mac地址长度 */	  
	//datalen += sizeof(struct mesa_ethernet_hdr);
	
	ret = dpdk_send_packet_dst((unsigned char *)data, datalen, dir);
	return ret;
}

int dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num)
{
	int ret;
	send_raw_args_t *snd_raw_args;
	
	(void)phandle;

	snd_raw_args = (send_raw_args_t *)arg;

	ret = dpdk_send_packet_port(data, datalen, snd_raw_args->port_id);

	return ret;
}

unsigned char *dl_io_get_sendbuf(void *phandle, int thread_num)
{
	dpdk_send_handle *send_handle = (dpdk_send_handle *)phandle;
	
	return send_handle->dpdk_send_buf;
}

void dl_io_free_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	
	/* DPDK模式无需释放 */
	return;
}

void *dl_io_get_send_handle(int thread_num)
{
	dpdk_send_handle *real_handle = (dpdk_send_handle *)malloc(SENDPACKET_BUF_LEN);	

	real_handle->thread_num = thread_num;

	return (void *)real_handle;
}

int dl_io_get_version(void)
{
	return g_dpdk_version_VERSION;
}

int dl_io_init(int argc, char *argv[])
{
	int i;
#if USE_MARSIO_API
	marsio_rawio_cb_reg(dpdk_hand, NULL);
#else
	dpdk_register_callfunc_dst(dpdk_hand);
#endif	

	for(i = 0; i < MAX_THREAD_NUM; i++){
		dpdk_low_level_io_para[i].raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
		memset(&dpdk_low_level_io_para[i].raw_pkt.raw_pkt_ts, 0, sizeof(struct timeval));
	}
	return dpdk_init(argc, argv);
}


void dl_io_run(void)
{
	dpdk_run();
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_dpdk_work_fun = fun;
	return 0;
}

#ifdef __cplusplus
}
#endif


