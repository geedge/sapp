#ifdef __cplusplus
extern "C" {
#endif

#include "agent_smith.h"
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int g_smith_version_VERSION_20161027;
static int g_smith_version_internal = 20161027;

typedef struct{
	int raw_eth_fd; /* 仅用于发送Ethernet原始报文 */
	int thread_num; 
	struct sockaddr saddr_up;
	struct sockaddr saddr_down;
	UINT8 pcap_send_buf[SENDPACKET_BUF_LEN];
}smith_send_handle;


static int g_smith_cap_mode = CAP_MODEL_PCAP_ONLINE;
static int g_smith_topology_mode = NET_CONN_PARALLEL;
static int g_smith_cap_level = CAP_LEVEL_IPV4; /* 本库捕包起始位置,默认MAC层 */
static int g_smith_work_thread_num = 1;
static PACKET_IO_CB_T g_smith_work_fun;
static PACKET_IO_EXIT_CB_T g_smith_exit_cb_fun;
static volatile long pcap_app_drop_num[MAX_THREAD_NUM];

//static struct mesa_ethernet_hdr *raw_pkt_hdr[MAX_THREAD_NUM]; /* 记录原始包头指针, 用于发包获取MAC地址用 */
//static unsigned char raw_pkt_route_dir[MAX_THREAD_NUM]; /* 记录原始包方向, 用于发送数据包 */

extern int g_use_MESA_sleep_sw;
extern void timestamp_record(enum timestamp_level level, const raw_pkt_t *raw_pkt, int thread_seq);
extern void timestamp_record_lib(const raw_pkt_t *raw_pkt);
/*

	注册控制命令,
	"set timestamp record minimum xxx",
	即超时最小是xxx时才显示.
	超时分为如下几个级别:

	硬件时间戳--->最底层拿到包-->IPv4层入口-->befor_stream_process()->after_stream_process()

	分别在__pkt_handle, ipv4_entry, stream_process()函数前后记录时间:
	"netdev--xxx---libentry---xxx---IPv4_entry---xxx---Before_call_plug---xxx---After_call_plug

	或者每次只打印时间值, 不要提示符, 
	"0 -- 1 -- 4 -- 10 -- 20"
*/


int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_smith_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int dl_io_set_cap_level(int cap_level)
{
	g_smith_cap_level = cap_level;

	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	g_smith_cap_mode = cap_mode;

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
	
	return 0;
	
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule;
	
	return 0;	
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max;

	return 0;
}

int dl_io_set_work_thread_num(int thread_num_max)
{
	if(thread_num_max > MAX_THREAD_NUM){
		return -1;
	}
	g_smith_work_thread_num = thread_num_max;

	return 0;
}

/* 此接口针对pag模式发送rst, 数据和日志, pcap模式不区别 */
int dl_io_set_send_type(int send_type)
{
	return 0;
}


long dl_io_get_app_drop_num(int thread_num)
{
	(void)thread_num;
	return 0;
}

long dl_io_get_lib_drop_num(void)
{
	return 0;
}



int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_smith_work_fun = fun;

	return 0;
}


int dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun)
{
	g_smith_exit_cb_fun = exit_fun;

	return 0;
}

unsigned char *dl_io_get_sendbuf(void *phandle, int thread_num)
{
	/*  */
	return NULL;
}

void dl_io_free_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	
	return;
}

int dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num)
{
	/*  */
	return -1;
}


void *dl_io_get_send_handle(int thread_num)
{
	/*  */
	return (void *)1324521345;
}

int dl_io_get_version(void)
{
	return g_smith_version_internal;
}

static void smith_entry(const unsigned char *data, int datalen, int thread_seq)
{
	raw_pkt_t pkt;

	memset(&pkt, 0, sizeof(raw_pkt_t));
	pkt.low_layer_type = (enum addr_type_t)g_smith_cap_level;
	pkt.magic_num = RAW_PKT_MAGIC_NUM;
	pkt.__lib_raw_pkt_data = data;
	pkt.__lib_raw_pkt_len = datalen;
	pkt.raw_pkt_data = data;
	pkt.raw_pkt_len = datalen;

	(*g_smith_work_fun)(&pkt, 0, thread_seq);
}

int dl_io_init(int argc, char *argv[])
{
	int ret;

	ret = agent_smith_init(g_smith_work_thread_num, smith_entry);

	return ret;
}

/* not return except some error occur. */
void dl_io_run(void)
{
	agent_smith_run();

	while(1){
		pause();
	}

	return;
}


#ifdef __cplusplus
}
#endif



#ifdef __cplusplus
}
#endif


