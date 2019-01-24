#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <pthread.h>
#include "packet_io.h"
#include "packet_io_internal.h"
#include "stream_internal.h"
#include "sendpacket.h"
#include "mesa_net.h"
#include "marsio.h"
#include "mrtunnat.h"
#include "MESA_sleep.h"
#include "MESA_prof_load.h"
#include <assert.h>

#if 0
	TODO, 
	从模式1和3的device获取包, 发包时, 根据target_id查找到对应的device_sendpath. 
	struct marsio4_io_handle{
		int device_mode;  /* 1:recv; 2:send; 3:I/O all,  pag.conf中配置的肯定是3, 即收又发, send_raw.conf中一般都是2模式, 虚拟网卡, 只发 */
		int target_id; 
		const char *device_name;
		struct mr_vdev *device_vdev;
		struct mr_sendpath *device_sendpath;	
	}

#endif

/*
	netconnection_mode:
		1: 多网卡纯收不发 
		2: 一共两块卡, 双进双出
		3: 一共一块卡, 单进单出


	TODO:
	    从send_raw_pkt.conf解析的数据存储于G_SND_RAW_PKT_INFO,
	    本模块虽不一定从这些网卡收包, 但肯定会从这些网卡发包, 用于注入数据包给从应用的虚拟网卡,
	    仍然要在初始化时打开这些设备, 创建send_path.
    
*/
typedef struct{
	int thread_seq; 
	void *send_mbuf_mtod_ptr;
	marsio_buff_t *send_mbuf[1];
	struct mr_vdev *dev_up, *dev_down; /* GDEV模式下, 直接使用dev_up[0]; 同时兼容双网卡串联模式 */
	struct mr_sendpath *sendpath_up, *sendpath_down; /* 并联模式下, 直接使用sendpath_up; 同时兼容双网卡串联模式 */
}marsio4_io_handle;

int g_marsio4_version_VERSION_20180716;
int g_marsio4_version_VERSION = 20180716;
static PACKET_IO_CB_T g_marsio4_work_fun;
static int g_marsio4_work_thread_num = 1;
static int g_marsio4_cap_level = CAP_LEVEL_MAC;
static int g_marsio4_topology_mode = NET_CONN_PARALLEL;
static int marsio4_work_thread_seq[MAX_THREAD_NUM];
static pthread_t marsio4_work_tid[MAX_THREAD_NUM];
extern int g_use_MESA_sleep_sw;
struct mr_instance * sapp_marsio4_instance = NULL;
static int g_mr4_device_num = 0;
static char **g_mr4_up_device_name; /* 设备名称集合, meth0, meth1, meth2... */
static char **g_mr4_down_device_name; /* 设备名称集合, meth0, meth1, meth2... */
static struct mr_vdev **g_mr4_dev_up_handle_set, **g_mr4_dev_down_handle_set; /* 设备句柄集合 */
static struct mr_sendpath **g_mr4_sendpath_up_set, **g_mr4_sendpath_down_set; /* 发包路径(句柄)集合 */
static marsio4_io_handle *g_mario4_io_handle;

#define MARSIO_BURST_PKT_MAX		(256)
static int marsio4_burst_process_pkt_num = 32; /* 批处理包数量, 从pag.conf中获取 */
static long marsio4_thread_bind_mask = 0;

#define TIME_DELAY_MONITOR	(1) /* 单包处理延时监测 */

extern void timestamp_region_update_driver(int tid, long long cpu_cycle);
extern int stream_process_polling(int thread_seq);

int dl_io_set_cap_level(int cap_level)
{
	g_marsio4_cap_level = cap_level;
	
	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode;
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_GDEV:
		case NET_CONN_SERIAL_2CARD:
			g_marsio4_topology_mode = topology_mode;
		break;

		default:
			printf("\033[1;31;40m[Error]Invalid net_connection_mode!\033[0m\n");
			return -1;
	}

	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{
	char *save_ptr, *tmp_cap_dev_name;
	const char *delim = ", ";
	char cfg_name_from_pag_conf[1024]; 
	char *single_device;
	
	 /* marsio4模式捕包网卡可能有多个, 复用原有的pcapdevice配置, 靠逗号分隔 */
	if(NULL == cap_dev){
		printf("\033[1;31;40m[Error]Invalid pcapdevice!\033[0m\n");
		return -1;
	}

	/* marsio模式从pag.conf中获取捕包网卡名称, 逗号分隔模式 */
	MESA_load_profile_string_def((char *)"conf/main.conf", (char *)"Module", (char *)"pcapdevice", cfg_name_from_pag_conf, 1024, "");
	if('\0' == cfg_name_from_pag_conf[0]){
		printf("\033[1;31;40m[Error]Can't get pcap device from ./conf/main.conf!\033[0m\n");
		return -1;
	}
	tmp_cap_dev_name = cfg_name_from_pag_conf;

	while((single_device = strtok_r(tmp_cap_dev_name, delim, &save_ptr)) != NULL){
		if(NULL == g_mr4_up_device_name){
			g_mr4_up_device_name = (char **)malloc(sizeof(void *) * (g_mr4_device_num + 1));
		}else{
			g_mr4_up_device_name = (char **)realloc(g_mr4_up_device_name, sizeof(void *) * (g_mr4_device_num + 1));
		}

		g_mr4_up_device_name[g_mr4_device_num] = strdup(single_device);

		g_mr4_device_num++;
		tmp_cap_dev_name = NULL;
	}

	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	char *save_ptr;
	const char *delim = ", ";
	char *tmp_cap_dev_name, *save_mem_ptr;
	char *single_device;
	int local_mr4_serial_device_num = 0;
	
	 /* marsio4模式捕包网卡可能有多个, 复用原有的pcapdevice配置, 靠逗号分隔 */
	if(NULL == down_dev){
		printf("\033[1;31;40m[Error]Invalid pcapdevice!\033[0m\n");
		return -1;
	}

	tmp_cap_dev_name = strdup(down_dev);
	save_mem_ptr = tmp_cap_dev_name;

	while((single_device = strtok_r(tmp_cap_dev_name, delim, &save_ptr)) != NULL){
		if(NULL == g_mr4_down_device_name){
			g_mr4_down_device_name = (char **)malloc(sizeof(void *) * (local_mr4_serial_device_num + 1));
		}else{
			g_mr4_down_device_name = (char **)realloc(g_mr4_down_device_name, sizeof(void *) * (local_mr4_serial_device_num + 1));
		}

		g_mr4_down_device_name[local_mr4_serial_device_num] = strdup(single_device);

		local_mr4_serial_device_num++;
		tmp_cap_dev_name = NULL;
	}

	if(local_mr4_serial_device_num != g_mr4_device_num){
		printf("\033[1;31;40m[Error]capture device up and down number is not match!\033[0m\n");
		return -1;
	}

	free(save_mem_ptr);

	return 0;
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule; /* marsio模式不支持过滤规则 */
	return 0;
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* 驱动设置 */
	return 0;
}
	
int dl_io_set_work_thread_num(int thread_num_max)
{
	g_marsio4_work_thread_num = thread_num_max;
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


unsigned char *dl_io_get_sendbuf(void *phandle, int thread_seq)
{
	marsio4_io_handle *mr4_handle = (marsio4_io_handle *)phandle;
	
#if 0	
	int ret;
	/* NOTE 
		调用者申请marsio内存, 实际暂时存储到mr4_handle->send_mbuf, 
		然后返回mbuf->data给实际调用者,
		但此模式必须要求调用者一次发送必须保证malloc和free成对使用!
	*/
	ret = marsio_buff_malloc_global(sapp_marsio4_instance, mr4_handle->send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
	if(ret < 0){
		return NULL;
	}
	g_SysInputInfo[thread_index][PKT_MARSIO_MALLOC]++;
	data_buf = (unsigned char *)marsio_buff_mtod(mr4_handle->send_mbuf[0]);	
#else
	/* 发送时, 需要mbuf结构, 但此函数接口无法直接返回mbuf, 而是调用marsio_buff_mtod()之后的真实数据缓冲区, 暂时使用malloc */

	mr4_handle->send_mbuf_mtod_ptr = malloc(SENDPACKET_PACKET_SIZE);
#endif
	return (unsigned char *)mr4_handle->send_mbuf_mtod_ptr;
}

void dl_io_free_sendbuf(void *phandle, int thread_seq)
{
	marsio4_io_handle *mr4_handle = (marsio4_io_handle *)phandle;
	
#if 0 /* marsio 底层发送完后自动free, 不需要显式free */
	marsio4_io_handle *mr4_handle = (marsio4_io_handle *)phandle;

	marsio_buff_free(sapp_marsio4_instance, mr4_handle->send_mbuf, 1, -1, thread_seq);
	g_SysInputInfo[tid][PKT_MARSIO_FREE]++;
#else
	free(mr4_handle->send_mbuf_mtod_ptr);
#endif	
	return;
}


int dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_seq)
{
	int ret;
	marsio_buff_t *send_mbuf[1];
	char *real_buf;
	struct mr_tunnat_ctrlzone mr_ctrlzone;

	ret = marsio_buff_malloc_global(sapp_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
	if(ret < 0){
		return -1;
	}	
	g_SysInputInfo[thread_seq][PKT_MARSIO_MALLOC]++;

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = marsio_buff_append(send_mbuf[0], datalen);
	
	memcpy(real_buf, data, datalen);

	mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));

	marsio_send_burst_with_options((struct mr_sendpath *)arg, thread_seq, send_mbuf, 1, MARSIO_SEND_OPT_FAST);
	g_SysInputInfo[thread_seq][PKT_MARSIO_SND]++;
	/* 发送接口自动free */
	//marsio_buff_free(sapp_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
	
	return datalen;
}

int dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num)
{
	int ret;

	struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)data;

	ehdr->ether_type = ntohs(ETHERTYPE_IP);/* 底层设为ethernte */
	
	ret = dl_io_raw_pkt_send(phandle, data, datalen, g_packet_device_alias[0].dl_io_param, thread_num);
	
	return ret;
}

void *dl_io_get_send_handle(int thread_seq)
{
	return (void *)&g_mario4_io_handle[thread_seq];
}


int dl_io_get_version(void)
{
	return g_marsio4_version_VERSION;
}

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif
static int tmp_vdevice_num;
static char **tmp_vdevice_name; /* 虚拟设备名称列表, 非pag.conf中的捕包设备, 用于主从应用模式回注 */
static struct mr_sendpath **tmp_vdevice_sendpath;
void * dl_io_device_alias(unsigned int target_id, char *device_args)
{
	int i;
	int len1, len2;

	len1 = strlen(device_args);

	for(i = 0; i < g_mr4_device_num; i++){
		len2 = strlen(g_mr4_up_device_name[i]);
		/* 使用最长的字符比较, 防止"eth12", "eth1"比较但相等的BUG */
		if(strncasecmp(device_args, g_mr4_up_device_name[i], MAX(len1, len2)) == 0){
			return (void *)g_mr4_sendpath_up_set[i];
			break;
		}
	}	

	if(NULL != g_mr4_down_device_name){
		for(i = 0; i < g_mr4_device_num; i++){
			len2 = strlen(g_mr4_down_device_name[i]);
			/* 使用最长的字符比较, 防止"eth12", "eth1"比较但相等的BUG */
			if(strncasecmp(device_args, g_mr4_down_device_name[i], MAX(len1, len2)) == 0){
				return (void *)g_mr4_sendpath_down_set[i];
				break;
			}
		}	
	}

	/* 此卡未在pag.conf中注册, 可能是虚拟设备网卡, 现场打开发送句柄 */
	struct mr_vdev *t_vdev;
	struct mr_sendpath *t_sendpath;

	for(i = 0; i < tmp_vdevice_num; i++){
		len2 = strlen(tmp_vdevice_name[i]);
		/* 使用最长的字符比较, 防止"eth12", "eth1"比较但相等的BUG */
		if(strncasecmp(device_args, tmp_vdevice_name[i], MAX(len1, len2)) == 0){
			return (void *)tmp_vdevice_sendpath[i];
			break;
		}		
	}
	/* 没找到, 打开设备, 并存储发送句柄 */
	if(0 == tmp_vdevice_num){
		tmp_vdevice_name = (char **)malloc(sizeof(void *));
		tmp_vdevice_sendpath = (struct mr_sendpath **)malloc(sizeof(void *));
	}else{
		tmp_vdevice_name = (char **)realloc(tmp_vdevice_name, sizeof(void *) * (tmp_vdevice_num + 1));
		tmp_vdevice_sendpath = (struct mr_sendpath **)realloc(tmp_vdevice_sendpath, sizeof(void *) * (tmp_vdevice_num + 1));
	}
	tmp_vdevice_name[tmp_vdevice_num] = strdup(device_args);
	
	t_vdev = marsio_open_device(sapp_marsio4_instance, device_args, 
								0, 
								g_marsio4_work_thread_num);	
	if(NULL == t_vdev){
		printf("\033[41m[Error]Can't open device '%s'!\033[0m\n", device_args);
		return NULL;
	}

	t_sendpath = marsio_sendpath_create_by_vdev(t_vdev);
	tmp_vdevice_sendpath[tmp_vdevice_num] = t_sendpath;
	
	tmp_vdevice_num++; /* 最后更新计算器 */
	
	return t_sendpath;
}

/*
	计算一个整型数包含了多少个bit是1的.
*/
static inline int calc_integer_bit_num(unsigned long long num)
{
	int i = 0;
	int bit_num = 0;
	
	for(i = 0; i < (int)sizeof(long long) * 8; i++){
		if(num & 1){
			bit_num++;
		}
		num = num >> 1;
		if(0 == num){ /* num已经是0了, 就没必要再判断后续bit位了 */
			break;
		}
	}

	return bit_num;
}



#if 0
static int marsio4_pkt_forward_for_2card_mode(int tid, struct mr_sendpath * sendpath, marsio_buff_t * mbufs[], int nr_mbufs)
{
	//TODO,  pcap1->pcap2,  pcap2->pcap1
	abort();
	return 0;
}
#endif

#if 0
static int marsio4_pkt_forward_for_gdev_mode(int tid, struct mr_sendpath * sendpath, marsio_buff_t * mbuf)
{
	char tmp_mac[6];
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)marsio_buff_mtod(mbuf);
	
	/* 交换源、目的MAC地址, 再把原始包再注入GDEV */
	memcpy(tmp_mac, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, tmp_mac, 6);

	g_SysInputInfo[tid][PKT_MARSIO_SND]++;

	return marsio_send_burst(sendpath, tid, &mbuf, 1);
}
#endif

static int marsio4_pkt_forward(int tid, marsio_buff_t * mbufs)
{
	int ret = 0;
	struct mr_sendpath * sendpath;
	struct mr_tunnat_ctrlzone *ctrl_zone;

	ctrl_zone = (struct mr_tunnat_ctrlzone *)marsio_buff_ctrlzone(mbufs, 0);

	/* 使用targetid=0的设备号回注, 即send_raw_pkt.conf->vxlan_user网卡 */
	sendpath = (struct mr_sendpath *)g_packet_device_alias[0].dl_io_param;

	/* 批量获取, 但考虑特殊情况下, vxlan和其他封装模式混杂使用, 要对每个mbuf判断底层封装模式 */

	if(ctrl_zone->__encap_len > 0){ /* 2018-06-01, marsio vxlan mode, 非vxlan封装的包不能回注 */
		/* vxlan封装内层数据转发不必做任何操作, 直接调用marsio_send_burst, 由marsio驱动负责 */
		ctrl_zone->action = TUNNAT_CZ_ACTION_FORWARD;
		marsio_buff_ctrlzone_set(mbufs, 0, ctrl_zone, sizeof(struct mr_tunnat_ctrlzone));
		ret = marsio_send_burst(sendpath, tid, &mbufs, 1);
		g_SysInputInfo[tid][PKT_MARSIO_SND]++;
	}
	else
	{
		ret = -1;
	}

#if 0 /* 2018-06-01 close, marsio用不调用普通二层模式 */	
	else{ /* standard ethernet */
		ret = marsio4_pkt_forward_for_gdev_mode(tid, sendpath, mbufs);
	}
#endif

	return ret;
}


static inline int marsio4_pkt_hand(int tid, marsio_buff_t *rx_buff, raw_pkt_t *raw_pkt, unsigned char dir)
{
	int ret;
	struct mr_tunnat_ctrlzone *mr_ctrlzone = (struct mr_tunnat_ctrlzone *)marsio_buff_ctrlzone(rx_buff, 0); /* index */
	
	raw_pkt->raw_pkt_data = marsio_buff_mtod(rx_buff);
	raw_pkt->raw_pkt_len = marsio_buff_datalen(rx_buff);
	raw_pkt->io_lib_pkt_reference = rx_buff;

	ret = (*g_marsio4_work_fun)((const raw_pkt_t *)raw_pkt, mr_ctrlzone->route_dir, tid);
	
	return ret;
}

#if 0
/*
	判断gdev模式下, 底层数据包方向,
	ethernte模式下, 是靠smac地址的最后一个bit;
	vxlan模式下, 取vxlan_hdr->dir标准位;
*/
static unsigned char gdev_route_dir(const marsio_buff_t * rx_buff)
{
	struct mr_tunnat_ctrlzone *mr_ctrlzone = (struct mr_tunnat_ctrlzone *)marsio_buff_ctrlzone(rx_buff, 0);

	
	return mr_ctrlzone->route_dir;
}
#endif

static int marsio4_process_packet(int tid, raw_pkt_t *raw_pkt)
{
	int i,j, pkt_num = 0;
	marsio_buff_t * rx_buff[MARSIO_BURST_PKT_MAX]; /* 多个设备之间是串行获取, 太少则性能低, 太多则相对延时高 */
	int rcv_res, hand_res;

#if TIME_DELAY_MONITOR
	struct timespec curtime;
	unsigned long long driver, recv_from_driver;
#endif

	if((__NET_CONN_PARALLEL & g_marsio4_topology_mode) != 0){
		for(i = 0; i < g_mr4_device_num; i++){
			rcv_res = marsio_recv_burst(g_mr4_dev_up_handle_set[i], tid, rx_buff, marsio4_burst_process_pkt_num);
			if(rcv_res > 0){
				g_SysInputInfo[tid][PKT_MARSIO_RCV]+=(unsigned long long)rcv_res;
				for(j = 0; j < rcv_res; j++){

					marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_UP); /* 并联模式不关心返回值 */

				}
				pkt_num += rcv_res;
				marsio_buff_free(sapp_marsio4_instance, rx_buff, rcv_res, MARSIO_SOCKET_ID_ANY, tid); /* 并联不涉及发送, 调用完业务插件后批量free */
				g_SysInputInfo[tid][PKT_MARSIO_FREE]+=rcv_res;

			}
		}
	}else if(NET_CONN_SERIAL_GDEV == g_marsio4_topology_mode){
		for(i = 0; i < g_mr4_device_num; i++){
			rcv_res = marsio_recv_burst(g_mr4_dev_up_handle_set[i], tid, rx_buff, 16);
			if(rcv_res > 0){
				g_SysInputInfo[tid][PKT_MARSIO_RCV] += (unsigned long long)rcv_res;
				for(j = 0; j < rcv_res; j++){
#if TIME_DELAY_MONITOR				
					driver = marsio_buff_get_timestamp(rx_buff[j]);		
					clock_gettime(CLOCK_MONOTONIC, &curtime);
					recv_from_driver = curtime.tv_nsec ;	
					if(recv_from_driver > driver){ // cross second
						timestamp_region_update_driver(tid, recv_from_driver - driver);
					}
#endif
					hand_res = marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_UP); /* 在marsio4_pkt_hand()更新dir */
					if((g_marsio4_topology_mode & __NET_CONN_SERIAL) && (PASS == hand_res)){
						/* NOTE: 
						    MARSIO主从模式独特性, 从虚拟网卡收包, 但要通过物理网卡回注包,  
						*/
#if 1	
						int ret = marsio4_pkt_forward(tid, rx_buff[j]);
						if(ret < 0)
						{
							marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
							g_SysInputInfo[tid][PKT_MARSIO_FREE]++;
						}
#else
						MESA_sendpacket_ethlayer(tid, marsio_buff_mtod(rx_buff[j]), marsio_buff_buflen(rx_buff[j]), 0);
#endif
					}else{
						/* 串联模式下只能单包free, 有可能batch收的N各包里, 某个包需要回注, 某个包不需要 */
						marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
						g_SysInputInfo[tid][PKT_MARSIO_FREE]++;
					}
				}
				pkt_num += rcv_res;
			}
		}
	}else if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){
		for(i = 0; i < g_mr4_device_num; i++){
			/* 双网卡串联模式下, 为了防止极端特殊情况下, 只有两个主机在通信, syn->syn/ack->ack, 这种单包模式, 没有第一个包就不会有后续的包, 一次只能取一个包 */
			rcv_res = marsio_recv_burst(g_mr4_dev_up_handle_set[i], tid, rx_buff, 1);
			if(rcv_res > 0){
				g_SysInputInfo[tid][PKT_MARSIO_RCV]+=(unsigned long long)rcv_res;
				for(j = 0; j < rcv_res; j++){
					hand_res = marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_UP);
					if((g_marsio4_topology_mode & __NET_CONN_SERIAL) && (PASS == hand_res)){
						//marsio4_pkt_forward(tid, rx_buff[j]);
						marsio_send_burst(g_mr4_sendpath_down_set[i], tid, &rx_buff[j], 1);
						g_SysInputInfo[tid][PKT_MARSIO_SND]++;
					}else{
						/* 串联模式下单包free, 有可能需要回注/发送 */
						marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
						g_SysInputInfo[tid][PKT_MARSIO_FREE]++;
					}
				}
				pkt_num += rcv_res;
			}
			rcv_res = marsio_recv_burst(g_mr4_dev_down_handle_set[i], tid, rx_buff, 1);
			if(rcv_res > 0){
				g_SysInputInfo[tid][PKT_MARSIO_RCV]+=(unsigned long long)rcv_res;
				for(j = 0; j < rcv_res; j++){
					hand_res = marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_DOWN);
					if((g_marsio4_topology_mode & __NET_CONN_SERIAL) && (PASS == hand_res)){
						//marsio4_pkt_forward(tid, rx_buff[j]);
						marsio_send_burst(g_mr4_sendpath_up_set[i], tid, &rx_buff[j], 1);
						g_SysInputInfo[tid][PKT_MARSIO_SND]++;
					}else{
						/* 串联模式下单包free, 有可能需要回注/发送 */
						marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
						g_SysInputInfo[tid][PKT_MARSIO_FREE]++;
					}
				}
				pkt_num += rcv_res;
			}
		}
	}
	
	return pkt_num;
}

static int marsio4_sleep_time_table[100] = 
{
	 5,  5,   5,   5,   5,   3,   3,   3,   3,   3,     
	 1,  1,   1,   1,   1,    1,   1,  1,   1,    1, 
	 1,  1,   1,   1,   1,    1,   1,  1,   1,    1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  	
	 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  	 
};


static inline void marsio4_sleep(int tot_call_times, int rcv_pkt_times)
{
	float work_percent = ((float)rcv_pkt_times/(float)tot_call_times) * 100.0;

	if((work_percent < 90.0) && (marsio4_sleep_time_table[(int)work_percent] > 0)){
		usleep(marsio4_sleep_time_table[(int)work_percent]);
	}

/*
	static float max_work_percent = 0.0;
	if(work_percent > max_work_percent){
		max_work_percent = work_percent;
		printf("max_work_percent = %f\n", max_work_percent);
	}
*/	
}

static void *marsio4_worker(void *arg)
{
	int tid = *((int *)arg);
	raw_pkt_t raw_pkt;
	int total_call_times = 0, rcv_pkt_tims = 0;

	if(marsio4_thread_bind_mask != 0){
		marsio_thread_init(sapp_marsio4_instance);
	}
	memset(&raw_pkt, 0, sizeof(raw_pkt_t));

	/* 固定不变的参数预先设置 */
	raw_pkt.low_layer_type = (enum addr_type_t)g_marsio4_cap_level;
	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	raw_pkt.offset_to_raw_pkt_hdr = 0;
	
	while(1){
		if(marsio4_process_packet(tid, &raw_pkt) > 0){
			rcv_pkt_tims++;
		}
		total_call_times++;

		stream_process_polling(tid);

		if(total_call_times >= 100){
			if(rcv_pkt_tims < 99){
				marsio4_sleep(total_call_times, rcv_pkt_tims);
			}
			total_call_times = 0;
			rcv_pkt_tims = 0;
		}
	}

	return NULL;
}

int dl_io_init(int argc, char *argv[])
{
	int i;
	char bind_mask_string[128];
	char app_name[32];

	MESA_load_profile_int_def((char *)"pag.conf", (char *)"pag", (char *)"burst_rx", &marsio4_burst_process_pkt_num, 32);
	if(marsio4_burst_process_pkt_num >= MARSIO_BURST_PKT_MAX){
		printf("\033[33m[Warning]pag.conf->burst_rx is too more, set to %d!!\033[0m\n", MARSIO_BURST_PKT_MAX - 1);
		marsio4_burst_process_pkt_num = MARSIO_BURST_PKT_MAX - 1;
	}

	/* TODO, 支持不连续MASK配置, 如1,2,3,5,9;  0 means not bind */
	MESA_load_profile_string_def((char *)"conf/main.conf", (char *)"Module", (char *)"cpu_bind_core_mask", bind_mask_string, 128, "$");
	if(bind_mask_string[0] == '$'){
		marsio4_thread_bind_mask = 0;
		printf("\033[33m[Warning]In marsio mode, not set main.conf->cpu_bind_core_mask value, maybe cause CPU preemption!\033[0m\n");
		sleep(1);
	}else if(strncmp("0x", bind_mask_string, 2) == 0){
		marsio4_thread_bind_mask = strtoul(bind_mask_string, NULL, 16);
		if(calc_integer_bit_num(marsio4_thread_bind_mask) != g_marsio4_work_thread_num){
			printf("\033[41m[Error]main.conf->cpu_bind_core_mask value is not match main.conf->threadnum!\033[0m\n");
			printf("\033[41m          main.conf->cpu_bind_core_mask bit numer must match main.conf->threadnum, \033[0m\n");
			printf("\033[41m          for example, threadnum=8, core_mask shoule be 0xFF, 0xFF0, 0xFF00, etc.\033[0m\n");
			printf("\033[41m          for example, threadnum=16, core_mask shoule be 0xFFFF, 0xFFFF0, 0xFFFF00, etc.\033[0m\n");
			return -1;
		}
	}else if(atoi(bind_mask_string) == 0){
		marsio4_thread_bind_mask = 0;
		printf("\033[33m[Warning]In marsio mode, main.conf->cpu_bind_core_mask value is 0, same as not set, maybe cause CPU preemption!\033[0m\n");
		sleep(1);
	}else{
		printf("\033[41m[Error]main.conf->cpu_bind_core_mask value incorrect!\033[0m\n");
		return -1;
	}

	sapp_marsio4_instance = marsio_create();
	if(NULL == sapp_marsio4_instance) {
		fprintf(stderr,"%s\n","marsio_create error!\n");
		return -1;
	}

	if(NET_CONN_SERIAL_GDEV == g_marsio4_topology_mode){
		if(g_mr4_device_num != 1){
			printf("\033[1;31;40m[Error] in gdev mode, capture device num is %d!\033[0m\n", g_mr4_device_num);			
			return -1;
		}
	}else if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){
		if(g_mr4_device_num != 1){
			printf("\033[1;31;40m[Error] in gdev mode, capture device num is %d!\033[0m\n", g_mr4_device_num);			
			return -1;
		}
	}

	g_mario4_io_handle = (marsio4_io_handle *)calloc(1, sizeof(marsio4_io_handle) * g_marsio4_work_thread_num);
	
	marsio_option_set(sapp_marsio4_instance, MARSIO_OPT_THREAD_NUM, &g_marsio4_work_thread_num, sizeof(int));
	if(marsio4_thread_bind_mask != 0){
		marsio_option_set(sapp_marsio4_instance, MARSIO_OPT_THREAD_MASK, &marsio4_thread_bind_mask, sizeof(long));
	}

	MESA_load_profile_string_def((char *)"conf/main.conf", (char *)"Module", (char *)"app_instance_name", app_name, 32, "sapp");
	marsio_init(sapp_marsio4_instance, app_name);

	g_mr4_dev_up_handle_set = (struct mr_vdev **)malloc(sizeof(void *) * g_mr4_device_num);
	g_mr4_dev_down_handle_set = (struct mr_vdev **)malloc(sizeof(void *) * g_mr4_device_num);	
	g_mr4_sendpath_up_set = (struct mr_sendpath **)malloc(sizeof(void *) * g_mr4_device_num);	
	g_mr4_sendpath_down_set = (struct mr_sendpath **)malloc(sizeof(void *) * g_mr4_device_num);	

	for(i = 0; i < g_mr4_device_num; i++){
		g_mr4_dev_up_handle_set[i] = marsio_open_device(sapp_marsio4_instance, g_mr4_up_device_name[i], 
											g_marsio4_work_thread_num, 
											INDEPENDENT_SEND_QUEUE_MAX_NUM);
		if(NULL == g_mr4_dev_up_handle_set[i]){
			printf("\033[1;31;40m[Error]Open device '%s' error, please check pag.conf and main.conf->pcapdevice!\033[0m\n", 
				g_mr4_up_device_name[i]);
			return -1;
		}
		g_mr4_sendpath_up_set[i] = marsio_sendpath_create_by_vdev(g_mr4_dev_up_handle_set[i]);
		
		if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){								
			g_mr4_dev_down_handle_set[i] = marsio_open_device(sapp_marsio4_instance, g_mr4_down_device_name[i], 
												g_marsio4_work_thread_num, 
												INDEPENDENT_SEND_QUEUE_MAX_NUM);
			if(NULL == g_mr4_dev_down_handle_set[i]){
				printf("\033[1;31;40m[Error]Open device '%s' error, please check pag.conf and main.conf->pcapdevice2!\033[0m\n", 
					g_mr4_up_device_name[i]);
				return -1;
			}
			g_mr4_sendpath_down_set[i] = marsio_sendpath_create_by_vdev(g_mr4_dev_down_handle_set[i]);
		}									
	}
	
	return 0;
}

void dl_io_run(void)
{
	int i=0;
	
	for(i = 0; i < g_marsio4_work_thread_num; i++)
	{
		marsio4_work_thread_seq[i] = i;
		pthread_create(&(marsio4_work_tid[i]), NULL, marsio4_worker, (void *) &(marsio4_work_thread_seq[i]));
	}
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_marsio4_work_fun = fun;
	return 0;
}


#ifdef __cplusplus
}
#endif


