
/* 
	因WY项目更新需求, 是否与GDEV保活是根据插件的运行状态动态决定, 而不是再固定一直保活,
	
	所以将GDEV-KEEPALIVE功能从平台中剥离, 
	挂载到IP、UDP层插件完成原有保活功能.

	目前没有arp_entry, ethernet_entry, ARP回复功能暂时仍留在平台内部.
*/

#include <pthread.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include "stream_inc/gdev_keepalive.h"
#include "field_stat2.h"

#if IOMODE_MARSIO	
static struct mr_instance * gdev_plug_extern_marsio4_instance; /* dlopen dynamic link sapp->marsio4 instance */
extern int marsio_send_burst_with_options_for_tcpdumpmesa(struct mr_sendpath * sendpath, queue_id_t sid, marsio_buff_t * mbufs[], int nr_mbufs, uint16_t options);
extern int (*ptr_marsio_buff_malloc_global)(struct mr_instance * instance, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs, int socket_id, int thread_id);
extern char * (*ptr_marsio_buff_append)(marsio_buff_t *m, uint16_t len);
extern void (*ptr_marsio_buff_free)(struct mr_instance * instance, marsio_buff_t *marsio_buff[],unsigned int nr_mbufs, int socket_id, int thread_id);
#endif

#ifdef GIT_VERSION
 __attribute__((__used__)) const char *g_device_plug_git_ver = GIT_VERSION;
#endif

#define MAX_SUPPORT_GDEV_NUM	(64)  /* 每个线程内最多支持inline device的数量, 根据分流策略和线程数的不同, 最小值是MAX_SUPPORT_GDEV_NUM, 最大值是MAX_SUPPORT_GDEV_NUM * sapp_thread_count */
#define MAX_VXLAN_SERVICE_NUM	(256) /* 目前最大支持255种不同业务, 数组下标最大是255 */

#define MAX_NO_PKT_TIMEOUT 		(120) /* 超过这么长时间一直没保活包, 把此设备剔除 */

static void *gdev_kp_log_handle;
enum prog_work_mode_t{
	PROG_MODE_MASTER = 1,
	PROG_MODE_SLAVE = 2,
};


enum gdev_keepalive_fs2_column_t{
	FS2_COLUMN_REQUEST_NUM = 0,
	FS2_COLUMN_REPLY_NUM,
	__FS2_COLUMN_MAX,
};

static int gdev_keepalive_fs2_column_id_array[__FS2_COLUMN_MAX];

/*
	每个线程, 每个Inline-DEV-IP, 每个业务分别统计.
*/

typedef struct {
	int gdev_keepalive_type;  /* for example: GDEV_KEEPALIVE_TYPE_BFD */
	//int gdev_keepalive_service_num; 
	unsigned int keepalive_request_num; /* 当前业务保活请求包数量, 每隔一段时间清零 */
	unsigned int keepalive_reply_num; /* 当前业务保活应答包数量, 根据service不同, 可能某些业务故意不回复应答, 导致request并不一定等于reply */
	int field_stat_line_id; /* fs2 矩阵的行id */
	time_t last_time; /* 当前业务最后一次收到保活包的时间 */	
}gdev_keepalive_status_per_service_t;


typedef struct{
	int inuse_flag; /* 此位置被占用 */
	unsigned int gdev_ip_network_order;
	unsigned int keepalive_request_num; /* 当前设备保活请求包数量, 每隔一段时间清零 */
	unsigned int keepalive_reply_num; /* 当前设备保活应答包数量, 根据service不同, 可能某些业务故意不回复应答, 导致request并不一定等于reply */	
	int fs2_line_id;
	time_t last_time; /* 当前设备最后一次收到保活包的时间 */	
	gdev_keepalive_status_per_service_t service_array[MAX_VXLAN_SERVICE_NUM]; /* 仅BFD协议可以区分service, ICMP默认都用0号业务 */
}gdev_keepalive_status_per_dev_t;



struct _gdev_keepalive_status_per_thread{
	gdev_keepalive_status_per_dev_t gdev_array[MAX_SUPPORT_GDEV_NUM];
}__attribute__ ((aligned (64)));

typedef struct _gdev_keepalive_status_per_thread gdev_keepalive_status_per_thread_t;


/*
	说明:  gdev的保活状态用了一个超大数组, 因为事先不知道数量, 

	那为什么不用hash? 链表? 动态数组? 

	整体模式是多个线程写, 一个线程读取并集中输出, 如果是动态的数据结构, 免不了要加锁, 
	使用数组事先分配好最大内存, 靠标志位inuse_flag表示是否已使用, 保证读写不冲突.
*/
static gdev_keepalive_status_per_thread_t GDEV_KEEPALIVE_STAT[MAX_THREAD_NUM];

static void *gdev_keepalive_fs2_handle;
static volatile int g_dev_keepalive_flag = 1; /* 全局保活标志, 所有插件都不保活或者重要插件崩溃的情况 */


static volatile struct gdev_keepalive_service_ctrl g_dev_keepalive_service_ctrl_array[MAX_VXLAN_SERVICE_NUM];/* 控制某类业务号是否保活  */ 

//extern int g_packet_io_thread_num;
//extern time_t g_CurrentTime;
static int g_dev_keepalive_default_action = 1; /* 对于g_dev_keepalive_service_ctrl_array里没有的业务号, 是保活还是不保活 */
static unsigned int sendto_gdev_card_ip; /* 与Gdev连接网卡的IP地址, 网络序, network-order */
extern int sendpacket_build_icmpv4_echo(u_int8_t type, u_int8_t code, u_int16_t sum,
	u_int16_t id, u_int16_t seq, u_int8_t *payload, u_int32_t payload_s, unsigned char *buf);
extern char *timet_to_str(time_t timet, char *time_str, int time_str_len);
static int vxlan_sport_service_map_init(void);
extern void del_last_rn(char *data, int max_len);
static unsigned char g_vxlan_sport_to_service_id[65536]; /* 数组下标为源端口, 值为service-id, 理论最大值是65535 */


static int gdev_kp_action_judge(int service_id)
{
	if(0 == g_dev_keepalive_flag){
		return 0;
	}
	
	return g_dev_keepalive_service_ctrl_array[service_id].keepalive_switch;
}


/*
	prometheus fs2 line名称不能包括这些字符:
	const char* reserverd="|:\n\r. \t<>[]#!@";

	所以ip地址的分隔符需要改成'_'
*/
static const char *fs2_inet_ntop(unsigned int gip_net, char *buf, int buf_len)
{
	const unsigned char *ip_char_array = (unsigned char *)&gip_net;
	
	snprintf(buf, buf_len, "%u_%u_%u_%u", ip_char_array[0], ip_char_array[1],ip_char_array[2], ip_char_array[3]);

	return buf;
}


static int gdev_keepalive_dynamic_register_fs2_line(gdev_keepalive_status_per_dev_t *cur_dev_stat, unsigned int gip_net)
{
	char ip_fs2_string[INET6_ADDRSTRLEN];

	fs2_inet_ntop(gip_net, ip_fs2_string, sizeof(ip_fs2_string));
	
	cur_dev_stat->fs2_line_id = FS_register(gdev_keepalive_fs2_handle, FS_STYLE_LINE, FS_CALC_SPEED, ip_fs2_string);

	return 0;
}


static void gdev_keepalive_stat_update(int tid, unsigned int gip_net, int type, int service_id, int action)
{
	gdev_keepalive_status_per_thread_t *cur_thread_stat = &GDEV_KEEPALIVE_STAT[tid];
	int bingo = 0, index;

	for(index = 0; index < MAX_SUPPORT_GDEV_NUM; index++){
		if((1 == cur_thread_stat->gdev_array[index].inuse_flag)
		 && (gip_net == cur_thread_stat->gdev_array[index].gdev_ip_network_order)){
		 	bingo = 1;
			break;
		}
	}

	/* not found this inline device */
	if(0 == bingo){
		/* search a empty place */
		for(index = 0; index < MAX_SUPPORT_GDEV_NUM; index++){
			if(0 == cur_thread_stat->gdev_array[index].inuse_flag){
				cur_thread_stat->gdev_array[index].inuse_flag = 1;
				break;
			}
		}

		if(index >= MAX_SUPPORT_GDEV_NUM){
			MESA_handle_runtime_log(gdev_kp_log_handle, RLOG_LV_FATAL, "[gdev_keepalive]", 
									"Too many inline devices, max support: %d!\n", MAX_SUPPORT_GDEV_NUM);
			return;
		}	

		/* 当前设备ip首次发现, 动态注册到fs2 */
		gdev_keepalive_dynamic_register_fs2_line(&cur_thread_stat->gdev_array[index], gip_net);
	}

	if(service_id < 0 || service_id >= MAX_VXLAN_SERVICE_NUM){
		MESA_handle_runtime_log(gdev_kp_log_handle, RLOG_LV_INFO, "[gdev_keepalive]", 
								"invalid service num: %d!\n", service_id);	
		return;
	}

	/* update this device */
	cur_thread_stat->gdev_array[index].inuse_flag = 1;
	cur_thread_stat->gdev_array[index].gdev_ip_network_order = gip_net;
	cur_thread_stat->gdev_array[index].last_time = g_CurrentTime;
	cur_thread_stat->gdev_array[index].keepalive_request_num++;
	cur_thread_stat->gdev_array[index].keepalive_reply_num++;

	/* update by service */
	cur_thread_stat->gdev_array[index].service_array[service_id].gdev_keepalive_type = type;
	cur_thread_stat->gdev_array[index].service_array[service_id].keepalive_request_num++;
	if(action){
		cur_thread_stat->gdev_array[index].service_array[service_id].keepalive_reply_num++;
	}
	cur_thread_stat->gdev_array[index].service_array[service_id].last_time = g_CurrentTime;
	
	return;
}

/* 特殊设备保活函数，BFD协议 */
static int gdev_keepalive_bfd_plug(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
{
	char payload_buf[1472];
	struct mesa_ethernet_hdr *raw_eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)((char *)raw_eth_hdr+ SENDPACKET_ETH_H);
	struct mesa_udp_hdr *udp_hdr = (struct mesa_udp_hdr *)((char *)raw_eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4);
	bfd_header_t *bfd_net_hdr = (bfd_header_t *)((char *)raw_eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4 + SENDPACKET_UDP_H);
	bfd_header_t *bfd_send_hdr = (bfd_header_t *)payload_buf;
	char bfd_buf[4];
	int payload_len = ntohs(udp_hdr->uh_ulen) - SENDPACKET_UDP_H;
	int service_id = 0;
	int action;
	
#if 0	 /* 做为UDP插件, 在gdev_bfd_pkt_identify已经判断过, 无需再次判断 */
	if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
		return -1;
	}

	if(ip_hdr->ip_p != IPPROTO_UDP){
		return -1;
	}

	if(ntohs(udp_hdr->uh_dport) != BFD_DEFAULT_PORT){
		return -1;
	}

	if(memcmp(&ip_hdr->ip_dst.s_addr, &sendto_gdev_card_ip, sizeof(int)) != 0){
		return -1;
	}

	if(payload_len != (int)sizeof(bfd_header_t)){
		return -1;
	}
#endif

	service_id = vxlan_sport_map_to_service_id(ntohs(udp_hdr->uh_sport));
	action = gdev_kp_action_judge(service_id);

	/* 即使action=0, stat_update也要更新, 还要统计不回复保活的业务信息 */	
	gdev_keepalive_stat_update(thread_id, ip_hdr->ip_src.s_addr, GDEV_KEEPALIVE_TYPE_BFD, service_id, action);
	if(0 == action){
		return -1;
	}
	
	/* 获取不到service_id, 或者应该回复保活应答, go on !! */

	memcpy(payload_buf, bfd_net_hdr, payload_len);

	// passive bfdd, DOWN->INIT, UP->UP
	if (bfd_send_hdr->state == BFD_MSG_FLAGS_DOWN)
	{
		//DOWN->INIT
		bfd_send_hdr->state = BFD_MSG_FLAGS_INIT;
		// set keep_alive ip as discriminator
		// memcpy(bfd_send_hdr->your_discriminator, &ip_hdr->ip_dst.s_addr, 4);
	}
	// swap discriminator
	memcpy(bfd_buf, bfd_send_hdr->my_discriminator, 4);
	memcpy(bfd_send_hdr->my_discriminator, bfd_send_hdr->your_discriminator, 4);
	memcpy(bfd_send_hdr->your_discriminator, bfd_buf, 4);

	sendpacket_build_ethernet(raw_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, ETH_P_IP, NULL, 0, send_buf);

	sendpacket_build_udp_dual_stack(ntohs(udp_hdr->uh_sport), /* BFD协议不交换源和目的端口 */
						 ntohs(udp_hdr->uh_dport),
						 (char *)bfd_send_hdr,
						 payload_len,
						 payload_len,
						 send_buf + SENDPACKET_ETH_H + SENDPACKET_IP_H);
	
    sendpacket_build_ipv4(SENDPACKET_UDP_H + payload_len,
    					  0, 
    					  ntohs(ip_hdr->ip_id),
    					  ntohs(ip_hdr->ip_off), 
    					  ip_hdr->ip_ttl, 
    					  IPPROTO_UDP, 
    					  ip_hdr->ip_dst.s_addr,
    					  ip_hdr->ip_src.s_addr, /* 交换源、目的IP地址 */
    					  NULL, 0, 
    					  send_buf + SENDPACKET_ETH_H);

    sendpacket_do_checksum(send_buf + SENDPACKET_ETH_H,
    					   IPPROTO_IP, 
    					   SENDPACKET_IP_H);
				   
    sendpacket_do_checksum(send_buf + SENDPACKET_ETH_H,
    					   IPPROTO_UDP, 
    					   payload_len + SENDPACKET_UDP_H);


	return SENDPACKET_IP_H + SENDPACKET_UDP_H+sizeof(bfd_header_t) + sizeof(struct mesa_ethernet_hdr);	
}

/* 特殊设备保活函数，BFD协议 */
static int gdev_keepalive_icmp_plug(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
{
	struct mesa_ethernet_hdr *raw_eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)((char *)raw_eth_hdr + SENDPACKET_ETH_H);
	struct mesa_icmp_echo_hdr *icmp_hdr = (struct mesa_icmp_echo_hdr *)((char *)raw_eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4);
	unsigned char *icmp_payload;
	int icmp_payload_len;

	gdev_keepalive_stat_update(thread_id, ip_hdr->ip_src.s_addr, GDEV_KEEPALIVE_TYPE_ICMP, 0, g_dev_keepalive_default_action);

	icmp_payload = (unsigned char *)icmp_hdr + sizeof(struct mesa_icmp_echo_hdr);
	icmp_payload_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4 - sizeof(struct mesa_icmp_echo_hdr);

	sendpacket_build_ethernet(raw_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, ETH_P_IP, NULL, 0, send_buf);

	sendpacket_build_icmpv4_echo(ICMP_ECHOREPLY, 0, 0, 
                                 ntohs(icmp_hdr->icd_id),
                                 ntohs(icmp_hdr->icd_seq),
                                 icmp_payload,
                                 icmp_payload_len,
                                 send_buf + SENDPACKET_ETH_H + SENDPACKET_IP_H);

    sendpacket_build_ipv4(icmp_payload_len + sizeof(struct mesa_icmp_echo_hdr),
    					  0, 0x1234, 0, 64, IPPROTO_ICMP, 
    					  ip_hdr->ip_dst.s_addr,
    					  ip_hdr->ip_src.s_addr,
    					  NULL, 0, 
    					  send_buf + SENDPACKET_ETH_H);
    	memcpy(send_buf + SENDPACKET_ETH_H+SENDPACKET_IP_H+sizeof(struct mesa_icmp_echo_hdr), 	
    	   	     icmp_payload,
    	   	     icmp_payload_len);
    	   	     

    sendpacket_do_checksum(send_buf + SENDPACKET_ETH_H,
    					   IPPROTO_IP, 
    					   SENDPACKET_IP_H);
    					   
    sendpacket_do_checksum(send_buf + SENDPACKET_ETH_H,
    					   IPPROTO_ICMP, 
    					   icmp_payload_len + sizeof(struct mesa_icmp_echo_hdr));

	return ntohs(ip_hdr->ip_len) + sizeof(struct mesa_ethernet_hdr);	
}


static int gdev_keepalive_plug(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, int keepalive_type)
{
	int ret = -1, send_len;
	MESA_send_handle *snd_handle = NULL;
#if IOMODE_MARSIO	
	const struct mesa_ethernet_hdr *raw_eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_ethernet_hdr *snd_eth_hdr;
#endif	

	snd_handle = packet_io_get_send_handle(thread_id);
	if(NULL == snd_handle){
		return -1;
	}
	snd_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_id);
	if(NULL == snd_handle->send_buf){
		return 0;
	}

	switch(keepalive_type){
		case GDEV_KEEPALIVE_TYPE_BFD:
			send_len = gdev_keepalive_bfd_plug(raw_pkt, thread_id, dir, snd_handle->send_buf);
			if(send_len < 0){
				goto err;
			}
		break;

		case GDEV_KEEPALIVE_TYPE_ICMP:
			send_len = gdev_keepalive_icmp_plug(raw_pkt, thread_id, dir, snd_handle->send_buf);
			if(send_len < 0){
				goto err;
			}
		break;

		default:
			return -1;
	}

#if 0
	snd_eth_hdr = 	(struct mesa_ethernet_hdr *)snd_handle->send_buf;
	memcpy(snd_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
	memcpy(snd_eth_hdr->ether_dhost, raw_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	snd_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);

	///MESA_sendpacket_ethlayer(thread_id, (char *)snd_handle->send_buf, send_len + 14, 0);
	
	marsio_buff_t *send_mbuf[1];
	char *real_buf;

	ret = ptr_marsio_buff_malloc_global(gdev_plug_extern_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_id);
	if(ret < 0){
		goto err;
	}

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = ptr_marsio_buff_append(send_mbuf[0], send_len + 14);
	if(NULL == real_buf){
		ptr_marsio_buff_free(gdev_plug_extern_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_id);
		goto err;
	}
	
	memcpy(real_buf, snd_handle->send_buf, send_len + 14); /* send_len没包括mac地址 */

	ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, 
								thread_id, send_mbuf, 1, MARSIO_SEND_OPT_FAST);
	/* mbuf 发送完后自动释放 */							
#else
	ret = packet_io_send(snd_handle, send_len, SEND_TYPE_LINK_INJECT, 
						__ADDR_TYPE_IP_PAIR_V4, dir, thread_id,
						(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, raw_pkt);	

#endif

    packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_id);
    return ret;

err:
    packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_id);
    return -1;
}

/* 在大量UDP包中, 快速识别哪些可能是BFD保活包 */
static inline int gdev_bfd_pkt_identify(const struct streaminfo *a_udp)
{
	if(g_topology_mode != NET_CONN_SERIAL_GDEV){ /* 非G串联模式 */
		return 0;
	}

	if((sendto_gdev_card_ip != a_udp->addr.tuple4_v4->daddr)
	  && (sendto_gdev_card_ip != a_udp->addr.tuple4_v4->saddr)){
		return 0;
	}

	if(BFD_DEFAULT_PORT != ntohs(a_udp->addr.tuple4_v4->dest)){
		return 0;
	}
	
	if(ADDR_TYPE_IPV4 != a_udp->addr.addrtype){ /* 目前仅处理IPv4 */
		return 0;
	}

	if(a_udp->pudpdetail->datalen != (int)sizeof(bfd_header_t)){
		return 0;
	}
	
	return 1;
}


static long _gdev_keepalive_rcv_pps;
static long _gdev_keepalive_snd_pps;

static void __gdev_keepalive_pkt_calc_pps(void)
{
	static long _last_rcv_num, _last_snd_num;
	long rcv_sum = 0;
	long snd_sum = 0;
	int tid, dev_num;
	
	for(tid = 0; tid < g_packet_io_thread_num; tid++){
		for(dev_num = 0; dev_num < MAX_SUPPORT_GDEV_NUM; dev_num++){
			if(GDEV_KEEPALIVE_STAT[tid].gdev_array[dev_num].inuse_flag != 0){
				rcv_sum += GDEV_KEEPALIVE_STAT[tid].gdev_array[dev_num].keepalive_request_num;
				snd_sum += GDEV_KEEPALIVE_STAT[tid].gdev_array[dev_num].keepalive_reply_num;
			}
		}
	}

	_gdev_keepalive_rcv_pps = rcv_sum - _last_rcv_num;
	_gdev_keepalive_snd_pps = snd_sum - _last_snd_num;

	_last_rcv_num = rcv_sum;
	_last_snd_num = snd_sum;

	return;
}


static void gdev_keepalive_update_local_log(void)
{
	FILE *gdev_status_fp;
	int dev_index, thread_seq, service_index;
	int platform_thread_num;
	char cur_time_str[64];
	char tmp_ip_str[INET6_ADDRSTRLEN];
	const char *tmp_keealive_type;
	time_t last_op_time;
	const gdev_keepalive_status_per_thread_t *this_thread_stat;
	const gdev_keepalive_status_per_dev_t *this_dev_stat;
	
	gdev_status_fp = fopen(ABBR_INLINE_KEEPALIVE_LOG_DATA_FILE, "w+");
	if(NULL == gdev_status_fp){
		return;
	}
	
	platform_thread_num = get_thread_count();
	timet_to_str(time(NULL), cur_time_str, 64);
	fprintf(gdev_status_fp, "%-20s %-16s %-11s %-5s %-5s %-16s %-16s\n", 
						"Last-update-time", "Gdev-ip", "Service-Num", "Ctrl", "Type", "Rcv-pkt", "Snd-pkt");
	
	for(thread_seq = 0; thread_seq < platform_thread_num; thread_seq++)
	{			
		this_thread_stat = &GDEV_KEEPALIVE_STAT[thread_seq];
		
		for(dev_index = 0; dev_index < MAX_SUPPORT_GDEV_NUM; dev_index++){
			if(0 == this_thread_stat->gdev_array[dev_index].inuse_flag){
				continue;
			}

			this_dev_stat = &this_thread_stat->gdev_array[dev_index];
			inet_ntop(AF_INET, &this_dev_stat->gdev_ip_network_order, tmp_ip_str, sizeof(tmp_ip_str));

			for(service_index = 0; service_index < MAX_VXLAN_SERVICE_NUM; service_index++){
				if(this_dev_stat->service_array[service_index].keepalive_request_num > 0){
					if(GDEV_KEEPALIVE_TYPE_ICMP == this_dev_stat->service_array[service_index].gdev_keepalive_type){
						tmp_keealive_type = "ICMP";
					}else if(GDEV_KEEPALIVE_TYPE_BFD == this_dev_stat->service_array[service_index].gdev_keepalive_type){
						tmp_keealive_type = "BFD";
					}else{
						tmp_keealive_type = "Unknown";
					}

	
					fprintf(gdev_status_fp, "%-20s %-16s %-11d %-5d %-5s %-16u %-16u\n",
							cur_time_str,
							tmp_ip_str,
							service_index, 
							gdev_kp_action_judge(service_index),
							tmp_keealive_type,
							this_dev_stat->service_array[service_index].keepalive_request_num,
							this_dev_stat->service_array[service_index].keepalive_reply_num);					
				}
			}
			
		}
	}
	
	fclose(gdev_status_fp);

}




static void gdev_keepalive_update_fs2(void)
{
	const gdev_keepalive_status_per_thread_t *this_thread_stat;
	const gdev_keepalive_status_per_dev_t *this_dev_stat;
	int dev_index, thread_seq, service_index;
	int platform_thread_num;
	
	platform_thread_num = get_thread_count();
	
	for(thread_seq = 0; thread_seq < platform_thread_num; thread_seq++)
	{			
		this_thread_stat = &GDEV_KEEPALIVE_STAT[thread_seq];
		
		for(dev_index = 0; dev_index < MAX_SUPPORT_GDEV_NUM; dev_index++){
			if(0 == this_thread_stat->gdev_array[dev_index].inuse_flag){
				continue;
			}
			this_dev_stat = &this_thread_stat->gdev_array[dev_index];
			
			FS_operate(gdev_keepalive_fs2_handle, this_dev_stat->fs2_line_id, gdev_keepalive_fs2_column_id_array[FS2_COLUMN_REQUEST_NUM], FS_OP_SET, this_dev_stat->keepalive_request_num);
			FS_operate(gdev_keepalive_fs2_handle, this_dev_stat->fs2_line_id, gdev_keepalive_fs2_column_id_array[FS2_COLUMN_REPLY_NUM], FS_OP_SET, this_dev_stat->keepalive_reply_num);
		}
	}

}


static void gdev_keepalive_clear_stat(void)
{
	int platform_thread_num, dev_index, thread_seq, service_index;
	gdev_keepalive_status_per_thread_t *this_thread_stat;
	gdev_keepalive_status_per_dev_t *this_dev_stat;

	platform_thread_num = get_thread_count();
	for(thread_seq = 0; thread_seq < platform_thread_num; thread_seq++){			
		this_thread_stat = &GDEV_KEEPALIVE_STAT[thread_seq];
			
		for(dev_index = 0; dev_index < MAX_SUPPORT_GDEV_NUM; dev_index++){
			if(0 == this_thread_stat->gdev_array[dev_index].inuse_flag){
				continue;
			}

			this_dev_stat = &this_thread_stat->gdev_array[dev_index];

			this_dev_stat->keepalive_request_num = 0;
			this_dev_stat->keepalive_reply_num = 0;

#if 0 /* 先不支持淘汰, 因为当前设备的line_id已经注册到fs2, 重新使用的话, name无法更新 */
			if(this_dev_stat->last_time + MAX_NO_PKT_TIMEOUT < g_CurrentTime){
				char dev_ip_str[INET6_ADDRSTRLEN];
				this_dev_stat->inuse_flag = 0;
				inet_ntop(AF_INET, &this_dev_stat->gdev_ip_network_order, dev_ip_str, sizeof(dev_ip_str));
				MESA_handle_runtime_log(gdev_kp_log_handle, RLOG_LV_INFO, "[gdev_keepalive]", " %s timeout, delete it.\n", dev_ip_str);
			} 
#endif
			for(service_index = 0; service_index < MAX_VXLAN_SERVICE_NUM; service_index++){
				if(this_dev_stat->service_array[service_index].keepalive_request_num > 0){
					this_dev_stat->service_array[service_index].keepalive_request_num = 0;
					this_dev_stat->service_array[service_index].keepalive_reply_num = 0;
				}
			}
		}
	}
}


static void *gdev_keepalive_log_thread(void *arg)
{
	time_t last_op_time = time(NULL);

	MESA_mkdir_p(sapp_global_val->config.data_file_path.data_files_root_dir, 0755);

	while(sapp_get_current_state() < SAPP_STATE_PROCESSING){
		sapp_usleep(100);
	}
	
	while(sapp_get_current_state() == SAPP_STATE_PROCESSING){
		while(last_op_time == time(NULL)){
			sapp_usleep(100);
		}
		last_op_time = time(NULL);
		__gdev_keepalive_pkt_calc_pps();
		gdev_keepalive_update_local_log();
		gdev_keepalive_update_fs2();
		//gdev_keepalive_clear_stat(); /* 每秒清空计数, 只计算一段时间的增量 */
	}

	return NULL;
}

static int gdev_kp_update_service_ctrl(const struct gdev_keepalive_service_ctrl *service_ctrl)
{
	if((service_ctrl->service_num < 0) || (service_ctrl->service_num >= MAX_VXLAN_SERVICE_NUM)){
		return -1;
	}
	
	g_dev_keepalive_service_ctrl_array[service_ctrl->service_num].keepalive_switch = service_ctrl->keepalive_switch;
	
	return 0;
}



/* vxlan特殊环境下, vpn-id, 源端口和业务ID之间的关系, 配置文件格式:

	service-id	VPN-id	Sport-range
	1			101		50000-50016
	2			102		50064-50080
	......

	用于告知上层应用业务号, 和处理哪类业务是否需要保活.
*/


static int vxlan_sport_service_map_update(int service_id, unsigned short begin_sport_host, unsigned short end_sport_host)
{
	unsigned short i;

	for(i = begin_sport_host; i <= end_sport_host;i++){
		g_vxlan_sport_to_service_id[i] = service_id;
		g_dev_keepalive_service_ctrl_array[service_id].keepalive_switch = 1;
	}

	return 0;
}

static int vxlan_sport_service_map_init(void)
{
	char line_buf[1024];
	FILE *fp;
	int tmp_service_id, tmp_int;
	const char *delim = "\t- ";
	char *save_ptr;
	char *section;
	unsigned short begin_sport, end_sport;

	fp = fopen(ABBR_VXLAN_SPORT_MAP_CONF_FILE, "r");
	if(NULL == fp){
		MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "open vxlan sport map file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
		return -1;
	}

	while(fgets(line_buf, 1024, fp) != NULL){
		if('#' == line_buf[0]){
			continue;
		}
		del_last_rn(line_buf, 1024);

		/* service-id */
		section = strtok_r(line_buf, delim, &save_ptr);
		if(NULL == section){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
			goto done;
		}
		tmp_service_id = atoi(section);

		/* VPN-id, 暂时不用转换, 直接减100即是业务号 */
		section = strtok_r(NULL, delim, &save_ptr);
		if(NULL == section){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
			goto done;
		}

		/* begin-port */
		section = strtok_r(NULL, delim, &save_ptr);
		if(NULL == section){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
			goto done;
		}
		tmp_int = atoi(section);
		if(tmp_int <= 0 || tmp_int > 65535){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
			goto done;
		}
		begin_sport = (unsigned short)tmp_int;

		/* end-port */
		section = strtok_r(NULL, delim, &save_ptr);
		if(NULL == section){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
			goto done;
		}	
		tmp_int = atoi(section);
		if(tmp_int <= 0 || tmp_int > 65535){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
			goto done;
		}	
		end_sport = (unsigned short)tmp_int;

		if(end_sport < begin_sport){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPORT_MAP_CONF_FILE);
			goto done;
		}

		while(strtok_r(NULL, delim, &save_ptr));

		vxlan_sport_service_map_update(tmp_service_id, begin_sport, end_sport);
	}

done:
	fclose(fp);
	
	return 0;
}


static int gdev_keepalive_fs2_init(void)
{
	int fs2_opt;
	unsigned short fs_server_port;
	
	gdev_keepalive_fs2_handle = FS_create_handle();

	/*
		prometheus相关的配置, 由  	   sapp_fs2_init() 初始化.
	*/

	fs2_opt = sapp_global_val->config.profiling.log.interval;
	FS_set_para(gdev_keepalive_fs2_handle, STAT_CYCLE, &fs2_opt, sizeof(int));	

	fs2_opt = 1; /* 1:Rewrite ,2: Append.  */
	FS_set_para(gdev_keepalive_fs2_handle, PRINT_MODE, &fs2_opt, sizeof(int));

	fs2_opt = 1;
	FS_set_para(gdev_keepalive_fs2_handle, PRINT_TRIGGER, &fs2_opt, sizeof(int));

	if(sapp_global_val->config.profiling.log.local.enabled){
		FS_set_para(gdev_keepalive_fs2_handle, OUTPUT_DEVICE, "./fs2_inline_keepalive.log", strlen("./fs2_inline_keepalive.log") + 1); 
	}
	
	FS_set_para(gdev_keepalive_fs2_handle, APP_NAME, "keepalive", strlen("keepalive")+1);

	if(sapp_global_val->config.profiling.log.remote.enabled){
		FS_set_para(gdev_keepalive_fs2_handle, STATS_SERVER_IP, (void *)sapp_global_val->config.profiling.log.remote.server_ip, strlen(sapp_global_val->config.profiling.log.remote.server_ip)+1);
		fs_server_port = (unsigned short)sapp_global_val->config.profiling.log.remote.server_port;
		FS_set_para(gdev_keepalive_fs2_handle, STATS_SERVER_PORT, &fs_server_port, sizeof(short));
	}

	if(sapp_global_val->config.profiling.log.prometheus.enabled){
		fs2_opt = 1;
		FS_set_para(gdev_keepalive_fs2_handle, OUTPUT_PROMETHEUS, &fs2_opt, sizeof(int));
	}

	/* 先注册列, 初始化后固定不变, 行以ip为单位动态注册, gdev_keepalive_dynamic_register_fs2_line() */
	gdev_keepalive_fs2_column_id_array[FS2_COLUMN_REQUEST_NUM] = FS_register(gdev_keepalive_fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, "req_pkt");
	gdev_keepalive_fs2_column_id_array[FS2_COLUMN_REPLY_NUM] = FS_register(gdev_keepalive_fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, "rpy_pkt");

	FS_start(gdev_keepalive_fs2_handle);

	return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

/* 用来检测vxlan模式下, 数据包是否给本机的 */
int vxlan_packet_is_myself(const raw_pkt_t *rawpkt)
{
	struct mesa_ip4_hdr *ip4h = (struct mesa_ip4_hdr *)((char *)rawpkt->raw_pkt_data + sizeof(struct mesa_ethernet_hdr));

	if(sendto_gdev_card_ip == ip4h->ip_dst.s_addr){
		return 1;
	}

	return 0;
}


unsigned char vxlan_sport_map_to_service_id(unsigned short sport_host_order)
{
	return g_vxlan_sport_to_service_id[sport_host_order];
}

unsigned char vxlan_id_map_to_service_id(int vxlan_id)
{
	return (unsigned char)(vxlan_id - 100);
}


int gdev_keepalive_set_opt(const SAPP_TLV_T *tlv_value)
{
	int ret = 0;
	static time_t last_log_time = 0;

	if((NULL == tlv_value) || (tlv_value->length <= 0)){
		return -1;
	}
	
	switch(tlv_value->type){
		case GDEV_KEEPALIVE_OPT_SERVICE_CTRL:
		{
			if(tlv_value->length != sizeof(struct gdev_keepalive_service_ctrl)){
				return -1;
			}
			const struct gdev_keepalive_service_ctrl *actual_val = (const struct gdev_keepalive_service_ctrl *)tlv_value->ptr_value;
			
			ret = gdev_kp_update_service_ctrl(actual_val);
			if(ret < 0){
				if(last_log_time < g_CurrentTime){
					last_log_time = g_CurrentTime;
					MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "set gdev-keepalive error! service:%d, action:%d", 
										   actual_val->service_num, actual_val->keepalive_switch);
				}					   
			}else{
				if(last_log_time < g_CurrentTime){
					last_log_time = g_CurrentTime;
					MESA_handle_runtime_log(gdev_kp_log_handle, 10, "[gdev_keepalive]", "set gdev-keepalive, service:%d, action:%d", 
										   actual_val->service_num, actual_val->keepalive_switch);
				}
			}
		}
		break;

		case GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH:
		{
			if(tlv_value->length != sizeof(int)){
				return -1;
			}
			g_dev_keepalive_flag = tlv_value->int_value;
			if(last_log_time < g_CurrentTime){
				MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "set global keepalive to %d", tlv_value->int_value);
				last_log_time = g_CurrentTime;
			}
		}
		break;

		default:
			ret = -2;
		break;
	}

	return ret;
}

int gdev_keepalive_get_opt(SAPP_TLV_T *tlv_value)
{
	int ret = 0;

	if((NULL == tlv_value) || (tlv_value->length <= 0)){
		return -1;
	}
	
	switch(tlv_value->type){
	
		case GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH:
		{
			tlv_value->int_value = g_dev_keepalive_flag;
		}
		break;

		case GDEV_KEEPALIVE_OPT_RCV_PKT_PPS:
		{
			tlv_value->long_value = _gdev_keepalive_rcv_pps;
		}
		break;

		case GDEV_KEEPALIVE_OPT_SND_PKT_PPS:
		{
			tlv_value->long_value = _gdev_keepalive_snd_pps;
		}
		break;
		
		default:
			ret = -1;
		break;
	}

	return ret;
}


char gdev_keepalive_udp_entry(const struct streaminfo *a_udp,  void **pme, int thread_seq, const void *ip_hdr)
{
	int entry_ret = APP_STATE_GIVEME;
	int kp_ret;
	const struct streaminfo_private *a_udp_pr;

	if(OP_STATE_PENDING == a_udp->opstate){
		if(0 == gdev_bfd_pkt_identify(a_udp)){
			return APP_STATE_DROPME;
		}
	}else if(OP_STATE_CLOSE == a_udp->opstate){
		return APP_STATE_DROPME;
	}

	a_udp_pr = (const struct streaminfo_private *)a_udp;
	kp_ret = gdev_keepalive_plug(a_udp_pr->raw_pkt, a_udp->threadnum, a_udp->routedir, GDEV_KEEPALIVE_TYPE_BFD);
	if(kp_ret < 0){
		/* 因网络, socket等错误不能返回APP_STATE_DROPME, 否则DROP ME后再也拿不到保活请求包, 但是插件可以通过gdev_keepalive_set_opt()关闭保活功能, 还是要返回DROPPKT, 不能把请求包回注 */
		entry_ret = APP_STATE_GIVEME | APP_STATE_DROPPKT; 
	}else{
		entry_ret = APP_STATE_GIVEME | APP_STATE_DROPPKT; /* 保活包, 丢弃当前包 */
	}

	return entry_ret;
}


char gdev_keepalive_ip_entry(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const struct mesa_ip4_hdr *ipv4_hdr)
{
	const struct mesa_icmp_echo_hdr *icmp_hdr;
	const struct streaminfo_private *pstream_pr;
	int entry_ret = APP_STATE_GIVEME;
	int kp_ret;
	
	if(ipv4_hdr->ip_p != IPPROTO_ICMP){
		return APP_STATE_DROPME;
	}

	if(ipv4_hdr->ip_dst.s_addr != sendto_gdev_card_ip){
		return APP_STATE_DROPME;
	}

	icmp_hdr = (struct mesa_icmp_echo_hdr *)((char *)ipv4_hdr + ipv4_hdr->ip_hl*4);
	if(icmp_hdr->icmp_type != ICMP_ECHO){
		return APP_STATE_DROPME;
	}

	pstream_pr = (const struct streaminfo_private *)pstream;
	kp_ret = gdev_keepalive_plug(pstream_pr->raw_pkt, thread_seq, pstream->routedir, GDEV_KEEPALIVE_TYPE_ICMP);
	if(kp_ret < 0){
		entry_ret = APP_STATE_DROPME | APP_STATE_DROPPKT;
	}else{
		entry_ret = APP_STATE_GIVEME | APP_STATE_DROPPKT; /* 保活包, 丢弃当前包 */
	}
	
	return entry_ret;
}


int gdev_keepalive_plug_init(void)
{
	char tmp_ip_buf[16];
	char deploy_mode_string[32];
	int opt_len;
	int i;
#if 0
	gdev_kp_log_handle = MESA_create_runtime_log_handle("./log/gdev_keeplive.log", 10);
#else
	/* 2020-12-23 保活插件内置, 此处复用sapp的log_handle, 靠module名称区别, 不再单独写文件了 */
	gdev_kp_log_handle = sapp_global_val->individual_fixed.log_handle;
#endif

#ifdef GIT_VERSION
	MESA_handle_runtime_log(gdev_kp_log_handle, 30, "[gdev_keepalive]", "g_device_plug version: %s\n", g_device_plug_git_ver);	
#endif

	/* 多线程模式下伪共享问题, 64B缓存对齐 */
	assert(sizeof(gdev_keepalive_status_per_thread_t) % 64 == 0);

	opt_len = sizeof(deploy_mode_string);
	if(sapp_get_platform_opt(SPO_DEPLOYMENT_MODE_STR, (void *)deploy_mode_string, &opt_len) < 0){
		MESA_handle_runtime_log(gdev_kp_log_handle, 30, "[gdev_keepalive]", 
								"can't get sapp deployment mode!\n");	
		return -1;
	}

	if(strncasecmp(deploy_mode_string, "inline", strlen("inline")) != 0){ /* 非G串联模式 */
		MESA_handle_runtime_log(gdev_kp_log_handle, 30, "[gdev_keepalive]", "not inline mode, can't load gdev_keepalive.so\n");
		return -1;
	}

	memset(g_vxlan_sport_to_service_id, 0, sizeof(g_vxlan_sport_to_service_id));

	memset(tmp_ip_buf, 0, 16);
	MESA_load_profile_string_nodef((char *)ABBR_INLINE_DEV_CONF_FILE, (char *)"Module", (char *)"sendto_gdev_ip", tmp_ip_buf, 16);
	if(tmp_ip_buf[0] == '\0'){
		MESA_handle_runtime_log(gdev_kp_log_handle, 30, "[gdev_keepalive]","can't get 'sendto_gdev_ip'");
		return -1;
	}

	inet_pton(AF_INET, tmp_ip_buf, &sendto_gdev_card_ip);

	MESA_load_profile_int_def((char *)ABBR_INLINE_DEV_CONF_FILE, (char *)"Module", (char *)"default_keepalive_action", &g_dev_keepalive_default_action, 1);
	///MESA_load_profile_int_def((char *)ABBR_INLINE_DEV_CONF_FILE, (char *)"Module", (char *)"gdev_status_switch", &GDEV_KEEPALIVE_LOG_SWITCH, 1);


	for(i = 0; i <  MAX_VXLAN_SERVICE_NUM; i++){
		g_dev_keepalive_service_ctrl_array[i].service_num = i;
		g_dev_keepalive_service_ctrl_array[i].keepalive_switch = g_dev_keepalive_default_action;
	}

	vxlan_sport_service_map_init();

	if(gdev_keepalive_fs2_init() < 0){
		return -1;
	}

	pthread_create(&sapp_global_val->individual_fixed.gdev_keepalive_log_thread_id, NULL, gdev_keepalive_log_thread, NULL);

	return 0;
}


void gdev_keepalive_plug_destroy(void)
{
	if(DEPOLYMENT_MODE_INLINE != sapp_global_val->config.packet_io.depolyment_mode_bin){
		return;
	}

	if(sapp_global_val->individual_fixed.gdev_keepalive_log_thread_id){
		pthread_join(sapp_global_val->individual_fixed.gdev_keepalive_log_thread_id, NULL);
		sapp_global_val->individual_fixed.gdev_keepalive_log_thread_id = 0;
	}

	if(gdev_keepalive_fs2_handle){
		FS_stop(&gdev_keepalive_fs2_handle);
		gdev_keepalive_fs2_handle = NULL;
	}

	memset(GDEV_KEEPALIVE_STAT, 0, sizeof(GDEV_KEEPALIVE_STAT));
	memset((void *)g_dev_keepalive_service_ctrl_array, 0, sizeof(g_dev_keepalive_service_ctrl_array));
	g_dev_keepalive_flag = 1;
	g_dev_keepalive_default_action = 1;
}


#ifdef __cplusplus
}
#endif

