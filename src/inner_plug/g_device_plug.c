#ifdef __cplusplus
extern "C" {
#endif
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

#define MAX_GDEV_STAT_LOG_NUM	(64)

static void *gdev_kp_log_handle;
enum prog_work_mode_t{
	PROG_MODE_MASTER = 1,
	PROG_MODE_SLAVE = 2,
};

typedef struct {
	int active_flag; /* 此IP启用 */
	int gdev_keepalive_type;
	int gdev_keepalive_service_num; /* BFD获取 */
	unsigned int gdev_ip_network_order;
	unsigned int tot_rcv_pkt_num;
	unsigned int tot_snd_pkt_num;
	time_t last_time;
	char __pad__[32]; /* 64byte cache aligned */
}gdev_keepalive_status_t;

static gdev_keepalive_status_t GDEV_KEEPALIVE_STAT[MAX_THREAD_NUM][MAX_GDEV_STAT_LOG_NUM];

static int g_dev_keepalive_flag = 1; /* 全局保活标志, 所有插件都不保活或者重要插件崩溃的情况 */

#define MAX_VXLAN_SERVICE_NUM	(256) /* 目前最大支持255种不同业务 */
static struct gdev_keepalive_service_ctrl g_dev_keepalive_service_ctrl_array[MAX_VXLAN_SERVICE_NUM];/* 控制某类业务号是否保活  */ 

static int GDEV_KEEPALIVE_LOG_SWITCH = 1;

//extern int g_packet_io_thread_num;
//extern time_t g_CurrentTime;
static int g_dev_keepalive_default_action = 1; /* 对于g_dev_keepalive_service_ctrl_array里没有的业务号, 是保活还是不保活 */
static unsigned int sendto_gdev_card_ip; /* 与Gdev连接网卡的IP地址, 网络序, network-order */
extern int sendpacket_build_icmpv4_echo(u_int8_t type, u_int8_t code, u_int16_t sum,
	u_int16_t id, u_int16_t seq, u_int8_t *payload, u_int32_t payload_s, unsigned char *buf);
extern char *timet_to_str(time_t timet, char *time_str, int time_str_len);
static int vxlan_sport_service_map_init(void);
extern void del_last_rn(char *data, int max_len);
static unsigned char g_vxlan_sport_to_service_id[65536]; /* 数组下标为源端口, 值为service-id */


static int gdev_kp_action_judge(int service_id)
{
	if(0 == g_dev_keepalive_flag){
		return 0;
	}
	
	return g_dev_keepalive_service_ctrl_array[service_id].keepalive_switch;
}


static void gdev_keepalive_stat_update(int tid, unsigned int gip_net, int type, int service_id, int action)
{
	int index;

	for(index = 0; index < MAX_GDEV_STAT_LOG_NUM; index++){
		if(0 == GDEV_KEEPALIVE_STAT[tid][index].active_flag){
			break;
		}
		if((gip_net == GDEV_KEEPALIVE_STAT[tid][index].gdev_ip_network_order)
		 &&(service_id == GDEV_KEEPALIVE_STAT[tid][index].gdev_keepalive_service_num)
		 && (type == GDEV_KEEPALIVE_STAT[tid][index].gdev_keepalive_type)){
			GDEV_KEEPALIVE_STAT[tid][index].last_time = g_CurrentTime;
			GDEV_KEEPALIVE_STAT[tid][index].tot_rcv_pkt_num++;
			GDEV_KEEPALIVE_STAT[tid][index].tot_snd_pkt_num += action;
		 	return;
		}
	}

	/* not found, check number */
	if(index >= MAX_GDEV_STAT_LOG_NUM){
		MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", 
								"Too many gdev ip, moren than %d!\n",
								MAX_GDEV_STAT_LOG_NUM);
		return;
	}
	
	GDEV_KEEPALIVE_STAT[tid][index].active_flag = 1;
	GDEV_KEEPALIVE_STAT[tid][index].gdev_keepalive_type = type;
	GDEV_KEEPALIVE_STAT[tid][index].gdev_keepalive_service_num = service_id;
	GDEV_KEEPALIVE_STAT[tid][index].gdev_ip_network_order = gip_net;
	GDEV_KEEPALIVE_STAT[tid][index].tot_rcv_pkt_num = 1;
	GDEV_KEEPALIVE_STAT[tid][index].tot_snd_pkt_num = action;
	GDEV_KEEPALIVE_STAT[tid][index].last_time = g_CurrentTime;
	return;
}

/* 特殊设备保活函数，BFD协议 */
static int gdev_keepalive_bfd_plug(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
{
	char payload_buf[1472];
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)((char *)eth_hdr+ SENDPACKET_ETH_H);
	struct mesa_udp_hdr *udp_hdr = (struct mesa_udp_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4);
	bfd_header_t *bfd_net_hdr = (bfd_header_t *)((char *)eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4 + SENDPACKET_UDP_H);
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

	gdev_keepalive_stat_update(thread_id, ip_hdr->ip_src.s_addr, GDEV_KEEPALIVE_TYPE_BFD, service_id, action);
	
	if(0 == action){
		return -1;
	}	
	/* 获取不到service_id, 或者应该回复保活应答, go on !! */

	memcpy(payload_buf, bfd_net_hdr, payload_len);

	// passive bfdd, DOWN->INIT, UP->UP
	if (bfd_send_hdr->flags == BFD_MSG_FLAGS_DOWN)
	{
		//DOWN->INIT
		bfd_send_hdr->flags = BFD_MSG_FLAGS_INIT;
		// set keep_alive ip as discriminator
		memcpy(bfd_send_hdr->your_discriminator, &ip_hdr->ip_dst.s_addr, 4);
	}
	// swap discriminator
	memcpy(bfd_buf, bfd_send_hdr->my_discriminator, 4);
	memcpy(bfd_send_hdr->my_discriminator, bfd_send_hdr->your_discriminator, 4);
	memcpy(bfd_send_hdr->your_discriminator, bfd_buf, 4);

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


	return SENDPACKET_IP_H + SENDPACKET_UDP_H+sizeof(bfd_header_t);	
}

/* 特殊设备保活函数，BFD协议 */
static int gdev_keepalive_icmp_plug(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
{
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H);
	struct mesa_icmp_echo_hdr *icmp_hdr = (struct mesa_icmp_echo_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4);
	unsigned char *icmp_payload;
	int icmp_payload_len;

	gdev_keepalive_stat_update(thread_id, ip_hdr->ip_src.s_addr, GDEV_KEEPALIVE_TYPE_ICMP, 0, g_dev_keepalive_default_action);

	icmp_payload = (unsigned char *)icmp_hdr + sizeof(struct mesa_icmp_echo_hdr);
	icmp_payload_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4 - sizeof(struct mesa_icmp_echo_hdr);


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

	return ntohs(ip_hdr->ip_len);	
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

#if IOMODE_MARSIO
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
		entry_ret = APP_STATE_GIVEME; /* 因网络, socket等错误不能返回APP_STATE_DROPME, 否则DROP ME后再也拿不到保活请求包 */
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
		entry_ret = APP_STATE_DROPME;
	}else{
		entry_ret = APP_STATE_GIVEME | APP_STATE_DROPPKT; /* 保活包, 丢弃当前包 */
	}
	
	return entry_ret;
}


static long _gdev_keepalive_rcv_pps;
static long _gdev_keepalive_snd_pps;

static void __gdev_keepalive_pkt_calc_pps(void)
{
	static long _last_rcv_num, _last_snd_num;
	long rcv_sum = 0;
	long snd_sum = 0;
	int tid, log_num;
	
	for(tid = 0; tid < g_packet_io_thread_num; tid++){
		for(log_num = 0; log_num < MAX_GDEV_STAT_LOG_NUM; log_num++){
			rcv_sum += GDEV_KEEPALIVE_STAT[tid][log_num].tot_rcv_pkt_num;
			snd_sum += GDEV_KEEPALIVE_STAT[tid][log_num].tot_snd_pkt_num;
		}
	}

	_gdev_keepalive_rcv_pps = rcv_sum - _last_rcv_num;
	_gdev_keepalive_snd_pps = snd_sum - _last_snd_num;

	_last_rcv_num = rcv_sum;
	_last_snd_num = snd_sum;

	return;
}

static void *gdev_keepalive_log_thread(void *arg)
{
	FILE *gdev_status_fp;
	int index, thread_seq;
	int platform_thread_num;
	char cur_time_str[64];
	char tmp_ip_str[32];
	const char *tmp_keealive_type;
	time_t last_op_time;

	last_op_time = time(NULL);
	
	while(1){
		gdev_status_fp = fopen("log/gdev_keeplive_status.log", "w+");
		if(NULL == gdev_status_fp){
			sleep(1);
			continue;
		}
		platform_thread_num = get_thread_count();
		timet_to_str(time(NULL), cur_time_str, 64);
		fprintf(gdev_status_fp, "%-20s %-16s %-11s %-5s %-5s %-16s %-16s\n", 
						    "Last-update-time", "Gdev-ip", "Service-Num", "Ctrl", "Type", "Rcv-pkt", "Snd-pkt");
		
		for(thread_seq = 0; thread_seq < platform_thread_num; thread_seq++)
		{			
			for(index = 0; index < MAX_GDEV_STAT_LOG_NUM; index++){
				if(0 == GDEV_KEEPALIVE_STAT[thread_seq][index].active_flag){
					continue;
				}
				inet_ntop(AF_INET, &GDEV_KEEPALIVE_STAT[thread_seq][index].gdev_ip_network_order, tmp_ip_str, 32);
				if(GDEV_KEEPALIVE_TYPE_ICMP == GDEV_KEEPALIVE_STAT[thread_seq][index].gdev_keepalive_type){
					tmp_keealive_type = "ICMP";
				}else if(GDEV_KEEPALIVE_TYPE_BFD == GDEV_KEEPALIVE_STAT[thread_seq][index].gdev_keepalive_type){
					tmp_keealive_type = "BFD";
				}else{
					tmp_keealive_type = "Unknown";
				}

				fprintf(gdev_status_fp, "%-20s %-16s %-11d %-5d %-5s %-16u %-16u\n",
								    cur_time_str,
								    tmp_ip_str,
								    GDEV_KEEPALIVE_STAT[thread_seq][index].gdev_keepalive_service_num,
								    gdev_kp_action_judge(GDEV_KEEPALIVE_STAT[thread_seq][index].gdev_keepalive_service_num),
								    tmp_keealive_type,
								    GDEV_KEEPALIVE_STAT[thread_seq][index].tot_rcv_pkt_num,
								    GDEV_KEEPALIVE_STAT[thread_seq][index].tot_snd_pkt_num);
			}
		}

		__gdev_keepalive_pkt_calc_pps();
		
		fclose(gdev_status_fp);

		while(last_op_time == time(NULL)){
			usleep(100);
		}
		last_op_time = time(NULL);
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

	fp = fopen(ABBR_VXLAN_SPOER_CONF_FILE, "r");
	if(NULL == fp){
		MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "open file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
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
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
			goto done;
		}
		tmp_service_id = atoi(section);

		/* VPN-id, 暂时不用转换, 直接减100即是业务号 */
		section = strtok_r(NULL, delim, &save_ptr);
		if(NULL == section){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
			goto done;
		}

		/* begin-port */
		section = strtok_r(NULL, delim, &save_ptr);
		if(NULL == section){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
			goto done;
		}
		tmp_int = atoi(section);
		if(tmp_int <= 0 || tmp_int > 65535){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
			goto done;
		}
		begin_sport = (unsigned short)tmp_int;

		/* end-port */
		section = strtok_r(NULL, delim, &save_ptr);
		if(NULL == section){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
			goto done;
		}	
		tmp_int = atoi(section);
		if(tmp_int <= 0 || tmp_int > 65535){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
			goto done;
		}	
		end_sport = (unsigned short)tmp_int;

		if(end_sport < begin_sport){
			MESA_handle_runtime_log(gdev_kp_log_handle, 20, "[gdev_keepalive]", "parse file %s error!\n", ABBR_VXLAN_SPOER_CONF_FILE);
			goto done;
		}

		while(strtok_r(NULL, delim, &save_ptr));

		vxlan_sport_service_map_update(tmp_service_id, begin_sport, end_sport);
	}

done:
	fclose(fp);
	
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

int gdev_keepalive_plug_init(void)
{
	char tmp_ip_buf[16];
	char deploy_mode_string[32];
	int opt_len;
	int i;

	gdev_kp_log_handle = MESA_create_runtime_log_handle("./log/gdev_keeplive.log", 10);

#ifdef GIT_VERSION
	MESA_handle_runtime_log(gdev_kp_log_handle, 30, "[gdev_keepalive]", "g_device_plug version: %s\n", g_device_plug_git_ver);	
#endif

#if IOMODE_MARSIO	
	gdev_plug_extern_marsio4_instance = sapp_get_marsio_instance();
	if(NULL == gdev_plug_extern_marsio4_instance){
		return -1;
	}
#endif

	assert(sizeof(gdev_keepalive_status_t) % 64 == 0);

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
	MESA_load_profile_string_nodef((char *)"./etc/gdev.conf", (char *)"Module", (char *)"sendto_gdev_ip", tmp_ip_buf, 16);
	if(tmp_ip_buf[0] == '\0'){
		MESA_handle_runtime_log(gdev_kp_log_handle, 30, "[gdev_keepalive]","can't get 'sendto_gdev_ip'");
		return -1;
	}

	inet_pton(AF_INET, tmp_ip_buf, &sendto_gdev_card_ip);

	MESA_load_profile_int_def((char *)"./etc/gdev.conf", (char *)"Module", (char *)"default_keepalive_action", &g_dev_keepalive_default_action, 1);
	MESA_load_profile_int_def((char *)"./etc/gdev.conf", (char *)"Module", (char *)"gdev_status_switch", &GDEV_KEEPALIVE_LOG_SWITCH, 1);


	for(i = 0; i <  MAX_VXLAN_SERVICE_NUM; i++){
		g_dev_keepalive_service_ctrl_array[i].service_num = i;
		g_dev_keepalive_service_ctrl_array[i].keepalive_switch = g_dev_keepalive_default_action;
	}

	vxlan_sport_service_map_init();

	if(GDEV_KEEPALIVE_LOG_SWITCH){
		pthread_t log_pid;
		pthread_create(&log_pid, NULL, gdev_keepalive_log_thread, NULL);
	}
	
	return 0;
}


#ifdef __cplusplus
}
#endif

