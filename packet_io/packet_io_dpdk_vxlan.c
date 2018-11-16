/*
	基于DPDK3.0捕包, 专用设备的三层VxLAN回流模式.

	1)需要处理三层保活信息, 同二层保活;
	2)剥离VxLAN信息, 本来普通DPDK和其他模式都可以处理, 通过pfather->pfather的链接关系, 可以同时处理外层和内层MAC;
	  但是:
	  	a)外层的地址其实只用来传输内层数据包, 不可调用ip_entry, udp_entry等插件入口;
	  	b)每次都要处理外层的IP->port->vxlan, 影响性能;

	所以, 将保活、外层地址解析和封装移动至packet_io层面, 对dealpkt层面透明.

	2016-12-27:
	    增加dpdk_get_mac_addr()接口, 解决无法获取发包网卡MAC地址问题.
*/
#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <pthread.h>
#include "packet_io.h"
#include "packet_io_internal.h"
#include "mesa_net.h"
#include "marsio.h"
#include "stream_manage.h"
#include "g_device.h"

#define USE_MARSIO_API					(0)

#define VXLAN_ASSIGNED_PORT			(4789)

int g_dpdk_vxlan_version_VERSION_20161227;
int g_dpdk_vxlan_version_VERSION = 20161227;
static PACKET_IO_CB_T g_dpdk_vxlan_work_fun;
static int g_dpdk_vxlan_work_thread_num = 1;
static int g_dpdk_vxlan_cap_level = CAP_LEVEL_MAC;
static int g_dpdk_vxlan_topology_mode = NET_CONN_PARA_NOSEND;
extern unsigned char sendto_gdev_card_mac[6];

#define VXLAN_DIR_BIT_INDEX			(1<<8) /* x设备规范中, vxlan头部的第8位表示方向 */

/*
	此结构定义与标准vxlan(RFC7348)不同, 是中心专用设备版, 使用了某些标准版的预留字段.
*/
#if 0
typedef struct{
	unsigned int r0:1;
	unsigned int r1:1;
	unsigned int r2:1;
	unsigned int vni_flag:1;
	unsigned int r4:1;
	unsigned int r5:1;
	unsigned int r6:1;
	unsigned int r7:1;
	/*------------byte delim -------*/ 
	unsigned int dir:1;
	unsigned int link_id:6;
	unsigned int online_test:1;
	/*------------byte delim -------*/ 
	unsigned int raw_ether_type:4; 
	unsigned int vlan_id:12;
	/*--------short delim -------*/ 
	unsigned int r8:24;
	unsigned int flags:8;
}vxlan_hdr_t;
#endif

#define RESERVED_HDR_LEN (sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_udp_hdr) + sizeof(vxlan_hdr_t))


typedef struct{
	struct mesa_ethernet_hdr *dpdk_raw_pkt_hdr; /* 记录原始包头指针, 用于发包获取MAC地址用 */
	unsigned char dpdk_raw_pkt_route_dir; /* 记录原始包方向, 用于发送数据包 */
	raw_pkt_t raw_pkt;
	const char *outer_mac_hdr; /*外层数据包指针, 用于发包时修改vxlan头部, IP地址, UDP端口等信息 */
	char __cache_align[48]; /* 整体结构64字节整数倍对齐 */
}dpdk_vxlan_low_level_io_para_t;

static dpdk_vxlan_low_level_io_para_t dpdk_vxlan_low_level_io_para[MAX_THREAD_NUM];

typedef struct{
	int thread_num; 
	UINT8 dpdk_send_buf[SENDPACKET_BUF_LEN];
}dpdk_vxlan_send_handle;

extern void idle_polling_call(int thread_seq);

void dpdk_empty_call(int thread_seq)
{
	idle_polling_call(thread_seq);
}

static int __dpdk_vxlan_gdev_build_bfd(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
{
	char payload_buf[1472];
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)((char *)eth_hdr+ SENDPACKET_ETH_H);
	struct mesa_udp_hdr *udp_hdr = (struct mesa_udp_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4);
	bfd_header_t *bfd_net_hdr = (bfd_header_t *)((char *)eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4 + SENDPACKET_UDP_H);
	bfd_header_t *bfd_send_hdr = (bfd_header_t *)payload_buf;
	char bfd_buf[4];
	int payload_len = ntohs(udp_hdr->uh_ulen) - SENDPACKET_UDP_H;
	
	/* 一些出错处理 */
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
	
	memcpy(payload_buf, bfd_net_hdr, payload_len);

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

static int __dpdk_vxlan_gdev_keepalive_bfd(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir)
{
	int ret;
	unsigned char tmp_buf[1500];	
	struct mesa_ethernet_hdr *snd_eth_hdr = (struct mesa_ethernet_hdr *)tmp_buf;
	const struct mesa_ethernet_hdr *raw_eth_hdr = (const struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;

	ret = __dpdk_vxlan_gdev_build_bfd(raw_pkt, thread_id, dir, tmp_buf);
	if(ret < 0){
		return ret;
	}

	memcpy(snd_eth_hdr->ether_dhost, raw_eth_hdr->ether_shost, 6);
	memcpy(snd_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, 6);
	snd_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);

	ret = dpdk_send_packet_dst(tmp_buf, ret+14, dir);

	return ret;
}

/* VxLan模式下, 发送保活包是不需要携带vxlan头的, 临时复用gdevice保活函数 */
static int __dpdk_vxlan_gdev_build_icmp(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
 {
     struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
     struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H);
     struct mesa_icmp_echo_hdr *icmp_hdr = (struct mesa_icmp_echo_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4);
     unsigned char *icmp_payload;
     int icmp_payload_len;
 
     /* 脪禄脨漏鲁枚麓铆麓娄脌铆 */
     if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
         return -1;
     }
 
     if(ip_hdr->ip_p != IPPROTO_ICMP){
         return -1;
     }
 
     if(icmp_hdr->icmp_type != ICMP_ECHO){
         return -1;
     }
 
     if(memcmp(&ip_hdr->ip_dst.s_addr, &sendto_gdev_card_ip, sizeof(int)) != 0){
         return -1;
     }
 
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

static int __dpdk_vxlan_gdev_keepalive_icmp(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir)
{
	int ret;
	unsigned char tmp_buf[1500];	
	struct mesa_ethernet_hdr *snd_eth_hdr = (struct mesa_ethernet_hdr *)tmp_buf;
	const struct mesa_ethernet_hdr *raw_eth_hdr = (const struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;

	ret = __dpdk_vxlan_gdev_build_icmp(raw_pkt, thread_id, dir, tmp_buf);
	if(ret < 0){
		return ret;
	}

	memcpy(snd_eth_hdr->ether_dhost, raw_eth_hdr->ether_shost, 6);
	memcpy(snd_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, 6);
	snd_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);

	ret = dpdk_send_packet_dst(tmp_buf, ret+14, dir);

	return ret;
}
/*  
	1: keepalive packet;
	0: not keepalive packet;
*/
static int dpdk_vxlan_keepalive_ip(raw_pkt_t *pkt, int thread_num, int dir)
{
	int ret = 0;
	const struct mesa_ip4_hdr *ip4 = (const struct mesa_ip4_hdr *)((char *)pkt->raw_pkt_data + sizeof(struct mesa_ethernet_hdr));

	switch(ip4->ip_p){
		case IPPROTO_ICMP:
			__dpdk_vxlan_gdev_keepalive_icmp(pkt, thread_num, dir);
			ret = 1; /* ICMP keepalive packet */
		break;

		case IPPROTO_UDP:
		{
			const struct mesa_udp_hdr *uh = (const struct mesa_udp_hdr *)((char *)ip4 + ip4->ip_hl * 4);
			if(BFD_DEFAULT_PORT == ntohs(uh->uh_dport)){
				ret = __dpdk_vxlan_gdev_keepalive_bfd(pkt, thread_num, dir);
			}else{
				if(VXLAN_ASSIGNED_PORT == ntohs(uh->uh_dport)){
				 	/* vxlan端口, 返回-1, 以便让dpdk_vxlan_hand可以继续处理 */
				 	ret = -1;
				}
			}
		}
		break;

		default:
			/* 外层IP但非UDP协议, 肯定不是vxlan报文, 当keepalive包丢弃 */
			ret = 1;		
		break;
	}

	return ret;
}

/*
	1:保活包, 或者不是vxlan格式的包, 都丢弃不给平台;
	0:vxlan包, 跳过vxlan层, 给平台.
*/
static int dpdk_vxlan_keepalive(raw_pkt_t *pkt, int thread_num, int dir)
{	
	int ret = 0;
	const struct mesa_ethernet_hdr *p_eth_hdr = (const struct mesa_ethernet_hdr *)pkt->__lib_raw_pkt_data;

	switch(ntohs(p_eth_hdr->ether_type)){
		case ETHERTYPE_ARP:
			gdev_keepalive(pkt, thread_num, GDEV_KEEPALIVE_TYPE_ARP, dir);
			/* 本机收到的ARP包, 不论是不是本机, 都不可能是vxlan包, 直接丢弃, 不给平台 */
			ret = 1;
		break;

		case ETHERTYPE_IP:
		{
			ret = dpdk_vxlan_keepalive_ip(pkt, thread_num, dir);
		}
		break;

		default:
			/* 非IP协议, 肯定不是vxlan报文, 当keepalive包丢弃 */
			ret = 1;
	}

	return ret;
}

/*
	源/目的IP, 端口交换, 
	从新计算IP层头部检验和, 其他不变.
*/
static int dpdk_vxlan_forward_pkt(unsigned char *data, int datalen, int dir)
{
	int ret;
	char tmp_mac_addr[ETHER_ADDR_LEN];
	int tmp_ipaddr;
	short tmp_port;
	
	struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)data;
	memcpy(tmp_mac_addr, ehdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ehdr->ether_shost, ehdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ehdr->ether_dhost, tmp_mac_addr, ETHER_ADDR_LEN);

	struct mesa_ip4_hdr *ip4_hdr = (struct mesa_ip4_hdr *)(data + sizeof(struct mesa_ethernet_hdr));
	tmp_ipaddr = ip4_hdr->ip_src.s_addr;
	ip4_hdr->ip_src.s_addr =  ip4_hdr->ip_dst.s_addr;
	ip4_hdr->ip_dst.s_addr = tmp_ipaddr;

	struct mesa_udp_hdr *uhdr = (struct mesa_udp_hdr *)(data + sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ip4_hdr));
	tmp_port = uhdr->uh_sport;
	uhdr->uh_sport = uhdr->uh_dport;
	uhdr->uh_dport = tmp_port;

	ret = dpdk_send_packet_dst((unsigned char *)data, datalen, dir);

	return ret;
}

#if USE_MARSIO_API
int dpdk_vxlan_hand(const char * data, int datalen, int thread_num, mr_pkt_desc_t * desc, void * arg)
#else
int dpdk_vxlan_hand(const unsigned char *data, int datalen, int dir, int thread_num)
#endif
{
	int ret;
	dpdk_vxlan_low_level_io_para_t *io_para = &dpdk_vxlan_low_level_io_para[thread_num];
	raw_pkt_t *raw_pkt = &io_para->raw_pkt;
	
#if USE_MARSIO_API
	unsigned char dir = desc->in_dest;
#endif

	io_para->dpdk_raw_pkt_route_dir = dir;
	io_para->dpdk_raw_pkt_hdr = (struct mesa_ethernet_hdr *)data;

	raw_pkt->low_layer_type = (enum addr_type_t)g_dpdk_vxlan_cap_level;
	raw_pkt->__lib_raw_pkt_data = (const void *)data;
	raw_pkt->__lib_raw_pkt_len = datalen;

	/* 因复用了g_keepalive_xxx()系列函数, 函数内都取自指针raw_pkt_data, 所以先执向外层MAC, 待确定不是保活包后, 再更新为内层MAC */
	raw_pkt->raw_pkt_data = data; 
	raw_pkt->raw_pkt_len = datalen;
	
#if USE_MARSIO_API	
	raw_pkt->hd_hash = desc->in_hash;
#endif	

	if(dpdk_vxlan_keepalive(raw_pkt, thread_num, dir) == 1){
		return DROP;
	}

	/* 此时确认不是保活后, 更新数据指针和长度, 给平台的指针从内层MAC开始, 跳过vxlan各层头部 */
	raw_pkt->raw_pkt_data = data + RESERVED_HDR_LEN; 
	raw_pkt->raw_pkt_len = datalen - RESERVED_HDR_LEN;
	
	ret =  (*g_dpdk_vxlan_work_fun)((const raw_pkt_t *)raw_pkt, dir, thread_num);

	/* DPDK靠返回值判断是否转发包, 所以在并联模式下, 固定返回DROP */
	if(likely(g_dpdk_vxlan_topology_mode & __NET_CONN_PARALLEL)){
		ret = DROP;
	}

	if(PASS == ret){
		ret = dpdk_vxlan_forward_pkt((unsigned char *)data, datalen, dir);
	}

	return ret;
}

int dl_io_set_cap_level(int cap_level)
{
	g_dpdk_vxlan_cap_level = cap_level;
	
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
			g_dpdk_vxlan_topology_mode = topology_mode;
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
	g_dpdk_vxlan_work_thread_num = thread_num_max;
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
	dpdk_vxlan_send_handle *snd_handle = (dpdk_vxlan_send_handle *)phandle;
	vxlan_hdr_t *vxlan_hdr = (vxlan_hdr_t *)(snd_handle->dpdk_send_buf + sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_udp_hdr));

	if(dir != dpdk_vxlan_low_level_io_para[thread_num].dpdk_raw_pkt_route_dir){
		dir_reverse = 1;
	}else{
		dir_reverse = 0;
	}
	
	if(0 == dir_reverse){
		/* 同向发送, 外层地址和转发一样, 源、目的交换即可 */
		/* do nothing! */
	}else{
		/* 反向发送, 先将vxlan的dir位反向, 其他的外层地址和转发一样, 源、目的交换即可 */
		vxlan_hdr->dir ^= 1;
	}
	
	ret = dpdk_vxlan_forward_pkt(snd_handle->dpdk_send_buf, datalen+RESERVED_HDR_LEN, dir);
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
	dpdk_vxlan_send_handle *send_handle = (dpdk_vxlan_send_handle *)phandle;
	
	/* VXLAN模式下, 给平台的缓冲区预留外层mac+ip+udp+vxlan的空间, packet_io模块负责填充 */
	return send_handle->dpdk_send_buf + RESERVED_HDR_LEN;
}

void dl_io_free_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	
	/* DPDK模式初始化时申请一次, 发送完无需每次释放 */
	return;
}

/* 初始化时调用一次 */
void *dl_io_get_send_handle(int thread_num)
{
	dpdk_vxlan_send_handle *real_handle = (dpdk_vxlan_send_handle *)malloc(sizeof(dpdk_vxlan_send_handle));	

	real_handle->thread_num = thread_num;

	return (void *)real_handle;
}

int dl_io_get_version(void)
{
	return g_dpdk_vxlan_version_VERSION;
}

int dl_io_init(int argc, char *argv[])
{
	int i;
#if USE_MARSIO_API
	marsio_rawio_cb_reg(dpdk_vxlan_hand, NULL);
#else
	dpdk_register_callfunc_dst(dpdk_vxlan_hand);
#endif	

	for(i = 0; i < MAX_THREAD_NUM; i++){
		dpdk_vxlan_low_level_io_para[i].raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
		memset(&dpdk_vxlan_low_level_io_para[i].raw_pkt.raw_pkt_ts, 0, sizeof(struct timeval));
	}
	return dpdk_init(argc, argv);
}


void dl_io_run(void)
{
	dpdk_run();
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_dpdk_vxlan_work_fun = fun;
	return 0;
}

#ifdef __cplusplus
}
#endif



