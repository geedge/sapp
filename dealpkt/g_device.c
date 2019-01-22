#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif

#include <arpa/inet.h>
#include <netinet/udp.h>
#include "stream_manage.h"
#include "logger.h"
#include "packet_io.h"
#include "g_device.h"
#include "mesa_net.h"
#include "packet_io_internal.h"
#include "sendpacket.h"
#include "deal_ipv4.h"
#include "MESA_prof_load.h"

extern int g_topology_mode;

char pcap_gdev_card[128]; 		/* 2012-08-14 LiJia add, 特殊设备模式下，捕包网卡名称，通常与sendto_gdev_card一样 */
char sendto_gdev_card[128];		/* 基于特殊设备的串联模式，发送数据接口名称 */
unsigned char sendto_gdev_card_mac[6];	/* 发送数据接口的MAC地址 */
int  sendto_gdev_card_ip = 0;	/* 发送数据接口的IP地址, 网络序 */
char  config_gdev_card_ip[20] = {};	/* 从配置文件中读入的发送数据接口IP， 接口没有配置IP地址时使用 */
extern char g_up_dev_name[DEV_NAME_STR_LEN]; /* 默认捕包网卡 */

#define GDEV_LOG_NAME			"gdev_ip.log"
#define GDEV_LOG_MAX_NUM		(128)



int GDEV_IP_NUM = 0;
//static struct gdev_status GDEV_IP_LOG[GDEV_LOG_MAX_NUM]; 
//static pthread_mutex_t GDEV_IP_LOG_MUTEX;
//static unsigned int gdev_log_write_counter = 1; /* 用于记数，到某个值时，写文件 */


extern char *timet_to_str(time_t timet, char *time_str, int time_str_len);

extern char *timet_to_str(time_t timet, char *time_str, int time_str_len);
extern int sendpacket_build_icmpv4_echo(u_int8_t type, u_int8_t code, u_int16_t sum,
		u_int16_t id, u_int16_t seq, u_int8_t *payload, u_int32_t payload_s, unsigned char *buf);
extern FILE *packet_io_open_log_file(const char *log_file_name, const char *mode);
extern int MESA_get_dev_ipv4(const char *device, int *ip_add);
extern int MESA_get_dev_mac(const char *device, unsigned char mac[6]);

/* 是否为IPv6私有地址 */
inline int is_private_addr_v6(struct in6_addr ip6_add)
{
	/* Link-Local address, first 10 bits is 1111111010 */
	if((ip6_add.s6_addr[0] == 0xFE)
	&& ((ip6_add.s6_addr[1] & 0xC0) == 0x80)) 
	{
		return 1;
	}

	/* Site-Local address, first 10 bits is 1111111011 */
	if((ip6_add.s6_addr[0] == 0xFE)
	&& ((ip6_add.s6_addr[1]&0xC0) == 0xC0)) 
	{
		return 1;
	}
	
    return 0;
}

/* 是否为IPv6组播地址 */
int is_multicast_addr_v6(struct in6_addr ip6_add)
{
	/* IPv6 multicast address first 8 bits is 11111111 */
    if(ip6_add.s6_addr[0] == 0xFF)
    {
        return 1;
    }

    return 0;
}

static int gdev_check_ipv6_pkt(struct mesa_ip6_hdr *a_packet)
{
	/* 2012-11-01 add, 在特殊设备模式下，不处理组播地址数据 */
	
	
/*
	if(is_private_addr_v6(a_packet->ip6_dst))
	{
		return DROP;
	}
*/
	if(is_multicast_addr_v6(a_packet->ip6_dst))
	{
		return DROP;
	}	
	
	return PASS;
}

static int gdev_check_ipv4_pkt(struct mesa_ip4_hdr *a_packet)
{

/*	
	if(is_private_addr_v4(ntohl(a_packet->ip_dst.s_addr)))
	{
		return DROP;
	}

*/
	if(is_multicast_addr_v4(ntohl(a_packet->ip_dst.s_addr)))
	{
		return DROP;
	}	

	return PASS;
}

int gdev_check_pkt(int addr_type, void *pkt_data)
{
	int ret = PASS;
	
	switch(addr_type)
	{
		case __ADDR_TYPE_IP_PAIR_V4:
			ret = gdev_check_ipv4_pkt((struct mesa_ip4_hdr *)pkt_data);
		break;
		
		case __ADDR_TYPE_IP_PAIR_V6:
			ret = gdev_check_ipv6_pkt((struct mesa_ip6_hdr *)pkt_data);
		break;

		default:
			ret = PASS;
			break;
	}

	return ret;
}

/* 特殊设备保活函数，ARP协议 
	return value:
	1: is gdev keepalive pkt;
	0: not gdev keepalive pkt;
*/
static int gdev_keepalive_arp(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir,unsigned char *send_buf)
{
	const struct mesa_ethernet_hdr *raw_eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_arp_hdr *arp_hdr = (struct mesa_arp_hdr *)((char *)raw_eth_hdr + ETHERNET_HDR_LEN);
	struct mesa_ethernet_hdr *send_eth_hdr;
	
	/* 一些出错处理 */
	if(ntohs(raw_eth_hdr->ether_type) != ETHERTYPE_ARP){
		return -1;
	}
	
	if(memcmp(&sendto_gdev_card_ip, arp_hdr->ar_tpa, sizeof(int)) != 0){
		return -1;
	}

	sendpacket_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, arp_hdr->ar_hln, arp_hdr->ar_pln,
						 ARPOP_REPLY, (u_char *)sendto_gdev_card_mac, arp_hdr->ar_tpa, 
						 arp_hdr->ar_sha, arp_hdr->ar_spa, 
						 NULL, 0,
						 send_buf + ETHERNET_HDR_LEN);

	send_eth_hdr = (struct mesa_ethernet_hdr * )send_buf;
	memcpy(send_eth_hdr->ether_dhost, raw_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(send_eth_hdr->ether_shost, sendto_gdev_card_mac, ETHER_ADDR_LEN);
	send_eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
	
	return sizeof(struct mesa_arp_hdr) + sizeof(struct mesa_ethernet_hdr);
}


/* 特殊设备保活函数，ICMP协议 */
#if 0  /* 改用IP层插件实现 */	
static int gdev_keepalive_icmp(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
{
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H);
	struct mesa_icmp_echo_hdr *icmp_hdr = (struct mesa_icmp_echo_hdr *)((char *)eth_hdr + SENDPACKET_ETH_H + ip_hdr->ip_hl*4);
	unsigned char *icmp_payload;
	int icmp_payload_len;

	/* 一些出错处理 */
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
#endif



/* 用于和特殊设备保活连接
   和特殊设备连接的接口一般没有路由和IP地址, 需要发送带mac层的原始包.

   return value:
	>0: is gdev keepalive pkt;
	 0: not gdev keepalive pkt;
	-1: error;
*/
int gdev_keepalive(const raw_pkt_t *raw_pkt, int thread_id, int pro_type, unsigned char dir)
{
	int ret = -1;
	MESA_send_handle *snd_handle = NULL;
	//int low_layer_type;

	if(g_topology_mode != NET_CONN_SERIAL_GDEV){
		return 0;
	}

	snd_handle = packet_io_get_send_handle(thread_id);
	if(NULL == snd_handle){
		return -1;
	}
	snd_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_id);
	if(NULL == snd_handle->send_buf){
		return 0;
	}
	
    switch(pro_type)
    {
#if 0	 /* 改用IP层插件实现 */	
		case GDEV_KEEPALIVE_TYPE_ICMP:
			ret = gdev_keepalive_icmp(raw_pkt, thread_id, dir, snd_handle->send_buf);
			low_layer_type = __ADDR_TYPE_IP_PAIR_V4;
		break;
#endif
		case GDEV_KEEPALIVE_TYPE_ARP:
			ret =  gdev_keepalive_arp(raw_pkt, thread_id, dir, snd_handle->send_buf);
			//low_layer_type = ADDR_TYPE_ARP;
		break;

#if 0	 /* 改用UDP层插件实现 */	
		case GDEV_KEEPALIVE_TYPE_BFD:
			ret = gdev_keepalive_bfd(raw_pkt, thread_id, dir, snd_handle->send_buf);
			low_layer_type = __ADDR_TYPE_IP_PAIR_V4;
		break;
#endif 
		default:
			goto err;
		break;
    }

    if(ret < 0){
		goto err;
    }

    /*
	TODO:
	arp协议的MAC地址填充和转发回注不一样, 原始包的目标MAC是全FF, 需要明确修改源MAC为本机IP,
	不能使用packet_io_send系列函数, 
	要使用packet_io_send_raw()函数.
    */

	ret = packet_io_send_raw(thread_id, (char *)snd_handle->send_buf, 
							sizeof(struct mesa_arp_hdr) + sizeof(struct mesa_ethernet_hdr),
							0);	

    packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_id);
    return ret;

err:
    packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_id);
    return -1;
}

#if 0
static void gdev_status_insert(int index, unsigned char *data, char keepalive_type)
{
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)data;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)(data + SENDPACKET_ETH_H);

	GDEV_IP_LOG[index].gdev_ip = ip_hdr->ip_src.s_addr;
	memcpy(GDEV_IP_LOG[index].gdev_mac, eth_hdr->ether_shost, 6);
	GDEV_IP_LOG[index].last_time = g_CurrentTime;

	if(GDEV_KEEPALIVE_TYPE_ICMP == keepalive_type)
	{
		GDEV_IP_LOG[index].gdev_keepalive_str = (char *)"ICMP";
	}	
	else if(GDEV_KEEPALIVE_TYPE_BFD == keepalive_type)
	{
		GDEV_IP_LOG[index].gdev_keepalive_str =(char *)"BFD";
	}
	else
	{
		GDEV_IP_LOG[index].gdev_keepalive_str =(char *) "Uknown";
	}

	GDEV_IP_NUM++;
}



void gdev_keepalive_log(void )
{
	int i;
	char local_ip_str[16];
	char gdev_ip_str[16];
	char time_now_str[32];

	FILE *gdev_status_fp =  NULL;// to do  packet_io_open_log_file("gdev_keepalive.log", "w+");
	if(NULL == gdev_status_fp)
	{
		return;
	}

	if(0 == GDEV_IP_NUM) /* 当前无数据 */
	{
		return;
	}

	fprintf(gdev_status_fp, "%-20s %-16s %-16s %-20s %-20s\n", "Last update time", "Local-ip", "Gdev-ip", "Gdev-mac", "Gdev-keepalive-type");

	for(i = 0; GDEV_IP_LOG[i].gdev_ip != 0 && i < GDEV_LOG_MAX_NUM; i++)
	{
		// to do timet_to_str
		//timet_to_str(GDEV_IP_LOG[i].last_time, time_now_str, 32);
		fprintf(gdev_status_fp, "%-20s ", time_now_str);
		inet_ntop(AF_INET, &sendto_gdev_card_ip, local_ip_str, 16);
		inet_ntop(AF_INET, &GDEV_IP_LOG[i].gdev_ip, gdev_ip_str, 16);
		fprintf(gdev_status_fp, "%-16s %-16s ", local_ip_str, gdev_ip_str);
		fprintf(gdev_status_fp, "%02x-%02x-%02x-%02x-%02x-%02x    ", 
								GDEV_IP_LOG[i].gdev_mac[0],
								GDEV_IP_LOG[i].gdev_mac[1],
								GDEV_IP_LOG[i].gdev_mac[2],
								GDEV_IP_LOG[i].gdev_mac[3],
								GDEV_IP_LOG[i].gdev_mac[4],
								GDEV_IP_LOG[i].gdev_mac[5]);
		fprintf(gdev_status_fp, "%-20s\n", GDEV_IP_LOG[i].gdev_keepalive_str);
	}

	return;
}
#endif

#if 0
static void gdev_status_update(unsigned char *data, char keepalive_type)
{
	int i;
	struct mesa_ip4_hdr *ip_hdr = (struct mesa_ip4_hdr *)(data + SENDPACKET_ETH_H);
	unsigned int gdev_ip = ip_hdr->ip_src.s_addr;

	pthread_mutex_lock(&GDEV_IP_LOG_MUTEX);
	
	for(i = 0; i < GDEV_LOG_MAX_NUM; i++)
	{
		if(gdev_ip == GDEV_IP_LOG[i].gdev_ip) /* 已经包含此记录,更新时间 */
		{
			GDEV_IP_LOG[i].last_time = g_CurrentTime;
			goto exit; 
		}

		if(0 == GDEV_IP_LOG[i].gdev_ip)
		{
			gdev_status_insert(i, data, keepalive_type);
			goto exit;
		}
	}

	if(GDEV_LOG_MAX_NUM == i)
	{
		//to do
		//MESA_runtime_log(RLOG_LV_INFO, "gdev_status", "Too many gdev ip!\n");
	}


exit:	
	pthread_mutex_unlock(&GDEV_IP_LOG_MUTEX);
	return;
}



/* 2012-08-03 LiJia add, 记录本机通信的所有特殊设备的IP、MAC和保活协议等信息，
   Bug: 如果有其他主机ping本机，因无法区别一台普通PC机和特殊设备，也会记录在日志中.
*/
int gdev_log_init(void)
{
	if(GDEV_STATUS_SWITCH)
	{
		pthread_mutex_init(&GDEV_IP_LOG_MUTEX, NULL);
	}
	
	return 0;
}
#endif

#ifdef CAPTURE_MODE_DPDK_VXLAN
/* 暂时解决DPDK-RTE无法使用时, 无法获取mac地址的问题 */
int dpdk_get_mac_addr(unsigned int port, uint8_t mac_addr[6]) ;
#endif


#if 0
int gdev_init(void)
{
	char gdev_ip_str[32];
	char gdev_device[128];
	
	if(g_topology_mode != NET_CONN_SERIAL_GDEV){
		return 0;
	}

	MESA_load_profile_string_def((char *)"conf/gdev.conf", (char *)"Module", (char *)"sendto_gdev_ip", gdev_ip_str, 32, (char *)"");
	MESA_load_profile_string_def((char *)"conf/gdev.conf", (char *)"Module", (char *)"sendto_gdev_card", gdev_device, 128, (char *)"");

	if('\0' == gdev_device[0]){
		printf("Can't get sendto_gdev_card in %s!\n", "conf/gdev.conf");
		assert(0);
	}
	
	if('\0' == gdev_ip_str[0]){	
		if(MESA_get_dev_ipv4(gdev_device, &sendto_gdev_card_ip) < 0){
			printf("Can't get gdev ip in %s!\n", "conf/gdev.conf");
			assert(0);
		}
	}
	
	if(inet_pton(AF_INET, gdev_ip_str, &sendto_gdev_card_ip) <= 0){
		printf("gdev ip in %s is invalid!\n", "conf/gdev.conf");
		assert(0);
	}

	if(0 == sendto_gdev_card_ip){
		printf("Can't get %s ip address!\n", sendto_gdev_card);
		assert(0);
	}

#if (0 == IOMODE_MARSIO)
	if(MESA_get_dev_mac(gdev_device, sendto_gdev_card_mac) < 0){
#ifdef CAPTURE_MODE_DPDK_VXLAN
		dpdk_get_mac_addr(0, sendto_gdev_card_mac);
		if(memcmp(empty_mac_addr, sendto_gdev_card_mac, 6) == 0){
		 	printf("Can't get gdev interface %s MAC!\n", sendto_gdev_card);
			assert(0);
		}
#else
		printf("Can't get gdev interface %s MAC!\n", sendto_gdev_card);
		assert(0);
#endif		
	}
#endif
	
	if(GDEV_STATUS_SWITCH)
	{
		gdev_log_init();
	}
	
	return 0;
}
#endif


#ifdef __cplusplus
}
#endif
