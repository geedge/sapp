#ifdef __cplusplus
extern "C" {
#endif
/* 
	将GDEV-KEEPALIVE功能从平台中剥离, 
	挂载到UDP层插件完成原有功能.

	因icmp和arp保活靠协议号精确识别, 暂时仍留在平台内部.
*/

#include <pthread.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif

#include <arpa/inet.h>
#include <netinet/udp.h>
#include "stream_internal.h"
#include "stream_manage.h"
#include "packet_io.h"
#include "g_device.h"
#include "mesa_net.h"
#include "packet_io_internal.h"
#include "sendpacket.h"
#include "deal_ipv4.h"
#include "MESA_prof_load.h"

static int sendto_gdev_card_ip; /* 与Gdev连接网卡的IP地址, 网络序 */


/* 特殊设备保活函数，ICMP协议 */
static int gdev_keepalive_bfd(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir, unsigned char *send_buf)
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

static int gdev_keepalive_udp_plug(const raw_pkt_t *raw_pkt, int thread_id, unsigned char dir)
{
	int ret = -1;
	MESA_send_handle *snd_handle = NULL;
	int low_layer_type;

	snd_handle = packet_io_get_send_handle(thread_id);
	if(NULL == snd_handle){
		return -1;
	}
	snd_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_id);
	if(NULL == snd_handle->send_buf){
		return 0;
	}
		
	ret = gdev_keepalive_bfd(raw_pkt, thread_id, dir, snd_handle->send_buf);
	if(ret < 0){
		goto err;
	}
	low_layer_type = __ADDR_TYPE_IP_PAIR_V4;

	/* 2015-01-04 lijia add, MESA_kill系列函数发送时包含了eth头长度, 此处要一致 */
	if(ADDR_TYPE_MAC == raw_pkt->low_layer_type){
		ret += sizeof(struct mesa_ethernet_hdr); 
	}
	/* gdev keepalive的回复方向dir使用"同向", 底层只需简单将MAC地址的src和dst颠倒即可 */
	ret = packet_io_send(snd_handle,ret, SEND_TYPE_LINK_INJECT, 
					low_layer_type, dir, thread_id,
					(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);	

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

	if(ADDR_TYPE_IPV4 != a_udp->addr.addrtype){
		return 0;
	}

	if(BFD_DEFAULT_PORT != ntohs(a_udp->addr.tuple4_v4->dest)){
		return 0;
	}

	return 1;
}


char gdev_keepalive_udp_entry(const struct streaminfo *a_udp,  void **pme, int thread_seq, const void *ip_hdr)
{
	int ret;
	const struct streaminfo_private *a_udp_pr;

	if(0 == gdev_bfd_pkt_identify(a_udp)){
		return APP_STATE_DROPME;
	}

	a_udp_pr = (const struct streaminfo_private *)a_udp;
	ret = gdev_keepalive_udp_plug(a_udp_pr->raw_pkt, a_udp->threadnum, a_udp->routedir);
	if(ret < 0){
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}

int gdev_keepalive_plug_init(void)
{
	char tmp_ip_buf[16];

	if(g_topology_mode != NET_CONN_SERIAL_GDEV){ /* 非G串联模式 */
		sapp_runtime_log(30, "In non-gdev mode, no need to load g_device_plug.so\n");
		return -1;
	}	

	memset(tmp_ip_buf, 0, 16);
	MESA_load_profile_string_nodef((char *)"conf/gdev.conf", (char *)"Module", (char *)"sendto_gdev_ip", tmp_ip_buf, 16);
	if(tmp_ip_buf[0] == '\0'){
		sapp_runtime_log(30, "can't get 'sendto_gdev_ip' \n");
		return -1;
	}

	inet_pton(AF_INET, tmp_ip_buf, &sendto_gdev_card_ip);
	
	return 0;
}

#ifdef __cplusplus
}
#endif
