#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "stream_manage.h"
#include "sendpacket.h"
#include "deal_ipv6.h"
#include "packet_io.h"

#if 0
static inline void set_mac_addr(struct layer_addr_mac *addr, const struct mesa_ethernet_hdr *p_eth_hdr)
{
	memcpy(addr->src_mac, p_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(addr->dst_mac, p_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
}


int eth_entry(struct streaminfo *fstream, void *raw_data, 
							int thread_num,  unsigned char dir)
{
	int ret = PASS;
	const struct mesa_ethernet_hdr *p_eth_hdr = (struct mesa_ethernet_hdr *)raw_data;
	unsigned short eth_type = ntohs(p_eth_hdr->ether_type);
	unsigned char *next_layer_data =(unsigned char *)raw_data + sizeof(struct mesa_ethernet_hdr);
	//int next_layer_len = datalen - sizeof(struct ethhdr);

	struct streamindex tmp_index;
	struct streamindex *ptmp = &tmp_index;
	struct layer_addr_mac addr;
	 
	memset(ptmp,0,sizeof(struct streamindex));
	set_mac_addr(&addr, p_eth_hdr);
	ptmp->stream.addr.paddr = &addr;
	ptmp->stream.addr.addrtype = ADDR_TYPE_MAC;

	ptmp->stream.pfather = fstream;
	ptmp->stream.type = STREAM_TYPE_NON;
	ptmp->stream.routedir = dir;
	ptmp->stream.threadnum = thread_num;
	
	switch(eth_type){
		case ETH_P_ARP:
			arp_entry(&(ptmp->stream), next_layer_data,  thread_num, dir);
		break;

		case ETH_P_8021Q:
			vlan_8021q_entry(&(ptmp->stream), next_layer_data, thread_num, dir);
		break;

		case ETH_P_IP:
			ipv4_entry(&(ptmp->stream),  next_layer_data, thread_num, dir);
		break;

		case ETH_P_IPV6:
			ipv6_entry(&(ptmp->stream),  next_layer_data, thread_num, dir);
		break;

		default:
			/* unknown protocol */
			ret = PASS;
		break;
	}

	return ret;
}
#endif


#ifdef __cplusplus
}
#endif


