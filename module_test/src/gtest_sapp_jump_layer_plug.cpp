#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include "stream.h"
#include "gtest_sapp_fun.h"
#include "stream_rawpkt.h"


static int jump_check_ipv4_pkt(const struct ip *ip4hdr, int expect_tot_len, unsigned char expect_protocol, const char *expect_src_addr_str, const char *expect_dst_addr_str)
{
	unsigned int expect_src_addr_net, expect_dst_addr_net;
	if(ip4hdr== NULL) return -1;
	/* 简单判断一下ipv4头部是否正确 */
	if(ip4hdr->ip_v != 4){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4 header check version error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}
	if(ip4hdr->ip_p != expect_protocol){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4 header check protocol error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}	
	if(ip4hdr->ip_hl*4 < 20){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4 header check header length error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}			
	if(ntohs(ip4hdr->ip_len) != expect_tot_len){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4 header check length error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}		

	inet_pton(AF_INET, expect_src_addr_str, &expect_src_addr_net);
	if(ip4hdr->ip_src.s_addr != expect_src_addr_net){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4 header check src addr error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}
	inet_pton(AF_INET, expect_dst_addr_str, &expect_dst_addr_net);
	if(ip4hdr->ip_dst.s_addr != expect_dst_addr_net){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4 header check dst addr error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}		

	return 0;
}


static int jump_check_ipv6_pkt(const struct ip6_hdr *ip6h, int expect_payload_len, unsigned char expect_protocol, const char *expect_src_addr_str, const char *expect_dst_addr_str)
{
	if((*(char *)ip6h & 0xF0) != 0x60){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6 header check version error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}
	if(ip6h->ip6_nxt != expect_protocol){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6 header check protocol error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}	
	
	if(ntohs(ip6h->ip6_plen) != expect_payload_len){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6 header check length error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}		
	
	struct in6_addr tmp_ip6_addr;
	inet_pton(AF_INET6, expect_src_addr_str, &tmp_ip6_addr);
	if(memcmp(&tmp_ip6_addr, &ip6h->ip6_src, sizeof(struct in6_addr) ) != 0){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6 header check src addr error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}
	
	inet_pton(AF_INET6, expect_dst_addr_str, &tmp_ip6_addr);
	if(memcmp(&tmp_ip6_addr, &ip6h->ip6_dst, sizeof(struct in6_addr) ) != 0){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6 header check dst addr error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}	

	return 0;
}

static int jump_check_tcp_pkt(const struct tcphdr *thdr, int expect_tcp_hdr_offset, unsigned short expect_sport_host, unsigned short expect_dport_host)
{
	if(thdr== NULL) return -1;
	if(thdr->doff * 4 != expect_tcp_hdr_offset){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): tcp header offset error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}
	if(ntohs(thdr->source) != expect_sport_host){  
		printf("\033[1;31;40mMESA_net_jump_to_layer(): tcp header sport error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}		
	if(ntohs(thdr->dest) != expect_dport_host){  
		printf("\033[1;31;40mMESA_net_jump_to_layer(): tcp header dport error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}

	return 0;
}

static int jump_check_udp_pkt(const struct udphdr *uhdr, unsigned short expect_udp_tot_len, unsigned short expect_sport_host, unsigned short expect_dport_host)
{
	if(uhdr== NULL) return -1;
	if(ntohs(uhdr->len) != expect_udp_tot_len){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): udp header length error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}
	
	if(ntohs(uhdr->source) != expect_sport_host){  
		printf("\033[1;31;40mMESA_net_jump_to_layer(): udp header sport error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}		
	if(ntohs(uhdr->dest) != expect_dport_host){	
		printf("\033[1;31;40mMESA_net_jump_to_layer(): udp header dport error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 
	}	

	return 0;
}

static int jump_check_vlan_pkt(const void *vlan_hdr, unsigned int expect_vlan_hex_data)
{
	if(vlan_hdr == NULL) return -1;
	if(memcmp(vlan_hdr, &expect_vlan_hex_data, sizeof(int)) != 0){
		printf("\033[1;31;40mMESA_net_jump_to_layer(): vlan header error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR); 
		 		
	}

	return 0;
}

extern "C" char jump_layer_eth_ipv4_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->pktstate == OP_STATE_PENDING){
		next_header = MESA_net_jump_to_layer((void *)a_packet, ADDR_TYPE_IPV4, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}	
		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		if(next_header != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ip header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		const struct ip* ip4hdr = (struct ip*)next_header; 

		jump_check_ipv4_pkt(ip4hdr, tot_pkt_len-sizeof(struct ethhdr), IPPROTO_TCP, "192.168.10.250", "192.168.10.234");

		next_header = MESA_net_jump_to_layer((void *)ip4hdr, __ADDR_TYPE_IP_PAIR_V4, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 40, 58725, 22);

		printf("\033[32mjump_layer_eth_ipv4_tcp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}

extern "C" char jump_layer_eth_ipv4_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->opstate == OP_STATE_PENDING){
		next_header = MESA_net_jump_to_layer((void *)a_packet, ADDR_TYPE_IPV4, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		if(next_header != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ip header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		const struct ip* ip4hdr = (struct ip*)next_header; 

		jump_check_ipv4_pkt(ip4hdr, tot_pkt_len-sizeof(struct ethhdr), IPPROTO_UDP, "192.168.210.153", "111.161.107.181");

		next_header = MESA_net_jump_to_layer((void *)ip4hdr, __ADDR_TYPE_IP_PAIR_V4, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		const struct udphdr* uhdr = (struct udphdr *)next_header; 
		jump_check_udp_pkt(uhdr, 155, 4001, 8000);

		printf("\033[32mjump_layer_eth_ipv4_udp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ipv6_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->pktstate == OP_STATE_PENDING){
		next_header = MESA_net_jump_to_layer((void *)a_packet, ADDR_TYPE_IPV6, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv6_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv6_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv6 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		if(next_header != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ip header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		const struct ip6_hdr* ip6h = (struct ip6_hdr *)next_header; 

		jump_check_ipv6_pkt(ip6h, tot_pkt_len - sizeof(struct ethhdr) - sizeof(struct ip6_hdr), IPPROTO_TCP, "2001::192:168:40:134", "2001::192:168:40:133");

		next_header = MESA_net_jump_to_layer((void *)ip6h, __ADDR_TYPE_IP_PAIR_V6, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 40, 37948, 22);

		printf("\033[32mjump_layer_eth_ipv6_tcp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ipv6_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->opstate == OP_STATE_PENDING){
		next_header = MESA_net_jump_to_layer((void *)a_packet, ADDR_TYPE_IPV6, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv6->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv6_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv6_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv6 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		if(next_header != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ip6 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		const struct ip6_hdr* ip6h = (struct ip6_hdr*)next_header; 
		jump_check_ipv6_pkt(ip6h, tot_pkt_len - sizeof(struct ethhdr) - sizeof(struct ip6_hdr), IPPROTO_UDP, "2001::192:168:40:134", "2001::192:168:40:133");

		next_header = MESA_net_jump_to_layer((void *)ip6h, __ADDR_TYPE_IP_PAIR_V6, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): ipv4->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		const struct udphdr* uhdr = (struct udphdr *)next_header; 
		jump_check_udp_pkt(uhdr, 10, 33225, 31337);

		printf("\033[32mjump_layer_eth_ipv6_udp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ipv4_gtp_ipv4_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->pktstate == OP_STATE_PENDING){		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ipv4_gtp_ipv4_tcpall_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ipv4_gtp_ipv4_tcpall_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4); /* 外层ipv4 */
		if(NULL == next_header){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): eth->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}				
		const struct ip* outer_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(outer_ip4hdr, 76, IPPROTO_UDP, "10.166.20.10", "10.2.3.35");


		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_GPRS_TUNNEL); /* gtp层 */
		if(NULL == next_header){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): eth->ipv4->gtp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		const struct gtp_hdr *net_gtp_hdr = (struct gtp_hdr *)next_header;
		if (net_gtp_hdr)
		{
			if (net_gtp_hdr->flags != 0x30)
			{
				printf("\033[1;31;40m gtp hdr flags is not 0x30!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
			if (net_gtp_hdr->msg_type != 0xFF)
			{
				printf("\033[1;31;40m gtp hdr msg_type is not 0xFF!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
			if (ntohs(net_gtp_hdr->len) != 40)
			{
				printf("\033[1;31;40m gtp hdr length is not 40!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
			if (ntohl(net_gtp_hdr->teid) != 0xb68311b)
			{
				printf("\033[1;31;40m gtp hdr teid is not 0xb68311b!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
		}

		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4); /* 内层ipv4 */
		if(NULL == next_header){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): eth->ipv4->gtp->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}	
		const struct ip* inner_ip4hdr = (struct ip*)next_header; 
		if(next_header != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): inner ip header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		jump_check_ipv4_pkt(inner_ip4hdr, 40, IPPROTO_TCP, "10.58.121.62", "217.76.78.112");


		next_header = MESA_net_jump_to_layer((void *)pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->gtp->ipv4->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 20, 52144, 443);

		printf("\033[32mjump_layer_eth_ipv4_gtp_ipv4_tcpall_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ipv4_pptp_ipv4_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->pktstate == OP_STATE_PENDING){		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip* outer_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(outer_ip4hdr, 88, IPPROTO_GRE, "172.16.0.100", "172.16.0.254");


		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->pptp->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}	
		const struct ip* inner_ip4hdr = (struct ip*)next_header; 
		if(next_header != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): inner ip header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		jump_check_ipv4_pkt(inner_ip4hdr, 52, IPPROTO_TCP, "172.16.2.100", "10.0.6.229");


		next_header = MESA_net_jump_to_layer((void *)pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->pptp->ipv4->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 32, 50072, 80);

		printf("\033[32mjump_layer_eth_ipv4_pptp_ipv4_tcpall_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}

extern "C" char jump_layer_eth_ip4_l2tp_ip4_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->pktstate == OP_STATE_PENDING){
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4); 
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}	
		const struct ip* outer_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(outer_ip4hdr, 92, IPPROTO_UDP, "172.16.0.100", "172.16.0.254");


		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_L2TP); 
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->l2tp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		const struct l2tp_hdr_v2 *p_l2tp_hdr = (struct l2tp_hdr_v2 *)next_header;
		if (p_l2tp_hdr)
		{
			if (p_l2tp_hdr->length_present != 1)
			{
				printf("\033[1;31;40mMESA_net_jump_to_layer():l2tp header length flag is not 1!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
			if (p_l2tp_hdr->version != 2)
			{
				printf("\033[1;31;40mMESA_net_jump_to_layer():l2tp header version is not 2!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
			const unsigned short *short_ptr = (unsigned short *)((char *)next_header + sizeof(struct l2tp_hdr_v2));
			if (ntohs(*short_ptr) != 64)
			{
				printf("\033[1;31;40mMESA_net_jump_to_layer():l2tp header lenth is not 64!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
			short_ptr++;
			if (ntohs(*short_ptr) != 28998)
			{
				printf("\033[1;31;40mMESA_net_jump_to_layer():l2tp header tunnel id is not 28998!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
			short_ptr++;
			if (ntohs(*short_ptr) != 2)
			{
				printf("\033[1;31;40mMESA_net_jump_to_layer():l2tp header session id is not 2!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
			}
		}
		/* 跳转到内层ipv4需要用greedy接口 */
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->l2tp->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
		}		
		const struct ip* inner_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(inner_ip4hdr, 52, IPPROTO_TCP, "172.16.2.100", "10.0.6.229");		

		if(inner_ip4hdr != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): inner ip4 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		
		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->l2tp->ipv4->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		
		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 32, 49250, 80);

		printf("\033[32mjump_layer_eth_ip4_l2tp_ip4_tcpall_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ip4_l2tp_ip4_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret, opt_len;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	unsigned short tunnel_type = STREAM_TUNNLE_NON;
	
	if(pstream->opstate == OP_STATE_PENDING){

		opt_len = sizeof(short);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
		if((ret < 0) || (tunnel_type != STREAM_TUNNLE_L2TP)){
			return APP_STATE_DROPME; /* l2tp隧道外层udp流, 不处理 */
		}
		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}	

		/* 跳转到内层ipv4需要用greedy接口 */
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->l2tp->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		const struct ip* inner_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(inner_ip4hdr, 66, IPPROTO_UDP, "172.16.2.100", "8.8.8.8");		

		if(inner_ip4hdr != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): inner ip4 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->l2tp->ipv4->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		
		const struct udphdr* uhdr = (struct udphdr *)next_header; 
		jump_check_udp_pkt(uhdr, 46, 53483, 53);

		printf("\033[32m jump_layer_eth_ip4_l2tp_ip4_udp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	int opt_len;
	unsigned short tunnel_type = STREAM_TUNNLE_NON;
	
	if(pstream->pktstate == OP_STATE_PENDING){
		opt_len = sizeof(short);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
		if((ret < 0) || (tunnel_type != STREAM_TUNNLE_L2TP)){
			return APP_STATE_DROPME; /* l2tp隧道外层udp流, 不处理 */
		}
	
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		/* 跳转到内层ipv4需要用greedy接口 */
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): eth->ipv4->l2tp->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip* inner_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(inner_ip4hdr, 1378, IPPROTO_UDP, "10.24.0.36", "64.233.185.99");		

		if(inner_ip4hdr != a_packet){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): inner ip4 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->udp->l2tp->ipv4->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		
		const struct udphdr* uhdr = (struct udphdr *)next_header; 
		jump_check_udp_pkt(uhdr, 1358, 52139, 443);

		printf("\033[32m jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ipv4_gre_ipv4_gre_ipv4_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->opstate == OP_STATE_PENDING){
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip* outer_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(outer_ip4hdr, 124, IPPROTO_GRE, "115.153.75.246", "122.112.114.66");
		

		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->gre->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip* inner_ip4hdr = (struct ip*)next_header; 
		if(inner_ip4hdr != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): inner ip header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		jump_check_ipv4_pkt(inner_ip4hdr, 72, IPPROTO_UDP, "122.112.114.73", "115.238.253.235");

		next_header = MESA_net_jump_to_layer((void *)pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->gre->ipv4->gre->ipv4->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		const struct udphdr* uhdr = (struct udphdr *)next_header; 
		jump_check_udp_pkt(uhdr, 52, 20755, 53);

		printf("\033[32mjump_layer_eth_ipv4_gre_ipv4_gre_ipv4_udp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_vlan_ip6_ip4_pptp_ip4_ip6_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	
	if(pstream->pktstate == OP_STATE_PENDING){		
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40mjump_layer_eth_ipv4_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_VLAN);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->vlan error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		jump_check_vlan_pkt(next_header, htonl(0x006486DD));

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->vlan->ipv6 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		jump_check_ipv6_pkt((const ip6_hdr *)next_header, 1412, 4, "2607:fcd0:100:2300::b108:2a6b", "2402:f000:1:8e01::5555");

		next_header = MESA_net_jump_to_layer(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->vlan->ipv6->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}	
		const struct ip* outer_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(outer_ip4hdr, 1412, IPPROTO_GRE, "192.52.166.154", "16.0.0.200");

		/* 跳转到内层ipv4需要用greedy接口 */
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->vlan->ipv6->ipv4->pptp->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip* inner_ip4hdr = (struct ip*)next_header; 
		jump_check_ipv4_pkt(inner_ip4hdr, 1376, IPPROTO_TCP, "173.194.72.18", "172.16.44.3");		

		if(inner_ip4hdr != a_packet){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): inner ip4 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->vlan->ipv6->ipv4->pptp->ipv4->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		
		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 20, 443, 56461);

		printf("\033[32mjump_layer_eth_vlan_ip6_ip4_pptp_ip4_ip6_tcpall_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ip4_udp_teredo_udp_ip6_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	int opt_len;
	unsigned short tunnel_type = STREAM_TUNNLE_NON;
	
	if(pstream->pktstate == OP_STATE_PENDING){
		opt_len = sizeof(short);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
		if((ret < 0) || (tunnel_type != STREAM_TUNNLE_TEREDO)){
			return APP_STATE_DROPME; /*teredo隧道外层udp流, 不处理 */
		}
	
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ip4_udp_teredo_udp_ip6_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ip4_udp_teredo_udp_ip6_tcp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		/* 跳转到内层ipv6需要用greedy接口 */
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
		if(NULL == next_header){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): eth->ipv4->teredo->ipv6 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip6_hdr* inner_ip6hdr = (struct ip6_hdr*)next_header; 
		jump_check_ipv6_pkt(inner_ip6hdr, 489, IPPROTO_TCP, "2001:0:4137:9E76:2463:F227:88D7:DABE", "2001:252:0:2::2000");		

		if(inner_ip6hdr != a_packet){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): inner ip6 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->udp->teredo->ipv6->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		
		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 20, 63622, 80);

		printf("\033[32m jump_layer_eth_ip4_udp_teredo_udp_ip6_tcp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}


extern "C" char jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	int opt_len;
	unsigned short tunnel_type = STREAM_TUNNLE_NON;
	
	if(pstream->opstate == OP_STATE_PENDING){
		opt_len = sizeof(short);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
		if((ret < 0) || (tunnel_type != STREAM_TUNNLE_TEREDO)){
			return APP_STATE_DROPME; /*teredo隧道外层udp流, 不处理 */
		}
	
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		/* 跳转到内层ipv6需要用greedy接口 */
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
		if(NULL == next_header){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): eth->ipv4->teredo->ipv6 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip6_hdr* inner_ip6hdr = (struct ip6_hdr*)next_header; 
		jump_check_ipv6_pkt(inner_ip6hdr, 56, IPPROTO_UDP, "FE80::8000:F227:3EFF:FFFE", "FE80::FFFF:FFFF:FFFF");		

		if(inner_ip6hdr != a_packet){
			printf("\033[1;31;40m MESA_net_jump_to_layer(): inner ip6 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_UDP);
		if(NULL == next_header){
			printf("\033[1;31;40mMESA_net_jump_to_layer(): eth->ipv4->udp->teredo->ipv6->udp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		
		const struct udphdr* uhdr = (struct udphdr *)next_header; 
		jump_check_udp_pkt(uhdr, 56, 32768, 20480);

		printf("\033[32m jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}

extern "C" char jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int tot_pkt_len;
	const void *pkt_header;
	const void *next_header;
	int opt_len;
	unsigned short tunnel_type = STREAM_TUNNLE_NON;
	
	if(pstream->pktstate == OP_STATE_PENDING){
		opt_len = sizeof(short);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
		if((ret < 0) || (tunnel_type != STREAM_TUNNEL_GPRS_TUNNEL)){
			return APP_STATE_DROPME; 
		}
	
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &pkt_header);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_DATA error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);		
			 
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &tot_pkt_len);
		if(ret < 0){
			printf("\033[1;31;40m jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry(), get_rawpkt_opt_from_streaminfo()->RAW_PKT_GET_TOT_LEN error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		

		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
		if(NULL == next_header){
			printf("\033[1;31;40m jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry(): eth->vlan->ipv6 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		const struct ip6_hdr* inner_ip6hdr = (struct ip6_hdr*)next_header; 
		jump_check_ipv6_pkt(inner_ip6hdr, 64, IPPROTO_UDP, "2409:8034:4025::1:941", "2409:8034:4040:5300::205");		


		const struct ip * inner_ip4hdr;
		inner_ip4hdr = ( struct ip *)MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
		if(NULL == inner_ip4hdr){
			printf("\033[1;31;jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry(): eth->ipv6->udp->gtp->ipv4 error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}				
		if(inner_ip4hdr != a_packet){
			printf("\033[1;31;40m jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry(): inner ip4 header is not equal with plug_entry->a_packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}
		
		next_header = MESA_net_jump_to_layer_greedy(pkt_header, ADDR_TYPE_MAC, ADDR_TYPE_TCP);
		if(NULL == next_header){
			printf("\033[1;31;jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry(): eth->ipv6->udp->gtp->ipv6->tcp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			 
		}		
		
		const struct tcphdr* thdr = (struct tcphdr *)next_header; 
		jump_check_tcp_pkt(thdr, 20, 47892, 80);

		printf("\033[32m jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_DROPME;
}

