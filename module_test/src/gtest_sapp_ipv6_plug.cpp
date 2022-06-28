#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"


//static gtest_plug_stat_t gtest_ipv6_stat;


extern "C" char ipv6_frag_assemble_simple(const struct streaminfo *pstream,
				unsigned char routedir,int thread_seq, const struct ip6_hdr *ipv6_hdr)
{
  int ip_len;

  ip_len = ntohs(ipv6_hdr->ip6_plen);
  if(65008 == ip_len){
    printf("\033[32mipv6_frag_assemble_simple() test succ, ip len is:65008!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
  }else{
	sapp_printf("\033[1;31;40mexpect ipv6 assemble len is:%d, but actual len is:%d!\033[0m\n", 65008, ip_len);
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
  }

  return APP_STATE_GIVEME;
}

extern "C" char ipv6_frag_assemble_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int i, ret;
	void *raw_pkt_data;
	const raw_ipfrag_list_t *raw_ipv6_frag_pkt_list;
	const struct ip6_hdr *raw_ipv6_frag_pkt;
	struct in6_addr expect_ip6_src;
	
	if(pstream->pudpdetail->datalen != 8192){
		sapp_printf("\033[1;31;40mipv6_frag_assemble_udp_entry() error, expect ipv6 assemble udp len is 8192, but actual len is:%u!\033[0m\n", pstream->pudpdetail->datalen);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
		return APP_STATE_DROPME;
	}

	ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &raw_pkt_data);
	if(1 == ret){
		raw_ipv6_frag_pkt_list = (raw_ipfrag_list_t *)raw_pkt_data;

		inet_pton(AF_INET6, "2001::192:168:40:22", &expect_ip6_src);
		
		/* 原始包有6个ipv4分片	  */
		for(i = 0; i < 6; i++){
			raw_ipv6_frag_pkt = (struct ip6_hdr *)((char *)raw_ipv6_frag_pkt_list->frag_packet + sizeof(struct ethhdr));
			if(ntohl(raw_ipv6_frag_pkt->ip6_flow) != 0x60098f50){
				sapp_printf("\033[1;31;40mipv6_frag_assemble_udp_entry() error, raw ip frag pkt index:%d ipv6_flow is not 0x60098f50!\033[0m\n", i);
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
				return APP_STATE_DROPME;		
			}
			if(memcmp(&raw_ipv6_frag_pkt->ip6_src, &expect_ip6_src, sizeof(struct in6_addr)) != 0){
				sapp_printf("\033[1;31;40mipv6_frag_assemble_udp_entry() error, raw ip frag pkt src addr is not 2001::192:168:40:22!\033[0m\n");
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
				return APP_STATE_DROPME;	
			}
			raw_ipv6_frag_pkt_list = raw_ipv6_frag_pkt_list->next;
		}
	}else{
		sapp_printf("\033[1;31;40mipv6_frag_assemble_udp_entry() error, not found raw ipv6 frag pkt list!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
		return APP_STATE_DROPME;
	}

	sapp_printf("\033[32mipv6_frag_assemble_udp_entry() test succ!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);

	return APP_STATE_DROPME;
}

