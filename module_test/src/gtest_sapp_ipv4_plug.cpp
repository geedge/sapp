#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"

//static gtest_plug_stat_t gtest_ipv4_stat;

extern "C" char ipv4_frag_assemble_simple(const struct streaminfo *pstream,
                  unsigned char routedir,int thread_seq, const struct ip *ipv4_hdr)
{
	int ip_len;

	ip_len = ntohs(ipv4_hdr->ip_len);
	if(65151 == ip_len){
		printf("\033[32mSUCC!ipv4 assemble expect len is 65151, actual len is:%d!\033[0m\n", ip_len);
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mexpect ipv4 assemble len is 65151, but actual len is:%d!\033[0m\n", ip_len);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
	}

	return APP_STATE_GIVEME;
}


extern "C" char ipv4_frag_assemble_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int i, ret;
	void *raw_pkt_data;
	const raw_ipfrag_list_t *raw_ipv4_frag_pkt_list;
	const struct ip *raw_ipv4_frag_pkt;
	
	if(pstream->pudpdetail->datalen != 8192){
		printf("\033[1;31;40mipv4_frag_assemble_udp_entry() error, expect ipv4 assemble udp len is 8192, but actual len is:%u!\033[0m\n", pstream->pudpdetail->datalen);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;
	}

	ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &raw_pkt_data);
	if(1 == ret){
		raw_ipv4_frag_pkt_list = (raw_ipfrag_list_t *)raw_pkt_data;
		
		/* 原始包有6个ipv4分片     */
		for(i = 0; i < 6; i++){
			raw_ipv4_frag_pkt = (struct ip *)((char *)raw_ipv4_frag_pkt_list->frag_packet + sizeof(struct ethhdr));
			if(ntohs(raw_ipv4_frag_pkt->ip_id) != 0x4023){
				printf("\033[1;31;40mipv4_frag_assemble_udp_entry() error, raw ip frag pkt index:%d ipid is not 0x4023!\033[0m\n", i);
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
				return APP_STATE_DROPME;		
			}
			if(ntohl(raw_ipv4_frag_pkt->ip_src.s_addr) != 0xC0A82816){
				printf("\033[1;31;40mipv4_frag_assemble_udp_entry() error, raw ip frag pkt src addr is not 192.168.40.22!\033[0m\n");
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
				return APP_STATE_DROPME;	
			}
			raw_ipv4_frag_pkt_list = raw_ipv4_frag_pkt_list->next;
		}
	}else{
		printf("\033[1;31;40mipv4_frag_assemble_udp_entry() error, not found raw ip frag pkt list!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;
	}

	printf("\033[32mipv4_frag_assemble_udp_entry() test succ!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);

	return APP_STATE_DROPME;
}


extern "C" char ipv4_frag_assemble_checksum(const struct streaminfo *pstream,
                  unsigned char routedir,int thread_seq, const struct ip *ipv4_hdr)
{
	int ip_len;
	char tmp_ip_buf[65536];
	const struct ip *after_checksum_iphdr;

	ip_len = ntohs(ipv4_hdr->ip_len);
	if(65151 != ip_len){
		printf("\033[1;31;40mexpect ipv4 assemble len is 65151, but actual len is:%d!\033[0m\n", ip_len);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	memcpy(tmp_ip_buf, ipv4_hdr, 65151);

	sendpacket_do_checksum((unsigned char *)tmp_ip_buf, IPPROTO_IP, sizeof(struct ip));

	after_checksum_iphdr = (struct ip *)tmp_ip_buf;

	if(ipv4_hdr->ip_sum != after_checksum_iphdr->ip_sum){
		printf("\033[1;31;40mraw ip hdr checksum is:0x%x, but expect checksum:0x%x\033[0m\n", ntohs(ipv4_hdr->ip_sum), ntohs(after_checksum_iphdr->ip_sum));
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;
	}

	printf("\033[32mipv4_frag_assemble_checksum() succ!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	
	return APP_STATE_GIVEME;
}


