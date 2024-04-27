#include <assert.h>
#include <sys/select.h>
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

#include "../../include/private/sapp_private_api.h"
extern volatile long long g_current_time_ms;
extern volatile time_t g_current_time;
/* If the Real World time is used, the time difference may be inaccurate due to overload CPU resources, operating system scheduling or other issues. */
extern "C" char iplayer_readjust_time_entry(const struct streaminfo *pstream, unsigned char nouse1, int nouse2, const struct ip *nouse3)
{
	int ret;
	struct timeval cur_pkt_stamp = {};
	static struct timeval first_pkt_stamp = {0,0};
	ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TIMESTAMP, &cur_pkt_stamp);
	if (ret < 0)
	{
		fprintf(stderr, "\033[1;31;40mipv4_adjust_time_entry get pcap timestamp error!\033[0m\n");
		return APP_STATE_DROPME;
	}

	unsigned long long tot_pkt = 0;
	int optlen = sizeof(long long);
	ret = sapp_get_platform_opt(SPO_TOTAL_RCV_PKT, &tot_pkt, &optlen);
	if (ret < 0)
	{
		fprintf(stderr, "\033[1;31;40msapp_get_platform_opt() error!\033[0m\n");
		return APP_STATE_DROPME;
	}

	if (tot_pkt <= 1)
	{
		/* stop background timer thread, and set current time based on the pcap header timestamp */
		pthread_cancel(sapp_global_val->individual_fixed.thread_timer_loop_id);
		usleep(1000 * 100);
		first_pkt_stamp.tv_sec = cur_pkt_stamp.tv_sec;
		first_pkt_stamp.tv_usec = cur_pkt_stamp.tv_usec;
		g_current_time_ms = 0; // set time to PanGu 
		g_current_time = 0;    // set time to PanGu 
		return APP_STATE_GIVEME;
	}

	g_current_time_ms = ((long)cur_pkt_stamp.tv_sec * 1000 + cur_pkt_stamp.tv_usec / 1000) - ((long)first_pkt_stamp.tv_sec * 1000 + first_pkt_stamp.tv_usec / 1000);
	g_current_time = g_current_time_ms / 1000;
	return APP_STATE_GIVEME;
}
