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
#include "stream_inc/gdev_keepalive.h"
#include "gtest_sapp_fun.h"

extern "C" char tcpall_pkt_stat(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet);
extern "C" char tcp_pkt_stat(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet);

extern gtest_plug_stat_t gtest_tcp_stat;
extern gtest_plug_stat_t gtest_tcpall_stat;

static void build_rst_tcp_paras(struct rst_tcp_para *inject_paras, unsigned char send_dir)
{
	memset(inject_paras, 0, sizeof(struct rst_tcp_para));
	
	inject_paras->th_flags = 0x14;
	inject_paras->rst_pkt_num = 1;
	inject_paras->dir = send_dir;
	inject_paras->signature_seed1 = 65535;
	inject_paras->signature_seed2 = 13;	
}


extern "C" char inline_rst_c2s_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct rst_tcp_para inject_paras = {};

	build_rst_tcp_paras(&inject_paras, DIR_C2S);

	/* 此处只发送错误结果, 注入数据包是否正确, 在 __tcp_inject_rst_reverse_gre_v0() 函数检查 */
	if(MESA_rst_tcp(pstream, &inject_paras, sizeof(struct rst_tcp_para)) < 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_rst_c2s_entry","\033[1;31;40mMESA_rst_tcp() C2S error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME | APP_STATE_DROPPKT;;
	}else{
		SAPP_PLUG_LOG(RLOG_LV_DEBUG,"inline_rst_c2s_entry", "MESA_rst_tcp C2S success!");
	}

	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}


extern "C" char inline_rst_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct rst_tcp_para inject_paras = {};
	
	build_rst_tcp_paras(&inject_paras, DIR_S2C);

	if(MESA_rst_tcp(pstream, &inject_paras, sizeof(struct rst_tcp_para)) < 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_rst_s2c_entry", "\033[1;31;40mMESA_rst_tcp() S2C error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}else{
		SAPP_PLUG_LOG(RLOG_LV_DEBUG,"inline_rst_s2c_entry", "MESA_rst_tcp S2C success!");
	}

	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}

extern "C" char inline_inject_payload_reverse_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(sapp_inject_pkt(pstream, SIO_DEFAULT, GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), pstream->routedir ^ 1) < 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_inject_payload_reverse_entry","\033[1;31;40minline_inject_payload_reverse_entry() : sapp_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}


/*
	vxlan模式下, 外层的ip属于overlay层, 普通ip插件不能被调用, 不应该看到10.3.36.1的IP层.
*/
extern "C" char vxlan_ip_plug_entry_not_call(const struct streaminfo *pstream,
                  unsigned char routedir,int thread_seq, const struct ip *ipv4_hdr)
{
	const char *vxlan_outer_sip = "10.3.36.1";
	const char *vxlan_outer_dip = "10.3.127.1";
	unsigned int sip, dip;

	inet_pton(AF_INET, vxlan_outer_sip, &sip);
	inet_pton(AF_INET, vxlan_outer_dip, &dip);

	if((ipv4_hdr->ip_src.s_addr == sip)
	 ||(ipv4_hdr->ip_src.s_addr == dip)
	 ||(ipv4_hdr->ip_dst.s_addr == sip)
	 ||(ipv4_hdr->ip_dst.s_addr == dip)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "inline_mode.ip_plug_entry_not_call","\033[1;31;40mvxlan_ip_plug_entry_not_call() error, recv ip addr:0x%x-->0x%x\033[0m\n", 
				ntohl(ipv4_hdr->ip_src.s_addr), ntohl(ipv4_hdr->ip_dst.s_addr));
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	 }

	SAPP_PLUG_LOG(RLOG_LV_INFO, "inline_mode.ip_plug_entry_not_call","\033[32m inline_mode.ip_plug_entry_not_call test success!\033[0m\n");
	fprintf(stderr,"\033[32m inline_mode.ip_plug_entry_not_call test success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
	exit(0);
	return APP_STATE_GIVEME;
}

/*
  vxlan模式下, 外层的udp属于overlay层, 普通udp插件不能被调用.
  内层的114.114.114.114 dns包可以被调用.
*/
extern "C" char vxlan_udp_plug_entry_not_call(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const unsigned short raw_pcap_sport=50709, raw_pcap_dport=4789;
	unsigned short stream_sport = ntohs(pstream->addr.tuple4_v4->source);
	unsigned short stream_dport = ntohs(pstream->addr.tuple4_v4->dest);

	if((stream_sport == raw_pcap_sport)
	||(stream_sport == raw_pcap_dport)
	||(stream_dport == raw_pcap_sport)
	||(stream_dport == raw_pcap_dport)){
	  SAPP_PLUG_LOG(RLOG_LV_FATAL,"vxlan_udp_plug_entry_not_call", "\033[1;31;40mvxlan_udp_plug_entry_not_call() error, recv sport:%u, dport:%u\033[0m\n", stream_sport, stream_dport);
	  gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
	  return APP_STATE_DROPME;
	}else if((stream_sport != 65290) || (stream_dport != 53)){
	  SAPP_PLUG_LOG(RLOG_LV_FATAL,"vxlan_udp_plug_entry_not_call","\033[1;31;40mvxlan_udp_plug_entry_not_call() error, recv sport:%u, dport:%u\033[0m\n", stream_sport, stream_dport);
	  gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
	  return APP_STATE_DROPME;	
	}else if(pstream->addr.tuple4_v4->daddr != 0x72727272){ /* dns server 114.114.114.114 */
	  SAPP_PLUG_LOG(RLOG_LV_FATAL,"vxlan_udp_plug_entry_not_call","\033[1;31;40mvxlan_udp_plug_entry_not_call() error, recv ip adress is not 114.114.114.114\033[0m\n");
	  gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
	  return APP_STATE_DROPME;		
	}
	if(OP_STATE_CLOSE == pstream->opstate){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"vxlan_udp_plug_entry_not_call","\033[32m inline_mode.udp_plug_entry_not_call test success!\033[0m\n");
		fprintf(stderr,"\033[32m inline_mode.udp_plug_entry_not_call test success!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
		exit(0);
	}
	return APP_STATE_GIVEME;
}


extern "C" char inline_vxlan_header_parse_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
	const struct streaminfo_private *pstream_vxlan_pr =  pstream_pr->pfather_pr->pfather_pr;
	const struct single_layer_addr_vxlan *c2s_vxlan_addr = &pstream_vxlan_pr->stream_public.addr.vxlan->C2S_vxlan_addr;
	const struct single_layer_addr_vxlan *s2c_vxlan_addr = &pstream_vxlan_pr->stream_public.addr.vxlan->S2C_vxlan_addr;
	
	if(DIR_C2S == pstream->curdir){
		if(c2s_vxlan_addr->dir != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry", "\033[1;31;40minline_vxlan_header_parse_entry() error, dir is:%d, expect is:%d\033[0m\n", c2s_vxlan_addr->dir, 1);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(htons(c2s_vxlan_addr->vlan_id) != 122){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry","\033[1;31;40minline_vxlan_header_parse_entry() error, vlanid is:%d, expect is:%d\033[0m\n", htons(c2s_vxlan_addr->vlan_id), 122);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(c2s_vxlan_addr->link_id != 3){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry","\033[1;31;40minline_vxlan_header_parse_entry() error, link_id is:%d, expect is:%d\033[0m\n", c2s_vxlan_addr->link_id, 3);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(c2s_vxlan_addr->link_type != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry","\033[1;31;40minline_vxlan_header_parse_entry() error, link_type is:%d, expect is:%d\033[0m\n", c2s_vxlan_addr->link_id, 0);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}			
	}else{
		if(s2c_vxlan_addr->dir != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry","\033[1;31;40minline_vxlan_header_parse_entry() error, dir is:%d, expect is:%d\033[0m\n", s2c_vxlan_addr->dir, 0);
			sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
		if(htons(s2c_vxlan_addr->vlan_id) != 122){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry","\033[1;31;40minline_vxlan_header_parse_entry() error, vlanid is:%d, expect is:%d\033[0m\n", htons(s2c_vxlan_addr->vlan_id), 122);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(s2c_vxlan_addr->link_id != 3){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry","\033[1;31;40minline_vxlan_header_parse_entry() error, link_id is:%d, expect is:%d\033[0m\n", s2c_vxlan_addr->link_id, 3);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(s2c_vxlan_addr->link_type != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_vxlan_header_parse_entry","\033[1;31;40minline_vxlan_header_parse_entry() error, link_type is:%d, expect is:%d\033[0m\n", s2c_vxlan_addr->link_id, 0);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		/* 就两个测试包, S2C方向测试完后, 可以发送结果了, 不用等到超时了 */
		SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_vxlan_header_parse_entry","\033[32m inline_mode.vxlan_header test succ!\033[0m\n");
		fprintf(stderr,"\033[32m inline_mode.vxlan_header test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
		exit(0);
		return APP_STATE_DROPME;
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char vxlan_udp_plug_drop_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}


extern "C" char inline_layer_addr_prefix_ntop_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const char *layer_type_string;

	layer_type_string = layer_addr_prefix_ntop(pstream);
	if(strncasecmp(layer_type_string, "IPv4_TCP", strlen("IPv4_TCP")) != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_layer_addr_prefix_ntop_entry", "\033[1;31;40minline_layer_addr_prefix_ntop_entry() error, tuple4 tcp layer ntop error!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	pstream = pstream->pfather;

	layer_type_string = layer_addr_prefix_ntop(pstream);
	if(strncasecmp(layer_type_string, "MAC", strlen("MAC")) != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_layer_addr_prefix_ntop_entry","\033[1;31;40minline_layer_addr_prefix_ntop_entry() error, inner ethernet layer ntop error!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}	
	pstream = pstream->pfather;
	
	/* inline模式下, 再底层的地址是看不到的, 此处应该是NULL才对 */
	if((pstream != NULL) && (ADDR_TYPE_VXLAN == pstream->addr.addrtype)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_layer_addr_prefix_ntop_entry","\033[1;31;40minline_layer_addr_prefix_ntop_entry() error, vxlan layer is visible!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}	

	SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_layer_addr_prefix_ntop_entry","\033[32minline_mode.layer_addr_ntop test succ!\033[0m\n");
	fprintf(stderr,"\033[32minline_mode.layer_addr_ntop test succ!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
	exit(0);

	return APP_STATE_DROPME;
}



extern "C" char inline_stream_addr_ntop_entry(struct streaminfo *stream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	char addr_list_str[4096];
	char addr_list_str_recover[4096];
	struct streaminfo recover_stream[16];

	if(OP_STATE_PENDING == stream->pktstate){
		ret = stream_addr_list_ntop(stream, addr_list_str, 4096);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_addr_ntop_entry", "stream_addr_list_ntop ret = %d\n", ret);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_addr_ntop_entry","	raw-addr-list len is:\t%d, value:\t%s\n", ret, addr_list_str);
		ret = stream_addr_list_pton(addr_list_str, recover_stream, sizeof(struct streaminfo)*16, stream->threadnum);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_addr_ntop_entry","stream_addr_list_pton ret = %d\n", ret);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		

		if(thread_seq != recover_stream[0].threadnum){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_addr_ntop_entry","stream_addr_list_pton threadnum is not match!\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		ret =  stream_addr_list_ntop(recover_stream, addr_list_str_recover, 4096);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_addr_ntop_entry","stream_addr_list_ntop ret = %d\n", ret);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		

		if(strncasecmp(addr_list_str, addr_list_str_recover, 4096) != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_addr_ntop_entry","stream_addr_list not same!\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_stream_addr_ntop_entry","\033[32m inline_stream_addr_ntop_entry() test succ!\033[0m\n");
		fprintf(stderr,"\033[32m inline_stream_addr_ntop_entry() test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
		exit(0);
	}

	return APP_STATE_GIVEME;
}


extern "C" char inline_tcpall_simple(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(pstream->pktstate == OP_STATE_CLOSE){
		if((1 == gtest_tcpall_stat.C2S_all_pkt)
		 &&(0 == gtest_tcpall_stat.C2S_all_byte)
		 &&(1 == gtest_tcpall_stat.S2C_all_pkt)
		 &&(0 == gtest_tcpall_stat.S2C_all_byte)){
		 	SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_tcpall_simple", "\033[32m inline_tcpall_simple() test succ!\033[0m\n");
			fprintf(stderr,"\033[32m inline_tcpall_simple() test succ!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
			exit(0);
		}else{
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_tcpall_simple","\033[1;31;40minline_tcpall_simple(): check data error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		}
	}else{
		tcpall_pkt_stat(pstream, pme, thread_seq, a_packet);
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char inline_stream_pfather_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(pstream->addr.addrtype != ADDR_TYPE_IPV4){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_pfather_entry","\033[1;31;40maddr type is not tuple4v4!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}
	pstream = pstream->pfather;
	if(pstream->addr.addrtype != ADDR_TYPE_MAC){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_pfather_entry","\033[1;31;40maddr type is not mac!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	

	/* 紧挨着ADDR_TYPE_IPV4的MAC层, 是普通插件能看到的最底层,   vxlan层不可见 */
	pstream = pstream->pfather;
	if(pstream != NULL){
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_stream_pfather_entry","\033[1;31;40mpstream is not NULL, has overlay protocol!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;	
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_stream_pfather_entry","\033[32m inline_mode.stream_pfather test succ!\033[0m\n");
	fprintf(stderr,"\033[32m inline_mode.stream_pfather test succ!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
	exit(0);
	return APP_STATE_DROPME;
}


extern "C" char inline_plug_stat_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{	
	unsigned long long stat_val;
	int stat_val_len = sizeof(long long);
	
	if(pstream->opstate != OP_STATE_CLOSE){
		tcp_pkt_stat(pstream, pme, thread_seq, a_packet);
	}else{
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, &stat_val, &stat_val_len);
		if(stat_val != 3){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_plug_stat_tcp_entry","\033[1;31;40minline_plug_stat_tcp_entry: inbound pkt is:%llu, but expect:%d\033[0m\n", stat_val, 3);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, &stat_val, &stat_val_len);
		if(stat_val != 3){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_plug_stat_tcp_entry","\033[1;31;40minline_plug_stat_tcp_entry: outbound pkt is:%llu, but expect:%d\033[0m\n", stat_val, 3);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}		

		sapp_get_platform_opt(SPO_TOTAL_INBOUND_BYTE, &stat_val, &stat_val_len);
		if(stat_val != 451){ /* 这个包的内层ethernet有6个字节的triller */
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_plug_stat_tcp_entry","\033[1;31;40minline_plug_stat_tcp_entry: inbound byte is:%llu, but expect:%d\033[0m\n", stat_val, 451);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_BYTE, &stat_val, &stat_val_len);
		if(stat_val != 366){ /* 这个包的内层ethernet有6个字节的triller */
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_plug_stat_tcp_entry","\033[1;31;40minline_plug_stat_tcp_entry: outbound byte is:%llu, but expect:%d\033[0m\n", stat_val, 366);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}	

		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV4_BYTE, &stat_val, &stat_val_len);
		if(stat_val != 403){  
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_plug_stat_tcp_entry","\033[1;31;40minline_plug_stat_tcp_entry: inbound ipv4 byte is:%llu, but expect:%d\033[0m\n", stat_val, 403);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV4_BYTE, &stat_val, &stat_val_len);
		if(stat_val != 318){  
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_plug_stat_tcp_entry","\033[1;31;40minline_plug_stat_tcp_entry: outbound ipv4 byte is:%llu, but expect:%d\033[0m\n", stat_val, 318);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}	

		if((1 == gtest_tcp_stat.C2S_data_pkt)
		 &&(186 == gtest_tcp_stat.C2S_data_byte)
		 &&(1 == gtest_tcp_stat.S2C_data_pkt)
		 &&(271 == gtest_tcp_stat.S2C_data_byte)){
		 	SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_plug_stat_tcp_entry","\033[32minline_mode.plug_stat test success!\033[0m\n");
			 fprintf(stderr,"\033[32minline_mode.plug_stat test success!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
			exit(0);
		}else{
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_plug_stat_tcp_entry","\033[1;31;40minline_plug_stat_tcp_entry: check stat error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		}
	}
	
	return APP_STATE_GIVEME;
}




extern "C" char inline_asymmetric_vxlan_addr_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{	
	unsigned long long stat_val;
	int stat_val_len = sizeof(long long);
	gtest_plug_stat_t *plug_status;

	if(OP_STATE_PENDING == pstream->pktstate){
		plug_status = (gtest_plug_stat_t *)calloc(1, sizeof(gtest_plug_stat_t));
		*pme = plug_status;
	}

	plug_status = (gtest_plug_stat_t *)(*pme);

	if(a_packet){
		if(DIR_C2S == pstream->curdir){
			plug_status->C2S_all_pkt++;
			plug_status->C2S_all_byte += pstream->ptcpdetail->datalen;
		}else{
			plug_status->S2C_all_pkt++;
			plug_status->S2C_all_byte += pstream->ptcpdetail->datalen;
		}
	}	

	if(pstream->pktstate == OP_STATE_CLOSE){
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, &stat_val, &stat_val_len);
		if(stat_val != 3){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"asymmetric_vxlan_addr_tcpall_entry","\033[1;31;40minline_plug_stat_tcp_entry: inbound pkt is:%llu, but expect:%d\033[0m\n", stat_val, 3);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, &stat_val, &stat_val_len);
		if(stat_val != 3){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"asymmetric_vxlan_addr_tcpall_entry","\033[1;31;40minline_plug_stat_tcp_entry: outbound pkt is:%llu, but expect:%d\033[0m\n", stat_val, 3);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}		
		
		if((3 == plug_status->C2S_all_pkt)
		 &&(186 == plug_status->C2S_all_byte)
		 &&(3 == plug_status->S2C_all_pkt)
		 &&(271 == plug_status->S2C_all_byte)){
		 	SAPP_PLUG_LOG(RLOG_LV_INFO,"asymmetric_vxlan_addr_tcpall_entry","\033[32minline_asymmetric_vxlan_addr test succ!\033[0m\n");
			 fprintf(stderr,"\033[32minline_asymmetric_vxlan_addr test succ!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
			exit(0);
		}else{
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"asymmetric_vxlan_addr_tcpall_entry","\033[1;31;40masymmetric_vxlan_addr check stat error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		}

		free(plug_status);
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char inline_polling_timeout_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* 此处简单一点, 直接用个static变量, 不用真正存pme里 */
	static time_t pending_time, close_time;
	
	if(OP_STATE_PENDING == pstream->opstate){
		pending_time = time(NULL);
	}else if(OP_STATE_CLOSE == pstream->opstate){
		close_time = time(NULL);
		if(close_time - pending_time <= 4){ /* sapp.toml timeout是3秒, 此处留一些富余量, 小于4秒认为是正确的 */
			SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_polling_timeout_entry","\033[32m inline_mode.polling_timeout(TCP or UDP) test success, timeout is:%u!\033[0m\n", close_time - pending_time);
			fprintf(stderr,"\033[32minline_mode.polling_timeout test success!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);		
			exit(0);	
		}else{
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_polling_timeout_entry","\033[1;31;40minline_mode.polling_timeout(TCP or UDP) test error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
	}

	return APP_STATE_GIVEME;
}

extern "C" char inline_polling_timeout_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	static time_t pending_time, close_time;
	
	if(OP_STATE_PENDING == pstream->pktstate){
		pending_time = time(NULL);
	}else if(OP_STATE_CLOSE == pstream->pktstate){
		close_time = time(NULL);
		if(close_time - pending_time <= 4){ /* sapp.toml timeout是3秒, 此处留一些富余量, 小于4秒认为是正确的 */
			SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_polling_timeout_tcpall_entry","\033[32m inline_mode.polling_timeout_tcp test success, timeout is:%ld!\033[0m\n", close_time - pending_time);
			fprintf(stderr,"\033[32minline_mode.polling_timeout_tcp test success!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);		
			exit(0);	
		}else{
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_polling_timeout_tcpall_entry","\033[1;31;40mpolling timeout test error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
	}

	return APP_STATE_GIVEME;
}

extern "C" char inline_cheat_dup_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if (pstream->opstate == OP_STATE_CLOSE)
	{
		if ((2 == pstream->ptcpdetail->serverpktnum) 
		&& (186 == pstream->ptcpdetail->serverbytes) 
		&& (2 == pstream->ptcpdetail->clientpktnum) 
		&& (271 == pstream->ptcpdetail->clientbytes))
		{
			SAPP_PLUG_LOG(RLOG_LV_INFO, "inline_cheat_dup_tcp_entry", 
						"\033[32minline_cheat_dup_tcp_entry test succ!\033[0m\n");
			fprintf(stderr, "\033[32minline_cheat_dup_tcp_entry test succ!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
			exit(0);
		}
		else
		{
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "inline_cheat_dup_tcp_entry", 
						"\033[1;31;40minline_cheat_dup_tcp_entry(): check tcp stat error!\
						serverpktnum=%u,serverbytes=%u,clientpktnum=%u,clientbytes=%u.\033[0m\n",
						pstream->ptcpdetail->serverpktnum, pstream->ptcpdetail->serverbytes,
						pstream->ptcpdetail->clientpktnum, pstream->ptcpdetail->clientbytes);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		}
	}

	return APP_STATE_GIVEME;
}


static char inline_dup_inject_pkt_comm_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet, unsigned char stream_op_state)
{
	const char *test_inject_dup_payload = "^test_inject_dup_payload string$";
	
	if(pstream->ptcpdetail->pdata && pstream->ptcpdetail->datalen){
		//printf("\n------------------- plug recv payload:-------------------\n%s\n", (char *)pstream->ptcpdetail->pdata);
		if(MESA_inject_pkt(pstream, test_inject_dup_payload, strlen(test_inject_dup_payload), a_packet, pstream->routedir) < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_dup_inject_pkt_comm_entry", "\033[1;31;40m MESA_inject_pkt() error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;		
		}

		/* 收到了自身注入的数据包! */
		if((strncmp((char *)pstream->ptcpdetail->pdata, (char *)test_inject_dup_payload, strlen(test_inject_dup_payload)) == 0)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_dup_inject_pkt_comm_entry","\033[1;31;40m inline_dup_inject_entry() error: recv inject pkt by myself!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}
	}

	if(stream_op_state == OP_STATE_CLOSE){
		SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_dup_inject_pkt_comm_entry","\033[32m stream:%s closed, inline_dup_inject_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));
		fprintf(stderr,"\033[32m stream:%s closed, inline_dup_inject_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
		exit(0);
		return APP_STATE_DROPME;
	}


	return APP_STATE_GIVEME;
}


extern "C" char inline_dup_inject_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{	
	return inline_dup_inject_pkt_comm_entry(pstream, pme, thread_seq, a_packet, pstream->pktstate);
}


extern "C" char inline_dup_inject_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	return inline_dup_inject_pkt_comm_entry(pstream, pme, thread_seq, a_packet, pstream->opstate);
}


extern "C" char inline_ssdp_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_CLOSE == pstream->opstate){
		if(ntohs(pstream->addr.tuple4_v4->source) != 50884){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ssdp_udp_entry", "\033[1;31;40m inline_ssdp_udp_entry() error: source port is not 50884!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;			
		}
		if(ntohs(pstream->addr.tuple4_v4->dest) != 1900){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ssdp_udp_entry","\033[1;31;40m inline_ssdp_udp_entry() error: dest port is not 1900!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;			
		}	

		if(pstream->pudpdetail->serverpktnum != 3){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ssdp_udp_entry","\033[1;31;40m inline_ssdp_udp_entry() error: C2S number is not 3!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;	
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_ssdp_udp_entry","\033[32m stream:%s closed, inline_ssdp_udp_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));
		fprintf(stderr,"\033[32m stream:%s closed, inline_ssdp_udp_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);	
		exit(0);
	}

	return APP_STATE_GIVEME;
}


extern "C" char inline_nbns_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_CLOSE == pstream->opstate){
		if(ntohs(pstream->addr.tuple4_v4->source) != 137){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_nbns_udp_entry", "\033[1;31;40m inline_nbns_udp_entry() error: source port is not 137!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;			
		}
		if(ntohs(pstream->addr.tuple4_v4->dest) != 137){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_nbns_udp_entry","\033[1;31;40m inline_nbns_udp_entry() error: dest port is not 137!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;			
		}	
		if(pstream->pudpdetail->clientbytes + pstream->pudpdetail->serverbytes != 128){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_nbns_udp_entry","\033[1;31;40m inline_nbns_udp_entry() error: total bytes is not 128!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}
		SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_nbns_udp_entry","\033[32m stream:%s closed, inline_nbns_udp_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));
		fprintf(stderr,"\033[32m stream:%s closed, inline_nbns_udp_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));	
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);	
		exit(0);
	}

	return APP_STATE_GIVEME;
}

extern "C" char inline_get_raw_pkt_data_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	void *raw_pkt_data;
	int ret, raw_pkt_len;
	const struct ethhdr *ehdr;
	
	if(OP_STATE_PENDING == pstream->opstate){
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &raw_pkt_data);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_get_raw_pkt_data_entry", "\033[1;31;40m inline_get_raw_pkt_data_entry() error: get RAW_PKT_GET_DATA fail!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;	
		}
		
		ehdr = (struct ethhdr *)raw_pkt_data;
		if((ehdr->h_source[0] != 0x3C)
		|| (ehdr->h_source[1] != 0x97)
		|| (ehdr->h_source[2] != 0x0E)
		|| (ehdr->h_source[3] != 0x18)
		|| (ehdr->h_source[4] != 0x18)
		|| (ehdr->h_source[5] != 0x41)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_get_raw_pkt_data_entry","\033[1;31;40m inline_get_raw_pkt_data_entry() error: src mac is not 3c:97:0e:18:18:41!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;		
		}
		if((ehdr->h_dest[0] != 0xE8)
		|| (ehdr->h_dest[1] != 0x61)
		|| (ehdr->h_dest[2] != 0x1F)
		|| (ehdr->h_dest[3] != 0x13)
		|| (ehdr->h_dest[4] != 0x70)
		|| (ehdr->h_dest[5] != 0x7A)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_get_raw_pkt_data_entry","\033[1;31;40m inline_get_raw_pkt_data_entry() error: dst mac is not e8:61:1f:13:70:7a!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;	
		}		

		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_TOT_LEN, &raw_pkt_len);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_get_raw_pkt_data_entry","\033[1;31;40m inline_get_raw_pkt_data_entry() error: get RAW_PKT_GET_TOT_LEN fail!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}

		if(raw_pkt_len != 74){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_get_raw_pkt_data_entry","\033[1;31;40m inline_get_raw_pkt_data_entry() error: raw pkt len is not 74!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;	
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO, "inline_get_raw_pkt_data_entry","\033[32m stream:%s inline_get_raw_pkt_data_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));
		fprintf(stderr,"\033[32m stream:%s inline_get_raw_pkt_data_entry test succ!\033[0m\n", printaddr(&pstream->addr, thread_seq));
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);	
		exit(0);
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}


extern "C" char inline_ipv4_frag_list_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int i, ret;
	void *raw_pkt_data;
	const raw_ipfrag_list_t *raw_ipv4_frag_pkt_list;
	const struct ip *raw_ipv4_frag_pkt;

	ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_DATA, &raw_pkt_data);
	if(1 == ret){
		raw_ipv4_frag_pkt_list = (raw_ipfrag_list_t *)raw_pkt_data;
		
		/* 原始包有2个ipv4分片     */
		for(i = 0; i < 2; i++){
			raw_ipv4_frag_pkt = (struct ip *)((char *)raw_ipv4_frag_pkt_list->frag_packet + sizeof(struct ethhdr));
			if(ntohs(raw_ipv4_frag_pkt->ip_id) != 0xE111){
				SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ipv4_frag_list_entry", "\033[1;31;40m inline_ipv4_frag_list_entry() error, raw ip frag pkt index:%d ipid is not 0xE111!\033[0m\n", i);
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
				return APP_STATE_DROPME;		
			}
			if(ntohl(raw_ipv4_frag_pkt->ip_src.s_addr) != 0xC0A82467){
				SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ipv4_frag_list_entry","\033[1;31;40mipv4_frag_assemble_udp_entry() error, raw ip frag pkt src addr is not 192.168.40.133!\033[0m\n");
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
				return APP_STATE_DROPME;	
			}			
			if(ntohl(raw_ipv4_frag_pkt->ip_dst.s_addr) != 0xC0A82C1D){
				SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ipv4_frag_list_entry","\033[1;31;40mipv4_frag_assemble_udp_entry() error, raw ip frag pkt dst addr is not 192.168.44.29!\033[0m\n");
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
				return APP_STATE_DROPME;	
			}
			if(raw_ipv4_frag_pkt->ip_p != IPPROTO_UDP){
				SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ipv4_frag_list_entry","\033[1;31;40mipv4_frag_assemble_udp_entry() error, raw ip frag pkt protocol is not UDP!\033[0m\n");
				gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
				return APP_STATE_DROPME;	
			}
			raw_ipv4_frag_pkt_list = raw_ipv4_frag_pkt_list->next;
		}
	}else{
		SAPP_PLUG_LOG(RLOG_LV_FATAL,"inline_ipv4_frag_list_entry","\033[1;31;40m inline_ipv4_frag_list_entry() error, not found raw ip frag pkt list!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO,"inline_ipv4_frag_list_entry","\033[32m inline_ipv4_frag_list_entry() test succ!\033[0m\n");
	fprintf(stderr,"\033[32m inline_ipv4_frag_list_entry() test succ!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);
	exit(0);

	return APP_STATE_DROPME;
}


/*
	inline模式, 根据原始包获取vxlan info 测试, 
*/
extern "C" char inine_udp_get_vxlan_info_plug(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{	
	int ret;
	
	if(pstream->opstate == OP_STATE_PENDING){
		int vinfo_gdev_ip;
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_GDEV_IP, &vinfo_gdev_ip);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug", "\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_GDEV_IP error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(ntohl(vinfo_gdev_ip) != 0xC0A80105){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: gdev ip is:0x%x, but expect 192.168.1.5!\033[0m\n", ntohl(vinfo_gdev_ip));
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		int vinfo_linkid;
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_ID, &vinfo_linkid);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_VXLAN_ID error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(ntohl(vinfo_linkid) != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: vxlan id is:%u, but expect 0!\033[0m\n", ntohl(vinfo_linkid));
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		unsigned short vinfo_sport;
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_SPORT, &vinfo_sport);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_VXLAN_SPORT error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(ntohs(vinfo_sport) != 50000){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: sport is:%u, but expect 50000!\033[0m\n", ntohs(vinfo_sport));
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		unsigned char service_no = vxlan_sport_map_to_service_id(ntohs(vinfo_sport));
		if(service_no != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: sport is:%u, service_no is:%u, but expect 1!\033[0m\n", ntohs(vinfo_sport), service_no);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}

		char vinfo_encap_type;
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_ENCAP_TYPE, &vinfo_encap_type);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_VXLAN_ENCAP_TYPE error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(vinfo_encap_type != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: encap type:%d, but expect 0!\033[0m\n", vinfo_encap_type);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		char vinfo_linkdir;
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_LINK_DIR, &vinfo_linkdir);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_VXLAN_LINK_DIR error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(vinfo_linkdir != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: link dir:%d, but expect 0!\033[0m\n", vinfo_linkdir);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		unsigned char vinfo_outer_gdev_mac[ETH_ALEN] = {};
		static const unsigned char expect_outer_gdev_mac[ETH_ALEN] = {0xFE, 0x53, 0x00, 0x00, 0x00, 0x00};
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC, vinfo_outer_gdev_mac);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(memcmp(vinfo_outer_gdev_mac, expect_outer_gdev_mac, ETH_ALEN) != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: outer gdev mac:%02x:%02x:%02x:%02x:%02x:%02x, but expect %s!\033[0m\n", 
				 vinfo_outer_gdev_mac[0],vinfo_outer_gdev_mac[1],vinfo_outer_gdev_mac[2],vinfo_outer_gdev_mac[3],vinfo_outer_gdev_mac[4],vinfo_outer_gdev_mac[5],
				 "fe:53:00:00:00:00");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		unsigned char vinfo_outer_local_mac[ETH_ALEN] = {};
		static const unsigned char expect_outer_local_mac[ETH_ALEN] = {0x52, 0x48, 0xdd, 0xcc, 0x47, 0x58};
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC, vinfo_outer_local_mac);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(memcmp(vinfo_outer_local_mac, expect_outer_local_mac, ETH_ALEN) != 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: outer local mac:%02x:%02x:%02x:%02x:%02x:%02x, but expect %s!\033[0m\n", 
				vinfo_outer_local_mac[0],vinfo_outer_local_mac[1],vinfo_outer_local_mac[2],vinfo_outer_local_mac[3],vinfo_outer_local_mac[4],vinfo_outer_local_mac[5],
				 "fe:53:00:00:00:00");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	
		
		int vinfo_vpnid;
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_VPNID, &vinfo_vpnid);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40minine_udp_get_vxlan_info_plug: get_rawpkt_opt_from_streaminfo->RAW_PKT_GET_VXLAN_VPNID error !\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(ntohl(vinfo_vpnid) != 120){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"inine_udp_get_vxlan_info_plug","\033[1;31;40m inine_udp_get_vxlan_info_plug: VPN id is:%u, but expect 120!\033[0m\n", ntohl(vinfo_vpnid));
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	

		SAPP_PLUG_LOG(RLOG_LV_INFO,"inine_udp_get_vxlan_info_plug","\033[32m inine_udp_get_vxlan_info_plug() test succ!\033[0m\n");
		fprintf(stderr,"\033[32m inine_udp_get_vxlan_info_plug() test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_INLINE_TO_SAPP_SUCC);	
		exit(0);
		return APP_STATE_DROPME;
	}
	
	return APP_STATE_GIVEME;
}


