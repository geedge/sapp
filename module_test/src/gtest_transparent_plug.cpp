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

extern "C" char tcp_pkt_stat(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet);
extern gtest_plug_stat_t gtest_tcp_stat;

extern "C" char transparent_tcp_simple(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(DIR_C2S == pstream->curdir){
		if(pstream->routedir != 0){ /* 双臂模式, 已经设inbound_route_dir=0, C2S方向的包是从up网卡回放,应该是0 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "transparent.simple","\033[1;31;40mtransparent_tcp_simple: check C2S route dir error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}else{
		if(pstream->routedir != 1){ /* 双臂模式, 已经设inbound_route_dir=0, S2C方向的包是从down网卡回放,应该是1 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "transparent.simple","\033[1;31;40mtransparent_tcp_simple: check S2C route dir error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR); 		
		}
	}

	/* 以下部分同 tcp_simple, 用于检查双臂模式下的基本tcp流还原功能 */	
	if(pstream->opstate != OP_STATE_CLOSE){
		tcp_pkt_stat(pstream, pme, thread_seq, a_packet);
	}else{
		if((16 == gtest_tcp_stat.C2S_data_pkt)
		 &&(2329 == gtest_tcp_stat.C2S_data_byte)
		 &&(30 == gtest_tcp_stat.S2C_data_pkt)
		 &&(11345 == gtest_tcp_stat.S2C_data_byte)){
		 	SAPP_PLUG_LOG(RLOG_LV_INFO, "transparent.simple","\033[32mtransparent_tcp_simple() check succ.\033[0m\n");
			sendto_test_result(GTEST_TRANSPARENT_TO_SAPP_SUCC);
		}else{
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "transparent.simple","\033[1;31;40mtcp_simple: check data error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char transparent_rst_c2s_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct rst_tcp_para inject_paras = {};

	inject_paras.th_flags = 0x14;
	inject_paras.rst_pkt_num = 1;
	inject_paras.dir = DIR_C2S;
	inject_paras.signature_seed1 = 65535;
	inject_paras.signature_seed2 = 13;	

	if(MESA_rst_tcp(pstream, &inject_paras, sizeof(struct rst_tcp_para)) < 0){
		printf("\033[1;31;40mtransparent_rst_c2s_entry() send C2S rst error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}else{
		printf("\033[32mtransparent_rst_c2s_entry() send rst succ.\033[0m\n");
	}

	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}


extern "C" char transparent_rst_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct rst_tcp_para inject_paras = {};

	inject_paras.th_flags = 0x14;
	inject_paras.rst_pkt_num = 1;
	inject_paras.dir = DIR_S2C;
	inject_paras.signature_seed1 = 65535;
	inject_paras.signature_seed2 = 13;	

	if(MESA_rst_tcp(pstream, &inject_paras, sizeof(struct rst_tcp_para)) < 0){
		printf("\033[1;31;40mtransparent_rst_c2s_entry() send C2S rst error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}else{
		printf("\033[32mtransparent_rst_s2c_entry() send rst succ.\033[0m\n");
	}

	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}


extern "C" char transparent_inject_c2s_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const unsigned char test_ip_pkt[] = { /* 这个包的内容其实就是tcp_drop_inject_c2s_trigger_by_c2s.pcap的IP头开始的二进制, 但是修改了ipid, ip_checksum, 便于区别原始包和注入包 */
	  0x45, 0x00,
	  0x00, 0x65, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
	  0x91, 0x2a, 0xc0, 0xa8, 0x0a, 0xfa, 0xc0, 0xa8,
	  0x0a, 0xea, 0xe5, 0x65, 0x00, 0x16, 0x9a, 0x34,
	  0x99, 0x14, 0x7a, 0x02, 0xb1, 0xe9, 0x80, 0x18,
	  0x41, 0x00, 0xe2, 0x8f, 0x00, 0x00, 0x01, 0x01,
	  0x08, 0x0a, 0x09, 0x48, 0x15, 0x65, 0x5d, 0x01,
	  0x39, 0x45, 0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e,
	  0x30, 0x2d, 0x6e, 0x73, 0x73, 0x73, 0x68, 0x32,
	  0x5f, 0x36, 0x2e, 0x30, 0x2e, 0x30, 0x30, 0x31,
	  0x33, 0x20, 0x4e, 0x65, 0x74, 0x53, 0x61, 0x72,
	  0x61, 0x6e, 0x67, 0x20, 0x43, 0x6f, 0x6d, 0x70,
	  0x75, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x49, 0x6e,
	  0x63, 0x2e, 0x0a
	};

	if(sapp_inject_pkt(pstream, SIO_EXCLUDE_THIS_LAYER_HDR, test_ip_pkt, sizeof(test_ip_pkt), pstream->routedir) < 0){
		printf("\033[1;31;40mtransparent_inject_c2s_entry() send C2S pkt error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}else{
		printf("\033[32mtransparent_inject_c2s_entry() send C2S ip pkt succ.\033[0m\n");
	}

	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}

extern "C" char transparent_inject_c2s_trigger_by_sc2_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const unsigned char test_ip_pkt[] = { /* 这个包的内容其实就是tcp_drop_inject_c2s_trigger_by_c2s.pcap的IP头开始的二进制, 但是修改了ipid, ip_checksum, 便于区别原始包和注入包 */
	  0x45, 0x00,
	  0x00, 0x65, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
	  0x91, 0x2a, 0xc0, 0xa8, 0x0a, 0xfa, 0xc0, 0xa8,
	  0x0a, 0xea, 0xe5, 0x65, 0x00, 0x16, 0x9a, 0x34,
	  0x99, 0x14, 0x7a, 0x02, 0xb1, 0xe9, 0x80, 0x18,
	  0x41, 0x00, 0xe2, 0x8f, 0x00, 0x00, 0x01, 0x01,
	  0x08, 0x0a, 0x09, 0x48, 0x15, 0x65, 0x5d, 0x01,
	  0x39, 0x45, 0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e,
	  0x30, 0x2d, 0x6e, 0x73, 0x73, 0x73, 0x68, 0x32,
	  0x5f, 0x36, 0x2e, 0x30, 0x2e, 0x30, 0x30, 0x31,
	  0x33, 0x20, 0x4e, 0x65, 0x74, 0x53, 0x61, 0x72,
	  0x61, 0x6e, 0x67, 0x20, 0x43, 0x6f, 0x6d, 0x70,
	  0x75, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x49, 0x6e,
	  0x63, 0x2e, 0x0a
	};

	if(sapp_inject_pkt(pstream, SIO_EXCLUDE_THIS_LAYER_HDR, test_ip_pkt, sizeof(test_ip_pkt), pstream->routedir ^ 1) < 0){
		printf("\033[1;31;40mtransparent_inject_c2s_trigger_by_sc2_entry() send C2S pkt error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}else{
		printf("\033[32mtransparent_inject_c2s_entry() send C2S ip pkt succ.\033[0m\n");
	}

	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}


extern "C" char transparent_inject_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const unsigned char test_ip_pkt[] = { /* 这个包的内容其实就是tcp_drop_inject_c2s_trigger_by_c2s.pcap的IP头开始的二进制, 但是修改了ipid, ip_checksum, 便于区别原始包和注入包 */
	  0x45, 0x00,
	  0x00, 0x65, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
	  0x91, 0x2a, 0xc0, 0xa8, 0x0a, 0xfa, 0xc0, 0xa8,
	  0x0a, 0xea, 0xe5, 0x65, 0x00, 0x16, 0x9a, 0x34,
	  0x99, 0x14, 0x7a, 0x02, 0xb1, 0xe9, 0x80, 0x18,
	  0x41, 0x00, 0xe2, 0x8f, 0x00, 0x00, 0x01, 0x01,
	  0x08, 0x0a, 0x09, 0x48, 0x15, 0x65, 0x5d, 0x01,
	  0x39, 0x45, 0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e,
	  0x30, 0x2d, 0x6e, 0x73, 0x73, 0x73, 0x68, 0x32,
	  0x5f, 0x36, 0x2e, 0x30, 0x2e, 0x30, 0x30, 0x31,
	  0x33, 0x20, 0x4e, 0x65, 0x74, 0x53, 0x61, 0x72,
	  0x61, 0x6e, 0x67, 0x20, 0x43, 0x6f, 0x6d, 0x70,
	  0x75, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x49, 0x6e,
	  0x63, 0x2e, 0x0a
	};

	if(sapp_inject_pkt(pstream, SIO_EXCLUDE_THIS_LAYER_HDR, test_ip_pkt, sizeof(test_ip_pkt), pstream->routedir ^ 1) < 0){
		printf("\033[1;31;40mtransparent_inject_c2s_entry() send S2C pkt error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}else{
		printf("\033[32mtransparent_inject_c2s_entry() send S2C ip pkt succ.\033[0m\n");
	}

	return APP_STATE_DROPME | APP_STATE_DROPPKT;
}


/*
	此函数同时挂载到TCP和UDP, 要被丢弃的包的ipid都一样, 是精确构造好的pcap包.
*/
extern "C" char drop_current_pkt_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct ip *ip4hdr = ( struct ip *)a_packet;
	int drop_opt = 1;

	/* 丢弃pcap包中, ipid 为0x487A的第2个包 */
	if(ip4hdr 
	&& (0x487A == ntohs(ip4hdr->ip_id))){
		MESA_set_stream_opt(pstream, MSO_DROP_CURRENT_PKT, &drop_opt, sizeof(int));
	}

	if(pstream->opstate == OP_STATE_CLOSE){
		if(pstream->ptcpdetail->serverpktnum != 3){
			printf("\033[1;31;40mdrop_current_pkt_tcp_entry() total pkt number error, expect 3, but actual is:%u, tuple4:%s\033[0m\n", pstream->ptcpdetail->serverpktnum, printaddr(&pstream->addr, thread_seq));
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}

	/*
		此处不发送送成功的结果, 在 g_transparent_pcap_md5_tuple 的函数中判断丢弃数据包是否成功, 再决定发送SUCC结果.
	*/

	return APP_STATE_GIVEME;
}

