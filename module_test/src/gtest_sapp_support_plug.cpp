#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
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


#ifndef GTEST_SAPP
static gtest_plug_stat_t gtest_ctrl_tcp_stat;
//static gtest_plug_stat_t gtest_ctrl_udp_stat;
static int project_notify_plug1_id = -1;
static int project_notify_plug2_id = -1;


extern "C" char ctrl_max_unorder_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
	struct max_unorder_opt mopt;
	int ret;
	
	if(pstream->opstate == OP_STATE_PENDING)
	{
		memset(&gtest_ctrl_tcp_stat, 0, sizeof(gtest_plug_stat_t));
		mopt.stream_dir = DIR_DOUBLE;
		mopt.max_unorder_val = 5; /* 重置当前流的最大乱序数为5 */
		ret = MESA_set_stream_opt(pstream, MSO_MAX_UNORDER, &mopt, sizeof(mopt));
		if(ret < 0){
			printf("\033[1;31;40mMESA_set_stream_opt():set max_unorder option error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}
	
	if(pstream->opstate != OP_STATE_CLOSE){
		if(DIR_C2S == pstream->curdir){
			gtest_ctrl_tcp_stat.C2S_data_pkt++;
			gtest_ctrl_tcp_stat.C2S_data_byte += pdetail->datalen;
		}else{
			gtest_ctrl_tcp_stat.S2C_data_pkt++;
			gtest_ctrl_tcp_stat.S2C_data_byte += pdetail->datalen;
		}
	}else{
		if((5 == gtest_ctrl_tcp_stat.C2S_data_pkt)
		 &&(315 == gtest_ctrl_tcp_stat.C2S_data_byte)
		 &&(0 == gtest_ctrl_tcp_stat.S2C_data_pkt)
		 &&(0 == gtest_ctrl_tcp_stat.S2C_data_byte)){
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mtcp_entry rcv bytes is not expected!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}

	return APP_STATE_GIVEME;
}

static int recv_ack_flag = 0;
extern "C" char ctrl_tcp_need_ack_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	//struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
	unsigned char mopt;
	int ret;
	const struct ip *ip4hdr;
	const struct tcphdr *thdr;
	
	if(pstream->opstate == OP_STATE_PENDING)
	{
		mopt = 1;
		ret = MESA_set_stream_opt(pstream, MSO_NEED_ACK, &mopt, sizeof(mopt));
		if(ret < 0){
			printf("\033[1;31;40mMESA_set_stream_opt():set need_ack option error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			   /* 如果设置失败则直接退出sapp进程 */
		}
	}
	
	if(pstream->opstate == OP_STATE_CLOSE){
		if(1 == recv_ack_flag){
			printf("\033[32m control.need_ack test succ!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mhas not recv tcp ack packet!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}else{
		if(a_packet){
			ip4hdr = (const struct ip *)a_packet;
			thdr = (const struct tcphdr *)((char *)a_packet + ip4hdr->ip_hl * 4);
			if((0xFF1F == ntohs(ip4hdr->ip_id))
			   &&(1 == thdr->ack)
			   &&(0 == thdr->syn)
			   &&(0 == thdr->fin)
			   &&(0 == thdr->rst)
			   &&(0xFE28 == ntohs(thdr->check))){
				recv_ack_flag = 1;
			}
		}
	}

	return APP_STATE_GIVEME;
}

static int tcp_plundered_entry_pkt_num = 0;
static int tcp_exclusive_entry_pkt_num = 1;
extern "C" char ctrl_takeover_plundered_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	tcp_plundered_entry_pkt_num++;
	return APP_STATE_GIVEME;	
}

extern "C" int stream_register_tcp_takeover (STREAM_CB_FUN_T fun);
extern "C" char ctrl_takeover_exclusive_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int mopt = 1;
	int ret;

	tcp_exclusive_entry_pkt_num++;

	if(OP_STATE_PENDING == pstream->pktstate){
		stream_register_tcp_takeover((STREAM_CB_FUN_T)ctrl_takeover_exclusive_entry);
	}
	
	ret = MESA_set_stream_opt(pstream, MSO_TAKEOVER, &mopt, sizeof(mopt));
	if(ret < 0){
		printf("\033[1;31;40mMESA_set_stream_opt():set takeover option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果设置失败则直接退出sapp进程 */
	}

	if(tcp_exclusive_entry_pkt_num >= 68){
		if(0 == tcp_plundered_entry_pkt_num){
			/* 此函数挂载到TCPALL入库, 设置takeover标志后,  
			   ctrl_takeover_plundered_entry一个包应该都收不到 
			*/
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mset takeover, but plundered_entry has recv %d packet!\033[0m\n", tcp_plundered_entry_pkt_num);
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}

	return APP_STATE_GIVEME;	
}

extern "C" char ctrl_tcp_timeout_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	static int rcv_pkt = 0;	
	unsigned char mclose_type;
	int opt_len = sizeof(mclose_type);

	if(OP_STATE_PENDING == pstream->opstate){
		gtest_sapp_sleep(5, "tcp time out"); /* 收到第一个包后, 强制sleep, 使当前流后续的包超时, 导致当前流被结束 */
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_CLOSE_REASON, (void *)&mclose_type, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mMESA_get_stream_opt():get close reason option error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			   /* 如果设置失败则直接退出sapp进程 */
		}
		
		if(STREAM_CLOSE_REASON_TIMEOUT != mclose_type){
			printf("\033[1;31;40mstream closed, but not because timeout, reason code is:%d!\033[0m\n", (int)mclose_type);
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
		
		if(1 == rcv_pkt){
			printf("\033[32m ctrl_tcp_timeout_entry() test succ!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mset timeout, but stream is hasn't close!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}else{
		rcv_pkt++;
	}

	return APP_STATE_GIVEME;
}


extern "C" char ctrl_tcp_isn_c2s_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	unsigned int c2s_isn;
	int opt_len = sizeof(int);

	ret = MESA_get_stream_opt(pstream, MSO_TCP_ISN_C2S, &c2s_isn, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt():get c2s isn option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}	

	if(c2s_isn == 991053713){
		sendto_test_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mget tcp c2s isn error, expect:991053713, but actual:%u\033[0m\n", c2s_isn);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	return APP_STATE_DROPME;
}

extern "C" char ctrl_tcp_isn_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	unsigned int c2s_isn, s2c_isn; /* S2C方向的单向流可以获取双向ISN */
	int opt_len = sizeof(int);

	ret = MESA_get_stream_opt(pstream, MSO_TCP_ISN_C2S, &c2s_isn, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt():get c2s isn option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}	
	ret = MESA_get_stream_opt(pstream, MSO_TCP_ISN_S2C, &s2c_isn, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt():get s2c isn option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}		

	if(c2s_isn == 991053713){
		sendto_test_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mget tcp c2s isn error, expect:991053713, but actual:%u!\033[0m\n", c2s_isn);
		sendto_test_result(GTEST_SAPP_ERR);
	}
	
	if(s2c_isn == 3965699644){
		sendto_test_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mget tcp s2c isn error, expect:3965699644, but actual:%u\033[0m\n", s2c_isn);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	return APP_STATE_DROPME;
}


extern "C" char ctrl_tcp_option_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int i, ret;
	struct tcp_option *syn_opt, *synack_opt;
	int syn_opt_num = 10, synack_opt_num = 10;
	int check_succ_num = 0;

	ret = MESA_get_stream_opt(pstream, MSO_TCP_SYN_OPT, &syn_opt, &syn_opt_num);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt():get syn option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}		

	ret = MESA_get_stream_opt(pstream, MSO_TCP_SYNACK_OPT, &synack_opt, &synack_opt_num);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt():get synack option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}	

	if(syn_opt_num != 4){
		printf("\033[1;31;40mMESA_get_stream_opt():get syn option number error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}
	if(synack_opt_num != 4){
		printf("\033[1;31;40mMESA_get_stream_opt():get synack option number error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}

	for(i = 0; i < syn_opt_num; i++){
		if((2 == syn_opt[i].type) 
		 && (syn_opt[i].len == 2) 
		 && (syn_opt[i].short_value == 65495)){ /* MSS */
			check_succ_num++;
		}
		if((4 == syn_opt[i].type) 
		 && (syn_opt[i].len == 0)){ /* SACK */
			check_succ_num++;
		}	
		if((8 == syn_opt[i].type) 
		 && (syn_opt[i].len == 8) 
		 && (syn_opt[i].opt_ts_val.ts_self == 2767168460) 
		 && (syn_opt[i].opt_ts_val.ts_echo_reply == 0)){ /* timestamp */
			check_succ_num++;
		}	
		if((3 == syn_opt[i].type)  /* Window scale */
		 && (syn_opt[i].len == 1) 
		 && (syn_opt[i].char_value  == 7)){ 
			check_succ_num++;
		}				
	}
	if(check_succ_num != 4){
		printf("\033[1;31;40mMESA_get_stream_opt():get syn option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	check_succ_num = 0;
	for(i = 0; i < synack_opt_num; i++){
		if((2 == synack_opt[i].type) 
		 && (synack_opt[i].len == 2) 
		 && (synack_opt[i].short_value == 65495)){ /* MSS */
			check_succ_num++;
		}
		if((4 == synack_opt[i].type) 
		 && (synack_opt[i].len == 0)){ /* SACK */
			check_succ_num++;
		}	
		if((8 == synack_opt[i].type) 
		 && (synack_opt[i].len == 8) 
		 && (synack_opt[i].opt_ts_val.ts_self == 2767168460) 
		 && (synack_opt[i].opt_ts_val.ts_echo_reply == 2767168460)){ /* timestamp */
			check_succ_num++;
		}	
		if((3 == synack_opt[i].type)  /* Window scale */
		 && (synack_opt[i].len == 1) 
		 && (synack_opt[i].char_value  == 7)){ 
			check_succ_num++;
		}
	}
	if(check_succ_num != 4){
		printf("\033[1;31;40mMESA_get_stream_opt():get synack option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	sendto_test_result(GTEST_SAPP_SUCC);
	
	return APP_STATE_DROPME;
}


static int ctrl_tunnel_type_common(struct streaminfo *pstream, unsigned short expect_type)
{
	int ret;
	unsigned short tunnel_type;
	int opt_len = sizeof(short);

	ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt():get tunnel type option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		   /* 如果获取失败则直接退出sapp进程 */
	}	

	if(expect_type == tunnel_type){
		sendto_test_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mMESA_get_stream_opt():get tunnel type option error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}
	
	return APP_STATE_DROPME;

}

extern "C" char ctrl_tunnel_6over4_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	ctrl_tunnel_type_common(pstream, STREAM_TUNNLE_6OVER4);
	
	return APP_STATE_DROPME;
}

extern "C" char ctrl_tunnel_gre_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	ctrl_tunnel_type_common(pstream, STREAM_TUNNLE_GRE);
	
	return APP_STATE_DROPME;
}

extern "C" char ctrl_tunnel_teredo_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	ctrl_tunnel_type_common(pstream, STREAM_TUNNLE_TEREDO);
	
	return APP_STATE_DROPME;
}


extern "C" char ctrl_tunnel_l2tp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	ctrl_tunnel_type_common(pstream, STREAM_TUNNLE_L2TP);
	
	return APP_STATE_DROPME;
}

extern "C" char ctrl_tunnel_pptp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	ctrl_tunnel_type_common(pstream, STREAM_TUNNLE_PPTP);
	
	return APP_STATE_DROPME;
}

extern "C" char ctrl_tunnel_gtp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	ctrl_tunnel_type_common(pstream, STREAM_TUNNEL_GPRS_TUNNEL);
	
	return APP_STATE_DROPME;
}

/* 测试sapp_get_platform_opt()接口相关功能 */
extern "C" char ctrl_tcp_stream_and_traffic_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	unsigned long long tot_pkt, tot_byte, egress_pkt, egress_byte, ingress_pkt, ingress_byte;
	unsigned long long tcp_stream_new, tcp_stream_close;
	int opt_len = sizeof(long long );
	const struct ip *ip4hdr;
	static int inbound_pkt_num = 0, outbound_pkt_num = 0;
	static int inbound_byte_num = 0, outbound_byte_num = 0;

	if(a_packet){
		//MESA_inject_pkt(pstream, "test_for_inject_pkt", strlen("test_for_inject_pkt"), a_packet, pstream->routedir);
		ip4hdr = (struct ip *)a_packet;
		if(MESA_dir_human_to_link('I') == pstream->routedir){
			inbound_pkt_num++;
			inbound_byte_num += ntohs(ip4hdr->ip_len) + sizeof(struct ethhdr);
		}else{
			outbound_pkt_num++;
			outbound_byte_num += ntohs(ip4hdr->ip_len) + sizeof(struct ethhdr);
		}
	}
	
	if(OP_STATE_CLOSE == pstream->pktstate){
		ret = sapp_get_platform_opt(SPO_TOTAL_RCV_PKT, &tot_pkt, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TOTAL_RCV_PKT error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if((unsigned long long)inbound_pkt_num+(unsigned long long)outbound_pkt_num != tot_pkt){
				printf("\033[1;31;40m tot pkt is:%llu, but plug stat is:%d!\033[0m\n", tot_pkt, inbound_pkt_num+outbound_pkt_num);
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}
		
		ret = sapp_get_platform_opt(SPO_TOTAL_RCV_BYTE, &tot_byte, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TOTAL_RCV_BYTE error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if((unsigned long long)inbound_byte_num+(unsigned long long)outbound_byte_num != tot_byte){
				printf("\033[1;31;40m tot byte is:%llu, but plug stat is:%d!\033[0m\n",tot_byte, inbound_byte_num+outbound_byte_num);
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}

		ret = sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, &ingress_pkt, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TOTAL_INBOUND_PKT error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if((unsigned long long)inbound_pkt_num != ingress_pkt){
				printf("\033[1;31;40m ingress pkt is:%llu, but plug stat is:%d!\033[0m\n", ingress_pkt,inbound_pkt_num);
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}
		
		ret = sapp_get_platform_opt(SPO_TOTAL_INBOUND_BYTE, &ingress_byte, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TOTAL_INBOUND_BYTE error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if((unsigned long long)inbound_byte_num != ingress_byte){
				printf("\033[1;31;40m ingress byte is:%llu,  but plug stat is:%d!\033[0m\n", ingress_byte, inbound_byte_num);
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}
		
		ret = sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, &egress_pkt, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TOTAL_OUTBOUND_PKT error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if((unsigned long long)outbound_pkt_num != egress_pkt){
				printf("\033[1;31;40m egress pkt is:%llu, but plug stat is:%d!\033[0m\n", egress_pkt,outbound_pkt_num);
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}
		
		ret = sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_BYTE, &egress_byte, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TOTAL_OUTBOUND_BYTE error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if((unsigned long long)outbound_byte_num != egress_byte){
				printf("\033[1;31;40m egress byte is:%llu,  but plug stat is:%d!\033[0m\n", egress_byte, outbound_byte_num);
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}
		
		ret = sapp_get_platform_opt(SPO_TCP_STREAM_NEW, &tcp_stream_new, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TCP_STREAM_NEW error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if(1 != tcp_stream_new){
				printf("\033[1;31;40m tcp_stream_new is not 1!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}

#if 0		
		ret = sapp_get_platform_opt(SPO_TCP_STREAM_ESTAB, &tcp_stream_live, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TCP_STREAM_ESTAB error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if(1 != tcp_stream_live){
				printf("\033[1;31;40m tcp estab stream is not 1!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}
#endif

		ret = sapp_get_platform_opt(SPO_TCP_STREAM_CLOSE, &tcp_stream_close, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40m sapp_get_platform_opt->SPO_TCP_STREAM_CLOSE error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if(0 != tcp_stream_close){
				printf("\033[1;31;40m tcp_stream_close is not 0!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}			

		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_GIVEME;
}



static int project_test_id = -1;
static const char *project_name = "project_test";
extern "C" char project_customer_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int res;

	res = project_req_get_int(pstream, project_test_id);
	if(0x12345678 == res){
		sendto_test_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mproject_req_get_int value error, expect 0x12345678, but actual is:%x!\033[0m\n", res);
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	return APP_STATE_DROPME;
}


extern "C" char project_producer_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_PENDING == pstream->pktstate){
#if 0	//v4.2版本后, 支持动态自动注册,不用写project_list.conf, 但是标签注册必须在初始化阶段, 
		project_test_id = project_producer_register(project_name, "int", NULL);
		if(project_test_id < 0){
			printf("\033[1;31;40mproject_producer_register error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
#endif
		project_req_add_int(pstream, project_test_id, 0x12345678);
	}

	return APP_STATE_DROPME;
}


extern "C" int project_test_init(void)
{
	if(gtest_sapp_slave_init() < 0){
		return -1;
	}

	//v4.2版本后, 支持动态自动注册,不用写project_list.conf, 但是标签注册必须在初始化阶段, 
	project_test_id = project_producer_register(project_name, "int", NULL);
	if(project_test_id < 0){
		printf("\033[1;31;40mproject_producer_register error!\033[0m\n");
		return -1;
	}

	return 0;
}

extern "C" int project_notify_cb1(const struct streaminfo *stream, int project_req_id, void *a_packet, void *user_arg)
{
	if((void *)0x11111111 != user_arg){
		printf("\033[1;31;40mproject_notify_cb1() error! user_arg1 is not 0x11111111!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}else{
		printf("\033[32mproject_notify_cb1 test succ, stream:%p, project_id:%d, user_arg:%lx!\033[0m\n", stream, project_req_id, (long unsigned int)user_arg);
	}

	return 0;
}

extern "C" int project_notify_cb2(const struct streaminfo *stream, int project_req_id, void *a_packet, void *user_arg)
{
	if((void *)0x22222222 != user_arg){
		printf("\033[1;31;40mproject_notify_cb1() error! user_arg2 is not 0x22222222!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}else{
		printf("\033[32mproject_notify_cb2 test succ, stream:%p, project_id:%d, user_arg:%lx!\033[0m\n", stream, project_req_id, (long unsigned int)user_arg);
	}

	return 0;
}

extern "C" char project_customer_no_result_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* 此处插件不发送正确结果, 只判断错误 */
	int res;
	
	res = project_req_get_int(pstream, project_test_id);
	if(0x12345678 != res){
		printf("\033[1;31;40mproject_customer_no_result_entry get value error, expect 0x12345678, but actual is:%x!\033[0m\n", res);
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	return APP_STATE_DROPME;
}



extern "C" char project_customer_entry1(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int res;
	/* 此处插件不发送正确结果, 只判断错误 */

	res = project_req_get_int(pstream, project_notify_plug1_id);
	if(0x12345678 != res){
		printf("\033[1;31;40mproject_customer_entry1 get project value error, expect 0x12345678, but actual is:%x!\033[0m\n", res);
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	return APP_STATE_DROPME;
}


extern "C" char project_customer_entry2(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int res;
	/* 第2个插件排在最后, 如果都正确, 则发送正确结果 */

	res = project_req_get_int(pstream, project_notify_plug2_id);
	if(0x12345678 == res){
		sendto_test_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mproject_customer_entry2 get project value error, expect 0x12345678, but actual is:%x!\033[0m\n", res);
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	return APP_STATE_DROPME;
}


#if 0 //用bridge接口代替

extern "C" int project_nofity_custom1_init(void)
{
	project_notify_plug1_id = project_customer_register_with_notify(project_name, "int", project_notify_cb1, (void *)0x11111111);
	assert(project_notify_plug1_id >= 0);

	printf("project_nofity_custom1_init, project_id=%d\n", project_notify_plug1_id);
	
	return 0;
}


extern "C" int project_nofity_custom2_init(void)
{
	project_notify_plug2_id = project_customer_register_with_notify(project_name, "int", project_notify_cb2, (void *)0x22222222);
	assert(project_notify_plug2_id >= 0);

	printf("project_nofity_custom2_init, project_id=%d\n", project_notify_plug2_id);
	
	return 0;
}


extern "C" char project_producer_notify_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_PENDING == pstream->pktstate){
		project_req_add_int(pstream, project_test_id, 0x12345678);
	}

	project_producer_notify(pstream, project_test_id, a_packet);

	return APP_STATE_DROPME;
}
#endif




#if SAPP_V4
#include "sapp_timer.h"

void sapp_timer_test_cbfun(sapp_timer_handle h, sapp_timer_event ev, int pkt_process_thread_id, void *user_arg)
{
	//struct streaminfo *pstream = (struct streaminfo *)user_arg;
	static time_t first_call_time = time(NULL);
	time_t diff;

	gtest_ctrl_tcp_stat.C2S_all_pkt++;
	//printf("call sapp_timer_test_cbfun(), %u\n", gtest_ctrl_tcp_stat.C2S_all_pkt);

	if(gtest_ctrl_tcp_stat.C2S_all_pkt >= 10){
		diff = time(NULL) - first_call_time;
		if(diff >= 9){ /* 理论上收到10个包, 也是延迟10秒, 允许一点误差, 此处判断9秒 */
			SAPP_PLUG_LOG(RLOG_LV_INFO, "timer.simple","timer_test succ! time pass %lds, call entry %u times!\n", diff, gtest_ctrl_tcp_stat.C2S_all_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
			memset(&gtest_ctrl_tcp_stat, 0, sizeof(gtest_plug_stat_t));
		}else{
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "timer.simple","\033[1;31;40mtimer test error, time pass %lds, but only call entry %u times!\033[0m\n", diff, gtest_ctrl_tcp_stat.C2S_all_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		}
	}
}


static void *sapp_timer_ev_new(int tid, void *arg)
{
	sapp_timer_handle th;
	sapp_timer_event tev;
	int iopt, ret;
	struct timeval topt;

	th = sapp_get_platform_timer(tid);
	if(th==NULL)return NULL;
	tev = sapp_timer_event_new(th);
	if(tev==NULL)return NULL;

	iopt = tid;
	sapp_event_set_opt(tev, STEO_EFFECTIVE_THREAD_ID, &iopt, sizeof(iopt));
	
	topt.tv_sec = 1;
	topt.tv_usec = 0;
	sapp_event_set_opt(tev, STEO_TIMEOUT_VAL, &topt, sizeof(topt));
	sapp_event_set_opt(tev, STEO_CALLBACK_FUN, (void *)&sapp_timer_test_cbfun, sizeof(void *));
	sapp_event_set_opt(tev, STEO_CALLBACK_FUN_ARG, arg, sizeof(void *));

	ret = sapp_timer_add(th, tev);
	assert(ret >= 0);

	return tev;
}



extern "C" char timer_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	sapp_timer_handle th;
	sapp_timer_event tev;

	//printf("into timer_tcpall_entry!\n");

	/* 设置回调函数sapp_timer_test_cbfun(), 判断时间 */
	if(pstream->pktstate== OP_STATE_PENDING){
		tev = sapp_timer_ev_new(pstream->threadnum, pstream);
		*pme = tev;
	}else{
		tev = *pme;

		if(OP_STATE_CLOSE == pstream->pktstate){
			th = sapp_get_platform_timer(pstream->threadnum);
			sapp_timer_del(th, tev);
			//printf("tid:%d, tcpstream close: %s, del timer\n",pstream->threadnum, printaddr(&(pstream->addr),pstream->threadnum));
			return APP_STATE_DROPME;
		}
	}

	return APP_STATE_GIVEME;
}

extern "C" char global_stream_id_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	time_t tt;
	struct tm ttm;
	void *res;
	int ret;
	unsigned long long sapp_global_id = 1010;
	int opt_len = sizeof(long long);

	ret = MESA_get_stream_opt(pstream, MSO_GLOBAL_STREAM_ID, &sapp_global_id, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt() MSO_GLOBAL_STREAM_ID error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	unsigned long long dev_id_from_sapp = (sapp_global_id & 0x7FF8000000000000UL) >> 51;
	if(dev_id_from_sapp != 1010){
		printf("\033[1;31;40m input args dev_id is not equal with sapp global id!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	unsigned long long thread_id_from_sapp = (sapp_global_id & 0x0007F80000000000UL) >> 43;
	if(thread_id_from_sapp != (unsigned long long)thread_seq){
		printf("\033[1;31;40m thread id is not equal with sapp global id!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	res = strptime("2018-08-08 08:08:08", "%Y-%m-%d %H:%M:%S", &ttm);
	if(NULL == res){
		printf("\033[1;31;40mstrptime error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	tt = mktime(&ttm);

	unsigned long long ts_from_time = (time(NULL) - tt) % 268435456L;

	unsigned long long ts_from_sapp = (sapp_global_id & 0x07ffffff8000) >> 15;
	if(ts_from_sapp > ts_from_time){
		if(ts_from_sapp > ts_from_time + 1){ /* 允许误差1秒 */
			printf("\033[1;31;40mtimestamp from sapp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
	}else{
		if(ts_from_time > ts_from_sapp + 1){ /* 允许误差1秒 */
			printf("\033[1;31;40mtimestamp from sapp error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
	}

	printf("\033[32mtest global_stream_id success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);

	return APP_STATE_DROPME;
}


/*
	读取tcp_tuple4_reuse.pcap, 应该有两个流被先后调用, stream_id应该生成两个不同的值.
*/
static int test_stream_id_num = 0;
static unsigned long long test_last_stream_id = 0;
extern "C" char global_stream_id_tuple4_reuse_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	//time_t tt;
	//struct tm ttm;
	//void *res;
	int ret;
	unsigned long long sapp_global_id = 1010;
	int opt_len = sizeof(long long);

	if(OP_STATE_PENDING == pstream->pktstate){
		ret = MESA_get_stream_opt(pstream, MSO_GLOBAL_STREAM_ID, &sapp_global_id, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mMESA_get_stream_opt() MSO_GLOBAL_STREAM_ID error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		if(0 == test_stream_id_num){
			test_last_stream_id = sapp_global_id;
		}else{
			if(test_last_stream_id == sapp_global_id){
				printf("\033[1;31;40mtuple4 reuse, but two stream id is equal!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;				
			}else{
				sendto_test_result(GTEST_SAPP_SUCC);
				return APP_STATE_DROPME;	
			}
		}

		test_stream_id_num++;
	}

	return APP_STATE_GIVEME;
}	

#endif


/*
	读取tcp_tuple4_reuse.pcap, 应该有两个流被先后调用, stream tcpdetail createtime应该有两个值.
*/
static int test_reuse_stream_num = 0;
static time_t first_stream_creatime, second_stream_creatime;
static long long first_stream_creatime_ms, second_stream_creatime_ms;
extern "C" char stream_creatime_tuple4_reuse_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int opt_len = sizeof(long long);
	
	if(OP_STATE_PENDING == pstream->pktstate){
		if(0 == test_reuse_stream_num){
			first_stream_creatime = pstream->ptcpdetail->createtime;
			MESA_get_stream_opt(pstream, MSO_STREAM_CREATE_TIMESTAMP_MS, &first_stream_creatime_ms, &opt_len);
		}else{
			/* 记录四元组重用, 第2个流的时间 */
			second_stream_creatime = pstream->ptcpdetail->createtime;
			MESA_get_stream_opt(pstream, MSO_STREAM_CREATE_TIMESTAMP_MS, &second_stream_creatime_ms, &opt_len);
			
			if(second_stream_creatime == first_stream_creatime){
				printf("\033[1;31;40mtuple4 reuse, but two stream creatime is equal, %lld!\033[0m\n", (long long)first_stream_creatime);
				sendto_test_result(GTEST_SAPP_ERR);
			}if(first_stream_creatime_ms == second_stream_creatime_ms){
				printf("\033[1;31;40mtuple4 reuse, but two stream creatime ms is equal, %lld!\033[0m\n", (long long)first_stream_creatime_ms);
				sendto_test_result(GTEST_SAPP_ERR);
			}else{
				printf("\033[32m stream_creatime_tuple4_reuse_tcp_entry() test succ!\033[0m\n");
				sendto_test_result(GTEST_SAPP_SUCC);
				return APP_STATE_DROPME;	
			}
		}

		test_reuse_stream_num++;
	}

	return APP_STATE_GIVEME;
}	


/*
	BUG: 一个流生成了多个stream_id.
*/
extern "C" int global_stream_id_check_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	unsigned long long gstream_id = 100;
	int opt_len = sizeof(long long);
	static unsigned long long history_gstream_id;

	ret = MESA_get_stream_opt(pstream, MSO_GLOBAL_STREAM_ID, &gstream_id, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mMESA_get_stream_opt() -->MSO_GLOBAL_STREAM_ID error! \033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;			
	}

	if(OP_STATE_PENDING == pstream->opstate){
		history_gstream_id = gstream_id;
	}

	if(history_gstream_id != gstream_id){
		printf("\033[1;31;40mhistory stream id:%llu, current stream id:%llu\033[0m\n", history_gstream_id, gstream_id);
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}

	if(gstream_id < (unsigned long long)time(NULL)){
		printf("\033[1;31;40m get stream id:%llu, but maybe is error\033[0m\n", gstream_id);
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;	
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		sendto_test_result(GTEST_SAPP_SUCC);
		return APP_STATE_DROPME;			
	}

	return APP_STATE_GIVEME;
}


extern "C" int test_get_platform_opt_init(void)
{
	char char_opt_val[256];
	int ret;
	int opt_len;
	
	if(gtest_sapp_slave_init() < 0){
		return -1;
	}

	opt_len = sizeof(char_opt_val);
	ret = sapp_get_platform_opt(SPO_DEPLOYMENT_MODE_STR, char_opt_val, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40msapp_get_platform_opt()->SPO_DEPLOYMENT_MODE_STR error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	if(strncasecmp("dumpfile", char_opt_val, strlen("dumpfile")) != 0){
		printf("\033[1;31;40msapp_get_platform_opt()->SPO_DEPLOYMENT_MODE_STR is not 'dumpfile'!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	printf("\033[32m40msapp_get_platform_opt success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);

	return 0;
}


extern "C" char stream_createtime_ms_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	static unsigned long long create_time_ms_pending, create_time_ms_close, create_time_s, lastm_time_ms1, lastm_time_ms2;
	unsigned long long *p_create_time_ms;
	int opt_len = sizeof(long long);

	if(OP_STATE_PENDING == pstream->pktstate){
		sleep(1);
		usleep(123456);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_CREATE_TIMESTAMP_MS, &create_time_ms_pending, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mMESA_get_stream_opt()->MSO_STREAM_CREATE_TIMESTAMP_MS error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		ret = MESA_get_stream_opt(pstream, MSO_STREAM_LASTUPDATE_TIMESTAMP_MS, &lastm_time_ms1, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mMESA_get_stream_opt()->MSO_STREAM_LASTUPDATE_TIMESTAMP_MS error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		create_time_s = pstream->ptcpdetail->createtime;
		p_create_time_ms = (unsigned long long *)malloc(sizeof(long long));
		*p_create_time_ms = create_time_ms_pending;
		*pme = p_create_time_ms;
	}	
	

	if(OP_STATE_CLOSE == pstream->pktstate){ /* 结束的时候再获取一遍 */
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_CREATE_TIMESTAMP_MS, &create_time_ms_close, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mMESA_get_stream_opt()->MSO_STREAM_CREATE_TIMESTAMP_MS error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		if(create_time_ms_pending != create_time_ms_close){
			printf("\033[1;31;40mMESA_get_stream_opt()->MSO_STREAM_CREATE_TIMESTAMP_MS pending:%llu diff with close:%llu\033[0m\n", create_time_ms_pending, create_time_ms_close);
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}

		if(((pstream->ptcpdetail->createtime != create_time_ms_pending/1000)
		&& (pstream->ptcpdetail->createtime != create_time_ms_pending/1000 - 1))/* 防止在执行的瞬间跨过了一秒 */
		|| pstream->ptcpdetail->createtime !=  create_time_s){ 
			printf("\033[1;31;40mMESA_get_stream_opt()->MSO_STREAM_CREATE_TIMESTAMP_MS is:%llu, but current time is:%llu\033[0m\n", create_time_ms_pending, pstream->ptcpdetail->createtime);
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}		
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_LASTUPDATE_TIMESTAMP_MS, &lastm_time_ms2, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mMESA_get_stream_opt()->MSO_STREAM_LASTUPDATE_TIMESTAMP_MS error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(lastm_time_ms2 == lastm_time_ms1){
			printf("\033[1;31;40mMESA_get_stream_opt()->MSO_STREAM_LASTUPDATE_TIMESTAMP_MS pending:%llu diff with close:%llu\033[0m\n", lastm_time_ms1, lastm_time_ms2);
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}
		sendto_test_result(GTEST_SAPP_SUCC);
		return APP_STATE_DROPME;			
	}

	return APP_STATE_GIVEME;
}


static int g_up_layer_non_num = 0;  /* 上层协议无其他隧道流计数 */
static int g_up_layer_is_tunnel_num = 0; /* 上层协议有其他隧道流计数 */
static int g_up_layer_plug_call_times = 0;

extern "C" char up_layer_tunnel_gtp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	enum stream_carry_tunnel_t up_layer_tunnel_type = STREAM_TUNNLE_NON;
	int opt_len = sizeof(short);

	g_up_layer_plug_call_times++;
	
	if(OP_STATE_CLOSE != pstream->pktstate){
		MESA_get_stream_opt(pstream, MSO_STREAM_UP_LAYER_TUNNEL_TYPE, &up_layer_tunnel_type, &opt_len);
		if(STREAM_TUNNEL_GPRS_TUNNEL != up_layer_tunnel_type){ /* 此处要精确判断隧道类型, 防止解析出错, 不能用STREAM_TUNNLE_NON模糊判断 */
			g_up_layer_non_num++;
		}else{
			g_up_layer_is_tunnel_num++;
		}	

		printf("stream: %s, tunnel:%d\n", printaddr(&pstream->addr, thread_seq), (int)up_layer_tunnel_type);
	}

	if(13 == g_up_layer_plug_call_times){ /* gtp_dns.pcap一共5个包, 5个外层udp, 5个内层udp, 外加3个流的close状态, 最终是调用本插件entry 13次 */
		if((5 == g_up_layer_non_num) && (5 == g_up_layer_is_tunnel_num)){
			printf("\033[32mup_layer_tunnel_gtp test success!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mnon-tunnel num: %d, is tunnel num: %d\033[0m\n", g_up_layer_non_num, g_up_layer_is_tunnel_num);
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}

	return APP_STATE_GIVEME;
}


extern "C" char up_layer_tunnel_l2tp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	enum stream_carry_tunnel_t up_layer_tunnel_type = STREAM_TUNNLE_NON;
	int opt_len = sizeof(short);

	g_up_layer_plug_call_times++;
	
	if(OP_STATE_CLOSE != pstream->pktstate){
		MESA_get_stream_opt(pstream, MSO_STREAM_UP_LAYER_TUNNEL_TYPE, &up_layer_tunnel_type, &opt_len);
		if(STREAM_TUNNLE_L2TP != up_layer_tunnel_type){  /* 此处要精确判断隧道类型, 防止解析出错, 不能用STREAM_TUNNLE_NON模糊判断 */
			g_up_layer_non_num++;
		}else{
			g_up_layer_is_tunnel_num++;
		}	

		printf("stream: %s, tunnel:%d\n", printaddr(&pstream->addr, thread_seq), (int)up_layer_tunnel_type);
	}

	if(11 == g_up_layer_plug_call_times){ /* l2tp_dns.pcap一共4个包, 4个外层udp, 4个内层udp, 外加3个流的close状态, 最终是调用本插件entry 11次 */
		if((4 == g_up_layer_non_num) && (4 == g_up_layer_is_tunnel_num)){
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mnon-tunnel num: %d, is tunnel num: %d\033[0m\n", g_up_layer_non_num, g_up_layer_is_tunnel_num);
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}

	return APP_STATE_GIVEME;
}

extern "C" char up_layer_tunnel_teredo_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	enum stream_carry_tunnel_t up_layer_tunnel_type = STREAM_TUNNLE_NON;
	int opt_len = sizeof(short);

	g_up_layer_plug_call_times++;
	
	if(OP_STATE_CLOSE != pstream->pktstate){
		MESA_get_stream_opt(pstream, MSO_STREAM_UP_LAYER_TUNNEL_TYPE, &up_layer_tunnel_type, &opt_len);
		if(STREAM_TUNNLE_TEREDO != up_layer_tunnel_type){  /* 此处要精确判断隧道类型, 防止解析出错, 不能用STREAM_TUNNLE_NON模糊判断 */
			g_up_layer_non_num++;
		}else{
			g_up_layer_is_tunnel_num++;
		}	

		printf("stream: %s, tunnel:%d\n", printaddr(&pstream->addr, thread_seq), (int)up_layer_tunnel_type);
	}

	if(10 == g_up_layer_plug_call_times){ /* teredo_udp.pcap一共3个包, 3个外层udp, 3个内层udp, 外加4个流的close状态, 最终是调用本插件entry 10次 */
		if((3 == g_up_layer_non_num) && (3 == g_up_layer_is_tunnel_num)){
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mnon-tunnel num: %d, is tunnel num: %d\033[0m\n", g_up_layer_non_num, g_up_layer_is_tunnel_num);
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}

	return APP_STATE_GIVEME;
}



extern "C" int get_plug_pme_init(void)
{
	/* 此处每个插件都要初始化一遍, 因为dlopen时业务层插件加载方式是RTLD_LOCAL, 看似一个全局变量gtest_slave_plug_fd, 实际上地址是不一样的 */
	gtest_sapp_slave_init(); 
	return 0;
}

/* 空函数, 啥也不干, 只是挂载这个层的一个插件 */
extern "C" char void_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	return APP_STATE_GIVEME;
}


/* 挂载到tcpall层入口,只处理本插件自身的pme   */
extern "C" char get_plug_pme_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int *plug1_pme;
	struct mso_plug_pme mso_plug_pme1 = {};
	int opt_val_len;
	
	/* 此处插件不发送正确结果, 只判断错误 */
	if(OP_STATE_PENDING == pstream->opstate){
		plug1_pme = (int *)malloc(sizeof(int));
		*plug1_pme = 0x11111111;
		*pme = plug1_pme;
	}

	/* 插件通过接口获取自身的pme测试 */
	if(OP_STATE_DATA == pstream->opstate){
		mso_plug_pme1.plug_name = "get_plug_pme1";
		mso_plug_pme1.plug_entry_type = "TCP_ALL";
		opt_val_len = sizeof(struct mso_plug_pme);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_PLUG_PME, &mso_plug_pme1, &opt_val_len);
		if(ret < 0){
			printf("\033[1;31;40mget_plug_pme_tcpall_entry get pme error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
		if(mso_plug_pme1.plug_pme != *pme){
			printf("\033[1;31;40mget_plug_pme_tcpall_entry get pme is diff with plug pme!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  		
		}

		if(*((int *)mso_plug_pme1.plug_pme) != 0x11111111){
			printf("\033[1;31;40mget_plug_pme_tcpall_entry get pme value is not 0x11111111!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		free(*pme);
	}
	
	return APP_STATE_GIVEME;
}

/* tcp插件最后被调用, 需要验证tcpall和udp插件的Pme获取状态 */
extern "C" char get_plug_pme_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int *plug2_pme;
	struct mso_plug_pme mso_plug_pme1 = {};	
	struct mso_plug_pme mso_plug_pme2 = {};
	int opt_val_len;

	if(OP_STATE_PENDING == pstream->opstate){
		plug2_pme = (int *)malloc(sizeof(int));
		*plug2_pme = 0x22222222;
		*pme = plug2_pme;
	}

	/* tcp插件通过接口获取自身的pme测试 */
	if(OP_STATE_DATA == pstream->opstate){
		mso_plug_pme2.plug_name = "get_plug_pme2";
		mso_plug_pme2.plug_entry_type = "TCP";		
		opt_val_len = sizeof(struct mso_plug_pme);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_PLUG_PME, &mso_plug_pme2, &opt_val_len);
		if(ret < 0){
			printf("\033[1;31;40mget_plug_pme_tcp_entry get  pme error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
		if(mso_plug_pme2.plug_pme != *pme){
			printf("\033[1;31;40mget_plug_pme_tcp_entry get pme is diff with plug pme!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  		
		}

		if(*((int *)mso_plug_pme2.plug_pme) != 0x22222222){
			printf("\033[1;31;40mget_plug_pme_tcp_entry get pme value is not 0x22222222!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}	

		/* 插件2获取插件1的pme测试 */
		mso_plug_pme1.plug_name = "get_plug_pme1";
		mso_plug_pme1.plug_entry_type = "TCP_ALL";
		opt_val_len = sizeof(struct mso_plug_pme);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_PLUG_PME, &mso_plug_pme1, &opt_val_len);
		if(ret < 0){
			printf("\033[1;31;40mget_plug_pme_tcp_entry get tcpall plug pme error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}

		if(*((int *)mso_plug_pme1.plug_pme) != 0x11111111){
			printf("\033[1;31;40mget_plug_pme_tcp_entry get tcpall plug value is not 0x11111111!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		free(*pme);
		printf("\033[32mget_plug_pme test success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_GIVEME;
}


/* 挂载到udp层入口,只处理本插件自身的pme   */
extern "C" char get_plug_pme_udp_entry1(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int *plug1_pme;
	struct mso_plug_pme mso_plug_pme1 = {};
	int opt_val_len;
	
	/* 此处插件不发送正确结果, 只判断错误 */
	if(OP_STATE_PENDING == pstream->opstate){
		plug1_pme = (int *)malloc(sizeof(int));
		*plug1_pme = 0x11111111;
		*pme = plug1_pme;
	}

	/* 插件通过接口获取自身的pme测试 */
	if(OP_STATE_DATA == pstream->opstate){
		mso_plug_pme1.plug_name = "get_plug_pme3";
		mso_plug_pme1.plug_entry_type = "UDP";
		opt_val_len = sizeof(struct mso_plug_pme);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_PLUG_PME, &mso_plug_pme1, &opt_val_len);
		if(ret < 0){
			printf("\033[1;31;40mget_plug_pme_udp_entry1 get pme error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
		if(mso_plug_pme1.plug_pme != *pme){
			printf("\033[1;31;40mget_plug_pme_udp_entry1 get pme is diff with plug pme!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  		
		}

		if(*((int *)mso_plug_pme1.plug_pme) != 0x11111111){
			printf("\033[1;31;40mget_plug_pme_udp_entry1 get pme value is not 0x11111111!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		free(*pme);
	}
	
	return APP_STATE_GIVEME;
}

/* udp2插件最后被调用, 需要验证udp1插件的Pme获取状态 */
extern "C" char get_plug_pme_udp_entry2(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	int *plug2_pme;
	struct mso_plug_pme mso_plug_pme1 = {};	
	struct mso_plug_pme mso_plug_pme2 = {};
	int opt_val_len;

	if(OP_STATE_PENDING == pstream->opstate){
		plug2_pme = (int *)malloc(sizeof(int));
		*plug2_pme = 0x22222222;
		*pme = plug2_pme;
	}

	/* tcp插件通过接口获取自身的pme测试 */
	if(OP_STATE_DATA == pstream->opstate){
		mso_plug_pme2.plug_name = "get_plug_pme4";
		mso_plug_pme2.plug_entry_type = "UDP";

		opt_val_len = sizeof(struct mso_plug_pme);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_PLUG_PME, &mso_plug_pme2, &opt_val_len);
		if(ret < 0){
			printf("\033[1;31;40mget_plug_pme_udp_entry2 get  pme error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
		if(mso_plug_pme2.plug_pme != *pme){
			printf("\033[1;31;40mget_plug_pme_udp_entry2 get pme is diff with plug pme!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  		
		}

		if(*((int *)mso_plug_pme2.plug_pme) != 0x22222222){
			printf("\033[1;31;40mget_plug_pme_udp_entry2 get pme value is not 0x22222222!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}	

		/* 插件2获取插件1的pme测试 */
		mso_plug_pme1.plug_name = "get_plug_pme3";
		mso_plug_pme1.plug_entry_type = "UDP";

		opt_val_len = sizeof(struct mso_plug_pme);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_PLUG_PME, &mso_plug_pme1, &opt_val_len);
		if(ret < 0){
			printf("\033[1;31;40mget_plug_pme_udp_entry2 get udp plug1 pme error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}

		if(*((int *)mso_plug_pme1.plug_pme) != 0x11111111){
			printf("\033[1;31;40mget_plug_pme_udp_entry2 get udp plug1 pme value is not 0x11111111!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		free(*pme);
		/* 正确结果在 get_plug_pme_tcp_entry() 函数中发送 */
		//printf("\033[32mget_plug_pme_entry test success!\033[0m\n");
		//sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_GIVEME;
}

extern "C" char get_duplicate_pkt_stat_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int opt_len = sizeof(int);
	int ret, has_dup_pkt;
	
	if(OP_STATE_PENDING == pstream->opstate){
		ret = MESA_get_stream_opt(pstream, MSO_HAVE_DUP_PKT, &has_dup_pkt, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mget_duplicate_pkt_stat_entry() get MSO_HAVE_DUP_PKT error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  
		}

		/* pending状态的第一个包, 不可能是1也不可能是0, 只能是-2 */
		if(has_dup_pkt != -2){
			printf("\033[1;31;40mget_duplicate_pkt_stat_entry(), first packet get MSO_HAVE_DUP_PKT is true!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  			
		}
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		MESA_get_stream_opt(pstream, MSO_HAVE_DUP_PKT, &has_dup_pkt, &opt_len);
		if(has_dup_pkt != 1){
			printf("\033[1;31;40mget_duplicate_pkt_stat_entry(), OP_CLOSE state get MSO_HAVE_DUP_PKT is false!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  			
		}		

		printf("\033[32mget_duplicate_pkt_stat_entry test success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_GIVEME;
}

/********************  stream_bridge_test_run 对应插件测试用例 start ****************************/
static void _test_stream_bridge_free_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	printf("stream:%s, free data:%s\n", printaddr(&stream->addr, stream->threadnum), (char *)data);
}

#define TEST_BRIDGE_NAME	"bridge_demo"
#define TEST_BRIDGE_ASYNC_DATA "bridge test async data"
#define TEST_BRIDGE_SYNC_DATA  "bridge test sync data"

static int g_test_bridge_id;

extern "C" char tcp_bridge_producer_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int bridge_id;
	static char *async_data;

	bridge_id = stream_bridge_build(TEST_BRIDGE_NAME, "r");
	assert(bridge_id == g_test_bridge_id);
	
	if(OP_STATE_PENDING == pstream->opstate){
		async_data = (char *)malloc(strlen(TEST_BRIDGE_ASYNC_DATA) + 1);
		strcpy(async_data, TEST_BRIDGE_ASYNC_DATA);
		stream_bridge_async_data_put(pstream, bridge_id, async_data);
		stream_bridge_sync_data_put(pstream, bridge_id, (void *)TEST_BRIDGE_SYNC_DATA); /* 第一次customer收不到, 因为customer还没有注册 */
	}else if(OP_STATE_DATA == pstream->opstate){
		stream_bridge_sync_data_put(pstream, bridge_id, (void *)TEST_BRIDGE_SYNC_DATA); 
	}else{
		; /* customer2最后被调用, 测试结果在customer2发送 */
	}

	return APP_STATE_GIVEME;
}

static int g_test_stream_bridge_sync_call_num1 = 0;
static int g_test_stream_bridge_sync_call_num2 = 0;

/* 测试同步调用接口 */
static int _test_stream_bridge_sync_cb1(const struct streaminfo *stream, int bridge_id, void *data)
{
	if(strncasecmp((char *)data, TEST_BRIDGE_SYNC_DATA, strlen(TEST_BRIDGE_SYNC_DATA)) != 0){
		printf("\033[1;31;40mtcp_bridge_customer1  sync data error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  				
	}

	g_test_stream_bridge_sync_call_num1++;
	return 0;
}

static int _test_stream_bridge_sync_cb2(const struct streaminfo *stream, int bridge_id, void *data)
{
	/* 测试同步调用接口 */
	if(strncasecmp((char *)data, TEST_BRIDGE_SYNC_DATA, strlen(TEST_BRIDGE_SYNC_DATA)) != 0){
		printf("\033[1;31;40mtcp_bridge_customer2 sync data error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  				
	}

	g_test_stream_bridge_sync_call_num2++;
	return 0;
}


extern "C" char tcp_bridge_customer1_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int bridge_id;
	const char *async_data;

	bridge_id = stream_bridge_build(TEST_BRIDGE_NAME, "r");
	assert(bridge_id == g_test_bridge_id);

	if(OP_STATE_CLOSE == pstream->opstate){
		async_data = (char *)stream_bridge_async_data_get(pstream, bridge_id);
		if(strncasecmp(async_data, TEST_BRIDGE_ASYNC_DATA, strlen(TEST_BRIDGE_ASYNC_DATA)) != 0){
			printf("\033[1;31;40mtcp_bridge_customer1_entry() sync call number error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  				
		}
	
		if(g_test_stream_bridge_sync_call_num1 != 46){ /* tcp_simple.pcap有46个负载包 */
			printf("\033[1;31;40mtcp_bridge_customer1_entry() sync call number error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  			
		} /* customer2最后被调用, 是否成功的结果在customer2里发送 */
	}

	return APP_STATE_GIVEME;
}

extern "C" char tcp_bridge_customer2_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int bridge_id;
	const char *async_data;

	bridge_id = stream_bridge_build(TEST_BRIDGE_NAME, "r");
	assert(bridge_id == g_test_bridge_id);


	if(OP_STATE_CLOSE == pstream->opstate){
		async_data = (char *)stream_bridge_async_data_get(pstream, bridge_id);
		if(strncasecmp(async_data, TEST_BRIDGE_ASYNC_DATA, strlen(TEST_BRIDGE_ASYNC_DATA)) != 0){
			printf("\033[1;31;40mtcp_bridge_customer2_entry() sync call number error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  				
		}
	
		if(g_test_stream_bridge_sync_call_num2 != 46){ /* tcp_simple.pcap有46个负载包 */
			printf("\033[1;31;40mtcp_bridge_customer2_entry() sync call number error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			  			
		}else{
			printf("\033[32mtcp_bridge_customer2_entry test success!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);				
		}
	}

	return APP_STATE_GIVEME;
}

extern "C" int tcp_bridge_producer_init(void)
{
	g_test_bridge_id = stream_bridge_build("bridge_demo", "w");
	assert(g_test_bridge_id >= 0);
	
	stream_bridge_register_data_free_cb(g_test_bridge_id, _test_stream_bridge_free_cb);

	return 0;
}

extern "C" int tcp_bridge_customer1_init(void)
{
	int bridge_id;
	
	bridge_id = stream_bridge_build(TEST_BRIDGE_NAME, "r");
	assert(bridge_id >= 0);
	stream_bridge_register_data_sync_cb(bridge_id, _test_stream_bridge_sync_cb1);

	return 0;
}

extern "C" int tcp_bridge_customer2_init(void)
{
	int bridge_id;
	int ret;

	ret = gtest_sapp_slave_init();
	if(ret < 0){
		return ret;
	}	
	bridge_id = stream_bridge_build(TEST_BRIDGE_NAME, "r");
	assert(bridge_id >= 0);
	stream_bridge_register_data_sync_cb(bridge_id, _test_stream_bridge_sync_cb2);

	return 0;
}
/********************  stream_bridge_test_run 对应插件测试用例 END ****************************/



extern "C" char inline_get_tcp_flow_stat_plug(struct streaminfo *stream,void **pme, int thread_seq, void *a_packet)
{
	int project_id;
	const struct tcp_flow_stat *tflow;

	if(OP_STATE_CLOSE == stream->pktstate){
		project_id = project_customer_register("tcp_flow_stat", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() project_customer_register  'tcp_flow_stat' error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		tflow = (struct tcp_flow_stat *)project_req_get_struct(stream, project_id);
		if(NULL == tflow){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() project_req_get_struct  'tcp_flow_stat' error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}

		if(tflow->C2S_all_pkt != 5){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() C2S_all_pkt is:%u, but expect 5\033[0m\n", tflow->C2S_all_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}
		if(tflow->S2C_all_pkt != 4){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() S2C_all_pkt is:%u, but expect 4\033[0m\n", tflow->S2C_all_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}		

		if(tflow->C2S_data_pkt != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() C2S_data_pkt is:%u, but expect 1\033[0m\n", tflow->C2S_data_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}
		if(tflow->S2C_data_pkt != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() S2C_data_pkt is:%u, but expect 1\033[0m\n", tflow->S2C_data_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}	

		if(tflow->C2S_data_byte != 186){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() C2S_data_byte is:%llu, but expect 186\033[0m\n", tflow->C2S_data_byte);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}
		if(tflow->S2C_data_byte != 271){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() S2C_data_byte is:%llu, but expect 271\033[0m\n", tflow->S2C_data_byte);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}	

		if(tflow->C2S_all_byte_raw != 486){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() C2S_all_byte_raw is:%llu, but expect 486\033[0m\n", tflow->C2S_all_byte_raw);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}
		if(tflow->S2C_all_byte_raw != 511){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_tcp_flow_stat","\033[1;31;40minline_get_tcp_flow_stat_entry() S2C_all_byte_raw is:%llu, but expect 511\033[0m\n", tflow->S2C_all_byte_raw);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}			

		SAPP_PLUG_LOG(RLOG_LV_INFO, "get_tcp_flow_stat","\033[32minline_get_tcp_flow_stat_entry() test success!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	
	}else{
		SAPP_PLUG_LOG(RLOG_LV_DEBUG, "get_udp_flow_stat","inline_get_tcp_flow_stat_entry() recv udp packet:%d\n", stream->ptcpdetail->clientpktnum+stream->ptcpdetail->serverpktnum);
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char inline_get_udp_flow_stat_plug(struct streaminfo *stream,void **pme, int thread_seq, void *a_packet)
{
	int project_id;
	const struct udp_flow_stat *tflow;


	if(OP_STATE_CLOSE == stream->opstate){
		project_id = project_customer_register("udp_flow_stat", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_udp_flow_stat","\033[1;31;40minline_get_udp_flow_stat_entry() project_customer_register  'udp_flow_stat' error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		tflow = (struct udp_flow_stat *)project_req_get_struct(stream, project_id);
		if(NULL == tflow){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"get_udp_flow_stat","\033[1;31;40minline_get_udp_flow_stat_entry() project_req_get_struct  'tcp_flow_stat' error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}

		if(tflow->C2S_pkt != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"get_udp_flow_stat","\033[1;31;40minline_get_udp_flow_stat_entry() C2S_all_pkt is:%u, but expect 1\033[0m\n", tflow->C2S_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;				
		}
		if(tflow->S2C_pkt != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"get_udp_flow_stat","\033[1;31;40minline_get_udp_flow_stat_entry() S2C_all_pkt is:%u, but expect 1\033[0m\n", tflow->S2C_pkt);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}	
		
		if(tflow->C2S_byte != 33){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"get_udp_flow_stat","\033[1;31;40minline_get_udp_flow_stat_entry() C2S_byte is:%llu, but expect 33\033[0m\n", tflow->C2S_byte);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}
		if(tflow->S2C_byte != 150){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"get_udp_flow_stat","\033[1;31;40minline_get_udp_flow_stat_entry() S2C_byte is:%llu, but expect 150\033[0m\n", tflow->S2C_byte);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}		

		if(tflow->C2S_all_byte_raw != 75){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"get_udp_flow_stat","\033[1;31;40minline_get_flow_stat_entry() C2S_all_byte_raw is:%llu, but expect 75\033[0m\n", tflow->C2S_all_byte_raw);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}
		if(tflow->S2C_all_byte_raw != 192){
			SAPP_PLUG_LOG(RLOG_LV_FATAL,"get_udp_flow_stat","\033[1;31;40minline_get_flow_stat_entry() S2C_all_byte_raw is:%llu, but expect 192\033[0m\n", tflow->S2C_all_byte_raw);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}			

		SAPP_PLUG_LOG(RLOG_LV_INFO, "get_udp_flow_stat","\033[32minline_get_udp_flow_stat_entry() test success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);	
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);

	}else{
		SAPP_PLUG_LOG(RLOG_LV_DEBUG, "get_udp_flow_stat","inline_get_udp_flow_stat_entry() recv udp packet:%d\n", stream->pudpdetail->clientpktnum+stream->pudpdetail->serverpktnum);
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char ctrl_get_root_dir_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int opt_len;
	int ret;
	char root_dir_buf[PATH_MAX];

	opt_len = 1;
	ret = sapp_get_platform_opt(SPO_CONFIG_ROOT_DIR, root_dir_buf, &opt_len);
	if(ret >= 0){
		printf("\033[1;31;40mctrl_get_root_dir_entry() error, opt len is too small, but SPO_CONFIG_ROOT_DIR result is succ!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	opt_len = PATH_MAX;
	ret = sapp_get_platform_opt(SPO_CONFIG_ROOT_DIR, root_dir_buf, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mctrl_get_root_dir_entry() error, can't get SPO_CONFIG_ROOT_DIR!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	if(strcmp("/tmp/sapp_change_root_dir_test/config", root_dir_buf) != 0){
		printf("\033[1;31;40mctrl_get_root_dir_entry() error, SPO_CONFIG_ROOT_DIR is:%s, but expect:%s\033[0m\n", root_dir_buf, "/tmp/sapp_change_root_dir_test/config");
		sendto_test_result(GTEST_SAPP_ERR);
		  		
	}	

	opt_len = 1;
	ret = sapp_get_platform_opt(SPO_DATA_ROOT_DIR, root_dir_buf, &opt_len);
	if(ret >= 0){
		printf("\033[1;31;40mctrl_get_root_dir_entry() error, opt len is too small, but SPO_DATA_ROOT_DIR result is succ!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}

	opt_len = PATH_MAX;
	ret = sapp_get_platform_opt(SPO_DATA_ROOT_DIR, root_dir_buf, &opt_len);
	if(ret < 0){
		printf("\033[1;31;40mctrl_get_root_dir_entry() error, can't get SPO_DATA_ROOT_DIR!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		  
	}	

	if(strcmp("/tmp/sapp_change_root_dir_test/data", root_dir_buf) != 0){
		printf("\033[1;31;40mctrl_get_root_dir_entry() error, SPO_DATA_ROOT_DIR is:%s, but expect is:%s\033[0m\n", root_dir_buf, "/tmp/sapp_change_root_dir_test/data");
		sendto_test_result(GTEST_SAPP_ERR);
		  		
	}

	printf("\033[32mctrl_get_root_dir_entry() test success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;	
}

static void find_streaminfo_build_tuple4v4(struct stream_tuple4_v4 *t4v4, const char *ipsrc, const char *ipdst, unsigned short sport, unsigned short dport)
{
	inet_pton(AF_INET, ipsrc, &t4v4->saddr);
	inet_pton(AF_INET, ipdst, &t4v4->daddr);
	t4v4->source = htons(sport);
	t4v4->dest = htons(dport);
}

static void find_streaminfo_build_tuple4v6(struct stream_tuple4_v6 *t4v6, const char *ipsrc, const char *ipdst, unsigned short sport, unsigned short dport)
{
	inet_pton(AF_INET6, ipsrc, t4v6->saddr);
	inet_pton(AF_INET6, ipdst, t4v6->daddr);
	t4v6->source = htons(sport);
	t4v6->dest = htons(dport);
}


extern "C" int find_streaminfo_by_addrv4(int thread_index, const struct stream_tuple4_v4 *tuplev4, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num);
extern "C" int find_streaminfo_by_addrv6(int thread_index, const struct stream_tuple4_v6 *tuplev6, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num);

/* 
    通过四元组查找streaminfo, 在一堆pcap里, 随机找四个流, 两个tcp, 两个udp ,
    两个方向分别查询, C2S和S2C.
*/
extern "C" char polling_find_streaminfo_entry_v4(struct streaminfo *nouse,void **nouse2, int thread_seq, void *nouse3)
{
	struct stream_tuple4_v4 t4v4;
	static int tcp_port_57269_80_c2s_bingo = 0;
	static int tcp_port_57269_80_s2c_bingo = 0;
	
	static int tcp_port_57232_20001_c2s_bingo = 0;
	static int tcp_port_57232_20001_s2c_bingo = 0;
	
	static int udp_port_64797_8000_c2s_bingo = 0;
	static int udp_port_64797_8000_s2c_bingo = 0;
	
	static int udp_port_55460_161_c2s_bingo = 0;
	static int udp_port_55460_161_s2c_bingo = 0;
	
	static int all_stream_have_found = 0;

	struct streaminfo *result[10];
	int result_num;

	if(1 == all_stream_have_found){
		return POLLING_STATE_IDLE;
	}

	if(tcp_port_57269_80_c2s_bingo && tcp_port_57269_80_s2c_bingo 
	&& tcp_port_57232_20001_c2s_bingo &&  tcp_port_57232_20001_s2c_bingo
	&& udp_port_64797_8000_c2s_bingo && udp_port_64797_8000_s2c_bingo
	&& udp_port_55460_161_c2s_bingo && udp_port_55460_161_s2c_bingo){
		printf("\033[32m find_streaminfo v4 check succ, thread:%d, all stream have been found!\033[0m\n", thread_seq);
		sendto_test_result(GTEST_SAPP_SUCC);
		all_stream_have_found = 1;
		return POLLING_STATE_IDLE;
	}	

	find_streaminfo_build_tuple4v4(&t4v4, "192.168.36.103", "112.90.216.109", 57269, 80);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_TCP, result, 10);
	if(result_num > 0){
		if(ntohs(result[0]->addr.tuple4_v4->source) == 57269){
			tcp_port_57269_80_c2s_bingo = 1;
		}
	}
	find_streaminfo_build_tuple4v4(&t4v4, "112.90.216.109", "192.168.36.103", 80, 57269);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_TCP, result, 10);
	if(result_num > 0){
		tcp_port_57269_80_s2c_bingo = 1;
	}

	find_streaminfo_build_tuple4v4(&t4v4, "192.168.36.103", "125.94.242.80", 57232, 20001);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_TCP, result, 10);
	if(result_num > 0){
		if(ntohs(result[0]->addr.tuple4_v4->source) == 57232){
			tcp_port_57232_20001_c2s_bingo = 1;
		}
	}	
	find_streaminfo_build_tuple4v4(&t4v4, "125.94.242.80", "192.168.36.103", 20001, 57232);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_TCP, result, 10);
	if(result_num > 0){
		tcp_port_57232_20001_s2c_bingo = 1;
	}	

	find_streaminfo_build_tuple4v4(&t4v4, "192.168.36.103", "182.254.21.27", 64797, 8000);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_UDP, result, 10);
	if(result_num > 0){
		if(ntohs(result[0]->addr.tuple4_v4->source) == 64797){
			udp_port_64797_8000_c2s_bingo = 1;
		}
	}	
	find_streaminfo_build_tuple4v4(&t4v4, "182.254.21.27", "192.168.36.103", 8000, 64797);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_UDP, result, 10);
	if(result_num > 0){
		udp_port_64797_8000_s2c_bingo = 1;
	}		

	find_streaminfo_build_tuple4v4(&t4v4, "192.168.36.103", "192.168.10.181", 55460, 161);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_UDP, result, 10);
	if(result_num > 0){
		if(ntohs(result[0]->addr.tuple4_v4->source) == 55460){
			udp_port_55460_161_c2s_bingo = 1;
		}
	}	
	find_streaminfo_build_tuple4v4(&t4v4, "192.168.10.181", "192.168.36.103", 161, 55460);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_UDP, result, 10);
	if(result_num > 0){
		udp_port_55460_161_s2c_bingo = 1;
	}	


	/************ 此处故意写个错的四元组, ip和port顺序反了, 理论上应该是查不到的 */
	find_streaminfo_build_tuple4v4(&t4v4, "192.168.36.103", "125.94.242.80", 20001, 57232);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_TCP, result, 10);
	if(result_num > 0){
		printf("\033[1;31;40mpolling_find_streaminfo_entry v4() error, found not exist streaminfo!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}	

	return POLLING_STATE_WORK;
}


/* 
    通过四元组查找streaminfo, 在一堆pcap里, 随机找四个流, 两个tcp, 两个udp ,
    两个方向分别查询, C2S和S2C.
*/
extern "C" char polling_find_streaminfo_entry_v6(struct streaminfo *nouse,void **nouse2, int thread_seq, void *nouse3)
{
	struct stream_tuple4_v6 t4v6;
	static int tcp_port_44444_39410_c2s_bingo = 0;
	static int tcp_port_44444_39410_s2c_bingo = 0;
	
	static int tcp_port_55555_52092_c2s_bingo = 0;
	static int tcp_port_55555_52092_s2c_bingo = 0;
	
	static int udp_port_60042_11111_c2s_bingo = 0;
	static int udp_port_60042_11111_s2c_bingo = 0;
	
	static int udp_port_43977_33333_c2s_bingo = 0;
	static int udp_port_43977_33333_s2c_bingo = 0;
	
	static int all_stream_have_found_v6 = 0;
	struct streaminfo *result_v6[10];
	int result_v6_num;

	if(1 == all_stream_have_found_v6){
		return POLLING_STATE_IDLE;
	}

	if(tcp_port_44444_39410_c2s_bingo && tcp_port_44444_39410_s2c_bingo 
	&& tcp_port_55555_52092_c2s_bingo &&  tcp_port_55555_52092_s2c_bingo
	&& udp_port_60042_11111_c2s_bingo && udp_port_60042_11111_s2c_bingo
	&& udp_port_43977_33333_c2s_bingo && udp_port_43977_33333_s2c_bingo){
		printf("\033[32m find_streaminfo v6 check succ, thread:%d, all stream have been found!\033[0m\n", thread_seq);
		sendto_test_result(GTEST_SAPP_SUCC);
		all_stream_have_found_v6 = 1;
		return POLLING_STATE_IDLE;
	}	

	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:161", "2001::192:168:40:162", 44444, 39410);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_TCP, result_v6, 10);
	if(result_v6_num > 0){
		if(ntohs(result_v6[0]->addr.tuple4_v6->source) == 44444){  
			printf("\033[32m find_streaminfo v6, thread:%d, tcp port 44444 found!\033[0m\n", thread_seq);
			tcp_port_44444_39410_c2s_bingo = 1;
		}else{
			printf("\033[1;31;40m find_streaminfo() found stream, but sport:%u, dport:%u\033[0m\n", ntohs(result_v6[0]->addr.tuple4_v6->source), ntohs(result_v6[0]->addr.tuple4_v6->dest));
		}
	}
	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:162", "2001::192:168:40:161", 39410, 44444);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_TCP, result_v6, 10);
	if(result_v6_num > 0){
		tcp_port_44444_39410_s2c_bingo = 1;
	}

	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:161", "2001::192:168:40:162", 55555, 52092);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_TCP, result_v6, 10);
	if(result_v6_num > 0){
		if(ntohs(result_v6[0]->addr.tuple4_v6->source) == 55555){
			printf("\033[32m find_streaminfo v6, thread:%d, tcp port 55555 found!\033[0m\n", thread_seq);
			tcp_port_55555_52092_c2s_bingo = 1;
		}else{
			printf("\033[1;31;40m find_streaminfo() found stream, but sport:%u, dport:%u\033[0m\n", ntohs(result_v6[0]->addr.tuple4_v6->source), ntohs(result_v6[0]->addr.tuple4_v6->dest));
		}
	}
	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:162", "2001::192:168:40:161", 52092, 55555);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_TCP, result_v6, 10);
	if(result_v6_num > 0){
		tcp_port_55555_52092_s2c_bingo = 1;
	}

	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:162", "2001::192:168:40:161", 60042, 11111);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_UDP, result_v6, 10);
	if(result_v6_num > 0){
		if(ntohs(result_v6[0]->addr.tuple4_v6->source) == 60042){
			printf("\033[32m find_streaminfo v6, thread:%d, udp port 11111 found!\033[0m\n", thread_seq);
			udp_port_60042_11111_c2s_bingo = 1;
		}else{
			printf("\033[1;31;40m find_streaminfo() found stream, but sport:%u, dport:%u\033[0m\n", ntohs(result_v6[0]->addr.tuple4_v6->source), ntohs(result_v6[0]->addr.tuple4_v6->dest));
		}
	}
	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:161", "2001::192:168:40:162", 11111, 60042);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_UDP, result_v6, 10);
	if(result_v6_num > 0){
		udp_port_60042_11111_s2c_bingo = 1;
	}

	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:162", "2001::192:168:40:161", 43977, 33333);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_UDP, result_v6, 10);
	if(result_v6_num > 0){
		if(ntohs(result_v6[0]->addr.tuple4_v6->source) == 43977){
			printf("\033[32m find_streaminfo v6, thread:%d, udp port 33333 found!\033[0m\n", thread_seq);
			udp_port_43977_33333_c2s_bingo = 1;
		}
	}
	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:161", "2001::192:168:40:162", 33333, 43977);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_UDP, result_v6, 10);
	if(result_v6_num > 0){
		udp_port_43977_33333_s2c_bingo = 1;
	}


	/************ 此处故意写个错的四元组, ip和port顺序反了, 理论上应该是查不到的 */
	find_streaminfo_build_tuple4v6(&t4v6, "2001::192:168:40:162", "2001::192:168:40:161", 44444, 39410);
	result_v6_num = find_streaminfo_by_addrv6(thread_seq, &t4v6, STREAM_TYPE_TCP, result_v6, 10);
	if(result_v6_num > 0){
		printf("\033[1;31;40mpolling_find_streaminfo_entry_v6() error, found not exist streaminfo!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}	


	return POLLING_STATE_WORK;
}

/*
	内层四元组一样, 但外层不一样的四元组地址查询.
*/
extern "C" char polling_find_diff_tunnel_streaminfo_entry_v4(struct streaminfo *nouse,void **nouse2, int thread_seq, void *nouse3)
{
	struct stream_tuple4_v4 t4v4;
	static int tcp_port_57638_80_c2s_bingo = 0;
	static int tcp_port_57638_80_s2c_bingo = 0;
	
	static int udp_port_1101_53_c2s_bingo = 0;
	static int udp_port_1101_53_s2c_bingo = 0;
	
	static int all_stream_have_found = 0;

	struct streaminfo *result[10];
	int result_num;

	if(1 == all_stream_have_found){
		return POLLING_STATE_IDLE;
	}

	if(tcp_port_57638_80_c2s_bingo && tcp_port_57638_80_s2c_bingo 
	&& udp_port_1101_53_c2s_bingo &&  udp_port_1101_53_s2c_bingo){
		printf("\033[32m find_streaminfo v4 check succ, thread:%d, all stream have been found!\033[0m\n", thread_seq);
		sendto_test_result(GTEST_SAPP_SUCC);
		all_stream_have_found = 1;
		return POLLING_STATE_IDLE;
	}	

	find_streaminfo_build_tuple4v4(&t4v4, "10.31.247.14", "217.76.78.43", 1101, 53);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_UDP, result, 10);
	if(result_num >= 2){
		if((ntohs(result[0]->addr.tuple4_v4->source) == 1101) && (ntohs(result[1]->addr.tuple4_v4->source) == 1101)){
			printf("\033[32m find_streaminfo udp_port_1101_53_c2s stream have been found!\033[0m\n");
			udp_port_1101_53_c2s_bingo = 1;
		}else{
			printf("\033[1;31;40m find_streaminfo() found stream, but stream1_sport:%u, stream2_sport:%u\033[0m\n", ntohs(result[0]->addr.tuple4_v4->source), ntohs(result[1]->addr.tuple4_v4->source));
		}
	}
	find_streaminfo_build_tuple4v4(&t4v4, "217.76.78.43", "10.31.247.14", 53, 1101);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_UDP, result, 10);
	if(result_num >= 2){
		if((ntohs(result[0]->addr.tuple4_v4->source) == 1101) && (ntohs(result[1]->addr.tuple4_v4->source) == 1101)){
			printf("\033[32m find_streaminfo udp_port_1101_53_s2c stream have been found!\033[0m\n");
			udp_port_1101_53_s2c_bingo = 1;
		}else{
			printf("\033[1;31;40m find_streaminfo() found stream, but stream1_sport:%u, stream2_sport:%u\033[0m\n", ntohs(result[0]->addr.tuple4_v4->source), ntohs(result[1]->addr.tuple4_v4->source));
		}
	}

	find_streaminfo_build_tuple4v4(&t4v4, "10.19.214.177", "173.194.44.16", 57638, 80);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_TCP, result, 10);
	if(result_num >= 2){
		if((ntohs(result[0]->addr.tuple4_v4->source) == 57638) && (ntohs(result[1]->addr.tuple4_v4->source) == 57638)){
			printf("\033[32m find_streaminfo tcp_port_57638_80_c2s stream have been found!\033[0m\n");
			tcp_port_57638_80_c2s_bingo = 1;
		}else{
			printf("\033[1;31;40m find_streaminfo() found stream, but stream1_sport:%u, stream2_sport:%u\033[0m\n", ntohs(result[0]->addr.tuple4_v4->source), ntohs(result[1]->addr.tuple4_v4->source));
		}
	}	
	find_streaminfo_build_tuple4v4(&t4v4, "173.194.44.16", "10.19.214.177", 80, 57638);
	result_num = find_streaminfo_by_addrv4(thread_seq, &t4v4, STREAM_TYPE_TCP, result, 10);
	if(result_num >= 2){
		if((ntohs(result[0]->addr.tuple4_v4->source) == 57638) && (ntohs(result[1]->addr.tuple4_v4->source) == 57638)){
			printf("\033[32m find_streaminfo tcp_port_57638_80_s2c stream have been found!\033[0m\n");
			tcp_port_57638_80_s2c_bingo = 1;
		}else{
			printf("\033[1;31;40m find_streaminfo() found stream, but stream1_sport:%u, stream2_sport:%u\033[0m\n", ntohs(result[0]->addr.tuple4_v4->source), ntohs(result[1]->addr.tuple4_v4->source));
		}
	}	


	return POLLING_STATE_WORK;
}


extern "C" char fork_listen_port_tcp_plug(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	pid_t fork_pid;
	char *sapp_args[2] = {(char *)"-d", NULL};
	
	if(pstream->opstate == OP_STATE_PENDING){
		fork_pid = fork();
		if(0 == fork_pid){
			printf("fork_listen_port child pid:%d\n", getpid());
			usleep(10000); /* 子进程等父sapp进程彻底结束 */

			/* 再次执行一次sapp, 保证不能再打开12345等监听端口, 且使用在线模式, 不退出 */

			update_config_file_by_lastline("etc/sapp.toml", "packet_io.depolyment", "mode", "mirror");
			update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "name", "lo");
			update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "name", "lo");
			update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "type", "pcap");  /* 此处用pcap模式测试, 不需要借助fake marsio */
			update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "type", "pcap");  /* 此处用pcap模式测试, 不需要借助fake marsio */
	
			update_config_file_by_lastline("etc/sapp.toml", "tools.pkt_dump", "enabled", "0"); 
			update_config_file_by_lastNline("etc/sapp.toml", "tools.pkt_dump", 2, "mode", "udp_socket");
			update_config_file_by_lastNline("etc/sapp.toml", "tools.pkt_dump", 3, "mode", "udp_socket");
			update_config_file("etc/sapp.toml", "command_port", "54321"); 
			update_config_file("etc/sapp.toml", "dumpfile_sleep_time_before_exit", "0"); 

			update_config_file("etc/sapp.toml", "prometheus_enabled", "0");

			system("> plug/conflist.inf"); /* 子进程启动不能再挂插件了, 否则死循环了 */
	
			execv("./sapp", sapp_args);  

			printf("\033[1;31;40mfork_listen_port plug error: execv sapp fail!\033[0m\n");
		}else{
			printf("fork_listen_port parent pid:%d, exit!\n", getpid());
			   /* sapp父进程退出 */
		}
	}
	
	return APP_STATE_GIVEME;
}


// Read in specified integer array value
extern "C" int tomlc99_wrap_load_int_array(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	int *array, // [OUT] returned value
	int *array_num); // [IN/OUT] IN: max array item number; OUT: config actual array number


// Read in specified long integer array value
extern "C" int tomlc99_wrap_load_long_array(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	long *array, // [OUT] returned value
	int *array_num); // [IN/OUT] IN: max array item number; OUT: config actual array number

extern "C" char toml_array_parse_plug(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int i, ret;
	int int_array[64] = {};
	long long_array[64] = {};
	int array_num = 64;
	
	system("echo \"[test]\" > /tmp/test.toml");
	system("echo \"array=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]\" >> /tmp/test.toml");


	/* check int array */
	ret = tomlc99_wrap_load_int_array("/tmp/test.toml", "test", (char *)"array", int_array, &array_num);
	if(ret < 0){
		printf("\033[1;31;40mtoml_array_parse_plug error: toml file parse fail!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(array_num != 64){
		printf("\033[1;31;40mtoml_array_parse_plug error: array num is:%d, but expect 64!\033[0m\n", array_num);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	for(i = 0; i < 64; i++){
		if(int_array[i] != i+1){
			printf("\033[1;31;40mtoml_array_parse_plug error: array value[%d] is:%d!\033[0m\n", i, int_array[i]);
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}

	/* check long array */
	ret = tomlc99_wrap_load_long_array("/tmp/test.toml", "test", (char *)"array", long_array, &array_num);
	if(ret < 0){
		printf("\033[1;31;40mtoml_array_parse_plug error: toml file parse fail!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(array_num != 64){
		printf("\033[1;31;40mtoml_array_parse_plug error: array num is:%d, but expect 64!\033[0m\n", array_num);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	for(i = 0; i < 64; i++){
		if(long_array[i] != i+1){
			printf("\033[1;31;40mtoml_array_parse_plug error: array value[%d] is:%ld!\033[0m\n", i, long_array[i]);
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}
	
	printf("\033[32mtoml_array_parse_plug test success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);
			
	return APP_STATE_DROPME;
}

extern "C" char get_linkdir_from_mac_tcpall_entry0(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(pstream->routedir != 0){ /* 原始包中方向位是0 */
		printf("\033[1;31;40mget_linkdir_from_mac_tcpall_entry0 error: route dir is not 0!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;
	}

	printf("\033[32mget_linkdir_from_mac_tcpall_entry0 test success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);
			
	return APP_STATE_DROPME;	
}

extern "C" char get_linkdir_from_mac_tcpall_entry1(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(pstream->routedir != 1){ /* 原始包中方向位是1 */
		printf("\033[1;31;40mget_linkdir_from_mac_tcpall_entry error: route dir is not 1!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;
	}

	printf("\033[32mget_linkdir_from_mac_tcpall_entry1 test success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);
			
	return APP_STATE_DROPME;	
}


static char __get_deployment_mode_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret, opt_len, res_value = GTEST_SAPP_ERR;
	char file_md5[64];
	char dep_mode_string[64];
	enum sapp_deploment_mode_t dep_mode;
	
		opt_len = sizeof(dep_mode);
		ret = sapp_get_platform_opt(SPO_DEPLOYMENT_MODE, &dep_mode, &opt_len);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error!\033[0m\n");
			exit(2);
			return APP_STATE_DROPME;
		}

		opt_len = sizeof(dep_mode_string);
		ret = sapp_get_platform_opt(SPO_DEPLOYMENT_MODE_STR, dep_mode_string, &opt_len);
		if(ret < 0){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);	
			fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error!\033[0m\n");
			exit(2);
			return APP_STATE_DROPME;
		}		

		/* 用了一个插件入口函数, 使用不同的dumpfile来表示不同的拓扑模式 */
		gtest_file_md5sum("dumpfile", file_md5, sizeof(file_md5));
		if(strncasecmp(file_md5, "df138740a6a22ca9c977052f21f7a470", strlen("df138740a6a22ca9c977052f21f7a470")) == 0){
			if(dep_mode != DEPOLYMENT_MODE_MIRROR){
				SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error, actual is:%d, but expect MIRROR !\033[0m\n", dep_mode);
				sendto_test_result(GTEST_SAPP_ERR);	
				fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error, actual is:%d, but expect MIRROR !\033[0m\n", dep_mode);
				exit(2);
				return APP_STATE_DROPME;				
			}
			if((strncasecmp(dep_mode_string, "mirror", strlen("mirror")) != 0)
			 &&(strncasecmp(dep_mode_string, "dumpfile", strlen("dumpfile")) != 0)){
				SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error, actual is:%s, but expect MIRROR !\033[0m\n", dep_mode_string);
				sendto_test_result(GTEST_SAPP_ERR);	
				fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error, actual is:%s, but expect MIRROR !\033[0m\n", dep_mode_string);
				exit(2);
				return APP_STATE_DROPME;				
			}	
			res_value = GTEST_SAPP_SUCC;
		}else if(strncasecmp(file_md5, "a5d0d96ee6f44f729d79aeac5cc2fee0", strlen("a5d0d96ee6f44f729d79aeac5cc2fee0")) == 0){
			if(dep_mode != DEPOLYMENT_MODE_TRANSPARENT){
				SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error, actual is:%d, but expect TRANSPARENT !\033[0m\n", dep_mode);
				sendto_test_result(GTEST_SAPP_ERR);
				fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error, actual is:%d, but expect TRANSPARENT !\033[0m\n", dep_mode);
				exit(2);
				return APP_STATE_DROPME;
			}
			if(strncasecmp(dep_mode_string, "transparent", strlen("transparent")) != 0){
				SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error, actual is:%s, but expect TRANSPARENT !\033[0m\n", dep_mode_string);
				sendto_test_result(GTEST_SAPP_ERR);	
				fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error, actual is:%s, but expect TRANSPARENT !\033[0m\n", dep_mode_string);
				return APP_STATE_DROPME;				
			}			
			res_value = GTEST_TRANSPARENT_TO_SAPP_SUCC;
		}else if(strncasecmp(file_md5, "917fd6b8bc70e02812a036adf637479b", strlen("917fd6b8bc70e02812a036adf637479b")) == 0){
			if(dep_mode != DEPOLYMENT_MODE_INLINE){
				SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error, actual is:%d, but expect INLINE !\033[0m\n", dep_mode);
				sendto_test_result(GTEST_SAPP_ERR);
				fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE error, actual is:%d, but expect INLINE !\033[0m\n", dep_mode);
				exit(2);
				return APP_STATE_DROPME;				
			}
			if(strncasecmp(dep_mode_string, "inline", strlen("inline")) != 0){
				SAPP_PLUG_LOG(RLOG_LV_FATAL, "get_deployment_mode", "\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error, actual is:%s, but expect INLINE !\033[0m\n", dep_mode_string);
				sendto_test_result(GTEST_SAPP_ERR);	
				fprintf(stderr,	"\033[1;31;40mget_deployment_mode_entry get SPO_DEPLOYMENT_MODE_STR error, actual is:%s, but expect INLINE !\033[0m\n", dep_mode_string);
				exit(2);
				return APP_STATE_DROPME;				
			}		

			res_value = GTEST_INLINE_TO_SAPP_SUCC;
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO, "get_deployment_mode", "\033[32mget_deployment_mode_entry test success!\033[0m\n");
		sendto_test_result(res_value);
		fprintf(stderr,	"\033[32mget_deployment_mode_entry test success!\033[0m\n");
		exit(0);
			
		return APP_STATE_DROPME;		
}

extern "C" char get_deployment_mode_tcp_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	return __get_deployment_mode_entry(pstream, pme, thread_seq, a_packet);
}

extern "C" char get_deployment_mode_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	return __get_deployment_mode_entry(pstream, pme, thread_seq, a_packet);
}


extern "C" int plug_fake_init(void)
{
	return 1;
}


extern "C" int plug_necessary_init(void)
{
	return -1; /* 测试necessary_plug_list功能, 故意初始化不成功 */
}

/* 排在necessary插件后面, 也不应该被调用 */
extern "C" int plug_indifferent_init(void)
{
	gtest_sapp_slave_init(); /* 每个插件有独立的符号名, 需要独立调用gtest_sapp_slave_init()函数, 创建socket, 否则发送结果会失败 */
	
	printf("\033[1;31;40mnecessary plug init error, can't call this function!\033[0m\n");
	sendto_test_result(GTEST_SAPP_ERR);	
	return 0;
}


extern "C" char plug_necessary_not_call_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	gtest_sapp_slave_init(); /* 每个插件有独立的符号名, 需要独立调用gtest_sapp_slave_init()函数, 创建socket, 否则发送结果会失败 */
	printf("\033[1;31;40minit error, can't call this entry!\033[0m\n");
	sendto_test_result(GTEST_SAPP_ERR);	
	return APP_STATE_GIVEME;
}

/* 排在necessary插件后面, 也不应该被调用 */
extern "C" char plug_indifferent_not_call_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	printf("\033[1;31;40mnecessary plug init error, can't call this entry!\033[0m\n");
	sendto_test_result(GTEST_SAPP_ERR);	
	return APP_STATE_GIVEME;
}



#endif



