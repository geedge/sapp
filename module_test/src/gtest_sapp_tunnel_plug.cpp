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


//static gtest_plug_stat_t gtest_tunnel_stat;
static int g_tcp_stream_index = 0;

extern "C" char teredo_unstandard_port_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
	int ret;
	unsigned short tunnel_type = 0;
	int opt_len = sizeof(tunnel_type);
	
	if(OP_STATE_PENDING == pstream->opstate){
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
		if(ret < 0){
			printf("\033[1;31;40mteredo_unstandard_port_tcp_entry: get tunnel type error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}else{
			if(tunnel_type != STREAM_TUNNLE_TEREDO){
				printf("\033[1;31;40mteredo_unstandard_port_tcp_entry: tunnel type is not teredo!\033[0m\n");
				sendto_test_result(GTEST_SAPP_ERR);
				return APP_STATE_DROPME;
			}
		}
	}else if(OP_STATE_CLOSE == pstream->opstate){
		if((pdetail->serverbytes)
		 &&(pdetail->serverpktnum)){
		 	printf("\033[32mteredo_unstandard_port_tcp_entry: success!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);
		}else{
			printf("\033[1;31;40mteredo_unstandard_port_tcp_entry: check data length error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char teredo_with_auth_hdr_ip6entry(const struct streaminfo *pstream,
				unsigned char routedir,int thread_seq, const struct ip6_hdr *ipv6_hdr)
{

	if(48 != ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)){
		printf("\033[1;31;40mteredo_with_auth_hdr_ip6entry: ipv6 payload length error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(58 != ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt){
		printf("\033[1;31;40mteredo_with_auth_hdr_ip6entry: ipv6 next header error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(0xc36ac762 != ipv6_hdr->ip6_src.s6_addr32[3]){
		printf("\033[1;31;40mteredo_with_auth_hdr_ip6entry: ipv6 src addr error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	if(0xfeffffff != ipv6_hdr->ip6_dst.s6_addr32[3]){
		printf("\033[1;31;40mteredo_with_auth_hdr_ip6entry: ipv6 src addr error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	printf("\033[32mteredo_with_auth_hdr_ip6entry: success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);

	return APP_STATE_GIVEME;
}


/* 识别是否是gtp隧道 */
extern "C" char gtp_identify_plug_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type;
	int opt_len = sizeof(short);
	
	MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(tunnel_type != STREAM_TUNNEL_GPRS_TUNNEL){
		printf("\033[1;31;40mstream tunnel is not GTP\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}else{
		printf("\033[32mstream tunnel is GTP\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_DROPME;
}

/* 识别是否是pptp隧道 */
extern "C" char pptp_identify_plug_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type;
	int opt_len = sizeof(short);
	
	MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(tunnel_type != STREAM_TUNNLE_PPTP){
		printf("\033[1;31;40mstream tunnel is not PPTP\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}else{
		printf("\033[32mstream tunnel is PPTP\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_DROPME;
}

/* 识别是否是l2tp隧道 */
extern "C" char l2tp_identify_plug_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type;
	int opt_len = sizeof(short);
	
	MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(tunnel_type != STREAM_TUNNLE_L2TP){
		printf("\033[1;31;40mstream tunnel is not L2TP\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}else{
		printf("\033[32mstream tunnel is L2TP\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_DROPME;
}

/* 不含ppp control, address字段, 识别是否是l2tp隧道 */
extern "C" char l2tp_identify_plug_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type;
	int opt_len = sizeof(short);

	if(ntohl(pstream->addr.tuple4_v4->saddr) != 0x0a180024){
		/* l2tp底层也是UDP层, port 1701, 不处理这一层 */
		return APP_STATE_DROPME;
	}
	if(ntohs(pstream->addr.tuple4_v4->source) != 52139){
		/* l2tp底层也是UDP层, port 1701, 不处理这一层 */
		return APP_STATE_DROPME;
	}	
	if(ntohs(pstream->addr.tuple4_v4->source) == 1701){
		/* l2tp底层也是UDP层, port 1701, 不处理这一层 */
		return APP_STATE_DROPME;
	}	
	
	MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(tunnel_type != STREAM_TUNNLE_L2TP){
		printf("\033[1;31;40mstream tunnel is not L2TP\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}

	

	printf("\033[32mstream tunnel is L2TP\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);

	return APP_STATE_DROPME;
}


/* l2tp业务插件 */
extern "C"  char l2tp_biz_timeout_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	/* 超时后解析层先被free, 然后调用业务层插件, 如果能收到CLOSE状态说明正确 */
	if(SESSION_STATE_CLOSE == session_info->session_state){
		printf("\033[32ml2tp_biz session close, test succ!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}
	
	return PROT_STATE_GIVEME;
}


/* 识别是否是teredo隧道 */
extern "C" char teredo_identify_plug_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type;
	int opt_len = sizeof(short);
	
	MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(tunnel_type != STREAM_TUNNLE_TEREDO){
		printf("\033[1;31;40mstream tunnel is not teredo\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}else{
		printf("\033[32mstream tunnel is teredo\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_DROPME;
}



/* 识别是否是pptp+4over6隧道 */
extern "C" char pptp_and_4over6_identify_plug_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type;
	int opt_len = sizeof(short);
	
	MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(tunnel_type != (STREAM_TUNNLE_4OVER6|STREAM_TUNNLE_PPTP)){
		printf("\033[1;31;40mstream tunnel is not pptp and 4over6\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}else{
		printf("\033[32mstream tunnel is pptp and 4over6\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_DROPME;
}

/* 识别是否是6over4隧道 */
extern "C" char t6over4_identify_plug_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type;
	int opt_len = sizeof(short);
	
	MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if(tunnel_type != STREAM_TUNNLE_6OVER4){
		printf("\033[1;31;40mstream tunnel is not 6over4\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}else{
		printf("\033[32mstream tunnel is 6over4\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_DROPME;
}


/* 相同的四元组, 不同的mpls地址, 被正确解析成两个不同的流 */
extern "C" char same_tuple4_diff_mpls_two_stream_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_CLOSE == pstream->pktstate){
		g_tcp_stream_index++;
		if(2 != pstream->ptcpdetail->serverpktnum){
			printf("\033[1;31;40msame_tuple4_diff_mpls_two_stream_tcpall_entry() error: C2S pkt is not 2!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
		if(1 != pstream->ptcpdetail->clientpktnum){
			printf("\033[1;31;40msame_tuple4_diff_mpls_two_stream_tcpall_entry() error: S2C pkt is not 1!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
		
		if(2 == g_tcp_stream_index){
			printf("\033[32msame_tuple4_diff_mpls_two_stream_tcpall_entry: success!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);		
		}
	}

	return APP_STATE_GIVEME;
}


/* 相同的四元组, 不同的mpls地址, 但是没开启stream_compare_layer.conf, 会被正确解析成一个TCP流 */
extern "C" char same_tuple4_diff_mpls_one_stream_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_CLOSE == pstream->pktstate){
		g_tcp_stream_index++;
		if(4 != pstream->ptcpdetail->serverpktnum){
			printf("\033[1;31;40msame_tuple4_diff_mpls_one_stream_tcpall_entry() error: C2S pkt is not 2!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
		if(2 != pstream->ptcpdetail->clientpktnum){
			printf("\033[1;31;40msame_tuple4_diff_mpls_one_stream_tcpall_entry() error: S2C pkt is not 1!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}

		if(1 == g_tcp_stream_index){
			printf("\033[32msame_tuple4_diff_mpls_one_stream_tcpall_entry: success!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);		
		}
	}

	return APP_STATE_GIVEME;
}

struct gtp_flow_stat{
	unsigned int c2s_pkt;
	unsigned int c2s_bytes;
	unsigned int s2c_pkt;
	unsigned int s2c_bytes;	
};

/* 
    内层TCP四元组相同, 但外层GTP四元组不同的流解析测试 
    pcap包(md5:7db60c7d3bbec640e77499a328ca591b)tcp序号及长度记录:
    
	C2S:
		seq:1,  len: 247
		seq:248, len:318
		seq:566, len:308
		seq:874, len:101

	S2C:    
		seq:1, len:1360
		seq:1361, len:1360
		seq:2721, len:563
		seq:3284, len:51
		seq:3335, len:1360
		seq:4695, len:1360
		seq:6055, len:1360
		seq:7415, len:1360
		seq:8775, len:15		
*/
extern "C" char gtp_diff_outer_tuple4_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct gtp_flow_stat *gtp_tcp_flow;
	
	if(OP_STATE_PENDING == pstream->opstate){
		gtp_tcp_flow = (struct gtp_flow_stat *)calloc(1, sizeof(struct gtp_flow_stat));
		*pme = gtp_tcp_flow;
	}
	
	gtp_tcp_flow = (struct gtp_flow_stat *)(*pme);

	if((pstream->ptcpdetail->datalen) > 0 && (pstream->ptcpdetail->pdata != NULL)){
		if(DIR_C2S == pstream->curdir){
			gtp_tcp_flow->c2s_pkt++;
			gtp_tcp_flow->c2s_bytes += pstream->ptcpdetail->datalen;
		}else{
			gtp_tcp_flow->s2c_pkt++;
			gtp_tcp_flow->s2c_bytes += pstream->ptcpdetail->datalen;
		}
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		if(22 != pstream->ptcpdetail->serverpktnum){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_tcp_entry() error: C2S ALL pkt is not 22!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
		if(26 != pstream->ptcpdetail->clientpktnum){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_tcp_entry() error: S2C ALL pkt is not 26!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}

		if(4 != gtp_tcp_flow->c2s_pkt){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_tcp_entry() error: C2S DATA pkt is not 4!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
		}
		if(9 != gtp_tcp_flow->s2c_pkt){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_tcp_entry() error: S2C DATA pkt is not 9, actual is:%u!\033[0m\n", gtp_tcp_flow->s2c_pkt);
			sendto_test_result(GTEST_SAPP_ERR);
		}
		
		if(974 != gtp_tcp_flow->c2s_bytes){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_tcp_entry() error: C2S bytes is not 974, actual is:%u!\033[0m\n", gtp_tcp_flow->c2s_bytes);
			sendto_test_result(GTEST_SAPP_ERR);
		}
		if(8789 != gtp_tcp_flow->s2c_bytes){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_tcp_entry() error: S2C bytes is not 8789, actual is:%u!\033[0m\n", gtp_tcp_flow->s2c_bytes);
			sendto_test_result(GTEST_SAPP_ERR);
		}		

		free(*pme);

		sendto_test_result(GTEST_SAPP_SUCC);	
	}

	return APP_STATE_GIVEME;
}

/*
	gtp_diff_external_ip_port_same_inner_tuple4.pcap,

	第26个包, C2S方向, 外层源ip由原来的10.7.85.9改成了10.7.85.134, 但是此时TEID没变, 因为TEID的含义是对方定的, 所以下次的回复包才会改;
	第28个包, S2C方向, 外层ip地址不变, TEID由38939改成了26892.
*/
extern "C" char gtp_diff_outer_tuple4_track_teid_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct layer_addr_gtp *gtpaddr;
	const struct stream_tuple4_v4 *tuple4addr;
	char ip_src_str[INET_ADDRSTRLEN], ip_dst_str[INET_ADDRSTRLEN];

	gtpaddr = pstream->pfather->addr.gtp;
	tuple4addr = pstream->pfather->pfather->addr.tuple4_v4;
	
	if(OP_STATE_PENDING == pstream->opstate){
		if(gtpaddr->teid_c2s != ntohl(525653173)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state C2S TEID is %u, but expect 525653173!\033[0m\n", ntohl(gtpaddr->teid_c2s));
			sendto_test_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}
		if(gtpaddr->teid_s2c != ntohl(38939)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state S2C TEID is %u, but expect 38939!\033[0m\n", ntohl(gtpaddr->teid_s2c));
			sendto_test_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}	

		if(tuple4addr->saddr != ntohl(0x0A075509)){
			inet_ntop(AF_INET, &tuple4addr->saddr, ip_src_str, sizeof(ip_src_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state outer sip is %s, but expect 10.7.85.9!\033[0m\n", ip_src_str);
			sendto_test_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}
		if(tuple4addr->daddr != ntohl(0x024e3f6f)){
			inet_ntop(AF_INET, &tuple4addr->daddr, ip_src_str, sizeof(ip_dst_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state outer dip is %s, but expect 2.78.63.111!\033[0m\n", ip_dst_str);
			sendto_test_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}		
			
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		if(gtpaddr->teid_c2s != ntohl(525653173)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state C2S TEID is %u, but expect 525653173!\033[0m\n", ntohl(gtpaddr->teid_c2s));
			sendto_test_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		if(gtpaddr->teid_s2c != ntohl(26892)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state S2C TEID is %u, but expect 26892!\033[0m\n", ntohl(gtpaddr->teid_s2c));
			sendto_test_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}	

		if(tuple4addr->saddr != ntohl(0x0A075586)){
			inet_ntop(AF_INET, &tuple4addr->saddr, ip_src_str, sizeof(ip_src_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state outer sip is %s, but expect 10.7.85.134!\033[0m\n", ip_src_str);
			sendto_test_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}
		if(tuple4addr->daddr != ntohl(0x024e3f6f)){
			inet_ntop(AF_INET, &tuple4addr->daddr, ip_src_str, sizeof(ip_dst_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state outer dip is %s, but expect 2.78.63.111!\033[0m\n", ip_dst_str);
			sendto_test_result(GTEST_SAPP_ERR);		
			return APP_STATE_DROPME;
		}		
	

		printf("\033[32mgtp_diff_outer_tuple4_track_teid_tcp_entry() test success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);	
	}


	return APP_STATE_GIVEME;
}


/*
	gtp_diff_outer_ip_same_inner_tuple4_s2c.pcap

	第5个包, S2C方向, 外层源ip由原来的2.78.63.111改成了2.78.63.254, 但是此时TEID=38939没变, 因为TEID的含义是对方定的, 所以下次的回复包才会改;
	第7个包, C2S方向, 外层ip地址不变, TEID由525653173改成了54453.
*/
extern "C" char gtp_diff_outer_tuple4_track_teid_s2c_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct layer_addr_gtp *gtpaddr;
	const struct stream_tuple4_v4 *tuple4addr;
	char ip_src_str[INET_ADDRSTRLEN], ip_dst_str[INET_ADDRSTRLEN];

	gtpaddr = pstream->pfather->addr.gtp;
	tuple4addr = pstream->pfather->pfather->addr.tuple4_v4;
	
	if(OP_STATE_PENDING == pstream->opstate){
		if(gtpaddr->teid_c2s != ntohl(525653173)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state C2S TEID is %u, but expect 525653173!\033[0m\n", ntohl(gtpaddr->teid_c2s));
			sendto_test_result(GTEST_SAPP_ERR); 	
			return APP_STATE_DROPME;
		}
		if(gtpaddr->teid_s2c != ntohl(38939)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state S2C TEID is %u, but expect 38939!\033[0m\n", ntohl(gtpaddr->teid_s2c));
			sendto_test_result(GTEST_SAPP_ERR); 	
			return APP_STATE_DROPME;
		}	

		if(tuple4addr->saddr != ntohl(0x0A075509)){
			inet_ntop(AF_INET, &tuple4addr->saddr, ip_src_str, sizeof(ip_src_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state outer sip is %s, but expect 10.7.85.9!\033[0m\n", ip_src_str);
			sendto_test_result(GTEST_SAPP_ERR); 	
			return APP_STATE_DROPME;
		}
		if(tuple4addr->daddr != ntohl(0x024e3f6f)){
			inet_ntop(AF_INET, &tuple4addr->daddr, ip_src_str, sizeof(ip_dst_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in pending state outer dip is %s, but expect 2.78.63.111!\033[0m\n", ip_dst_str);
			sendto_test_result(GTEST_SAPP_ERR); 	
			return APP_STATE_DROPME;
		}		
		
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		if(gtpaddr->teid_c2s != ntohl(54453)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state C2S TEID is %u, but expect 54453!\033[0m\n", ntohl(gtpaddr->teid_c2s));
			sendto_test_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(gtpaddr->teid_s2c != ntohl(38939)){
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state S2C TEID is %u, but expect 38939!\033[0m\n", ntohl(gtpaddr->teid_s2c));
			sendto_test_result(GTEST_SAPP_ERR); 	
			return APP_STATE_DROPME;
		}	

		if(tuple4addr->saddr != ntohl(0x0A075509)){
			inet_ntop(AF_INET, &tuple4addr->saddr, ip_src_str, sizeof(ip_src_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state outer sip is %s, but expect 10.7.85.9!\033[0m\n", ip_src_str);
			sendto_test_result(GTEST_SAPP_ERR); 	
			return APP_STATE_DROPME;
		}
		if(tuple4addr->daddr != ntohl(0x024e3ffe)){
			inet_ntop(AF_INET, &tuple4addr->daddr, ip_src_str, sizeof(ip_dst_str));
			printf("\033[1;31;40mgtp_diff_outer_tuple4_track_teid_tcp_entry() error: in close state outer dip is %s, but expect 2.78.63.254!\033[0m\n", ip_dst_str);
			sendto_test_result(GTEST_SAPP_ERR); 	
			return APP_STATE_DROPME;
		}		


		printf("\033[32mgtp_diff_outer_tuple4_track_teid_tcp_entry() test success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);	
	}


	return APP_STATE_GIVEME;
}


/*
	本测试插件用于测试完全没有mpls层的Pcap包, 
	但是开启了非对称mpls对准配置, 即etc/asymmetric_presence_layer.conf,
	此时mpls是凭空造出来的, 插件也不应该看到.
*/
extern "C" char pcap_no_mpls_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(ADDR_TYPE_MPLS == pstream->pfather->addr.addrtype){
		printf("\033[1;31;40mThis pcap has no MPLS layer actually, but has mpls layer in plugin!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		printf("\033[32mpcap_no_mpls_tcp_entry() test success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);	
	}

	return APP_STATE_GIVEME;
}

/*
	之前发生过sapp -d读包模式, 但是overlay_mode=vxlan的情况下, ethernet被认成了是overlay, 导致日志不全缺mac字段.
*/
extern "C" char l2tp_tunnel_stream_pfather_iterate_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(pstream->addr.addrtype != ADDR_TYPE_IPV4){
		printf("\033[1;31;40maddr type is not tuple4v4!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}
	pstream = pstream->pfather;
	if((NULL == pstream) || (pstream->addr.addrtype != ADDR_TYPE_L2TP)){
		printf("\033[1;31;40maddr type is not l2tp!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	

	pstream = pstream->pfather;
	if((NULL == pstream) || (pstream->addr.addrtype != ADDR_TYPE_IPV4)){
		printf("\033[1;31;40maddr type is not outer tuple4v4!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	
	
	pstream = pstream->pfather;
	if((NULL == pstream) || (pstream->addr.addrtype != ADDR_TYPE_MAC)){
		printf("\033[1;31;40maddr type is not mac!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	

	printf("\033[32ml2tp_tunnel_stream_pfather_iterate_entry() test success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);
	return APP_STATE_DROPME;
}

/*
	之前发生过sapp -d读包模式, 但是overlay_mode=vxlan的情况下, ethernet被认成了是overlay, 导致日志不全缺mac字段.
*/
extern "C" char pptp_tunnel_stream_pfather_iterate_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(pstream->addr.addrtype != ADDR_TYPE_IPV4){
		printf("\033[1;31;40maddr type is not tuple4v4!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}
	pstream = pstream->pfather;
	if((NULL == pstream) || (pstream->addr.addrtype != ADDR_TYPE_PPTP)){
		printf("\033[1;31;40maddr type is not pptp!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	

	pstream = pstream->pfather;
	if((NULL == pstream) || (pstream->addr.addrtype != __ADDR_TYPE_IP_PAIR_V4)){
		printf("\033[1;31;40maddr type is not outer pure ipv4!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	
	
	pstream = pstream->pfather;
	if((NULL == pstream) || (pstream->addr.addrtype != ADDR_TYPE_MAC)){
		printf("\033[1;31;40maddr type is not mac!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	

	printf("\033[32mpptp_tunnel_stream_pfather_iterate_entry() test success!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);
	return APP_STATE_DROPME;
}


