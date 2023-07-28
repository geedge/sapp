/**************************************************************
	papp平台用于WY项目串联环境, 有如下接口, 
	sapp新平台为了保持向后兼容, 保留如下接口.
***************************************************************/


#ifdef __cplusplus
extern "C" {
#endif
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

#ifndef GSERIAL_PLUGID_MAX
#define GSERIAL_PLUGID_MAX 	(64)
#endif

unsigned long long g_plug_rx_pkts[MAX_THREAD_NUM][GSERIAL_PLUGID_MAX+1]; /* temp add, for总控记录包数 */

volatile unsigned long long Gserial_sendpacket_ip_info[MAX_THREAD_NUM][GSERIAL_PLUGID_MAX];
volatile unsigned long long Gserial_sendpacket_ipv6_info[MAX_THREAD_NUM][GSERIAL_PLUGID_MAX];
volatile unsigned long long Gserial_sendpacket_tcp_info[MAX_THREAD_NUM][GSERIAL_PLUGID_MAX];
volatile unsigned long long Gserial_sendpacket_udp_info[MAX_THREAD_NUM][GSERIAL_PLUGID_MAX];

#if IOMODE_MARSIO
extern int MESA_fakepacket_send_ipv6_options(const struct streaminfo *stream, uint8_t protocol,
							struct in6_addr *sip, struct in6_addr *dip,
							const char *payload, int payload_len, uint8_t dir, 
							SAPP_TLV_T *options, int opt_num);
extern int MESA_fakepacket_send_ipv6_tcp_options(const struct streaminfo *stream,
							struct in6_addr *sip, struct in6_addr *dip,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,
							const char* payload,int payload_len, u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);
extern int MESA_fakepacket_send_ipv6_udp_options(const struct streaminfo *stream,
							struct in6_addr *sip, struct in6_addr *dip,
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);	
extern int MESA_sendpacket_iplayer_options(int thread_index,const char *data,  int data_len, u_int8_t dir, SAPP_TLV_T *options, int opt_num);		
#endif



int Gserial_sendpacket_iplayer(int plug_id, struct streaminfo *stream,const char *buf, int buf_len, u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		sapp_runtime_log(30, "Gserial_sendpacket_iplayer(): Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}
	
#if IOMODE_MARSIO
	ret = MESA_sendpacket_iplayer_options(plug_id, buf, buf_len, dir, NULL, 0);
	return ret;
#endif

	ret = MESA_sendpacket_iplayer(stream->threadnum, buf, buf_len, dir);

	Gserial_sendpacket_ip_info[stream->threadnum][plug_id]++;

	return ret;
}

int Gserial_sendpacket_ipv6_layer(int plug_id, struct streaminfo *stream,const char *buf, int buf_len, u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}
	
#if IOMODE_MARSIO
	ret = MESA_sendpacket_iplayer_options(plug_id, buf, buf_len, dir, NULL, 0);
	return ret;
#endif

	ret = MESA_sendpacket_iplayer(stream->threadnum, buf, buf_len, dir);

	Gserial_sendpacket_ip_info[stream->threadnum][plug_id]++;

	return ret;
}

int Gserial_sendpacket_ipv4(int plug_id, struct streaminfo *stream,u_char ttl,u_char protocol,uint sip, uint dip,
									const char *payload,int payload_len,u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}

#if IOMODE_MARSIO
	SAPP_TLV_T opt;
	opt.type = SAPP_SEND_OPT_IP_TTL;
	opt.length = sizeof(char);
	opt.char_value = ttl;
	ret = MESA_fakepacket_send_ipv4_options(stream, protocol, sip, dip, payload, payload_len, dir, &opt, 1);
#else
	ret = MESA_fakepacket_send_ipv4(stream->threadnum, ttl, protocol, sip, dip, payload, payload_len, dir);
#endif	

	Gserial_sendpacket_ip_info[stream->threadnum][plug_id]++;

	char sip_str[16],  dip_str[16];
	uint sip_net = htonl(sip);
	uint dip_net = htonl(dip);
	inet_ntop(AF_INET, &sip_net, sip_str, 16);
	inet_ntop(AF_INET, &dip_net, dip_str, 16);
	sapp_runtime_log(20,  "Gserial_sendpacket_ipv4: ret=%d, plugid:%d, %s->%s, protocol:%u, payload_len:%d\n", 
					ret, plug_id, sip_str, dip_str, protocol, payload_len);
	
	return ret;
}


int Gserial_sendpacket_ipv4_detail(int plug_id,struct streaminfo *stream,u_char ttl,u_char protocol,uint sip, uint dip, 
						u_short ipid, const char *payload,int payload_len,u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}
#if IOMODE_MARSIO
	SAPP_TLV_T opt[2];
	opt[0].type = SAPP_SEND_OPT_IP_TTL;
	opt[0].length = sizeof(char);
	opt[0].char_value = ttl;
	opt[1].type = SAPP_SEND_OPT_IP_ID;
	opt[1].length = sizeof(short);
	opt[1].short_value = (short)ipid;	
	ret = MESA_fakepacket_send_ipv4_options(stream, protocol, sip, dip, payload, payload_len, dir, opt, 2);
#else
	ret = MESA_fakepacket_send_ipv4_detail(stream->threadnum, ttl, protocol, sip, dip, ipid, payload, payload_len, dir);
#endif

	Gserial_sendpacket_ip_info[stream->threadnum][plug_id]++;

	char sip_str[16],  dip_str[16];
	uint sip_net = htonl(sip);
	uint dip_net = htonl(dip);
	inet_ntop(AF_INET, &sip_net, sip_str, 16);
	inet_ntop(AF_INET, &dip_net, dip_str, 16);
	sapp_runtime_log(20,  "Gserial_sendpacket_ipv4_detail: ret=%d, plugid:%d, %s->%s, protocol:%u, ipid:0x%x, payload_len:%d\n", 
						ret,plug_id,sip_str, dip_str, protocol, ipid, payload_len);
	
	return ret;
}


int Gserial_sendpacket_ipv6(int plug_id, struct streaminfo *stream,u_char ttl,u_char protocol,
						struct in6_addr *sip, struct in6_addr *dip, 
						const char *payload,int payload_len,u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}
#if IOMODE_MARSIO
	SAPP_TLV_T opt[1];
	opt[0].type = SAPP_SEND_OPT_IP_TTL;
	opt[0].length = sizeof(char);
	opt[0].char_value = ttl;
	ret = MESA_fakepacket_send_ipv6_options(stream, protocol, sip, dip, payload, payload_len, dir, &opt[0], 1);
#else	
	ret = -1;
	assert(0);
#endif
	
	Gserial_sendpacket_ipv6_info[stream->threadnum][plug_id]++;

	char sip_str[64],  dip_str[64];
	inet_ntop(AF_INET6, sip, sip_str, 64);
	inet_ntop(AF_INET6, dip, dip_str, 64);
	sapp_runtime_log(20,  "Gserial_sendpacket_ipv6: ret=%d, plugid:%d, %s->%s, protocol:%u, payload_len:%d\n", 
						ret,plug_id,sip_str, dip_str, protocol, payload_len);
	
	return ret;
}
						
int Gserial_sendpacket_tcp(int plug_id,struct streaminfo *stream,u_int sip,u_int dip,u_short sport,
									u_short dport,u_int sseq,u_int sack,u_char control,
									const char* payload,int payload_len, u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}

#if IOMODE_MARSIO
	ret = MESA_fakepacket_send_tcp_options(stream, sip,dip,sport,dport,sseq,sack,control,payload, payload_len, dir, NULL, 0);
#else
	ret = MESA_fakepacket_send_tcp(stream->threadnum, sip, dip, sport, dport, sseq, sack, 
								 control, payload, payload_len, dir);	
#endif

	Gserial_sendpacket_tcp_info[stream->threadnum][plug_id]++;

	char sip_str[16],  dip_str[16];
	uint sip_net = htonl(sip);
	uint dip_net = htonl(dip);
	inet_ntop(AF_INET, &sip_net, sip_str, 16);
	inet_ntop(AF_INET, &dip_net, dip_str, 16);
	sapp_runtime_log(20,  "Gserial_sendpacket_tcp: ret=%d, plugid:%d, %s:%u->%s:%u, seq:%u, ack:%u, payload_len:%d\n", 
				    ret, plug_id, sip_str, sport, dip_str, dport, sseq, sack, payload_len);
	
	return ret;
}

int Gserial_sendpacket_tcp_detail(int plug_id,struct streaminfo *stream, u_int sip,u_int dip, u_short ip_id, 
							u_char ip_ttl, u_short sport, u_short dport,u_int sseq,
							u_int sack,u_char control, u_short tcp_win, 
							const char* payload,int payload_len, u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}

#if IOMODE_MARSIO
	SAPP_TLV_T opt[3];
	opt[0].type = SAPP_SEND_OPT_IP_TTL;
	opt[0].length = sizeof(char);
	opt[0].char_value = ip_ttl;
	opt[1].type = SAPP_SEND_OPT_IP_ID;
	opt[1].length = sizeof(short);
	opt[1].short_value = (short)ip_id;	
	opt[2].type = SAPP_SEND_OPT_TCP_WIN;
	opt[2].length = sizeof(short);
	opt[2].short_value = (short)tcp_win;		
	ret = MESA_fakepacket_send_tcp_options(stream, sip,dip,sport,dport,sseq,sack,control,payload, payload_len, dir, opt,3);
#else
	ret = MESA_fakepacket_send_tcp_detail(stream->threadnum, sip, dip, ip_id, ip_ttl, sport, dport, sseq, sack, 
								 control, tcp_win, payload, payload_len, dir);
#endif

	Gserial_sendpacket_tcp_info[stream->threadnum][plug_id]++;

	char sip_str[16],  dip_str[16];
	uint sip_net = htonl(sip);
	uint dip_net = htonl(dip);
	inet_ntop(AF_INET, &sip_net, sip_str, 16);
	inet_ntop(AF_INET, &dip_net, dip_str, 16);
	sapp_runtime_log(20,  "Gserial_sendpacket_tcp_detail: ret=%d, plugid:%d, %s:%u->%s:%u, ipid:0x%x, seq:%u, ack:%u, payload_len:%d\n", 
						ret, plug_id, sip_str, sport, dip_str, dport, ip_id, sseq, sack, payload_len);
	
	return ret;
}


int Gserial_sendpacket_ipv6_tcp_detail(int plug_id,struct streaminfo *stream,struct in6_addr *sip, struct in6_addr *dip, 
							u_char ip_ttl, u_short sport, u_short dport,u_int sseq,
							u_int sack,u_char control, u_short tcp_win, 
							const char* payload,int payload_len, u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}

#if IOMODE_MARSIO
	SAPP_TLV_T opt[2];
	opt[0].type = SAPP_SEND_OPT_IP_TTL;
	opt[0].length = sizeof(char);
	opt[0].char_value = ip_ttl;
	opt[1].type = SAPP_SEND_OPT_TCP_WIN;
	opt[1].length = sizeof(short);
	opt[1].short_value = (short)tcp_win;		
	ret = MESA_fakepacket_send_ipv6_tcp_options(stream, sip,dip,sport,dport,sseq,sack,control,payload, payload_len, dir, opt,2);
#else
	ret = -1;
	assert(0);
#endif

	Gserial_sendpacket_tcp_info[stream->threadnum][plug_id]++;

	char sip_str[64],  dip_str[64];
	inet_ntop(AF_INET6, sip, sip_str, 64);
	inet_ntop(AF_INET6, dip, dip_str, 64);
	sapp_runtime_log(20,  "Gserial_sendpacket_tcp_detail: ret=%d, plugid:%d, %s.%u->%s.%u, seq:%u, ack:%u, payload_len:%d\n", 
						ret, plug_id, sip_str, sport, dip_str, dport, sseq, sack, payload_len);
	
	return ret;
}

int Gserial_sendpacket_udp(int plug_id,struct streaminfo *stream, u_int sip, u_int dip, u_short sport,
									u_short dport, const char *payload, int payload_len,u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}

#if IOMODE_MARSIO
	ret = MESA_fakepacket_send_udp_options(stream, sip,dip,sport,dport, payload, payload_len, dir, NULL, 0);
#else
	ret = MESA_fakepacket_send_udp(stream->threadnum, sip, dip, sport, dport, payload, payload_len, dir);
#endif

	Gserial_sendpacket_udp_info[stream->threadnum][plug_id]++;

	char sip_str[16],  dip_str[16];
	uint sip_net = htonl(sip);
	uint dip_net = htonl(dip);
	inet_ntop(AF_INET, &sip_net, sip_str, 16);
	inet_ntop(AF_INET, &dip_net, dip_str, 16);
	sapp_runtime_log(20,  "Gserial_sendpacket_udp: ret=%d, plugid:%d, %s:%u->%s:%u, payload_len:%d\n", 
						ret, plug_id, sip_str, sport, dip_str, dport, payload_len);
	
	return ret;
}

int Gserial_sendpacket_udp_detail(int plug_id,struct streaminfo *stream, u_int sip, u_int dip, 
 							u_short ip_id, u_char ip_ttl, u_short sport, 
 							u_short dport, const char *payload, int payload_len,u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id >= GSERIAL_PLUGID_MAX)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}

#if IOMODE_MARSIO
	SAPP_TLV_T opt[2];
	opt[0].type = SAPP_SEND_OPT_IP_TTL;
	opt[0].length = sizeof(char);
	opt[0].char_value = ip_ttl;
	opt[1].type = SAPP_SEND_OPT_IP_ID;
	opt[1].length = sizeof(short);
	opt[1].short_value = (short)ip_id;	
	ret = MESA_fakepacket_send_udp_options(stream, sip,dip,sport,dport, payload, payload_len, dir, opt, 2);
#else	
	ret = MESA_fakepacket_send_udp_detail(stream->threadnum, sip, dip, ip_id, ip_ttl, sport, dport, payload, payload_len, dir);
#endif

	Gserial_sendpacket_udp_info[stream->threadnum][plug_id]++;

	char sip_str[16],  dip_str[16];
	uint sip_net = htonl(sip);
	uint dip_net = htonl(dip);
	inet_ntop(AF_INET, &sip_net, sip_str, 16);
	inet_ntop(AF_INET, &dip_net, dip_str, 16);
	sapp_runtime_log(20,  "Gserial_sendpacket_udp_detail: ret=%d, plugid:%d, %s:%u->%s:%u, ipid:0x%x, payload_len:%d\n", 
					ret, plug_id, sip_str, sport, dip_str, dport, ip_id, payload_len);
	
	return ret;
}

int Gserial_sendpacket_ipv6_udp_detail(int plug_id,struct streaminfo *stream, struct in6_addr *sip, struct in6_addr *dip, 
 								u_char ip_ttl, u_short sport, 
 								u_short dport, const char *payload, int payload_len,u_char dir)
{
	int ret;
	
	if(plug_id <= 0 || plug_id > GSERIAL_PLUGID_MAX-1)
	{
		printf("Plug id error, must be [1,%d]!\n", GSERIAL_PLUGID_MAX);
		return -1;
	}

#if IOMODE_MARSIO
	SAPP_TLV_T opt[1];
	opt[0].type = SAPP_SEND_OPT_IP_TTL;
	opt[0].length = sizeof(char);
	opt[0].char_value = ip_ttl;
	ret = MESA_fakepacket_send_ipv6_udp_options(stream, sip,dip,sport,dport, payload, payload_len, dir, &opt[0], 1);
#else	
	ret = -1;
	assert(0);
#endif

	Gserial_sendpacket_udp_info[stream->threadnum][plug_id]++;

	char sip_str[64],  dip_str[64];
	inet_ntop(AF_INET6, sip, sip_str, 64);
	inet_ntop(AF_INET6, dip, dip_str, 64);
	sapp_runtime_log(20,  "Gserial_sendpacket_udp_detail: ret=%d, plugid:%d, %s:%u->%s:%u, payload_len:%d\n", 
					ret, plug_id, sip_str, sport, dip_str, dport, payload_len);
	
	return ret;
}

#if 0

/* 
	发包的同时, 给tcpdump_mesa一份, 便于捕包分析,
	回注的包无需tcpdump_mesa捕获, 直接在驱动底层捕获即可.
*/
extern void cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt);
extern int G_PKT_DUMP_SW;
int marsio_send_burst_with_options_for_tcpdumpmesa(struct mr_sendpath * sendpath, queue_id_t sid, marsio_buff_t * mbufs[],
    int nr_mbufs, uint16_t options)
{
	raw_pkt_t rawpkt;
	char *rawpkt_data;
	uint32_t rawpkt_len;

	if(G_PKT_DUMP_SW != 0){
		rawpkt_data = marsio_buff_mtod(mbufs[0]);
		rawpkt_len = marsio_buff_buflen(mbufs[0]);

		rawpkt.magic_num = RAW_PKT_MAGIC_NUM;
		rawpkt.low_layer_type = ADDR_TYPE_MAC;
		rawpkt.raw_pkt_data = rawpkt_data;
		rawpkt.raw_pkt_len = rawpkt_len;
		rawpkt.__lib_raw_pkt_data = rawpkt_data;
		rawpkt.__lib_raw_pkt_len = rawpkt_len;

		cycle_pkt_dump(sid, &rawpkt);
	}

	return ptr_marsio_send_burst_with_options(sendpath, sid, mbufs, nr_mbufs, options);	
}
#endif

#ifdef __cplusplus
}
#endif

