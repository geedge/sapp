#include <stdlib.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include "stream.h"
#include "stream_control.h"
#include "mesa_net.h"
#include "gserial_sendpacket.h"
#include "gdev_keepalive.h"
#include "mrtunnat.h"
#include "sysinfo.h"

#ifdef __cplusplus
extern "C" {
#endif 

#define TEST_PLUG_ID 1

extern time_t g_CurrentTime;
extern void del_last_rn(char *data, int max_len);
extern int MESA_mac_pton(const char *str, int delim, char *mac);

char send_iplayer_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_payload[] = 
	{
		0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0x19,0xF9,
		0x0A,0x0A,0x06,0x6C,
		0x0A,0x00,0x06,0x3B,
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

	Gserial_sendpacket_iplayer(TEST_PLUG_ID,stream, snd_pkt_payload, sizeof(snd_pkt_payload), 0);

	return APP_STATE_GIVEME;
}


char send_ipv4_pkt_options_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const struct mesa_ip4_hdr *iphdr = (const struct mesa_ip4_hdr *)raw_pkt;
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_payload[] = 
	{
		0x08,0x00,0xD9,0x71,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

#if 0 /* 同向发送 */
	if(0xeca597d == iphdr->ip_src.s_addr) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_ipv4_options(stream, 1, ntohl(stream->addr.ipv4->saddr), 
									ntohl(stream->addr.ipv4->daddr), 
									snd_pkt_payload, sizeof(snd_pkt_payload), stream->routedir, send_opt_array, 1);
	}
#else /* 反向发送 */
	if(0xeca597d == iphdr->ip_src.s_addr) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
		
	MESA_fakepacket_send_ipv4_options(stream, 1, ntohl(stream->addr.ipv4->daddr), 
									ntohl(stream->addr.ipv4->saddr), 
									snd_pkt_payload, sizeof(snd_pkt_payload), 
									stream->routedir ^ 1, send_opt_array, 1);
	}
#endif

	return APP_STATE_GIVEME;
}



char test_wy_send_tcp_pkt_detail(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	Gserial_sendpacket_tcp_detail(TEST_PLUG_ID, stream, 0x0A0A066C, 0x0A00063B, 0x1234, 55, 0x1111,0x2222,
							0x12345678, 0x87654321, 0x10, 9999, "TCP payload test", strlen("TCP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_wy_send_tcp_pkt_options(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	if(NULL == raw_pkt){
		return APP_STATE_GIVEME;
	}
	
	const struct mesa_ip4_hdr *iphdr = (const struct mesa_ip4_hdr *)raw_pkt;
	const struct mesa_tcp_hdr *tcphdr = (const struct mesa_tcp_hdr *)((char *)iphdr + iphdr->ip_hl * 4);
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char http_request[] = "GET alsdkfj/asd/fasd/index.htm HTTP/1.1\r\n";


#if 0 /* 主动造包, 非当前包地址 */
	MESA_fakepacket_send_ipv4_options(stream, 17, 0x01010101, 0x02020202, snd_pkt_payload, sizeof(snd_pkt_payload), 0, NULL, 0);
#elif 0 /* 同向发送 */
	if((0x1A59 == iphdr->ip_id) && (0xd7b2267d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_tcp_options(stream, ntohl(iphdr->ip_src.s_addr), 
									ntohl(iphdr->ip_dst.s_addr), 
									ntohs(tcphdr->th_sport),
									ntohs(tcphdr->th_dport),
									0x11111111,
									0x22222222,
									TH_ACK | TH_PUSH,
									http_request, sizeof(http_request), 
									stream->routedir, send_opt_array, 1);
	}
#else /* 反向发送 */
	if((0x1A59 == iphdr->ip_id) && (0xd7b2267d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_tcp_options(stream, ntohl(iphdr->ip_dst.s_addr), 
									ntohl(iphdr->ip_src.s_addr), 
									ntohs(tcphdr->th_dport),
									ntohs(tcphdr->th_sport),
									0x22222222,
									0x11111111,
									TH_ACK | TH_PUSH,
									http_request, sizeof(http_request), 
									stream->routedir ^ 1, send_opt_array, 1);
	}
#endif
	return APP_STATE_GIVEME;
}
char test_wy_send_udp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	Gserial_sendpacket_udp(TEST_PLUG_ID, stream, 0x0A0A066C, 0x0A00063B, 0x1111,0x2222,
							"UDP payload test", strlen("UDP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_wy_send_udp_pkt_detail(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	Gserial_sendpacket_udp_detail(TEST_PLUG_ID, stream, 0x0A0A066C, 0x0A00063B, 0x1234, 55, 0x1111,0x2222,
							"UDP payload test", strlen("UDP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_wy_send_udp_pkt_options(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	if(NULL == raw_pkt){
		return APP_STATE_DROPME;
	}
	
	const struct mesa_ip4_hdr *iphdr = (const struct mesa_ip4_hdr *)raw_pkt;
	const struct mesa_udp_hdr *udphdr = (const struct mesa_udp_hdr *)((char *)iphdr + iphdr->ip_hl * 4);
	char udp_paylaod[] = "UDP test payload\r\n";


#if 0 /* 主动造包, 非当前包地址 */
	MESA_fakepacket_send_ipv4_options(stream, 17, 0x01010101, 0x02020202, snd_pkt_payload, sizeof(snd_pkt_payload), 0, NULL, 0);
#elif 0 /* 同向发送 */
	if((0x024e == iphdr->ip_id) && (0xdebb487d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_udp_options(stream, ntohl(stream->addr.ipv4->saddr), 
									ntohl(stream->addr.ipv4->daddr), 
									0x1111,
									0x2222,
									udp_paylaod, sizeof(udp_paylaod), 
									stream->routedir, 
									send_opt_array, 1);
	}
#else /* 反向发送 */
	if((0x024e == iphdr->ip_id) && (0xdebb487d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_udp_options(stream, ntohl(stream->addr.ipv4->daddr), 
									ntohl(stream->addr.ipv4->saddr), 
									0x2222,
									0x1111,
									udp_paylaod, sizeof(udp_paylaod), 
									stream->routedir ^ 1, 
									send_opt_array, 1);
	}
#endif
	return APP_STATE_GIVEME;
}

char test_wy_forward_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	sapp_forward_current_pkt(stream, 1);	
	sapp_forward_current_pkt(stream, 2);	
	return APP_STATE_GIVEME;
}

extern int gdev_keepalive_set_opt(const SAPP_TLV_T *tlv_value);

char test_gdev_keepalive_ctrl(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	SAPP_TLV_T global_cmd;
	struct gdev_keepalive_service_ctrl service_cmd;
	global_cmd.type = GDEV_KEEPALIVE_OPT_SERVICE_CTRL;
	global_cmd.length = sizeof(struct gdev_keepalive_service_ctrl);
	service_cmd.service_num = 1;
	service_cmd.keepalive_switch = 0;
	global_cmd.ptr_value = &service_cmd;
	
	gdev_keepalive_set_opt(&global_cmd);

	global_cmd.type = GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH;
	global_cmd.length = sizeof(int);
	global_cmd.int_value = 1;

	gdev_keepalive_set_opt(&global_cmd);

	return APP_STATE_GIVEME;	
}

char test_wy_send_ipv4_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int test_ip;

	if(NULL == raw_pkt){
		return APP_STATE_DROPME;
	}
	
	inet_pton(AF_INET, "202.197.121.1", &test_ip);

	if((test_ip == stream->addr.tuple4_v4->saddr) || (test_ip == stream->addr.tuple4_v4->daddr)){
		Gserial_sendpacket_ipv4(1, stream, 32, 17, 
							  ntohl(stream->addr.tuple4_v4->saddr),
							  ntohl(stream->addr.tuple4_v4->daddr),
							  "11111111111111111111111111111111111111",
							  20,
							  0);
	}
	return APP_STATE_GIVEME;		
}

char test_wy_send_ipv6_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct in6_addr sip, dip;
	char payload[] = {
		0x80,0x00, 0x63,0x9d, 0x00,0x30,0xe1,0x38,
		0xc2,0xf6, 0x23,0x5a, 0x00,0x00, 0x00,0x00,
		0xc1,0xe6, 0x00,0x00, 0x00, 0x00, 0x00,0x00,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
	};

	inet_pton(AF_INET6, "2001::10:0:6:203", &sip);
	inet_pton(AF_INET6, "2001::10:0:6:201", &dip);


	Gserial_sendpacket_ipv6(10, stream, 33, 17, &sip, &dip, payload, sizeof(payload), 0);

	return APP_STATE_GIVEME;	
}


char test_wy_send_ipv6_tcp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct in6_addr sip, dip;
	char payload[] = {
		0x80,0x00, 0x63,0x9d, 0x00,0x30,0xe1,0x38,
		0xc2,0xf6, 0x23,0x5a, 0x00,0x00, 0x00,0x00,
		0xc1,0xe6, 0x00,0x00, 0x00, 0x00, 0x00,0x00,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
	};

	inet_pton(AF_INET6, "2001::10:0:6:203", &sip);
	inet_pton(AF_INET6, "2001::10:0:6:201", &dip);

	Gserial_sendpacket_ipv6_tcp_detail(10, stream, &sip, &dip, 33, 12345, 54321, 11111111, 22222222, 0x14, 10000, payload, sizeof(payload), 0);

	return APP_STATE_GIVEME;	
}

char test_wy_send_ipv6_udp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct in6_addr sip, dip;
	char payload[] = {
		0x80,0x00, 0x63,0x9d, 0x00,0x30,0xe1,0x38,
		0xc2,0xf6, 0x23,0x5a, 0x00,0x00, 0x00,0x00,
		0xc1,0xe6, 0x00,0x00, 0x00, 0x00, 0x00,0x00,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
	};

	inet_pton(AF_INET6, "2001::10:0:6:203", &sip);
	inet_pton(AF_INET6, "2001::10:0:6:201", &dip);

	Gserial_sendpacket_ipv6_udp_detail(10, stream, &sip, &dip, 33, 12345, 54321, payload, sizeof(payload), 0);

	return APP_STATE_GIVEME;	
}

static void *plug_thread_send(void *arg)
{
	int send_tid;
	int opt_len = sizeof(int);

	char snd_eth_pkt_data[] = 
	{
		0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
		0x08, 0x00,
		0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0x19,0xF9,0x0A,0x0A,0x06,0x6C,
		0x0A,0x00,0x06,0x3B,
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	
	char snd_ip_pkt_payload[] = 
	{
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	
	sapp_get_platform_opt(SPO_INDEPENDENT_THREAD_ID,  &send_tid,  &opt_len);
	sleep(5); /* 等待packet_io初始化成功 */
	
	while(1){
		struct streaminfo phony_stream;
		phony_stream.threadnum = send_tid;
//		Gserial_sendpacket_ipv4(1, &phony_stream, 32, 17, 0x01010101, 0x02020202, snd_ip_pkt_payload, sizeof(snd_ip_pkt_payload), 0);
		MESA_sendpacket_ethlayer(send_tid, snd_eth_pkt_data, sizeof(snd_eth_pkt_data), 0);	
		sleep(1);
	}

	return NULL;
}

char test_pkt_action(int net_conn_mode, char plug_action)
{
	char ret = 1;
	
	if(plug_action == 1){
		ret = 0;	
	}

	printf("test_pkt_action_cb return DROP!\n");

	return ret;
}


int test_wy_init(void)
{
	pthread_t tid;

	pthread_create(&tid, NULL, plug_thread_send, NULL);
	
	return 0;
}


#ifdef __cplusplus
}
#endif

