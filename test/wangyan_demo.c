#include <stdlib.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif 

/*
函数名:Gserial_sendpacket_iplayer();
函数功能:发送伪造数据包,伪造的数据包存储在buf中,
			 且数据包最低层ip层，不能发送链路层的数据。
			  即buf中依次存储ip层、tcp/udp层、(应用层)数据；
			  程序只负责将buf中内容发送出去。
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		buf:伪造数据包
		buf_len:buf长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；
			若发送失败则返回FAILE (-1);
*/
int Gserial_sendpacket_iplayer(int plug_id, struct streaminfo *stream,const char *buf, int buf_len, u_char dir);

/*
函数名:Gserial_sendpacket_ipv4_detail();
函数功能:发送伪造IPv4包；
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		ttl:生存时间；
		sip:发送数据包的源IP地址,主机字节序；
		dip:发送数据包的目的IP地址，主机字节序；
		ipid:IPID字段, 0表示随机, 主机字节序;
		protocol:上层协议类型,例如:
		payload:负载内容；
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；
		若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_ipv4_detail(int plug_id,struct streaminfo *stream,u_char ttl,u_char protocol,uint sip, uint dip, 
						u_short ipid, const char *payload,int payload_len,u_char dir);
/*
函数名:Gserial_sendpacket_tcp_detail();
函数功能:发送伪造TCP包；
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		sip:发送数据包的源IP地址，主机字节序；
		dip:发送数据包的目的IP地址，主机字节序；
		ip_id: 发送数据包的IP-ID字段，主机字节序, 0表示随机；
		ip_ttl: 发送数据包的IP-TTL字段，0表示随机；
		sport:发送数据包的源端口号，主机字节序;
		dport:发送数据包的目的端口号，主机字节序；
		sseq:发送数据包的序列号(seq)，主机字节序；
		sack:发送数据包的应答码(ack)，主机字节序；
		control:发送数据包的控制标记，即表示数据包为ack,syn,rest等类型；
		tcp_win:发送数据包的TCP-WINDOW字段，主机字节序，0表示随机；
		payload:负载内容；
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_tcp_detail(int plug_id,struct streaminfo *stream,u_int sip,u_int dip, u_short ip_id, 
							u_char ip_ttl, u_short sport, u_short dport,u_int sseq,
							u_int sack,u_char control, u_short tcp_win, 
							const char* payload,int payload_len, u_char dir);						
/*
函数名:Gserial_sendpacket_udp();
函数功能:发送伪造UDP包
参数说明:
		plug_id:插件ID;
		thread_indes:线程号;
		sip:发送数据包的源IP地址,主机字节序;
		dip:发送数据包的目的IP地址,主机字节序；
		ip_id: 发送数据包的IP-ID字段，主机字节序, 0表示随机；
		ip_ttl: 发送数据包的IP-TTL字段，0表示随机；
		sport:发送数据包的源端口号，主机字节序；
		dport:发送数据包的目的端口号，主机字节序；
		payload:UDP负载内容;
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_udp_detail(int plug_id,struct streaminfo *stream, u_int sip, u_int dip, 
 							u_short ip_id, u_char ip_ttl, u_short sport, 
 							u_short dport, const char *payload, int payload_len,u_char dir);
 							
#define PLUG_DEMO_ID   1

const char *trigger_ipstr = "10.0.6.203";

char send_iplayer_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	/* ICMP request, from 10.10.6.203 to 10.0.6.59 */
	char snd_pkt_payload[] = 
	{
		0x45,0x00,0x00,0x54,
		0xD2,0x84,0x40,0x00,
		0x40,0x01,0x47,0x1F, 
		0x0A,0x0A,0x06,0xCB, /* SRC IP 10.10.6.203 */
		0x0A,0x00,0x06,0x3B, /* DST IP 10.0.6.59 */
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

	Gserial_sendpacket_iplayer(PLUG_DEMO_ID,stream, snd_pkt_payload, sizeof(snd_pkt_payload), 0);

	return APP_STATE_GIVEME;
}


char sendpacket_ipv4_detail_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const struct iphdr *ipv4hdr = (const struct iphdr *)raw_pkt;
	unsigned int trigger_ip;

	inet_pton(AF_INET, trigger_ipstr, &trigger_ip);
	
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

     /* 同向发送 */
	if(trigger_ip == ipv4hdr->saddr) /* 根据特定包造包 */
	{
		Gserial_sendpacket_ipv4_detail(1, stream, 128, 1, ntohl(ipv4hdr->saddr), 
										ntohl(ipv4hdr->daddr),  0x5555,
										snd_pkt_payload, sizeof(snd_pkt_payload), 
										stream->routedir);
	}
       /* 反向发送 */
	else if(trigger_ip == ipv4hdr->daddr) /* 根据特定包造包 */
	{
		Gserial_sendpacket_ipv4_detail(PLUG_DEMO_ID, stream, 128, 1, ntohl(ipv4hdr->daddr), 
										ntohl(ipv4hdr->saddr),  0x5555,
										snd_pkt_payload, sizeof(snd_pkt_payload), 
										MESA_dir_reverse(stream->routedir));
	}

	return APP_STATE_GIVEME;
}



char sendpacket_tcp_detail_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const struct iphdr *ipv4hdr = (const struct iphdr *)raw_pkt;
	unsigned int trigger_ip;

	if(raw_pkt == NULL)
	{
		return APP_STATE_DROPME;
	}

	inet_pton(AF_INET, trigger_ipstr, &trigger_ip);
	if(trigger_ip == ipv4hdr->saddr){ /* 根据特定包造包 */
		Gserial_sendpacket_tcp_detail(PLUG_DEMO_ID, stream, ntohl(ipv4hdr->saddr), ntohl(ipv4hdr->daddr), 
								   0x1234, 64, 0x1111,0x2222,
								  0x12345678, 0x87654321, 
								  0x12, 8192, 
								  "TCP payload test", strlen("TCP payload test"), stream->routedir);	
	}else if(trigger_ip == ipv4hdr->daddr){
		Gserial_sendpacket_tcp_detail(PLUG_DEMO_ID, stream, ntohl(ipv4hdr->daddr), ntohl(ipv4hdr->saddr), 
								   0x1234, 64, 0x1111,0x2222,
								  0x12345678, 0x87654321, 
								  0x12, 8192, 
								  "TCP payload test", strlen("TCP payload test"), MESA_dir_reverse(stream->routedir));	
	}
	return APP_STATE_GIVEME;
}


char sendpacket_udp_detail_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const struct iphdr *ipv4hdr = (const struct iphdr *)raw_pkt;
	unsigned int trigger_ip;

	if(raw_pkt == NULL)
	{
		return APP_STATE_DROPME;
	}
	
	inet_pton(AF_INET, trigger_ipstr, &trigger_ip);
	if(trigger_ip == ipv4hdr->saddr){ /* 根据特定包造包 */
		Gserial_sendpacket_udp_detail(PLUG_DEMO_ID, stream, ntohl(ipv4hdr->saddr), ntohl(ipv4hdr->daddr),  
									0x1234, 64, 0x1111,0x2222,
									"UDP payload test", strlen("UDP payload test"), stream->routedir);
	}else{
		Gserial_sendpacket_udp_detail(PLUG_DEMO_ID, stream, ntohl(ipv4hdr->daddr), ntohl(ipv4hdr->saddr),  
									0x1234, 64, 0x1111,0x2222,
									"UDP payload test", strlen("UDP payload test"), MESA_dir_reverse(stream->routedir));
	}
	
	return APP_STATE_GIVEME;
}



int test_wangyan_init(void)
{	
	return PLUG_DEMO_ID;
}

#ifdef __cplusplus
}
#endif

