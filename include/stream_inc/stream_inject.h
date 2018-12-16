#ifndef _APP_STREAM_INJECT_H_
#define _APP_STREAM_INJECT_H_ 

#include <sys/types.h>
#include <stdint.h>
#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_INJECT_H_VERSION		(20181108)


/* 
	CHN : 链接GK相关函数 
	ENG : to force terminate a stream;

	MESA_kill_tcp: use RST to terminate a TCP stream;
	MESA_kill_tcp_synack: send phony SYN/ACK packet to cheat client and server.
	MESA_kill_connection: for non-TCP stream, such as UDP stream, only available in serial mode.

    return value:
		>= 0: success.
		-1  : error.
*/
int MESA_kill_tcp(struct streaminfo *stream, const void *raw_pkt);
int MESA_kill_tcp_synack(struct streaminfo *stream, const void *raw_pkt);
int MESA_kill_connection(struct streaminfo *stream, const void *ext_raw_pkt);

/*
	带反馈功能的MESA_kill_xxx系列函数.
	附加功能为: 
	    将实际发送的数据包copy到feedback_buf空间内, 并设置feedback_buf_len为实际数据包长度.

	注意: feedback_buf_len为传入传出参, 传入表示feedback_buf长度, 传出表示实际发送的数据包长度.

    return value:
		>= 0: success.
		-1  : error.	
		-2  : feedback_buf or feedback_buf_len error.
*/
int MESA_kill_tcp_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len);
int MESA_kill_tcp_synack_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len);
int MESA_kill_connection_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len);

/* 
	CHN : 反向route_dir函数, 为了兼容papp;
	ENG : compat for papp, dir reverse.
 */
unsigned char MESA_dir_reverse(unsigned char raw_route_dir);

/*
	ARG:
		stream: 流结构体指针;
		payload: 要发送的数据指针;
		payload_len: 要发送的数据负载长度;
		raw_pkt: 原始包指针;
		snd_routedir: 要发送数据的route方向, 
			 如果待发送的包与当前包同向, snd_routedir = stream->routedir, 
			 如果待发送的包与当前包反向, snd_routedir = MESA_dir_reverse(stream->routedir).
	return value:
		-1: error.
		>0: 发送的数据包实际总长度(payload_len + 底层包头长度);
*/
int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, const void *raw_pkt, UCHAR snd_routedir);


/*
	带反馈功能的MESA_inject_pkt_feedback函数, 功能同MESA_inject_pkt().
	将实际发送的数据包copy到feedback_buf空间内, 并设置feedback_buf_len为实际数据包长度.

	注意: feedback_buf_len为传入传出参, 传入表示feedback_buf长度, 传出表示实际发送的数据包长度.

    return value:
		>= 0: success.
		-1  : error.	
		-2  : feedback_buf or feedback_buf_len error.
*/
int MESA_inject_pkt_feedback(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir,
						char *feedback_buf, int *feedback_buf_len);
						
int MESA_sendpacket_ethlayer(int thread_index,const char *buf, int buf_len, unsigned int target_id);//papp online, shuihu

/* 发送已构造好的完整IPv4包, IPv4头部校验和等均需调用者计算 */
int MESA_sendpacket_iplayer(int thread_index,const char *buf,  int buf_len, __uint8_t dir);

/* 发送已构造好的完整IPv4包, 用于vxlan环境, options用于填充和vxlan相关的选项 */
int MESA_sendpacket_iplayer_options(int thread_index,const char *data,  int data_len, u_int8_t dir, SAPP_TLV_T *options, int opt_num);

/* 发送已构造好的完整IPv6包, 校验和等均需调用者计算, 用于vxlan环境, options用于填充和vxlan相关的选项 */
int MESA_sendpacket_ipv6_layer_options(int thread_index,const char *data,  int data_len, u_int8_t dir, SAPP_TLV_T *options, int opt_num);

/* 发送指定参数IP包, 可指定负载内容, 校验和由平台自动计算,
   sip, dip为主机序. */
int MESA_fakepacket_send_ipv4(int thread_index,__uint8_t ttl,__uint8_t protocol,
							u_int32_t sip_host_order, u_int32_t dip_host_order, 
							const char *payload, int payload_len,__uint8_t dir);

int MESA_fakepacket_send_ipv4_options(const struct streaminfo *stream, uint8_t protocol,
							uint32_t sip_host_order, uint32_t dip_host_order, 
							const char *payload, int payload_len, uint8_t dir, 
							SAPP_TLV_T *options, int opt_num);
							
int MESA_fakepacket_send_ipv4_detail(int thread_index,u_int8_t ttl,
							u_int8_t protocol,u_int32_t sip, u_int32_t dip, u_int16_t ipid, 
							const char *payload, int payload_len,u_int8_t dir);

int MESA_fakepacket_send_ipv6_options(const struct streaminfo *stream, uint8_t protocol,
							struct in6_addr *sip, struct in6_addr *dip,
							const char *payload, int payload_len, uint8_t dir, 
							SAPP_TLV_T *options, int opt_num);
							
/* 发送指定参数TCP包, 可指定负载内容, 校验和由平台自动计算,
   sip, dip,sport,dport,sseq,sack都为主机序. */
int MESA_fakepacket_send_tcp(int thread_index,u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,const char* payload,int payload_len, u_int8_t dir);

int MESA_fakepacket_send_tcp_detail(int thread_index,u_int sip_host_order,u_int dip_host_order,
										u_short ipid, u_char ip_ttl,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order, 
							u_char control, u_short tcp_win, const char* payload,int payload_len, u_int8_t dir);
int MESA_fakepacket_send_tcp_options(const struct streaminfo *stream,
							u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,
							const char* payload,int payload_len, u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);	
int MESA_fakepacket_send_ipv6_tcp_options(const struct streaminfo *stream,
							struct in6_addr *sip, struct in6_addr *dip,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,
							const char* payload,int payload_len, u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);							
/* 发送指定参数UDP包, 可指定负载内容, 校验和由平台自动计算,
   sip, dip,sport,dport都为主机序. */
int MESA_fakepacket_send_udp(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir);
							
int MESA_fakepacket_send_udp_detail(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short ipid, u_int8_t ip_ttl, u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir);
int MESA_fakepacket_send_udp_options(const struct streaminfo *stream,
							u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);							
int MESA_fakepacket_send_ipv6_udp_options(const struct streaminfo *stream,
							struct in6_addr *sip, struct in6_addr *dip,
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);							
/* 
   转发/发送当前上下文数据包, 
   target_id: 用于指定转发/发送目标, 由配置文件conf->send_raw_pkt.conf指定最终目标网卡或设备号.
*/
int sapp_forward_current_pkt(const struct streaminfo *stream, unsigned int target_id);

enum sapp_send_pkt_opt_type{
	SAPP_SEND_OPT_IP_ID			= 0x10,			
	SAPP_SEND_OPT_IP_TTL			= 0x11,
	
	SAPP_SEND_OPT_TCP_WIN		= 0x20,
	
	SAPP_SEND_OPT_GDEV_DMAC		= 0x1101, /* GDEV-DMAC, 整个包的最外层DMAC */
	SAPP_SEND_OPT_GDEV_SMAC		= 0x1102, /* local-SMAC, 整个包的最外层SMAC */
	SAPP_SEND_OPT_GDEV_DIP		= 0x1103, /* GDEV-DIP, network order */
	SAPP_SEND_OPT_GDEV_SIP		= 0x1104, /* local-SIP, network order */
	SAPP_SEND_OPT_GDEV_UDP_DPORT=0x1105, /* GDEV udp dst port, network order */
	SAPP_SEND_OPT_GDEV_UDP_SPORT= 0x1106, /* local udp src port, network order */
	SAPP_SEND_OPT_VXLAN_FLAGS	= 0x1201, /* vxlan 标志位 */
	SAPP_SEND_OPT_VXLAN_VPN_ID	= 0x1202, /* vxlan vlan_id/vpn_id */
	SAPP_SEND_OPT_VXLAN_LINK_ID	= 0x1203, /* vxlan 链路id */
	SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE = 0x1204,  /* vxlan原始二层封装格式 */
	SAPP_SEND_OPT_VXLAN_ONLINE_TEST_FLAG = 0x1205, /* vxlan在线测试位 */
	SAPP_SEND_OPT_VXLAN_LINK_DIR = 0x1206, /* vxlan链路方向位 */
	SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE = 1301,  /* 内层二层封装格式 */
	SAPP_SEND_OPT_INNER_SMAC	= 0x1302, /* 内层源MAC */
	SAPP_SEND_OPT_INNER_DMAC	= 0x1303, /* 内层目的MAC */
	SAPP_SEND_OPT_INNER_VLANID	= 0x1304, /* 内层如果有VLAN需设置 */
	SAPP_SEND_OPT_VIRTUAL_LINK_ID = 0x1305, /* 设置虚拟链路号， 同时需要置TUNNAT_CZ_ACTION_ENCAP_VIRTUAL_LINK_ID*/
	SAPP_SEND_OPT_REHASH_INDEX = 0x1306, /*设置rehash index， 同时需要置TUNNAT_CZ_ACTION_ENCAP_VIRTUAL_LINK_ID*/
};

int MESA_fakepacket_send_ipv4_options(const struct streaminfo *stream, uint8_t protocol,
							uint32_t sip_host_order, uint32_t dip_host_order, 
							const char *payload, int payload_len, uint8_t dir, 
							SAPP_TLV_T *options, int opt_num);

int MESA_fakepacket_send_tcp_options(const struct streaminfo *stream,
							u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,
							const char* payload,int payload_len, u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);

int MESA_fakepacket_send_udp_options(const struct streaminfo *stream,
							u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir,
							SAPP_TLV_T *options, int opt_num);
							
#ifdef __cplusplus
}
#endif

#endif

