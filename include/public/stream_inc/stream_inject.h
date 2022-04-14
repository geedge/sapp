#ifndef _APP_STREAM_INJECT_H_
#define _APP_STREAM_INJECT_H_ 

#include <sys/types.h>
#include <stdint.h>
#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_INJECT_H_VERSION		(20191120)


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

struct rst_tcp_para{
	unsigned char  th_flags; /* TCP头部标志位, 可选值为[TH_RST, TH_RST|TH_ACK] */
	unsigned char  rst_pkt_num;  /* 调用一次MESA_rst_tcp()发送的rst包数量, 可选值[1,2,3], 针对单个方向, 即rst_pkt_num=2, dir=DIR_DOUBLE时,总发包数量是4个  */
	/*  
	    dir:
	    发送rst包方向, 可选值为[DIR_C2S, DIR_S2C, DIR_DOUBLE], 此值参考:streaminfo->curdir,  
		如果待发送的包与当前包同向, dir = stream->curdir, 
		如果待发送的包与当前包反向, dir = stream->curdir ^ 3, 即反向.
		如果是双向发送, dir = DIR_DOUBLE;
	*/
	unsigned char  dir; 
	unsigned char __pad_no_use; /* padding for alignment */
	
	/* 
	   rst包指纹信息, 推荐值seed1=65535, seed2为素数, 如13,17,19等; 
	   signature_seed1=0 && signature_seed1=0, 表示本次调用不指定signature, 使用全局配置, 规则如下:
	   if(sapp.toml->stream.tcp.inject.signature_enabled == 1){
			signature_seed1 = sapp.toml->stream.tcp.inject.signature_seed1;
			signature_seed2 = sapp.toml->stream.tcp.inject.signature_seed2;
	   }else{
		   signature_seed1 = rand();
		   signature_seed2 = rand();
	   }
	*/
	unsigned short signature_seed1; 
	unsigned short signature_seed2; 
};

/*
	args:
		stream: 当前流上下文;
		paras : 发送rst相关参数, 详见struct rst_tcp_para结构体说明;
		para_len: sizeof(struct rst_tcp_para), 预留后续升级需求, 根据此长度判断版本.
		
	MESA_rst_tcp与MESA_kill_tcp区别:
		MESA_kill_tcp实际上是几个动作的大杂烩: 发送RST包, 类似返回了APP_STATE_KILL_OTHER, 及DROP当前流后续所有包;
		MESA_rst_tcp只专心做一件事情: 发送RST包!

	note: 除上面的参数之外, kill_tcp还有一个特性是FD补救, 
	      即可能因为丢包、序号错误、网络延时等原因, 导致单次FD不生效, 调用MESA_kill_tcp之后可以自动进行FD补救, 
	      但对于MESA_rst_tcp来说, 所有行为只对当前包有效, 
	      remedy功能是作用于整个stream的, 需要调用MESA_set_stream_opt(), opt=MSO_TCP_RST_REMEDY 完成.
		
    return value:
		>= 0: success.
		-1  : error.
*/
int MESA_rst_tcp(struct streaminfo *stream, struct rst_tcp_para *paras, int para_len);



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
int MESA_send_smart_offload(const struct streaminfo *pstream, const void *raw_pkt, int thread_num);

/* 
	CHN : 反向route_dir函数, 为了兼容papp;
	ENG : compat for papp, dir reverse.
 */
unsigned char MESA_dir_reverse(unsigned char raw_route_dir);

/*************************************************************************************** 	
	NOTE:
		在被动模式下, 插件无需关心route_dir的绝对值, 只需要理解同向和反向即可,
		但主动发包必须要精确理解route_dir是0还是1, 因外界网络拓扑模式不同, 可能随时会变化,
		所以设置此接口, 插件只需传入人易理解的方向, 返回当前链路的link route dir,
		注意etc/sapp.toml inbound_route_dir要设置正确.

	args: 表示发包目标相对于当前设备所在的地理位置,
		'E' or 'e': 表示发包方向是从Internal to External.
		'I' or 'i': 表示发包方向是从External to Internal.

	return value:
		0 or 1: success.
		-1 : error.
****************************************************************************************/
int MESA_dir_human_to_link(int human_dir);

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

/* 发送已构造好的完整IP包, 校验和等均需调用者计算 */
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
	SAPP_SEND_OPT_IP_TTL		= 0x11,
	
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
	SAPP_SEND_OPT_REHASH_INDEX 	= 0x1306, /*设置rehash index， 同时需要置TUNNAT_CZ_ACTION_ENCAP_VIRTUAL_LINK_ID*/
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

