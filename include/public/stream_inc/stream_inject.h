#ifndef _APP_STREAM_INJECT_H_
#define _APP_STREAM_INJECT_H_ 

#include <sys/types.h>
#include <stdint.h>
#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

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
					
#ifdef __cplusplus
}
#endif

#endif

