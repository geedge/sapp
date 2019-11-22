#ifndef __cplusplus
#error("This file must be compiled with c++ compiler!")
#endif

#ifndef _STREAM_INJECT_PLUS_H
#define _STREAM_INJECT_PLUS_H 1

#define STREAM_INJECT_PLUS_H_VERSION		(20191121)

/*
	MESA_rst_tcp与MESA_kill_tcp区别:
		MESA_kill_tcp实际上是几个动作的大杂烩: 发送RST包, 类似返回了(DROPME | KILL_OTHER), 及DROP当前流后续所有包;
		MESA_rst_tcp只专心做一件事情: 发送RST包!

	args:
		stream			: 当前流上下文结构体;
		th_flags		: TCP头部标志位, 可选值为TH_RST, TH_RST|TH_ACK; 无此参数时默认值是TH_RST|TH_ACK;
		rst_pkt_num		: 发送的rst包数量; 无此参数时默认使用sapp.toml配置文件中的值;
		dir				: 发送rst包方向, 可选值为stream_base.h中的DIR_C2S, DIR_S2C, DIR_DOUBLE; 无此参数时默认值为DIR_DOUBLE;
		signature_seed1,2: rst包指纹信息, 推荐值seed1=65535, seed2为素数, 如13,17,19等; 
		                   无此参数时使用sapp.toml配置文件的值, 如果全局配置signature_enabled=0, 随机生成.
		                   signature_seed1=0 && signature_seed1=0, 表示随机生成.

	note: 除上面的参数之外, rst_tcp还有一个特性是auto remedy, 即可能因为丢包、序号错误、网络延时等原因, 导致FD不生效, 
	      调用MESA_kill_tcp之后可以自动进行FD补救, 但对于MESA_rst_tcp来说, 所有行为只对当前包有效, 
	      remedy功能是作用于整个stream的, 需要调用MESA_set_stream_opt(), opt=MSO_TCP_RST_REMEDY 完成.
		
    return value:
		>= 0: success.
		-1  : error.
*/
int MESA_rst_tcp(struct streaminfo *stream);
int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags);
int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags, int rst_pkt_num);
int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags, int rst_pkt_num, unsigned char dir);
int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags, int rst_pkt_num, unsigned char dir, unsigned short signature_seed1, unsigned short signature_seed2);


#endif
