/****************************************************************************
Filename   : Gserial_sendpacket.h
Author     : liuyang
Time       : 2012-04

功能说明：
	在串联特殊设备情况下，能够发送ipv4,tcp,udp及已经构造好的IP层数据包

Update log:
	2012-07-04, modify by LiJia<lijia@nismail.iie.ac.cn>
				修改传输方向参数定义, dir最高位表示传输方向，低7位另有其他含义.
****************************************************************************/
/*
	关于传输方向的说明:
	底层平台在调用上层回调处理函数(插件)时，
	会传递一个参数dir，最高位表示传输方向, 1表示上行，0表示下行,
	dir参数的低0-6位，底层平台另有其他含义，请勿更改!

	| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | 
	|dir|----平台保留位,请勿更改----|
	
	上层插件在需要发送数据包时，判断与包的原始传输方向是否一致:
	如果发包和收包方向一致，保持dir值不变;
	如果发包和收包方向相反，将dir参数的最高位取反;
*/

#include <sys/types.h>
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
		buf:伪造数据包(IPv4头)
		buf_len:buf长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；
			若发送失败则返回FAILE (-1);
*/
int Gserial_sendpacket_iplayer(int plug_id, struct streaminfo *stream,const char *buf, int buf_len, u_char dir);

/*
函数名:Gserial_sendpacket_ipv6_layer();
函数功能:发送伪造数据包,伪造的数据包存储在buf中,
			 且数据包最低层ipv6层，不能发送链路层的数据。
			  即buf中依次存储ip层、tcp/udp层、(应用层)数据；
			  程序只负责将buf中内容发送出去。
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		buf:伪造数据包(IPv6头)
		buf_len:buf长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；
			若发送失败则返回FAILE (-1);
*/
int Gserial_sendpacket_ipv6_layer(int plug_id, struct streaminfo *stream,const char *buf, int buf_len, u_char dir);

/*
函数名:Gserial_sendpacket_ipv4();
函数功能:发送伪造IPv4包；
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		ttl:生存时间；
		sip:发送数据包的源IP地址,主机字节序；
		dip:发送数据包的目的IP地址，主机字节序；
		protocol:上层协议类型,例如:
		payload:负载内容；
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；
		若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_ipv4(int plug_id, struct streaminfo *stream,u_char ttl,u_char protocol,uint sip, uint dip,
									const char *payload,int payload_len,u_char dir);


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
函数名:Gserial_sendpacket_ipv6();
函数功能:发送伪造IPv6包；
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		ttl:生存时间；
		sip:发送数据包的源IP地址,主机字节序；
		dip:发送数据包的目的IP地址，主机字节序；
		protocol:上层协议类型,例如:
		payload:负载内容；
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；
		若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_ipv6(int plug_id, struct streaminfo *stream,u_char ttl,u_char protocol,
						struct in6_addr *sip, struct in6_addr *dip, 
						const char *payload,int payload_len,u_char dir);
									
/*
函数名:Gserial_sendpacket_tcp();
函数功能:发送伪造TCP包；
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		sip:发送数据包的源IP地址，主机字节序；
		dip:发送数据包的目的IP地址，主机字节序；
		sport:发送数据包的源端口号，主机字节序;
		dport:发送数据包的目的端口号，主机字节序；
		sseq:发送数据包的序列号(seq)，主机字节序；
		sack:发送数据包的应答码(ack)，主机字节序；
		control:发送数据包的控制标记，即表示数据包为ack,syn,rest等类型；
		payload:负载内容；
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_tcp(int plug_id,struct streaminfo *stream,u_int sip,u_int dip,u_short sport,
									u_short dport,u_int sseq,u_int sack,u_char control,
									const char* payload,int payload_len, u_char dir);




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
函数名:Gserial_sendpacket_ipv6_tcp_detail();
函数功能:发送伪造基于ipv6的TCP包；
参数说明:
		plug_id:插件ID;
		thread_index:线程号；
		sip:发送数据包的源IPv6地址，网络字节序；
		dip:发送数据包的目的IPv6地址，网络字节序；
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
int Gserial_sendpacket_ipv6_tcp_detail(int plug_id,struct streaminfo *stream,struct in6_addr *sip, struct in6_addr *dip, 
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
		sport:发送数据包的源端口号，主机字节序；
		dport:发送数据包的目的端口号，主机字节序；
		payload:UDP负载内容;
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_udp(int plug_id,struct streaminfo *stream, u_int sip, u_int dip, u_short sport,
									u_short dport, const char *payload, int payload_len,u_char dir);

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

/*
函数名:Gserial_sendpacket_ipv6_udp_detail();
函数功能:发送伪造UDP包
参数说明:
		plug_id:插件ID;
		thread_indes:线程号;
		sip:发送数据包的源IP地址,网络字节序;
		dip:发送数据包的目的IP地址,网络字节序；
		ip_ttl: 发送数据包的IP-TTL字段，0表示随机；
		sport:发送数据包的源端口号，主机字节序；
		dport:发送数据包的目的端口号，主机字节序；
		payload:UDP负载内容;
		payload_len:负载长度，主机字节序；
		dir:传输方向
返回值:发送成功则返回发送数据字节数；若发送失败则返回FAILE (-1)；
*/
int Gserial_sendpacket_ipv6_udp_detail(int plug_id,struct streaminfo *stream, struct in6_addr *sip, struct in6_addr *dip, 
 								u_char ip_ttl, u_short sport, 
 								u_short dport, const char *payload, int payload_len,u_char dir);
 								
#ifdef __cplusplus
}
#endif

