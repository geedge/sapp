#ifndef _APP_STREAM_REGISTER_H_
#define _APP_STREAM_REGISTER_H_ 

#include "stream_inc/stream_base.h"
#include "stream_inc/stream_entry.h"

#define MAX_FUN_NUM 64

enum fun_type_t{
	FUN_TYPE_IPV4=0,
   	FUN_TYPE_IPV6,		
   	FUN_TYPE_TCP,		
   	FUN_TYPE_TCPALL,		
   	FUN_TYPE_UDP,		
   	FUN_TYPE_IPV4_RAW,		
   	FUN_TYPE_IPV6_RAW,		
   	FUN_TYPE_TCP_RAW,		
   	FUN_TYPE_TCPALL_RAW,		
   	FUN_TYPE_UDP_RAW,		
   	/* 2015-02-03 lijia add ip frag entry */
 	FUN_TYPE_IPV4_FRAG,
 	FUN_TYPE_IPV4_FRAG_RAW,
 	FUN_TYPE_IPV6_FRAG,
 	FUN_TYPE_IPV6_FRAG_RAW,
 	FUN_TYPE_PHONY, /* 2016-09-01 lijia add, phony plug entry, will not be called in fact. */
 	FUN_TYPE_POLLING, /* 2016-09-26 lijia add, polling plug entry, will be called wherether has received packet or not. */
 	__FUN_TYPE_MAX,
};


typedef struct _stFunArray
{
	int funtype;
	union
	{
		SAPP_STREAM_FUN_T sapp_stream_fun;
		SAPP_PKT_CB_FUN_T sapp_pkt_fun;
		STREAM_CB_FUN_T	stream_fun;
		IPv4_CB_FUN_T	stream_ipv4_fun;
		IPv6_CB_FUN_T	stream_ipv6_fun;
		char (*pfun)(void);
	};	
}stFunArray;

#ifdef __cplusplus
extern "C" {
#endif


int stream_register_tcp_allpkt (STREAM_CB_FUN_T fun);
int stream_register_tcp_takeover (STREAM_CB_FUN_T fun);

int stream_register_tcp (STREAM_CB_FUN_T fun);
int stream_register_udp (STREAM_CB_FUN_T fun);
int stream_register_ip (IPv4_CB_FUN_T fun);
int stream_register_ipv6 (IPv6_CB_FUN_T fun);
int stream_register_ip_frag (IPv4_CB_FUN_T x);
int stream_register_ipv6_frag(IPv6_CB_FUN_T fun);

int stream_register_fun(int funtype,char (*x)(void));

//业务层回调接口
char PROT_PROCESS(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet);

/*
	平台是否转发当前包, 最后由此回调函数决定,
	参数:
		net_conn_mode:网络拓扑模式;
		plug_action  :当前包业务插件的返回值;
		
	返回值:
		PASS or DROP;
*/
int platform_register_action_judge(char (*action_cb_fun)(int net_conn_mode, char plug_action));

#ifdef __cplusplus
}
#endif



#endif

