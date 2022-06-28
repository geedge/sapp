#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>	 
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "stream.h"
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "sapp_benchmark.h"
#include "gtest_sapp_fun.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 此处写几个最常用的插件入口函数,
   包括最常用的返回值, DROP, 注入数据包等动作,
   但是跟具体流量、数据包无关, 方便用一套代码测试不同的数据包.
 */


char KEEP_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_GIVEME;
}

char DROP_STREAM_PKT(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_DROPPKT;
}


static char __RST_STREAM_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet, unsigned char state, unsigned char dir)
{
	struct rst_tcp_para rst_args = {};

	if(OP_STATE_CLOSE == state){
		return APP_STATE_DROPME;
	}
	
	rst_args.th_flags = 0x4;
	rst_args.rst_pkt_num = 1;
	rst_args.dir = dir;
	rst_args.signature_seed1 = 65535;
	rst_args.signature_seed2 = 13;
	
	int ret = MESA_rst_tcp(a_tcp, &rst_args, sizeof(struct rst_tcp_para));
	if(ret < 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "RST_STREAM_S2C", "MESA_rst_tcp() dir:%d, error!\n", dir);
	}else{
		SAPP_PLUG_LOG(RLOG_LV_DEBUG, "RST_STREAM_S2C", "MESA_rst_tcp() dir:%d, success!\n", dir);
	}

	return APP_STATE_DROPME;
}


char RST_STREAM_C2S_TCPALL_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return __RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->pktstate, DIR_C2S);
}

char RST_STREAM_S2C_TCPALL_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return __RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->pktstate, DIR_S2C);
}


char RST_STREAM_C2S_TCP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return __RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->opstate, DIR_C2S);
}

char RST_STREAM_S2C_TCP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return __RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->opstate, DIR_S2C);
}

/* 发送两个方向的rst, 只针对双向流, 先发C2S方向, 再发S2C方向 */
char RST_STREAM_TCP_C2S_and_S2C(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct rst_tcp_para rst_args = {};

	if(a_tcp->dir != DIR_DOUBLE){
		return APP_STATE_GIVEME;
	}

	__RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->opstate, DIR_C2S);
	__RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->opstate, DIR_S2C);

	return APP_STATE_DROPME |APP_STATE_DROPPKT;
}

/* 发送两个方向的rst, 只针对双向流, 先发C2S方向, 再发S2C方向 */
char RST_STREAM_TCPALL_C2S_and_S2C(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct rst_tcp_para rst_args = {};

	if(a_tcp->dir != DIR_DOUBLE){
		return APP_STATE_GIVEME;
	}

	__RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->pktstate, DIR_C2S);
	__RST_STREAM_ENTRY(a_tcp, pme, thread_seq, a_packet, a_tcp->pktstate, DIR_S2C);

	return APP_STATE_DROPME |APP_STATE_DROPPKT;
}


char PKT_DELAY_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	static int pkt_index = 0;
	static time_t last_recv_time = time(NULL);
	
	pkt_index++;
	
	/* 测试用例在第3个包之前会休眠一会 */
	if(pkt_index == 3){
		if(time(NULL) >= last_recv_time + 5){
			sapp_benchmark_set_plug_result(SAPP_BCHMK_RES_SUCC);
			printf("PKT_DELAY_ENTRY(): set res succ!\n");
		}else{
			sapp_benchmark_set_plug_result(SAPP_BCHMK_RES_FAIL);
			printf("PKT_DELAY_ENTRY(): set res fail!\n");
		}
		
		return APP_STATE_DROPME;
	}
	
	last_recv_time = time(NULL);
	
	return APP_STATE_GIVEME;
}


#ifdef __cplusplus
}
#endif
