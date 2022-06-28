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

#ifdef __cplusplus
extern "C" {
#endif


char KEEP_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_GIVEME;
}

char DROP_STREAM_PKT(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_DROPPKT;
}

char RST_STREAM_C2S(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct rst_tcp_para rst_args = {};
	
	rst_args.th_flags = 0x4;
	rst_args.rst_pkt_num = 1;
	rst_args.dir = DIR_C2S;
	rst_args.signature_seed1 = 65535;
	rst_args.signature_seed2 = 13;
	
	MESA_rst_tcp(a_tcp, &rst_args, sizeof(struct rst_tcp_para));


	return APP_STATE_GIVEME;

}

char RST_STREAM_S2C(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct rst_tcp_para rst_args = {};
	
	rst_args.th_flags = 0x4;
	rst_args.rst_pkt_num = 1;
	rst_args.dir = DIR_S2C;
	rst_args.signature_seed1 = 65535;
	rst_args.signature_seed2 = 17;
	
	MESA_rst_tcp(a_tcp, &rst_args, sizeof(struct rst_tcp_para));


	return APP_STATE_GIVEME;
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

int SAPP_BENCHMARK_INIT(void)
{
	return 1;
}

void SAPP_BENCHMARK_DESTROY(void)
{
	return;
}

#ifdef __cplusplus
}
#endif
