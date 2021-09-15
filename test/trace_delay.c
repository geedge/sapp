#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream_internal.h"
#include "stream_project.h"
#include "mesa_net.h"


/* Client-----Gate-----Server */

#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM  (128)
#endif

int trace_delay_version_VERSION_20160405;


static FILE *G_TRACE_DELAY_LOG_FP;

/* 
	NOTE:
	data阶段每单个流只计算第一次的数据包, 全局再计算最大、最小和区间值.

	所有的计算延时都是单向链路一次传输时间.
*/
struct trace_delay{
	uint64_t C2S_SYN_time;
	uint64_t S2C_SYNACK_time;	
	uint64_t C2S_ACK_time;

	uint32_t C2S_SYN_SEQ; /* C2S方向SYN的序号 */
	uint32_t S2C_SYN_SEQ; /* S2C方向SYN的序号 */

	uint8_t last_stream_dir; /* 上次的流传输方向 */
	uint64_t last_data_pkt_time; /* 上次数据包的时间 */
	uint64_t GSG_data_round_time; /* 带有数据的包, 从G收到包开始, 到Server, 再从S->C的ack包到达G的时间, 除以2, 其实是两次传输延时+1次server的处理延时 */
	uint64_t GCG_data_round_time;  /* 带有数据的包, 从G收到包开始, 到Client, 再从C->S的ack包到达G的时间, 除以2, 其实是两次传输延时+1次Client的处理延时 */
};


#define DELAY_REGION_VAL		(6) /* 5ms, 10ms, 20ms, 40ms, 50ms, >100ms */

#define	DELAY_REG0  5000000UL
#define	DELAY_REG1  10000000UL
#define	DELAY_REG2  20000000UL
#define	DELAY_REG3  40000000UL
#define	DELAY_REG4  50000000UL
#define	DELAY_REG5  100000000UL


struct delay_stat{
	uint64_t MIN_delay_C2G;
	uint64_t MAX_delay_C2G;
	uint64_t AVG_delay_C2G_sum; /* 延时的总和, 单位:ms */
	uint64_t AVG_delay_C2G_times;

	uint64_t MIN_delay_G2S;
	uint64_t MAX_delay_G2S;
	uint64_t AVG_delay_G2S_sum;	/* 延时的总和, 单位:ms */
	uint64_t AVG_delay_G2S_times;	

	uint64_t delay_C2G_region_num[DELAY_REGION_VAL]; /* 记录各个区间中的延时个数, 只看平均值不一定能反映出全局状况 */
	uint64_t delay_G2S_region_num[DELAY_REGION_VAL]; /* 记录各个区间中的延时个数, 只看平均值不一定能反映出全局状况 */
};

static struct delay_stat G_DELAY_HANDSHAKE_STSATUS[MAX_THREAD_NUM]; /* 三次握手阶段延时 */
static struct delay_stat G_DELAY_DATA_STSATUS[MAX_THREAD_NUM];		/* 数据传输阶段延时 */


static inline void update_handshake_delay_time(int tid, uint64_t C2G_time, uint64_t G2S_time)
{
	struct delay_stat *pstat = &G_DELAY_HANDSHAKE_STSATUS[tid];

	if((C2G_time <= 0) || (C2G_time > 1000000000UL)){ /* 大于秒级的暂不统计 */
		return;
	}

	if((G2S_time <= 0) || (G2S_time > 1000000000UL)){ /* 大于秒级的暂不统计 */
		return;
	}
	
	/* min */
	if(C2G_time < pstat->MIN_delay_C2G){
		pstat->MIN_delay_C2G = C2G_time;
	}
	if(G2S_time < pstat->MIN_delay_G2S){
		pstat->MIN_delay_G2S = G2S_time;
	}
	
	/* max */
	if(C2G_time > pstat->MAX_delay_C2G){
		pstat->MAX_delay_C2G = C2G_time;
	}
	if(G2S_time > pstat->MAX_delay_G2S){
		pstat->MAX_delay_G2S = G2S_time;
	}

	/* AVG */
	pstat->AVG_delay_C2G_sum += C2G_time/1000000UL;
	pstat->AVG_delay_G2S_sum += G2S_time/1000000UL;
	pstat->AVG_delay_C2G_times++;
	pstat->AVG_delay_G2S_times++;

	if(C2G_time <= DELAY_REG0){
		pstat->delay_C2G_region_num[0]++;
	}else if(C2G_time <= DELAY_REG1){
		pstat->delay_C2G_region_num[1]++;
	}else if(C2G_time <= DELAY_REG2){
		pstat->delay_C2G_region_num[2]++;
	}else if(C2G_time <= DELAY_REG3){
		pstat->delay_C2G_region_num[3]++;
	}else if(C2G_time <= DELAY_REG4){
		pstat->delay_C2G_region_num[4]++;
	}else{
		pstat->delay_C2G_region_num[5]++;
	}

	if(G2S_time <= DELAY_REG0){
		pstat->delay_G2S_region_num[0]++;
	}else if(G2S_time <= DELAY_REG1){
		pstat->delay_G2S_region_num[1]++;
	}else if(G2S_time <= DELAY_REG2){
		pstat->delay_G2S_region_num[2]++;
	}else if(G2S_time <= DELAY_REG3){
		pstat->delay_G2S_region_num[3]++;
	}else if(G2S_time <= DELAY_REG4){
		pstat->delay_G2S_region_num[4]++;
	}else{
		pstat->delay_G2S_region_num[5]++;
	}
	
}

static inline void update_data_GCG_delay_time(int tid, uint64_t GCG_data_delay)
{
	struct delay_stat *pstat = &G_DELAY_DATA_STSATUS[tid];

	if((GCG_data_delay <= 0) || (GCG_data_delay > 1000000000UL)){ /* 大于秒级的暂不统计 */
		return;
	}

	
	/* MIN */
	if(GCG_data_delay < pstat->MIN_delay_C2G){
		pstat->MIN_delay_C2G = GCG_data_delay;
	}

	/* MAX */
	if(GCG_data_delay > pstat->MAX_delay_C2G){
		pstat->MAX_delay_C2G = GCG_data_delay;
	}

	/* AVG */
	pstat->AVG_delay_C2G_sum += GCG_data_delay/1000000UL;
	pstat->AVG_delay_C2G_times++;

	if(GCG_data_delay <= DELAY_REG0){
		pstat->delay_C2G_region_num[0]++;
	}else if(GCG_data_delay <= DELAY_REG1){
		pstat->delay_C2G_region_num[1]++;
	}else if(GCG_data_delay <= DELAY_REG2){
		pstat->delay_C2G_region_num[2]++;
	}else if(GCG_data_delay <= DELAY_REG3){
		pstat->delay_C2G_region_num[3]++;
	}else if(GCG_data_delay <= DELAY_REG4){
		pstat->delay_C2G_region_num[4]++;
	}else{
		pstat->delay_C2G_region_num[5]++;
	}	
}

static inline void update_data_GSG_delay_time(int tid, uint64_t GSG_data_delay)
{
	struct delay_stat *pstat = &G_DELAY_DATA_STSATUS[tid];

	if((GSG_data_delay <= 0) || (GSG_data_delay > 1000000000UL)){ /* 大于秒级的暂不统计 */
		return;
	}
	
	/* MIN */
	if(GSG_data_delay < pstat->MIN_delay_G2S){
		pstat->MIN_delay_G2S = GSG_data_delay;
	}

	/* MAX */
	if(GSG_data_delay > pstat->MAX_delay_G2S){
		pstat->MAX_delay_G2S = GSG_data_delay;
	}

	/* AVG */
	pstat->AVG_delay_G2S_sum += GSG_data_delay/1000000UL;
	pstat->AVG_delay_G2S_times++;


	if(GSG_data_delay <= DELAY_REG0){
		pstat->delay_G2S_region_num[0]++;
	}else if(GSG_data_delay <= DELAY_REG1){
		pstat->delay_G2S_region_num[1]++;
	}else if(GSG_data_delay <= DELAY_REG2){
		pstat->delay_G2S_region_num[2]++;
	}else if(GSG_data_delay <= DELAY_REG3){
		pstat->delay_G2S_region_num[3]++;
	}else if(GSG_data_delay <= DELAY_REG4){
		pstat->delay_G2S_region_num[4]++;
	}else{
		pstat->delay_G2S_region_num[5]++;
	}
	
}

static void update_delay_stat(int tid, struct streaminfo *a_tcp,  struct trace_delay *ptd)
{
	if(DIR_DOUBLE != a_tcp->dir){  /* 必须是双向流才能计算延时 */
		return;
	}

	if(ptd->C2S_SYN_time && ptd->S2C_SYNACK_time && ptd->C2S_ACK_time){
		update_handshake_delay_time(tid, 
								  (ptd->C2S_ACK_time - ptd->S2C_SYNACK_time)/2, 
								  (ptd->S2C_SYNACK_time - ptd->C2S_SYN_time)/2);
	}

	if(ptd->GCG_data_round_time){
		update_data_GCG_delay_time(tid, ptd->GCG_data_round_time);
	}

	if(ptd->GSG_data_round_time){
		update_data_GSG_delay_time(tid, ptd->GSG_data_round_time);
	}
	
}


static uint64_t get_cur_time_in_ns(void)
{
	struct timespec cur_time;
	uint64_t cur_second, cur_nano;

	clock_gettime(CLOCK_REALTIME, &cur_time);

	cur_second = cur_time.tv_sec;
	cur_nano = cur_time.tv_nsec;
	return cur_second * 1000000000 + cur_nano;
}

char TCP_ALL_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct mesa_ip4_hdr *ip4hdr;
	struct mesa_ip6_hdr *ip6hdr;
	struct mesa_tcp_hdr *thdr;
	struct trace_delay *ptd;
	struct tcpdetail *ptcpdetail = a_tcp->ptcpdetail;
	uint8_t thflags;
	uint64_t cur_ns_time;

	if(NULL == a_packet){ /* 可能是最后一个包了 */
		goto maybe_close;
	}

	cur_ns_time = get_cur_time_in_ns();
	
	if(a_tcp->pktstate == OP_STATE_PENDING){
		ptd = dictator_malloc(thread_seq, sizeof(struct trace_delay));
		memset(ptd, 0, sizeof(struct trace_delay));
		*pme = ptd;
	}
	ptd = (struct trace_delay *)(*pme);

	if(ptd->GSG_data_round_time && ptd->GCG_data_round_time){ /* data传输阶段延时计算完, 结束当前流 */
		update_delay_stat(thread_seq, a_tcp, ptd);
		goto dropme;
	}

	if(ADDR_TYPE_IPV4 == a_tcp->addr.addrtype){
		ip4hdr = (struct mesa_ip4_hdr *)a_packet;	
		thdr = (struct mesa_tcp_hdr *)((char *)a_packet + ip4hdr->ip_hl * 4);
	}else{
		ip6hdr = (struct mesa_ip6_hdr *)a_packet;	
		thdr = (struct mesa_tcp_hdr *)MESA_jump_layer(a_packet, ADDR_TYPE_IPV6, ADDR_TYPE_TCP);
		if(NULL == thdr){
			goto dropme;
		}
	}

	thflags = thdr->th_flags;

	if(TH_SYN == thflags){
		ptd->C2S_SYN_time = cur_ns_time;
		ptd->C2S_SYN_SEQ = ntohl(thdr->th_seq);
	}else if((TH_SYN|TH_ACK) == thflags){
		ptd->S2C_SYNACK_time = cur_ns_time;
		ptd->S2C_SYN_SEQ = ntohl(thdr->th_seq);
	}else if(TH_ACK & thflags){
		if(ptd->S2C_SYN_SEQ + 1 == ntohl(thdr->th_ack)){
			ptd->C2S_ACK_time = cur_ns_time;
		}
	}

	if((DIR_C2S == a_tcp->curdir) && (DIR_S2C == ptd->last_stream_dir)){
		ptd->GCG_data_round_time = (cur_ns_time - ptd->last_data_pkt_time)/2;
	}else if((DIR_S2C == a_tcp->curdir) && (DIR_C2S == ptd->last_stream_dir)){
		ptd->GSG_data_round_time = (cur_ns_time - ptd->last_data_pkt_time)/2;
	}
	
	if(ptcpdetail->datalen > 0){
		if(DIR_C2S == a_tcp->curdir){
			ptd->last_stream_dir = DIR_C2S;
			ptd->last_data_pkt_time = cur_ns_time;
		}else{
			ptd->last_stream_dir = DIR_S2C;
			ptd->last_data_pkt_time = cur_ns_time;
		}
	}

maybe_close:	
	if(a_tcp->pktstate == OP_STATE_CLOSE){
		ptd = (struct trace_delay *)*pme;
		update_delay_stat(thread_seq, a_tcp, ptd);
		goto dropme;
	}

	return APP_STATE_GIVEME;

dropme:
	if(ptd){
		dictator_free(thread_seq, ptd);
	}
	return APP_STATE_DROPME;
}


const char *trace_delay_get_time_now(char *time_res, int len)
{
	time_t cur;
	struct tm *date_loc;
	static char __time_str[64];

	if(time_res && (len < 64)){
	    strncpy(time_res, "", len);
        return "";
	}
	
	time(&cur);
	date_loc = localtime(&cur);
	snprintf(__time_str, 64, "%04d-%02d-%02d %02d:%02d:%02d", date_loc->tm_year+1900, date_loc->tm_mon+1,date_loc->tm_mday, 
		date_loc->tm_hour, date_loc->tm_min, date_loc->tm_sec);

    if(time_res){
        strncpy(time_res, __time_str, 64);
    }
    
	return __time_str;
}

static void *trace_delay_show_stat(void *nouse)
{
	char time_now_str[64];
	
	while(1){
		trace_delay_get_time_now(time_now_str, 64);
		fprintf(G_TRACE_DELAY_LOG_FP, "\n%s - Client-->Gateway-->Server, C2G:Client-->Gateway, G2S:Gateway-->Server --\n", time_now_str);

		fprintf(G_TRACE_DELAY_LOG_FP,"%13s %7s %7s %7s %8s %8s %8s %8s %8s %9s\n", 
			 "  ", "MIN", "MAX", "AVG", "region5", "region10", "region20",  "region40",  "region50",  "region100");
			 
		fprintf(G_TRACE_DELAY_LOG_FP,"%13s %-3.3f %-3.3f %-3.3f %8llu %8llu %8llu %8llu %8llu %10llu\n", 
			 "handshake-C2G",
			 G_DELAY_HANDSHAKE_STSATUS[0].MIN_delay_C2G > 1000000000UL ? 0: (double)G_DELAY_HANDSHAKE_STSATUS[0].MIN_delay_C2G/1000000UL,
			 (double)G_DELAY_HANDSHAKE_STSATUS[0].MAX_delay_C2G/1000000UL,
			 G_DELAY_HANDSHAKE_STSATUS[0].AVG_delay_C2G_times > 0 ? (double)G_DELAY_HANDSHAKE_STSATUS[0].AVG_delay_C2G_sum/G_DELAY_HANDSHAKE_STSATUS[0].AVG_delay_C2G_times : 0,
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_C2G_region_num[0],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_C2G_region_num[1],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_C2G_region_num[2],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_C2G_region_num[3],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_C2G_region_num[4],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_C2G_region_num[5] );
			 
		fprintf(G_TRACE_DELAY_LOG_FP, "%13s %-3.3f %-3.3f %-3.3f %8llu %8llu %8llu %8llu %8llu %10llu\n", 
			 "handshake-G2S",
			 G_DELAY_HANDSHAKE_STSATUS[0].MIN_delay_G2S > 1000000000UL ? 0: (double)G_DELAY_HANDSHAKE_STSATUS[0].MIN_delay_G2S/1000000UL,
			 (double)G_DELAY_HANDSHAKE_STSATUS[0].MAX_delay_G2S/1000000UL,
			 G_DELAY_HANDSHAKE_STSATUS[0].AVG_delay_G2S_times > 0 ? (double)G_DELAY_HANDSHAKE_STSATUS[0].AVG_delay_G2S_sum/G_DELAY_HANDSHAKE_STSATUS[0].AVG_delay_G2S_times : 0,
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_G2S_region_num[0],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_G2S_region_num[1],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_G2S_region_num[2],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_G2S_region_num[3],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_G2S_region_num[4],
			 G_DELAY_HANDSHAKE_STSATUS[0].delay_G2S_region_num[5] );

		fprintf(G_TRACE_DELAY_LOG_FP, "%13s %-3.3f %-3.3f %-3.3f %8llu %8llu %8llu %8llu %8llu %10llu\n", 
			 "data-C2G",
			 G_DELAY_DATA_STSATUS[0].MIN_delay_C2G > 1000000000UL ? 0: (double)G_DELAY_DATA_STSATUS[0].MIN_delay_C2G/1000000UL,
			 (double)G_DELAY_DATA_STSATUS[0].MAX_delay_C2G/1000000UL,
			 G_DELAY_DATA_STSATUS[0].AVG_delay_C2G_times > 0 ? (double)G_DELAY_DATA_STSATUS[0].AVG_delay_C2G_sum/G_DELAY_DATA_STSATUS[0].AVG_delay_C2G_times : 0,
			 G_DELAY_DATA_STSATUS[0].delay_C2G_region_num[0],
			 G_DELAY_DATA_STSATUS[0].delay_C2G_region_num[1],
			 G_DELAY_DATA_STSATUS[0].delay_C2G_region_num[2],
			 G_DELAY_DATA_STSATUS[0].delay_C2G_region_num[3],
			 G_DELAY_DATA_STSATUS[0].delay_C2G_region_num[4],
			 G_DELAY_DATA_STSATUS[0].delay_C2G_region_num[5] );
			 
		fprintf(G_TRACE_DELAY_LOG_FP,"%13s %-3.3f %-3.3f %-3.3f %8llu %8llu %8llu %8llu %8llu %10llu\n", 
			 "data-G2S",
			 G_DELAY_DATA_STSATUS[0].MIN_delay_G2S > 1000000000UL ? 0: (double)G_DELAY_DATA_STSATUS[0].MIN_delay_G2S/1000000UL,
			 (double)G_DELAY_DATA_STSATUS[0].MAX_delay_G2S/1000000UL,
			 G_DELAY_DATA_STSATUS[0].AVG_delay_G2S_times > 0 ? (double)G_DELAY_DATA_STSATUS[0].AVG_delay_G2S_sum/G_DELAY_DATA_STSATUS[0].AVG_delay_G2S_times : 0,
			 G_DELAY_DATA_STSATUS[0].delay_G2S_region_num[0],
			 G_DELAY_DATA_STSATUS[0].delay_G2S_region_num[1],
			 G_DELAY_DATA_STSATUS[0].delay_G2S_region_num[2],
			 G_DELAY_DATA_STSATUS[0].delay_G2S_region_num[3],
			 G_DELAY_DATA_STSATUS[0].delay_G2S_region_num[4],
			 G_DELAY_DATA_STSATUS[0].delay_G2S_region_num[5] );

		fflush(G_TRACE_DELAY_LOG_FP);
		sleep(10);
	}

	return NULL;
}

int CHAR_INIT(void)
{
	int demo_plugid = 100;
	int i, j;
	pthread_t pid;

	/* 存最小值的变量设成uint64最大值, 平均值设成1ms */
	for(i = 0; i < MAX_THREAD_NUM; i++){
		G_DELAY_HANDSHAKE_STSATUS[i].MIN_delay_C2G = ~0;
		G_DELAY_HANDSHAKE_STSATUS[i].MIN_delay_G2S = ~0;
		G_DELAY_DATA_STSATUS[i].MIN_delay_C2G = ~0;
		G_DELAY_DATA_STSATUS[i].MIN_delay_G2S = ~0;
	}

	G_TRACE_DELAY_LOG_FP = fopen("./log/trace_delay.log", "a");
	if(NULL == G_TRACE_DELAY_LOG_FP){
		printf("trace_delay init error!\n");
		return -1;
	}

	pthread_create(&pid, NULL, trace_delay_show_stat, NULL);
	
	return demo_plugid;
}

