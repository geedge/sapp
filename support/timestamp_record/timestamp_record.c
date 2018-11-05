#ifdef __cplusplus
extern "C" {
#endif

#include "common_io_dll.h"
#include "packet_io.h"
#include "packet_io_internal.h"
#include "stream_manage.h"
#include "stream_internal.h"
#include "net/mesa_net.h"
#include "sendpacket.h"
#include "iknow.h"
//#include "logger.h"

//#define CPU_CLOCK_TO_1US				(2199) /* 1微妙转换成CPU周期数, 比如2.2GHz就是2200 */


#if 1


/* 2015-11-26 lijia add, 时间戳记录 */
typedef struct{
	long ts_rd[__TS_LEVEL_MAX];
	long __pad__[3]; /* 64字节cache对齐 */
}timestamp_record_t;
extern int g_packet_io_thread_num;
extern int g_timestamp_record_sw;
static long timestamp_out_min = 0;

static long long g_timestamp_record_benchmark[TIMESTAMP_SINGLE_PKT_REGION_MAX];
//extern void *PLATFORM_IHANDLE;

extern void sapp_statsd_add_para(const char *key, unsigned long long value);

void __timestamp_print_max_tuple4(const raw_pkt_t *raw_pkt, long timedelay, int tid)
{
	const struct mesa_ethernet_hdr *ehdr;
	const struct mesa_ip4_hdr *ip4hdr;
	const struct mesa_tcp_hdr *thdr;
	const struct mesa_udp_hdr *uhdr;
	char ipsrc_str[16], ipdst_str[16];
	unsigned short sport, dport, ipid;

	if(CAP_LEVEL_MAC == raw_pkt->low_layer_type){
		ehdr = (const struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
		if(ETHERTYPE_IP == ntohs(ehdr->ether_type)){
			ip4hdr = (const struct mesa_ip4_hdr * )((char *)ehdr + sizeof(struct mesa_ethernet_hdr));
		}else{
			return;
		}
	}else if(CAP_LEVEL_IPV4 == raw_pkt->low_layer_type){
		ip4hdr = (const struct mesa_ip4_hdr * )raw_pkt->raw_pkt_data;
	}else{
		return;
	}

	inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, ipsrc_str, 16);
	inet_ntop(AF_INET, &ip4hdr->ip_dst.s_addr, ipdst_str, 16);
	ipid = ntohs(ip4hdr->ip_id);

	if(IPPROTO_TCP == ip4hdr->ip_p){
		thdr = (const struct mesa_tcp_hdr *)((char *)ip4hdr + ip4hdr->ip_hl * 4);
		sport = ntohs(thdr->th_sport);
		dport = ntohs(thdr->th_dport);
		sapp_runtime_log(RLOG_LV_FATAL, "tid%d, timedaly CPU-CYCLE:%lld, TCP:%s:%u - %s:%u, ipid=%u, th_flags=0x%x\n", 
						tid, timedelay, ipsrc_str, sport, ipdst_str, dport, ipid, thdr->th_flags);			
	}else if(IPPROTO_UDP == ip4hdr->ip_p){
		uhdr = (const struct mesa_udp_hdr *)((char *)ip4hdr + ip4hdr->ip_hl * 4);
		sport = ntohs(uhdr->uh_sport);
		dport = ntohs(uhdr->uh_dport);
		sapp_runtime_log(RLOG_LV_FATAL, "tid:%d, timedaly CPU-CYCLE:%lld, UDP:%s:%u - %s:%u, ipid=%u\n", 
						tid,timedelay, ipsrc_str, sport, ipdst_str, dport, ipid);
	}else{
		sapp_runtime_log(RLOG_LV_FATAL, "tid:%d, timedaly CPU-CYCLE:%lld, IPPROTO:%u\n", 
						tid,timedelay, ip4hdr->ip_p);
	}

	return;
}

#if 0
void timestamp_record(enum timestamp_level level, const raw_pkt_t *raw_pkt, int thread_seq)
{
	struct timeval curtime;

	if(0 == g_timestamp_record_sw){
		return;
	}

	if(NULL == raw_pkt){
		/* 没有实际包到达, 可能是被超时淘汰的流, 把之前的值清空, 返回.  不记录此次时间 */
		memset(&g_timestamp_record[thread_seq].ts_rd, 0, sizeof(long)*__TS_LEVEL_MAX);
		return;
	}

	gettimeofday(&curtime, NULL);
	g_timestamp_record[thread_seq].ts_rd[level] = curtime.tv_sec * 1000000 + curtime.tv_usec 
					- (raw_pkt->raw_pkt_ts.tv_sec*1000000 + raw_pkt->raw_pkt_ts.tv_usec);

	/* 某线程的最后一条时间戳记录到达时, 选择是否输出 */
	if((TS_LEVEL_AFTER_PLUG) == level && (g_timestamp_record[thread_seq].ts_rd[level] >= timestamp_out_min)){
		ibroadcast(PLATFORM_IHANDLE, 3, "timestamp", "%8ld %8ld %8ld %8ld %8ld \n",
				 g_timestamp_record[thread_seq].ts_rd[TS_LEVEL_LIB],
				 g_timestamp_record[thread_seq].ts_rd[TS_LEVEL_WORK],
				 g_timestamp_record[thread_seq].ts_rd[TS_LEVEL_IP_ENTRY],
				 g_timestamp_record[thread_seq].ts_rd[TS_LEVEL_BEFORE_PLUG],
				 g_timestamp_record[thread_seq].ts_rd[TS_LEVEL_AFTER_PLUG]);
	}

	return;
}

void timestamp_record_lib(const raw_pkt_t *raw_pkt)
{
	int i;
	struct timeval curtime;
	long time_delay;
	
	if((0 == g_timestamp_record_sw) || (NULL == raw_pkt)){
		return;
	}

	gettimeofday(&curtime, NULL);
	time_delay = curtime.tv_sec * 1000000 + curtime.tv_usec 
			 - (raw_pkt->raw_pkt_ts.tv_sec*1000000 + raw_pkt->raw_pkt_ts.tv_usec);

	/* 更新所有工作线程的计数 */
	for(i = 0; i < g_packet_io_thread_num; i++){
		g_timestamp_record[i].ts_rd[TS_LEVEL_LIB] = time_delay;
	}

	return ;
}
#else
void timestamp_record(enum timestamp_level level, const raw_pkt_t *raw_pkt, int thread_seq)
{
}
void timestamp_record_lib(const raw_pkt_t *raw_pkt)
{
}
#endif


void timestamp_region_update(int tid, long long cpu_cycle)
{
	int range;

	if(cpu_cycle > sapp_global_mthread[tid].runtime_record.runtime_pkt_max_delay){
		sapp_global_mthread[tid].runtime_record.runtime_pkt_max_delay = cpu_cycle;
	}

	sapp_global_mthread[tid].runtime_record.pkt_total_time += cpu_cycle;
	
	/* 分区统计 */
	for(range = 0; range < TIMESTAMP_SINGLE_PKT_REGION; range++){
		if(cpu_cycle <= g_timestamp_record_benchmark[range]){
			sapp_global_mthread[tid].runtime_record.pkt_total_num[range]++;
			return;
		}
	}

	/* 超过统计区间, 放最后一个 */
	sapp_global_mthread[tid].runtime_record.pkt_total_num[TIMESTAMP_SINGLE_PKT_REGION]++;

	return;
}

void pkt_runtime_output(void)
{
	int i, offset = 0 , ret = 0, left_len = 1024;
	FILE* fp;
	char log_out_buf[1024];
	int tid, region_index;
	unsigned long long per_thread_region_pkt_sum[TIMESTAMP_SINGLE_PKT_REGION_MAX][MAX_THREAD_NUM];
	unsigned long long per_thread_region_time_sum[MAX_THREAD_NUM];
	unsigned long long per_region_pkt[TIMESTAMP_SINGLE_PKT_REGION_MAX];
	unsigned long long per_thread_pkt[MAX_THREAD_NUM];
	double per_thread_avg[MAX_THREAD_NUM];
	unsigned long long per_thread_max[MAX_THREAD_NUM];
	unsigned long long summary_max_delay = 0;
	unsigned long long summary_avg_delay = 0, summary_total_pkt = 0, summary_tot_time = 0;

	fp = fopen("./runtime.log","w+");
	if(fp == NULL)
	{
		return;
	}

	memset(per_thread_region_pkt_sum, 0, sizeof(per_thread_region_pkt_sum));
	memset(per_thread_region_time_sum, 0, sizeof(per_thread_region_time_sum));
	memset(per_thread_max, 0, sizeof(per_thread_max));
	memset(per_region_pkt, 0, sizeof(per_region_pkt));
	memset(per_thread_pkt, 0, sizeof(per_thread_pkt));

	/* 多线程, 多个range计数求和 */
	for(tid = 0; tid < g_packet_io_thread_num; tid++){
		summary_tot_time += sapp_global_mthread[tid].runtime_record.pkt_total_time;
		per_thread_region_time_sum[tid] += sapp_global_mthread[tid].runtime_record.pkt_total_time;
		
		for(region_index = 0; region_index < TIMESTAMP_SINGLE_PKT_REGION_MAX; region_index++){
			per_thread_region_pkt_sum[region_index][tid] += sapp_global_mthread[tid].runtime_record.pkt_total_num[region_index];
			summary_total_pkt += sapp_global_mthread[tid].runtime_record.pkt_total_num[region_index];

			per_region_pkt[region_index] += sapp_global_mthread[tid].runtime_record.pkt_total_num[region_index]; 
			per_thread_pkt[tid] += sapp_global_mthread[tid].runtime_record.pkt_total_num[region_index];
		}

		if(sapp_global_mthread[tid].runtime_record.runtime_pkt_max_delay > summary_max_delay){
			summary_max_delay = sapp_global_mthread[tid].runtime_record.runtime_pkt_max_delay;
		}

		if(sapp_global_mthread[tid].runtime_record.runtime_pkt_max_delay > per_thread_max[tid]){
			per_thread_max[tid] = sapp_global_mthread[tid].runtime_record.runtime_pkt_max_delay;
		}

		/* 防止除零错误 */
		if(per_thread_pkt[tid] > 0){
			per_thread_avg[tid] = (double)per_thread_region_time_sum[tid]/(double)per_thread_pkt[tid];
		}else{
			per_thread_avg[tid] = (double)0.0;
		}
	}

	fprintf(fp,"------------------------------- pkt process delay status ----------------------------------\n");
	fprintf(fp,"Implication: \n\t10000, 40000, 70000 is CPU-Cycle range, the value below this is packet number.\n\tAVG, MAX is CPU-Cycle statistics of processed packet.\n");
	fprintf(fp,"---------------------------------------- summary ------------------------------------------\n");
	
	ret = snprintf(log_out_buf + offset, left_len, "%6s ", "range");
	offset += ret;
	left_len -= ret;

	for(i = 0; i < TIMESTAMP_SINGLE_PKT_REGION; i++){
		ret = snprintf(log_out_buf + offset, left_len, "%12lld ", g_timestamp_record_benchmark[i]);
		left_len -= ret;
		offset += ret;
	}
	
	ret = snprintf(log_out_buf + offset, left_len, "%12s ", "more");
	left_len -= ret;
	offset += ret;
	
	ret = snprintf(log_out_buf + offset, left_len, "%9s %9s", "AVG", "MAX");
	left_len -= ret;
	offset += ret;	
	fprintf(fp, "%s\n", log_out_buf);

	ret = 0;
	offset = 0;
	left_len = 1024;

	ret = snprintf(log_out_buf + offset, left_len, "%6s ", "number");
	offset += ret;
	left_len -= ret;
	
	for(i = 0; i < TIMESTAMP_SINGLE_PKT_REGION_MAX; i++){
		ret = snprintf(log_out_buf + offset, left_len, "%12lld ", per_region_pkt[i]);
		left_len -= ret;
		offset += ret;
	}
	if(summary_total_pkt > 0){/* 防止除零错误 */
		ret = snprintf(log_out_buf + offset, left_len, "%9.1f %9llu",  (double)summary_tot_time/(double)summary_total_pkt, summary_max_delay);
		//sapp_statsd_add_para("runtime", (unsigned long long)((double)summary_tot_time/(double)summary_total_pkt));
	}else{
		ret = snprintf(log_out_buf + offset, left_len, "%9.1f %9llu",  (double)0, summary_max_delay);
		//sapp_statsd_add_para("runtime", 0);
	}
	left_len -= ret;
	offset += ret;		
	fprintf(fp, "%s\n", log_out_buf);


	fprintf(fp,"--------------------------------------- per-thread ----------------------------------------\n");	
	for(tid = 0; tid < g_packet_io_thread_num; tid++){
		ret = 0;
		offset = 0;
		left_len = 1024;	
		ret = snprintf(log_out_buf + offset, left_len, "%6d ", tid);
		offset += ret;
		left_len -= ret;
		for(region_index = 0; region_index < TIMESTAMP_SINGLE_PKT_REGION_MAX; region_index++){
			ret = snprintf(log_out_buf + offset, left_len, "%12lld ", per_thread_region_pkt_sum[region_index][tid]);
			left_len -= ret;
			offset += ret;
		}
		ret = snprintf(log_out_buf + offset, left_len, "%9.1f %9lld", per_thread_avg[tid], per_thread_max[tid]);
		offset += ret;
		left_len -= ret;

		fprintf(fp, "%s\n", log_out_buf);
	}

	fclose(fp);

	return;
}

static  long show_timestamp_summary_cb(iknow_handle ihandle, iknow_conn iconn, const void *cb_arg, const char *user_cmd_args)
{
#if 0
	int tid, region_index;
	long long local_region_sum[TIMESTAMP_SINGLE_PKT_REGION];
	char iknow_out_buf[1024];
	int i, ret = 0, left_len = 1024;

	memset(local_region_sum, 0, sizeof(long long) * TIMESTAMP_SINGLE_PKT_REGION);

	/* 多线程计数求和 */
	for(tid = 0; tid < g_packet_io_thread_num; tid++){
		for(region_index = 0; region_index < TIMESTAMP_SINGLE_PKT_REGION; region_index++){
			local_region_sum[region_index] += g_timestamp_record_region[tid].ts_region[region_index];
		}
	}

	ret = snprintf(iknow_out_buf + ret, left_len, "%8s ", "region");
	left_len -= ret;

	for(i = 0; i < TIMESTAMP_SINGLE_PKT_REGION; i++){
		ret = snprintf(iknow_out_buf + ret, left_len, "%10lld ", g_timestamp_record_benchmark[i]);
		left_len -= ret;
	}
	
	iprintf(ihandle, iconn, "%s\n", iknow_out_buf);

	ret = 0;
	left_len = 1024;
	for(i = 0; i < TIMESTAMP_SINGLE_PKT_REGION; i++){
		ret = snprintf(iknow_out_buf + ret, left_len, "%8s %10lld ", "", local_region_sum[i]);
		left_len -= ret;
	}
	iprintf(ihandle, iconn, "%s\n", iknow_out_buf);
#endif
	return;
}


int timestamp_record_init(void)
{
	int i;

	assert(TIMESTAMP_SINGLE_PKT_REGION_MAX == TIMESTAMP_SINGLE_PKT_REGION + 1);

	for(i = 0; i < TIMESTAMP_SINGLE_PKT_REGION; i++){
		g_timestamp_record_benchmark[i] = 10000 + i*30000;
	}

	//iknow_register_cmd(PLATFORM_IHANDLE, "show timestamp summary", "show timestamp summary", 
	//				  show_timestamp_summary_cb, 
	//				  NULL, 0, NULL);

	return 0;	
}

#endif


#ifdef __cplusplus
}
#endif
