#include "field_stat2.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

#define STATS_STR_LEN	(32)

volatile int update_packet_io_status_sw = 1;

static unsigned long long sysinfo_old[COUNTER_NUM] = {0};

static const unsigned long long TO_KB = 1024;
static const unsigned long long TO_MB = 0x100000ULL;
static const unsigned long long TO_GB = 0x40000000ULL;
static const unsigned long long TO_TB = 0x1000000000ULL;

static unsigned long long cur_count[SAPP_STAT_NUM_MAX] = {0};
static unsigned long long cur_length[SAPP_STAT_NUM_MAX] = {0};


//extern int g_packet_io_thread_num;
extern void sapp_statsd_add_para(const char *key, unsigned long long value);
extern void pkt_runtime_output(void);
extern void sapp_statsd_flush_buf(void);
extern struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];

/* 转换成人容易读的网络流量字符串, 如123bps, 34.5Mbps */
static char *byte_convert_human(unsigned long long bytes, int interval, int multiple, char * byte_str)
{
    bytes *= multiple; /* to network pattern, or human pattern */

    bytes /= interval; /* per second */

    if(bytes < TO_KB){
        snprintf(byte_str,STATS_STR_LEN,"%llu", bytes);
    }else if(bytes < TO_MB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fK", (float)bytes/TO_KB);
    }else if(bytes < TO_GB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fM", (float)bytes/TO_MB);
    }else if(bytes < TO_TB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fG", (float)bytes/TO_GB);
    }else{
        snprintf(byte_str,STATS_STR_LEN,"%.2fT", (double)bytes/TO_TB);	
    }

    return byte_str;
}


void line_protocol_update_metrics(void)
{
	log_line_protocol_handle_t *lp_handle;
	char metrics_buf[65000];
	int buf_len;

	if(0 == sapp_global_val->config.profiling.log.remote.enabled){
		return;
	}
	
	if(strncasecmp(sapp_global_val->config.profiling.log.remote.remote_send_out_type, "line_protocol", strlen("line_protocol")) != 0){
		return;
	}

	lp_handle = (log_line_protocol_handle_t *)sapp_global_val->individual_fixed.profiling_log_remote_handle;

	//if((sapp_global_val->individual_volatile->current_time % sapp_global_val->config.profiling.log.interval) != 0){ /* 每隔N秒发送一次 */
		//return;
	//}

	/* line_protocol的输出间隔跟sysinfo.log可能不一样, 不能用统一的瞬时值, 此处自行保存历史数值, 再用当前值相减 */
	buf_len = snprintf(metrics_buf, 65000, "protocol,flow_type=inline Eth_Pkt=%llu,Eth_Bit=%llu,Ipv4_Pkt=%llu,Ipv4_Bit=%llu,Ipv6_Pkt=%llu,Ipv6_Bit=%llu,Tcp_Pkt=%llu,Tcp_Bit=%llu,Udp_Pkt=%llu,Udp_Bit=%llu\n",
				cur_count[SAPP_STAT_RCV_ETHERNET] - lp_handle->history_count[SAPP_STAT_RCV_ETHERNET], 
				8 *( cur_length[SAPP_STAT_RCV_ETHERNET]) - 8 * lp_handle->history_length[SAPP_STAT_RCV_ETHERNET],
				cur_count[SAPP_STAT_RCV_IPV4] - lp_handle->history_count[SAPP_STAT_RCV_IPV4], 
				8 *( cur_length[SAPP_STAT_RCV_IPV4]) - 8 * lp_handle->history_length[SAPP_STAT_RCV_IPV4],
				cur_count[SAPP_STAT_RCV_IPV6] - lp_handle->history_count[SAPP_STAT_RCV_IPV6], 
				8 *( cur_length[SAPP_STAT_RCV_IPV6]) - 8 * lp_handle->history_length[SAPP_STAT_RCV_IPV6],
				cur_count[SAPP_STAT_RCV_TCP] - lp_handle->history_count[SAPP_STAT_RCV_TCP],
				8 *( cur_length[SAPP_STAT_RCV_TCP]) - 8 * lp_handle->history_length[SAPP_STAT_RCV_TCP],
				cur_count[SAPP_STAT_RCV_UDP] - lp_handle->history_count[SAPP_STAT_RCV_UDP], 
				8 *( cur_length[SAPP_STAT_RCV_UDP]) - 8 * lp_handle->history_length[SAPP_STAT_RCV_UDP]
				);
	sendto(lp_handle->sock_fd, metrics_buf, buf_len, 0, (const struct sockaddr *)&lp_handle->sock_addr, sizeof(struct sockaddr_in));			

	/*
		对于status类型的值入influxDB的说明:
			Tcp_Concurrent这类值是二次计算得到的, 表示当前时间点的瞬时值, 并没有时序特性, 
            直接写入InfluxDB, 显示时要使用MEAN, 按平均值显示即可.
	*/
	buf_len = snprintf(metrics_buf, 65000, "stream,flow_type=inline Tcp_Concurrent=%llu,Tcp_Link_New=%llu,Tcp_Link_Del=%llu,Tcp_Link_Double=%llu,Tcp_Link_C2S=%llu,Tcp_Link_S2C=%llu\n",
				cur_count[SAPP_STAT_TCP_STREAM_DATA], 
				(cur_count[SAPP_STAT_TCP_STREAM_NEW] - lp_handle->history_count[SAPP_STAT_TCP_STREAM_NEW])/sapp_global_val->config.profiling.log.interval,
				(cur_count[SAPP_STAT_TCP_STREAM_DEL] - lp_handle->history_count[SAPP_STAT_TCP_STREAM_DEL])/sapp_global_val->config.profiling.log.interval,
				(cur_count[SAPP_STAT_TCP_STREAM_DOUBLE] - lp_handle->history_count[SAPP_STAT_TCP_STREAM_DOUBLE])/sapp_global_val->config.profiling.log.interval,
				(cur_count[SAPP_STAT_TCP_STREAM_C2S] - lp_handle->history_count[SAPP_STAT_TCP_STREAM_C2S])/sapp_global_val->config.profiling.log.interval,
				(cur_count[SAPP_STAT_TCP_STREAM_S2C] - lp_handle->history_count[SAPP_STAT_TCP_STREAM_S2C])/sapp_global_val->config.profiling.log.interval
				);
	sendto(lp_handle->sock_fd, metrics_buf, buf_len, 0, (const struct sockaddr *)&lp_handle->sock_addr, sizeof(struct sockaddr_in));			
	
	memcpy(lp_handle->history_count, cur_count, sizeof(cur_count));
	memcpy(lp_handle->history_length, cur_length, sizeof(cur_length));
	
}


static void field_stat2_update_metrics(void)
{
	if((0 == sapp_global_val->config.profiling.log.local.enabled)
	  &&(strncasecmp(sapp_global_val->config.profiling.log.remote.remote_send_out_type, "field_stat2", strlen("field_stat2")) != 0)){
		return;
	}
	
    /* 2018-08-29 lijia add field statsd */
	sapp_fs2_update_count(SAPP_STAT_RCV_UNKNOWN, cur_count[SAPP_STAT_RCV_UNKNOWN]);
	sapp_fs2_update_length(SAPP_STAT_RCV_UNKNOWN, 8 *( cur_length[SAPP_STAT_RCV_UNKNOWN])); /* to bps, bit per second */
	
	sapp_fs2_update_count(SAPP_STAT_RCV_ETHERNET, cur_count[SAPP_STAT_RCV_ETHERNET]);
	sapp_fs2_update_length(SAPP_STAT_RCV_ETHERNET, 8 *( cur_length[SAPP_STAT_RCV_ETHERNET])); /* to bps, bit per second */

	if((DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin)
	 || (DEPOLYMENT_MODE_TRANSPARENT == sapp_global_val->config.packet_io.depolyment_mode_bin)){
		sapp_fs2_update_count(SAPP_STAT_ETH_INBOUND, cur_count[SAPP_STAT_ETH_INBOUND]);
		sapp_fs2_update_length(SAPP_STAT_ETH_INBOUND, 8 *( cur_length[SAPP_STAT_ETH_INBOUND])); /* to bps, bit per second */

		sapp_fs2_update_count(SAPP_STAT_ETH_OUTBOUND, cur_count[SAPP_STAT_ETH_OUTBOUND]);
		sapp_fs2_update_length(SAPP_STAT_ETH_OUTBOUND, 8 *( cur_length[SAPP_STAT_ETH_OUTBOUND])); /* to bps, bit per second */
	}
	
	sapp_fs2_update_count(SAPP_STAT_RCV_IPV4, cur_count[SAPP_STAT_RCV_IPV4]);
	sapp_fs2_update_length(SAPP_STAT_RCV_IPV4, 8 *(cur_length[SAPP_STAT_RCV_IPV4]));

	sapp_fs2_update_count(SAPP_STAT_RCV_IPV6, cur_count[SAPP_STAT_RCV_IPV6]);
	sapp_fs2_update_length(SAPP_STAT_RCV_IPV6, 8 *(cur_length[SAPP_STAT_RCV_IPV6]));

	sapp_fs2_update_count(SAPP_STAT_RCV_TCP, cur_count[SAPP_STAT_RCV_TCP]);
	sapp_fs2_update_length(SAPP_STAT_RCV_TCP, 8 *(cur_length[SAPP_STAT_RCV_TCP]));
	
	sapp_fs2_update_count(SAPP_STAT_RCV_UDP, cur_count[SAPP_STAT_RCV_UDP]);	
	sapp_fs2_update_length(SAPP_STAT_RCV_UDP, 8 *(cur_length[SAPP_STAT_RCV_UDP]));
	
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_NEW,cur_count[SAPP_STAT_TCP_STREAM_NEW]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_DEL, cur_count[SAPP_STAT_TCP_STREAM_DEL]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_DATA, cur_count[SAPP_STAT_TCP_STREAM_DATA]);

	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_DOUBLE,cur_count[SAPP_STAT_TCP_STREAM_DOUBLE]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_C2S, cur_count[SAPP_STAT_TCP_STREAM_C2S]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_S2C, cur_count[SAPP_STAT_TCP_STREAM_S2C]);

	sapp_fs2_update_count(SAPP_STAT_SND_TCP_RST,  cur_count[SAPP_STAT_SND_TCP_RST]);
	sapp_fs2_update_count(SAPP_STAT_SND_TCP_SYNACK,  cur_count[SAPP_STAT_SND_TCP_SYNACK]);
	sapp_fs2_update_count(SAPP_STAT_SND_UDP,  cur_count[SAPP_STAT_SND_UDP]);
}

void sysinfo_output(void)
{
	int i, j;
	FILE* fp;
	//unsigned long long cur_count[COUNTER_NUM] = {0};
	//static unsigned long long g_SysInputInfo_old[MAX_THREAD_NUM][COUNTER_NUM];
	char time_string[32];
	static unsigned long long history_count[SAPP_STAT_NUM_MAX];
	static unsigned long long history_length[SAPP_STAT_NUM_MAX];
	static sapp_gval_mthread_sys_stat_t history_threads_stat[SAPP_MAX_THREADS];
	
	char s1[STATS_STR_LEN], s2[STATS_STR_LEN];
	sapp_gval_mthread_t **mstat = sapp_global_val->mthread_volatile;

	if(0 == update_packet_io_status_sw){
		return;
	}
	fp = fopen("./sysinfo.log","w+");
	if(fp == NULL)
	{
		//runtime_log(RLOG_LV_FATAL,(char *)"test_dealpkt",(char *)"sysinfo.log fopen error!\n");
		return;
	}

	memset(cur_count, 0, sizeof(cur_count));
	memset(cur_length, 0, sizeof(cur_length));

	timet_to_str(ABBR_CURRENT_TIME, time_string, sizeof(time_string));

	for(i=0;i<g_packet_io_thread_num;i++){
		for(j = 0; j < SAPP_STAT_NUM_MAX; j++){
			cur_count[j] +=  mstat[i]->sys_stat.count[j];
			cur_length[j] +=  mstat[i]->sys_stat.length[j];		
		}
	}

	fprintf(fp,"\n*********************** %s *********************\n", time_string);
	fprintf(fp,"*********************** \033[41m%s\033[0m *************************\n", "sysinfo exactly");
	fprintf(fp,"%-12s %12s %12s %12s %12s\n","RCV-PKT", "total_pkt", "total_len","pps", "Bps");
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "Polling_work", 0,0,(cur_count[SAPP_POLLING_WORK]-history_count[SAPP_POLLING_WORK]),0);
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "Polling_idle", 0,0,(cur_count[SAPP_POLLING_IDLE]-history_count[SAPP_POLLING_IDLE]),0);

	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "Ethernet", cur_count[SAPP_STAT_RCV_ETHERNET],cur_length[SAPP_STAT_RCV_ETHERNET],(cur_count[SAPP_STAT_RCV_ETHERNET]-history_count[SAPP_STAT_RCV_ETHERNET]),(cur_length[SAPP_STAT_RCV_ETHERNET]-history_length[SAPP_STAT_RCV_ETHERNET]));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "IPv4", cur_count[SAPP_STAT_RCV_IPV4],cur_length[SAPP_STAT_RCV_IPV4],(cur_count[SAPP_STAT_RCV_IPV4]-history_count[SAPP_STAT_RCV_IPV4]),(cur_length[SAPP_STAT_RCV_IPV4]-history_length[SAPP_STAT_RCV_IPV4]));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n","IPv6",cur_count[SAPP_STAT_RCV_IPV6],cur_length[SAPP_STAT_RCV_IPV6],(cur_count[SAPP_STAT_RCV_IPV6]-history_count[SAPP_STAT_RCV_IPV6]),(cur_length[SAPP_STAT_RCV_IPV6]-history_length[SAPP_STAT_RCV_IPV6]));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n","TCP",cur_count[SAPP_STAT_RCV_TCP],cur_length[SAPP_STAT_RCV_TCP],(cur_count[SAPP_STAT_RCV_TCP]-history_count[SAPP_STAT_RCV_TCP]),(cur_length[SAPP_STAT_RCV_TCP]-history_length[SAPP_STAT_RCV_TCP]));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n","UDP",cur_count[SAPP_STAT_RCV_UDP],cur_length[SAPP_STAT_RCV_UDP],(cur_count[SAPP_STAT_RCV_UDP]-history_count[SAPP_STAT_RCV_UDP]),(cur_length[SAPP_STAT_RCV_UDP]-history_length[SAPP_STAT_RCV_UDP]));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n","Unknown",cur_count[SAPP_STAT_RCV_UNKNOWN],cur_length[SAPP_STAT_RCV_UNKNOWN],(cur_count[SAPP_STAT_RCV_UNKNOWN]-history_count[SAPP_STAT_RCV_UNKNOWN]),(cur_length[SAPP_STAT_RCV_UNKNOWN]-history_length[SAPP_STAT_RCV_UNKNOWN]));
	fprintf(fp,"\n***************************************************************\n");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n","SND-PKT", "total_pkt", "total_len","pps", "Bps");
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "TCP_RST", cur_count[SAPP_STAT_SND_TCP_RST],cur_length[SAPP_STAT_SND_TCP_RST],(cur_count[SAPP_STAT_SND_TCP_RST]-history_count[SAPP_STAT_SND_TCP_RST]),(cur_length[SAPP_STAT_SND_TCP_RST]-history_length[SAPP_STAT_SND_TCP_RST]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "TCP_S/A", cur_count[SAPP_STAT_SND_TCP_SYNACK],cur_length[SAPP_STAT_SND_TCP_SYNACK],(cur_count[SAPP_STAT_SND_TCP_SYNACK]-history_count[SAPP_STAT_SND_TCP_SYNACK]),(cur_length[SAPP_STAT_SND_TCP_SYNACK]-history_length[SAPP_STAT_SND_TCP_SYNACK]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "UDP", cur_count[SAPP_STAT_SND_UDP],cur_length[SAPP_STAT_SND_UDP],(cur_count[SAPP_STAT_SND_UDP]-history_count[SAPP_STAT_SND_UDP]),(cur_length[SAPP_STAT_SND_UDP]-history_length[SAPP_STAT_SND_UDP]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "SEND-ERR", cur_count[SAPP_STAT_SND_ERROR], cur_length[SAPP_STAT_SND_ERROR], (cur_count[SAPP_STAT_SND_ERROR]-history_count[SAPP_STAT_SND_ERROR]), cur_length[SAPP_STAT_SND_ERROR]-history_length[SAPP_STAT_SND_ERROR]);

	fprintf(fp,"\n%-10s %12s %12s\n", "TUNNEL", "total_pkt", "total_len");	
	fprintf(fp,"%-10s %12llu %12llu\n", "6over4", cur_count[SAPP_STAT_TUNNEL_6OVER4], cur_length[SAPP_STAT_TUNNEL_6OVER4]); 
	fprintf(fp,"%-10s %12llu %12llu\n","teredo",cur_count[SAPP_STAT_TUNNEL_TEREDO], cur_length[SAPP_STAT_TUNNEL_TEREDO]);
	fprintf(fp,"%-10s %12llu %12llu\n","GTP",cur_count[SAPP_STAT_TUNNEL_GTP], cur_length[SAPP_STAT_TUNNEL_GTP]);
	fprintf(fp,"%-10s %12llu %12llu\n","L2TP",cur_count[SAPP_STAT_TUNNEL_L2TP], cur_length[SAPP_STAT_TUNNEL_L2TP]);
	fprintf(fp,"%-10s %12llu %12llu\n","PPTP",cur_count[SAPP_STAT_TUNNEL_PPTP], cur_length[SAPP_STAT_TUNNEL_PPTP]);

	fprintf(fp,"\n%-10s %12s\n", "Drop_by_lib", "total_pkt");
	fprintf(fp,"%-10s %12ld\n", "app", packet_io_get_app_drop_num_tot());
	fprintf(fp,"%-10s %12ld\n\n", "lib", packet_io_get_lib_drop_num());
	
	fprintf(fp,"\n%12s %12s %12s\n", "Drop_by_sapp", "total_pkt", "total_len");
	fprintf(fp,"%12s %12llu %12llu\n", "ETH", cur_count[SAPP_STAT_DROP_ETHERNET], cur_length[SAPP_STAT_DROP_ETHERNET]);
	fprintf(fp,"%12s %12llu %12llu\n", "IPV4", cur_count[SAPP_STAT_DROP_IPV4], cur_length[SAPP_STAT_DROP_IPV4]);
	fprintf(fp,"%12s %12llu %12llu\n", "IPV6", cur_count[SAPP_STAT_DROP_IPV6], cur_length[SAPP_STAT_DROP_IPV6]);


	fprintf(fp,"\n------------------------------- TCP statistics detail -----------------------------\n");
	fprintf(fp,"%3s %-27s %-19s %-27s %-27s\n", "", "|-----------Current---------|", "|------Realtime-----|",
			"|--------From-of-startup---------|", "|--------Special---------|");
	fprintf(fp,"%3s %8s %9s %10s %10s %10s %10s %9s %13s %17s\n", "tid", "link-syn", "link-data", "link-nouse",
			"link-new/s", "link-del/s", "stream-num", "reset-num", "hash-list-max", "special-timeout");
	for(i = 0; i < g_packet_io_thread_num; i++){	
		fprintf(fp, "%3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13llu %13d\n",
				i, 
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_SYN], 
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DATA],
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NOUSE], 
				(mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NEW]-history_threads_stat[i].count[SAPP_STAT_TCP_STREAM_NEW]), 
				(mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DEL]-history_threads_stat[i].count[SAPP_STAT_TCP_STREAM_DEL]),
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NEW],
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DEL],
				mstat[i]->sys_stat.count[SAPP_STAT_HASH_LIST_MAX],
				sapp_global_mthread[i].tcp_stream_special_timeout_num);
	}

	fprintf(fp,"\n-------------------------- UDP statistics detail ------------------------\n");
	fprintf(fp,"%3s %-27s %-19s %-20s %-20s\n", "  ", "|-----------Current---------|", "|------Realtime-----|",
	        "|--From-of-startup--|", "|--------Special---------|");
	fprintf(fp,"%3s %8s %9s %10s %10s %10s %10s %9s %17s\n", "tid", "link-one", "link-two", "link-more", "link-new/s",
			"link-del/s", "stream-num", "reset-num", "special-timeout");
	for(i = 0; i < g_packet_io_thread_num; i++){	
		fprintf(fp, "%3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13d\n",
				i, 
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_ONE], 
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_TWO],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_MORE], 
				(mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_NEW]-history_threads_stat[i].count[SAPP_STAT_UDP_STREAM_NEW]), 
				(mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_DEL]-history_threads_stat[i].count[SAPP_STAT_UDP_STREAM_DEL]),
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_NEW],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_RESET],
				sapp_global_mthread[i].udp_stream_special_timeout_num);
	}
	
	fprintf(fp,"*****************************************************************\n\n");
	fprintf(fp,"################# \033[41m%s\033[0m --- is same as above! #########\n", "sysinfo humanly");
	fprintf(fp,"%-12s %12s %12s %12s %12s\n", "RCV-PKT", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "Polling_work", 0,0,(cur_count[SAPP_POLLING_WORK]-history_count[SAPP_POLLING_WORK]),0);
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "Polling_idle", 0,0,(cur_count[SAPP_POLLING_IDLE]-history_count[SAPP_POLLING_IDLE]),0);
	
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","Ethernet",cur_count[SAPP_STAT_RCV_ETHERNET],byte_convert_human(cur_length[SAPP_STAT_RCV_ETHERNET],1 ,1,s1),(cur_count[SAPP_STAT_RCV_ETHERNET]-history_count[SAPP_STAT_RCV_ETHERNET]),byte_convert_human((cur_length[SAPP_STAT_RCV_ETHERNET]-history_length[SAPP_STAT_RCV_ETHERNET]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","IPv4",cur_count[SAPP_STAT_RCV_IPV4],byte_convert_human(cur_length[SAPP_STAT_RCV_IPV4],1 ,1,s1),(cur_count[SAPP_STAT_RCV_IPV4]-history_count[SAPP_STAT_RCV_IPV4]),byte_convert_human((cur_length[SAPP_STAT_RCV_IPV4]-history_length[SAPP_STAT_RCV_IPV4]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","IPv6",cur_count[SAPP_STAT_RCV_IPV6],byte_convert_human(cur_length[SAPP_STAT_RCV_IPV6],1,1,s1),(cur_count[SAPP_STAT_RCV_IPV6]-history_count[SAPP_STAT_RCV_IPV6]),byte_convert_human((cur_length[SAPP_STAT_RCV_IPV6]-history_length[SAPP_STAT_RCV_IPV6]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","TCP",cur_count[SAPP_STAT_RCV_TCP],byte_convert_human(cur_length[SAPP_STAT_RCV_TCP],1,1,s1),(cur_count[SAPP_STAT_RCV_TCP]-history_count[SAPP_STAT_RCV_TCP]),byte_convert_human((cur_length[SAPP_STAT_RCV_TCP]-history_length[SAPP_STAT_RCV_TCP]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","UDP",cur_count[SAPP_STAT_RCV_UDP],byte_convert_human(cur_length[SAPP_STAT_RCV_UDP],1,1,s1),(cur_count[SAPP_STAT_RCV_UDP]-history_count[SAPP_STAT_RCV_UDP]),byte_convert_human((cur_length[SAPP_STAT_RCV_UDP]-history_length[SAPP_STAT_RCV_UDP]),1,8,s2));	
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","Unknown",cur_count[SAPP_STAT_RCV_UNKNOWN],byte_convert_human(cur_length[SAPP_STAT_RCV_UNKNOWN],1,1,s1),(cur_count[SAPP_STAT_RCV_UNKNOWN]-history_count[SAPP_STAT_RCV_UNKNOWN]),byte_convert_human((cur_length[SAPP_STAT_RCV_UNKNOWN]-history_length[SAPP_STAT_RCV_UNKNOWN]),1,8,s2));

	fprintf(fp,"#################################################################\n");
	fprintf(fp,"Network Link Quality:\n");	
	fprintf(fp,"%-12s %12s %12s %12s \n","LOST_STAT", "total", "lost", "percent");
	if((cur_length[SAPP_STAT_RCV_TCP] > 0) && (cur_length[SAPP_STAT_TCP_LOST_PKT] > 0)){
		fprintf(fp,"%-12s %12llu %12llu %2.10f\n", "bytes", cur_length[SAPP_STAT_RCV_TCP], cur_length[SAPP_STAT_TCP_LOST_PKT], (double)cur_length[SAPP_STAT_TCP_LOST_PKT]/(double)cur_length[SAPP_STAT_RCV_TCP]);
	}else{
		fprintf(fp,"%-12s %12llu %12llu %2.10f\n", "bytes", cur_length[SAPP_STAT_RCV_TCP], cur_length[SAPP_STAT_TCP_LOST_PKT], 0);
	}
	if((cur_count[SAPP_STAT_TCP_STREAM_NEW] > 0) && (cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM] > 0)){
		fprintf(fp,"%-12s %12llu %12llu %2.10f\n", "stream", cur_count[SAPP_STAT_TCP_STREAM_NEW], cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM], (double)cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]/(double)cur_count[SAPP_STAT_TCP_STREAM_NEW]);
	}else{
		fprintf(fp,"%-12s %12llu %12llu %2.10f\n", "stream", cur_count[SAPP_STAT_TCP_STREAM_NEW], cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM], 0);
	}
	
	fprintf(fp,"-----------------------------------------------------------------\n");
	fprintf(fp,"%-12s %12s %12s\n","STREAM_TYPE", "total_stream", "link_del/s");
	fprintf(fp,"%-12s %12llu %12llu\n", "TCP_DOU", cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE] - history_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE]);
	fprintf(fp,"%-12s %12llu %12llu\n", "TCP_C2S", cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S] - history_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S]);
	fprintf(fp,"%-12s %12llu %12llu\n", "TCP_S2C", cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C] - history_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C]);	

	fprintf(fp,"%-12s %12llu %12llu\n", "UDP_DOU", cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE] - history_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE]);
	fprintf(fp,"%-12s %12llu %12llu\n", "UDP_C2S", cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S] - history_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S]);
	fprintf(fp,"%-12s %12llu %12llu\n", "UDP_S2C", cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C] - history_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C]);
			
	fprintf(fp,"----------------------------------------------------------------\n");		
	fprintf(fp, "The follow TCP statistics meet the conditions:(total pkt_num>=%d and byte>=%d)\n", 
				sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_pkt, 
				sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_byte);
	fprintf(fp, "The follow UDP statistics meet the conditions:(total pkt_num>=%d and byte>=%d)\n", 
				sapp_global_val->config.stream.udp.meaningful_statistics_minimum_pkt, 
				sapp_global_val->config.stream.udp.meaningful_statistics_minimum_byte);				
	fprintf(fp,"%-12s %12s %12s\n","STREAM_TYPE", "total_stream", "link_del/s");
	fprintf(fp,"%-12s %12llu %12llu\n", "TCP_DOU", cur_count[SAPP_STAT_TCP_STREAM_DOUBLE],
			cur_count[SAPP_STAT_TCP_STREAM_DOUBLE] - history_count[SAPP_STAT_TCP_STREAM_DOUBLE]);
	fprintf(fp,"%-12s %12llu %12llu\n", "TCP_C2S", cur_count[SAPP_STAT_TCP_STREAM_C2S],
			cur_count[SAPP_STAT_TCP_STREAM_C2S] - history_count[SAPP_STAT_TCP_STREAM_C2S]);
	fprintf(fp,"%-12s %12llu %12llu\n", "TCP_S2C", cur_count[SAPP_STAT_TCP_STREAM_S2C],
			cur_count[SAPP_STAT_TCP_STREAM_S2C] - history_count[SAPP_STAT_TCP_STREAM_S2C]);

	fprintf(fp,"%-12s %12llu %12llu\n", "UDP_DOU", cur_count[SAPP_STAT_UDP_STREAM_DOUBLE],
			cur_count[SAPP_STAT_UDP_STREAM_DOUBLE] - history_count[SAPP_STAT_UDP_STREAM_DOUBLE]);
	fprintf(fp,"%-12s %12llu %12llu\n", "UDP_C2S", cur_count[SAPP_STAT_UDP_STREAM_C2S],
			cur_count[SAPP_STAT_UDP_STREAM_C2S] - history_count[SAPP_STAT_UDP_STREAM_C2S]);
	fprintf(fp,"%-12s %12llu %12llu\n", "UDP_S2C", cur_count[SAPP_STAT_UDP_STREAM_S2C],
			cur_count[SAPP_STAT_UDP_STREAM_S2C] - history_count[SAPP_STAT_UDP_STREAM_S2C]);

	fprintf(fp,"#################################################################\n");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n","SND-PKT", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "TCP_RST", cur_count[SAPP_STAT_SND_TCP_RST], byte_convert_human(cur_length[SAPP_STAT_SND_TCP_RST], 1, 1, s1),(cur_count[SAPP_STAT_SND_TCP_RST]-history_count[SAPP_STAT_SND_TCP_RST]), byte_convert_human((cur_length[SAPP_STAT_SND_TCP_RST]-history_length[SAPP_STAT_SND_TCP_RST]), 1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "TCP_S/A", cur_count[SAPP_STAT_SND_TCP_SYNACK], byte_convert_human(cur_length[SAPP_STAT_SND_TCP_SYNACK], 1, 1, s1),(cur_count[SAPP_STAT_SND_TCP_SYNACK]-history_count[SAPP_STAT_SND_TCP_SYNACK]), byte_convert_human((cur_length[SAPP_STAT_SND_TCP_SYNACK]-history_length[SAPP_STAT_SND_TCP_SYNACK]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "UDP", cur_count[SAPP_STAT_SND_UDP], byte_convert_human(cur_length[SAPP_STAT_SND_UDP],1,1,s1),(cur_count[SAPP_STAT_SND_UDP]-history_count[SAPP_STAT_SND_UDP]), byte_convert_human((cur_length[SAPP_STAT_SND_UDP]-history_length[SAPP_STAT_SND_UDP]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "SEND-ERR", cur_count[SAPP_STAT_SND_ERROR], byte_convert_human(cur_length[SAPP_STAT_SND_ERROR],1,1,s1),(cur_count[SAPP_STAT_SND_ERROR]-history_count[SAPP_STAT_SND_ERROR]), byte_convert_human((cur_length[SAPP_STAT_SND_ERROR]-history_length[SAPP_STAT_SND_ERROR]),1,8,s2));

    fprintf(fp,"#################################################################\n\n");

	field_stat2_update_metrics();

	////line_protocol_update_metrics();

	//memcpy(sysinfo_old,cur_count,sizeof(unsigned long long)*COUNTER_NUM);
	///memcpy(g_SysInputInfo_old, (void *)g_SysInputInfo, sizeof(g_SysInputInfo));
	fclose(fp);
	memcpy(history_count, cur_count, sizeof(history_count));
	memcpy(history_length, cur_length, sizeof(history_length));

	for(i = 0;i < g_packet_io_thread_num;i++){
		memcpy(&history_threads_stat[i], &mstat[i]->sys_stat, sizeof(sapp_gval_mthread_sys_stat_t));
	}

	return ;
}


#ifdef __cplusplus
}
#endif

