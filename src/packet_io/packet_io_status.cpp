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

//extern int g_packet_io_thread_num;
extern void sapp_statsd_add_para(const char *key, unsigned long long value);
extern void pkt_runtime_output(void);
extern void sapp_statsd_flush_buf(void);
extern void sapp_fs2_update(int field_index, unsigned long long value);
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


void sysinfo_output(void)
{
	int i, j;
	FILE* fp;
	//unsigned long long cur_count[COUNTER_NUM] = {0};
	//static unsigned long long g_SysInputInfo_old[MAX_THREAD_NUM][COUNTER_NUM];
	unsigned long long cur_count[SAPP_STAT_NUM_MAX];
	unsigned long long cur_length[SAPP_STAT_NUM_MAX];
	static unsigned long long history_count[SAPP_STAT_NUM_MAX];
	static unsigned long long history_length[SAPP_STAT_NUM_MAX];
	static sapp_gval_mthread_sys_stat_t history_threads_stat[SAPP_MAX_THREADS];
	
	char s1[STATS_STR_LEN], s2[STATS_STR_LEN];
	sapp_gval_mthread_t *mstat = sapp_global_val->mthread_volatile;

	if(0 == update_packet_io_status_sw){
		return;
	}
	fp = fopen("./sysinfo.log","w+");
	if(fp == NULL)
	{
		//runtime_log(RLOG_LV_FATAL,(char *)"test_dealpkt",(char *)"sysinfo.log fopen error!\n");
		return;
	}

	for(i=0;i<g_packet_io_thread_num;i++){
		for(j = 0; j < SAPP_STAT_NUM_MAX; j++){
			cur_count[j] +=  mstat[i]->sys_stat.count[j];
			cur_length[j] +=  mstat[i]->sys_stat.length[j];
		}
	}

	fprintf(fp,"\n*********************** \033[41m%s\033[0m *************************\n", "sysinfo exactly");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n","RCV-PKT", "total_pkt", "total_len","pps", "Bps");
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "Ethernet", cur_count[SAPP_STAT_RCV_ETHERNET],cur_length[SAPP_STAT_RCV_ETHERNET],(cur_count[SAPP_STAT_RCV_ETHERNET]-history_count[SAPP_STAT_RCV_ETHERNET]),(cur_length[SAPP_STAT_RCV_ETHERNET]-history_length[SAPP_STAT_RCV_ETHERNET]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "IPv4", cur_count[SAPP_STAT_RCV_IPV4],cur_length[SAPP_STAT_RCV_IPV4],(cur_count[SAPP_STAT_RCV_IPV4]-history_count[SAPP_STAT_RCV_IPV4]),(cur_length[SAPP_STAT_RCV_IPV4]-history_length[SAPP_STAT_RCV_IPV4]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","IPv6",cur_count[SAPP_STAT_RCV_IPV6],cur_length[SAPP_STAT_RCV_IPV6],(cur_count[SAPP_STAT_RCV_IPV6]-history_count[SAPP_STAT_RCV_IPV6]),(cur_length[SAPP_STAT_RCV_IPV6]-history_length[SAPP_STAT_RCV_IPV6]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","TCP",cur_count[SAPP_STAT_RCV_TCP],cur_length[SAPP_STAT_RCV_TCP],(cur_count[SAPP_STAT_RCV_TCP]-history_count[SAPP_STAT_RCV_TCP]),(cur_length[SAPP_STAT_RCV_TCP]-history_length[SAPP_STAT_RCV_TCP]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","UDP",cur_count[SAPP_STAT_RCV_UDP],cur_length[SAPP_STAT_RCV_UDP],(cur_count[SAPP_STAT_RCV_UDP]-history_count[SAPP_STAT_RCV_UDP]),(cur_length[SAPP_STAT_RCV_UDP]-history_length[SAPP_STAT_RCV_UDP]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","Unknown",cur_count[SAPP_STAT_RCV_UNKNOWN],cur_length[SAPP_STAT_RCV_UNKNOWN],(cur_count[SAPP_STAT_RCV_UNKNOWN]-history_count[SAPP_STAT_RCV_UNKNOWN]),(cur_length[SAPP_STAT_RCV_UNKNOWN]-history_length[SAPP_STAT_RCV_UNKNOWN]));
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

	fprintf(fp,"\n%-10s %12s\n", "DROP", "total_pkt");
	fprintf(fp,"%-10s %12ld\n", "app", packet_io_get_app_drop_num_tot());
	fprintf(fp,"%-10s %12ld\n\n", "lib", packet_io_get_lib_drop_num());
	
#if 0	/* 20190522 lijia close */
	if(ABBR_INTERFACE_TYPE == CAP_MODEL_MARSIOV4)
	{
		fprintf(fp,"\n------------------------------- MARSIO mbuf statistics detail -----------------------------\n");
		fprintf(fp,"%3s %-27s %-19s %-27s\n", "", "|-----------Current---------|", "|------Realtime-----|", "|--------From-of-startup---------|");
		fprintf(fp,"%3s %8s %9s %10s %10s %10s %10s %9s %13s\n", "tid", "mbuf-recv", "mbuf-alloc", "mbuf-send",
				"mbuf-free",
				"mbuf-recv/s", "mbuf-alloc/s", "mbuf-send/s", "mbuf-free/s");
		for(i = 0; i < g_packet_io_thread_num; i++){
			fprintf(fp, "%3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13llu\n",
					i,
					g_SysInputInfo[i][PKT_MARSIO_RCV],
					g_SysInputInfo[i][PKT_MARSIO_MALLOC],
					g_SysInputInfo[i][PKT_MARSIO_SND],
					g_SysInputInfo[i][PKT_MARSIO_FREE],
					(g_SysInputInfo[i][PKT_MARSIO_RCV]-g_SysInputInfo_old[i][PKT_MARSIO_RCV]),
					(g_SysInputInfo[i][PKT_MARSIO_MALLOC]-g_SysInputInfo_old[i][PKT_MARSIO_MALLOC]),
					(g_SysInputInfo[i][PKT_MARSIO_SND]-g_SysInputInfo_old[i][PKT_MARSIO_SND]),
					(g_SysInputInfo[i][PKT_MARSIO_FREE]-g_SysInputInfo_old[i][PKT_MARSIO_FREE]));
		}
	}
#endif

	fprintf(fp,"\n------------------------------- TCP statistics detail -----------------------------\n");
	fprintf(fp,"%3s %-27s %-19s %-27s %-27s\n", "", "|-----------Current---------|", "|------Realtime-----|",
			"|--------From-of-startup---------|", "|--------Special---------|");
	fprintf(fp,"%3s %8s %9s %10s %10s %10s %10s %9s %13s %17s\n", "tid", "link-syn", "link-data", "link-nouse",
			"link-new/s", "link-del/s", "stream-num", "reset-num", "hash-list-max", "special-timeout");
	for(i = 0; i < g_packet_io_thread_num; i++){	
		fprintf(fp, "%3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13llu %13llu\n",
				i, 
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_SYN], 
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DATA],
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NOUSE], 
				(mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NEW]-history_threads_stat[i].count[SAPP_STAT_TCP_STREAM_NEW]), 
				(mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DEL]-history_threads_stat[i].count[[SAPP_STAT_TCP_STREAM_DEL]]),
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
		fprintf(fp, "%3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13llu\n",
				i, 
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_ONE], 
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_TWO],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_MORE], 
				(mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_NEW]-history_threads_stat[i].count[SAPP_STAT_UDP_STREAM_NEW]), 
				(mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_DEL]-history_threads_stat[i].count[[SAPP_STAT_UDP_STREAM_DEL]]),
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_NEW],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_RESET],
				sapp_global_mthread[i].udp_stream_special_timeout_num);
	}
	
	fprintf(fp,"*****************************************************************\n\n");
	fprintf(fp,"################# \033[41m%s\033[0m --- is same as above! #########\n", "sysinfo humanly");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n", "RCV-PKT", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","Ethernet",cur_count[PKT_ETHERNET],byte_convert_human(cur_count[PKT_ETHERNET_LEN],1 ,1,s1),(cur_count[PKT_ETHERNET]-sysinfo_old[PKT_ETHERNET]),byte_convert_human((cur_count[PKT_ETHERNET_LEN]-sysinfo_old[PKT_ETHERNET_LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","IPv4",cur_count[PKT_IP],byte_convert_human(cur_count[PKT_IPLEN],1 ,1,s1),(cur_count[PKT_IP]-sysinfo_old[PKT_IP]),byte_convert_human((cur_count[PKT_IPLEN]-sysinfo_old[PKT_IPLEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","IPv6",cur_count[PKT_IPV6],byte_convert_human(cur_count[PKT_IPV6LEN],1,1,s1),(cur_count[PKT_IPV6]-sysinfo_old[PKT_IPV6]),byte_convert_human((cur_count[PKT_IPV6LEN]-sysinfo_old[PKT_IPV6LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","TCP",cur_count[PKT_TCP],byte_convert_human(cur_count[PKT_TCPLEN],1,1,s1),(cur_count[PKT_TCP]-sysinfo_old[PKT_TCP]),byte_convert_human((cur_count[PKT_TCPLEN]-sysinfo_old[PKT_TCPLEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","UDP",cur_count[PKT_UDP],byte_convert_human(cur_count[PKT_UDPLEN],1,1,s1),(cur_count[PKT_UDP]-sysinfo_old[PKT_UDP]),byte_convert_human((cur_count[PKT_UDPLEN]-sysinfo_old[PKT_UDPLEN]),1,8,s2));	
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","Unknown",cur_count[PKT_UNKNOWN],byte_convert_human(cur_count[PKT_UNKNOWN_LEN],1,1,s1),(cur_count[PKT_UNKNOWN]-sysinfo_old[PKT_UNKNOWN]),byte_convert_human((cur_count[PKT_UNKNOWN_LEN]-sysinfo_old[PKT_UNKNOWN_LEN]),1,8,s2));

	fprintf(fp,"#################################################################\n");

	fprintf(fp,"%-10s %12s %12s\n","TCP_LINK", "total_link", "link/s");
	//fprintf(fp,"%-10s %12llu %12llu\n", "TCP_NEW", cur_count[SYS_TCP_LINK_NEW],cur_count[SYS_TCP_LINK_NEW] - sysinfo_old[SYS_TCP_LINK_NEW]);
	//fprintf(fp,"%-10s %12llu %12llu\n", "TCP_DATA", cur_count[SYS_TCP_LINK_DATA],cur_count[SYS_TCP_LINK_DATA] - sysinfo_old[SYS_TCP_LINK_DATA]);
	///fprintf(fp,"%-10s %12llu %12llu\n", "TCP_DEL", cur_count[SYS_TCP_LINK_DEL],cur_count[SYS_TCP_LINK_DEL] - sysinfo_old[SYS_TCP_LINK_DEL]);
	fprintf(fp,"%-10s %12llu %12llu\n", "TCP_DOU", cur_count[LINK_DOUBLE],
			cur_count[LINK_DOUBLE] - sysinfo_old[LINK_DOUBLE]);
	fprintf(fp,"%-10s %12llu %12llu\n", "TCP_C2S", cur_count[LINK_SINGLE_C2S],
			cur_count[LINK_SINGLE_C2S] - sysinfo_old[LINK_SINGLE_C2S]);
	fprintf(fp,"%-10s %12llu %12llu\n", "TCP_S2C", cur_count[LINK_SINGLE_S2C],
			cur_count[LINK_SINGLE_S2C] - sysinfo_old[LINK_SINGLE_S2C]);

	fprintf(fp,"#################################################################\n");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n","SND-PKT", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "TCP_RST", cur_count[SEND_TCP_RST], byte_convert_human(cur_count[SEND_TCP_RST_LEN], 1, 1, s1),(cur_count[SEND_TCP_RST]-sysinfo_old[SEND_TCP_RST]), byte_convert_human((cur_count[SEND_TCP_RST_LEN]-sysinfo_old[SEND_TCP_RST_LEN]), 1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "TCP_S/A", cur_count[SEND_TCP_SYN_ACK], byte_convert_human(cur_count[SEND_TCP_SYN_ACK_LEN], 1, 1, s1),(cur_count[SEND_TCP_SYN_ACK]-sysinfo_old[SEND_TCP_SYN_ACK]), byte_convert_human((cur_count[SEND_TCP_SYN_ACK_LEN]-sysinfo_old[SEND_TCP_SYN_ACK_LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "UDP", cur_count[SEND_UDP_PKT], byte_convert_human(cur_count[SEND_UDP_PKT_LEN],1,1,s1),(cur_count[SEND_UDP_PKT]-sysinfo_old[SEND_UDP_PKT]), byte_convert_human((cur_count[SEND_UDP_PKT_LEN]-sysinfo_old[SEND_UDP_PKT_LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "SEND-ERR", cur_count[SEND_PKT_ERR], byte_convert_human(cur_count[SEND_PKT_ERR_LEN],1,1,s1),(cur_count[SEND_PKT_ERR]-sysinfo_old[SEND_PKT_ERR]), byte_convert_human((cur_count[SEND_PKT_ERR_LEN]-sysinfo_old[SEND_PKT_ERR_LEN]),1,8,s2));

    fprintf(fp,"#################################################################\n\n");


    /* 2018-08-29 lijia add field statsd */
#if 0	
	sapp_statsd_add_para("Ethernet_pps", cur_count[PKT_ETHERNET]-sysinfo_old[PKT_ETHERNET]);
	sapp_statsd_add_para("Ethernet_bps", 8 *( cur_count[PKT_ETHERNET_LEN]-sysinfo_old[PKT_ETHERNET_LEN]));
	
	sapp_statsd_add_para("IPv4_pps", cur_count[PKT_IP]-sysinfo_old[PKT_IP]);
	sapp_statsd_add_para("IPv4_bps", 8 *(cur_count[PKT_IPLEN]-sysinfo_old[PKT_IPLEN]));

	sapp_statsd_add_para("IPv6_pps", cur_count[PKT_IPV6]-sysinfo_old[PKT_IPV6]);
	sapp_statsd_add_para("IPv6_bps", 8 *(cur_count[PKT_IPV6LEN]-sysinfo_old[PKT_IPV6LEN]));

	sapp_statsd_add_para("TCP_pps", cur_count[PKT_TCP]-sysinfo_old[PKT_TCP]);
	sapp_statsd_add_para("TCP_bps", 8 *(cur_count[PKT_TCPLEN]-sysinfo_old[PKT_TCPLEN]));
	sapp_statsd_add_para("UDP_pps", cur_count[PKT_UDP]-sysinfo_old[PKT_UDP]);	
	sapp_statsd_add_para("UDP_bps", 8 *(cur_count[PKT_UDPLEN]-sysinfo_old[PKT_UDPLEN]));
	
	sapp_statsd_add_para("TCP_LINK_NEW",cur_count[SYS_TCP_LINK_NEW]-sysinfo_old[SYS_TCP_LINK_NEW]);
	sapp_statsd_add_para("TCP_LINK_DEL", cur_count[SYS_TCP_LINK_DEL]-sysinfo_old[SYS_TCP_LINK_DEL]);

	sapp_statsd_add_para("TCP_RST_SEND",  cur_count[SEND_TCP_RST]-sysinfo_old[SEND_TCP_RST]);
	sapp_statsd_add_para("TCP_S/A_SEND",  cur_count[SEND_TCP_SYN_ACK]-sysinfo_old[SEND_TCP_SYN_ACK]);
	sapp_statsd_add_para("UDP_SEND",  cur_count[SEND_UDP_PKT]-sysinfo_old[SEND_UDP_PKT]);

	sapp_statsd_flush_buf(); /* statsd输出, 最后无论缓存是否满, 强制刷新一次 */
#elif 0
	sapp_fs2_update(PKT_ETHERNET, cur_count[PKT_ETHERNET]-sysinfo_old[PKT_ETHERNET]);
	sapp_fs2_update(PKT_ETHERNET_LEN, 8 *( cur_count[PKT_ETHERNET_LEN]-sysinfo_old[PKT_ETHERNET_LEN]));
	
	sapp_fs2_update(PKT_IP, cur_count[PKT_IP]-sysinfo_old[PKT_IP]);
	sapp_fs2_update(PKT_IPLEN, 8 *(cur_count[PKT_IPLEN]-sysinfo_old[PKT_IPLEN]));

	sapp_fs2_update(PKT_IPV6, cur_count[PKT_IPV6]-sysinfo_old[PKT_IPV6]);
	sapp_fs2_update(PKT_IPV6LEN, 8 *(cur_count[PKT_IPV6LEN]-sysinfo_old[PKT_IPV6LEN]));

	sapp_fs2_update(PKT_TCP, cur_count[PKT_TCP]-sysinfo_old[PKT_TCP]);
	sapp_fs2_update(PKT_TCPLEN, 8 *(cur_count[PKT_TCPLEN]-sysinfo_old[PKT_TCPLEN]));
	sapp_fs2_update(PKT_UDP, cur_count[PKT_UDP]-sysinfo_old[PKT_UDP]);	
	sapp_fs2_update(PKT_UDPLEN, 8 *(cur_count[PKT_UDPLEN]-sysinfo_old[PKT_UDPLEN]));
	
	sapp_fs2_update(SYS_TCP_LINK_NEW,cur_count[SYS_TCP_LINK_NEW]-sysinfo_old[SYS_TCP_LINK_NEW]);
	sapp_fs2_update(SYS_TCP_LINK_DEL, cur_count[SYS_TCP_LINK_DEL]-sysinfo_old[SYS_TCP_LINK_DEL]);

	sapp_fs2_update(SEND_TCP_RST,  cur_count[SEND_TCP_RST]-sysinfo_old[SEND_TCP_RST]);
	sapp_fs2_update(SEND_TCP_SYN_ACK,  cur_count[SEND_TCP_SYN_ACK]-sysinfo_old[SEND_TCP_SYN_ACK]);
	sapp_fs2_update(SEND_UDP_PKT,  cur_count[SEND_UDP_PKT]-sysinfo_old[SEND_UDP_PKT]);
#else
	sapp_fs2_update(PKT_ETHERNET, cur_count[PKT_ETHERNET]);
	sapp_fs2_update(PKT_ETHERNET_LEN, 8 *( cur_count[PKT_ETHERNET_LEN]));
	
	sapp_fs2_update(PKT_IP, cur_count[PKT_IP]);
	sapp_fs2_update(PKT_IPLEN, 8 *(cur_count[PKT_IPLEN]));

	sapp_fs2_update(PKT_IPV6, cur_count[PKT_IPV6]);
	sapp_fs2_update(PKT_IPV6LEN, 8 *(cur_count[PKT_IPV6LEN]));

	sapp_fs2_update(PKT_TCP, cur_count[PKT_TCP]);
	sapp_fs2_update(PKT_TCPLEN, 8 *(cur_count[PKT_TCPLEN]));
	sapp_fs2_update(PKT_UDP, cur_count[PKT_UDP]);	
	sapp_fs2_update(PKT_UDPLEN, 8 *(cur_count[PKT_UDPLEN]));
	
	sapp_fs2_update(SYS_TCP_LINK_NEW,cur_count[SYS_TCP_LINK_NEW]);
	sapp_fs2_update(SYS_TCP_LINK_DEL, cur_count[SYS_TCP_LINK_DEL]);
	sapp_fs2_update(SYS_TCP_LINK_DATA, cur_count[SYS_TCP_LINK_DATA]);

	sapp_fs2_update(LINK_DOUBLE,cur_count[LINK_DOUBLE]);
	sapp_fs2_update(LINK_SINGLE_C2S, cur_count[LINK_SINGLE_C2S]);
	sapp_fs2_update(LINK_SINGLE_S2C, cur_count[LINK_SINGLE_S2C]);

	sapp_fs2_update(SEND_TCP_RST,  cur_count[SEND_TCP_RST]);
	sapp_fs2_update(SEND_TCP_SYN_ACK,  cur_count[SEND_TCP_SYN_ACK]);
	sapp_fs2_update(SEND_UDP_PKT,  cur_count[SEND_UDP_PKT]);
#endif

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

