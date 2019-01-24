#include "field_stat2.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "dealpkt.h"
#include "packet_io.h"
#include "packet_io_internal.h"
#include "stream_manage.h"
#include "mesa_net.h"
#include "sysinfo.h"
#include "logger.h"
#include <assert.h>

#define STATS_STR_LEN	(32)

volatile int update_packet_io_status_sw = 1;

static unsigned long long sysinfo_old[COUNTER_NUM] = {0};
static unsigned long long TO_KB = 1024;
static unsigned long long TO_MB = 1024 * 1024;
static unsigned long long TO_GB = 1024 * 1024 * 1024UL;
static unsigned long long TO_TB;

extern int g_packet_io_thread_num;
extern void sapp_statsd_add_para(const char *key, unsigned long long value);
extern void pkt_runtime_output(void);
extern void sapp_statsd_flush_buf(void);
extern void sapp_fs2_update(int field_index, unsigned long long value);
extern int top_mode;
extern int cap_mode;
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
	unsigned long long sysinfo_new[COUNTER_NUM] = {0};
	static unsigned long long g_SysInputInfo_old[MAX_THREAD_NUM][COUNTER_NUM];
	char s1[STATS_STR_LEN], s2[STATS_STR_LEN];

	if(0 == update_packet_io_status_sw){
		return;
	}

	for(i=0;i<g_packet_io_thread_num;i++)
	{
#if 0	
		sysinfo_new[PKT_ETHERNET]  += g_SysInputInfo[i][PKT_ETHERNET];
		sysinfo_new[PKT_ETHERNET_LEN]  += g_SysInputInfo[i][PKT_ETHERNET_LEN];
		sysinfo_new[PKT_IP]  += g_SysInputInfo[i][PKT_IP];
		sysinfo_new[PKT_IPLEN]  += g_SysInputInfo[i][PKT_IPLEN];
		sysinfo_new[PKT_IPV6]  += g_SysInputInfo[i][PKT_IPV6];
		sysinfo_new[PKT_IPV6LEN]  += g_SysInputInfo[i][PKT_IPV6LEN];
		sysinfo_new[PKT_TCP]  += g_SysInputInfo[i][PKT_TCP];
		sysinfo_new[PKT_TCPLEN]  += g_SysInputInfo[i][PKT_TCPLEN];
		sysinfo_new[PKT_UDP]  += g_SysInputInfo[i][PKT_UDP];
		sysinfo_new[PKT_UDPLEN]  += g_SysInputInfo[i][PKT_UDPLEN];
		sysinfo_new[PKT_UNKNOWN]  += g_SysInputInfo[i][PKT_UNKNOWN];
		sysinfo_new[PKT_UNKNOWN_LEN]  += g_SysInputInfo[i][PKT_UNKNOWN_LEN];

		sysinfo_new[SYS_TCP_LINK_NEW] +=  g_SysInputInfo[i][SYS_TCP_LINK_NEW];
		sysinfo_new[SYS_TCP_LINK_DEL] +=  g_SysInputInfo[i][SYS_TCP_LINK_DEL];
		sysinfo_new[SYS_TCP_LINK_DATA] += g_SysInputInfo[i][SYS_TCP_LINK_DATA];

		sysinfo_new[TCPV4_LINK_TOTAL]  += g_SysInputInfo[i][TCPV4_LINK_TOTAL];
		sysinfo_new[TCPV4_LINK_NEW_CREATE] += g_SysInputInfo[i][TCPV4_LINK_NEW_CREATE];
		sysinfo_new[TCPV4_LINK_CLOSE] += g_SysInputInfo[i][TCPV4_LINK_CLOSE];

		sysinfo_new[TCPV6_LINK_TOTAL]  +=  g_SysInputInfo[i][TCPV6_LINK_TOTAL];
		sysinfo_new[TCPV6_LINK_NEW_CREATE] += g_SysInputInfo[i][TCPV6_LINK_NEW_CREATE];
		sysinfo_new[TCPV6_LINK_CLOSE] += g_SysInputInfo[i][TCPV6_LINK_CLOSE];
		
		sysinfo_new[UDPV4_LINK_TOTAL]  += g_SysInputInfo[i][UDPV4_LINK_TOTAL];;
		sysinfo_new[UDPV4_LINK_NEW_CREATE] += g_SysInputInfo[i][UDPV4_LINK_NEW_CREATE];
		sysinfo_new[UDPV4_LINK_CLOSE] += g_SysInputInfo[i][UDPV4_LINK_CLOSE];		

		sysinfo_new[UDPV6_LINK_TOTAL]  += g_SysInputInfo[i][UDPV6_LINK_TOTAL];;
		sysinfo_new[UDPV6_LINK_NEW_CREATE] += g_SysInputInfo[i][UDPV6_LINK_NEW_CREATE];
		sysinfo_new[UDPV6_LINK_CLOSE] += g_SysInputInfo[i][UDPV6_LINK_CLOSE];	

		sysinfo_new[TUNNEL_6OVER4] += g_SysInputInfo[i][TUNNEL_6OVER4];
		sysinfo_new[TUNNEL_6OVER4_LEN] += g_SysInputInfo[i][TUNNEL_6OVER4_LEN];
		sysinfo_new[TUNNEL_TEREDO] += g_SysInputInfo[i][TUNNEL_TEREDO];
		sysinfo_new[TUNNEL_TEREDO_LEN] += g_SysInputInfo[i][TUNNEL_TEREDO_LEN];

		sysinfo_new[TUNNEL_GTP] += g_SysInputInfo[i][TUNNEL_GTP];

		sysinfo_new[SEND_TCP_RST] += g_SysInputInfo[i][SEND_TCP_RST];
		sysinfo_new[SEND_TCP_RST_LEN] += g_SysInputInfo[i][SEND_TCP_RST_LEN];

		sysinfo_new[SEND_TCP_SYN_ACK] += g_SysInputInfo[i][SEND_TCP_SYN_ACK];
		sysinfo_new[SEND_TCP_SYN_ACK_LEN] += g_SysInputInfo[i][SEND_TCP_SYN_ACK_LEN];

		sysinfo_new[SEND_UDP_PKT] += g_SysInputInfo[i][SEND_UDP_PKT];
		sysinfo_new[SEND_UDP_PKT_LEN] += g_SysInputInfo[i][SEND_UDP_PKT_LEN];	

		sysinfo_new[SEND_PKT_ERR] += g_SysInputInfo[i][SEND_PKT_ERR];
		sysinfo_new[SEND_PKT_ERR_LEN] += g_SysInputInfo[i][SEND_PKT_ERR_LEN];	
#else
		for(j = 0; j < COUNTER_NUM; j++){
			sysinfo_new[j] +=  g_SysInputInfo[i][j];	
		}
#endif
	}

	fp = fopen("./sysinfo.log","w+");
	if(fp == NULL)
	{
		//runtime_log(RLOG_LV_FATAL,(char *)"test_dealpkt",(char *)"sysinfo.log fopen error!\n");
		return;
	}

	fprintf(fp,"\n*********************** \033[41m%s\033[0m *************************\n", "sysinfo exactly");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n","RCV-PKT", "total_pkt", "total_len","pps", "Bps");
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "Ethernet", sysinfo_new[PKT_ETHERNET],sysinfo_new[PKT_ETHERNET_LEN],(sysinfo_new[PKT_ETHERNET]-sysinfo_old[PKT_ETHERNET]),(sysinfo_new[PKT_ETHERNET_LEN]-sysinfo_old[PKT_ETHERNET_LEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "IPv4", sysinfo_new[PKT_IP],sysinfo_new[PKT_IPLEN],(sysinfo_new[PKT_IP]-sysinfo_old[PKT_IP]),(sysinfo_new[PKT_IPLEN]-sysinfo_old[PKT_IPLEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","IPv6",sysinfo_new[PKT_IPV6],sysinfo_new[PKT_IPV6LEN],(sysinfo_new[PKT_IPV6]-sysinfo_old[PKT_IPV6]),(sysinfo_new[PKT_IPV6LEN]-sysinfo_old[PKT_IPV6LEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","TCP",sysinfo_new[PKT_TCP],sysinfo_new[PKT_TCPLEN],(sysinfo_new[PKT_TCP]-sysinfo_old[PKT_TCP]),(sysinfo_new[PKT_TCPLEN]-sysinfo_old[PKT_TCPLEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","UDP",sysinfo_new[PKT_UDP],sysinfo_new[PKT_UDPLEN],(sysinfo_new[PKT_UDP]-sysinfo_old[PKT_UDP]),(sysinfo_new[PKT_UDPLEN]-sysinfo_old[PKT_UDPLEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n","Unknown",sysinfo_new[PKT_UNKNOWN],sysinfo_new[PKT_UNKNOWN_LEN],(sysinfo_new[PKT_UNKNOWN]-sysinfo_old[PKT_UNKNOWN]),(sysinfo_new[PKT_UNKNOWN_LEN]-sysinfo_old[PKT_UNKNOWN_LEN]));
	fprintf(fp,"\n***************************************************************\n");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n","SND-PKT", "total_pkt", "total_len","pps", "Bps");
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "TCP_RST", sysinfo_new[SEND_TCP_RST],sysinfo_new[SEND_TCP_RST_LEN],(sysinfo_new[SEND_TCP_RST]-sysinfo_old[SEND_TCP_RST]),(sysinfo_new[SEND_TCP_RST_LEN]-sysinfo_old[SEND_TCP_RST_LEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "TCP_S/A", sysinfo_new[SEND_TCP_SYN_ACK],sysinfo_new[SEND_TCP_SYN_ACK_LEN],(sysinfo_new[SEND_TCP_SYN_ACK]-sysinfo_old[SEND_TCP_SYN_ACK]),(sysinfo_new[SEND_TCP_SYN_ACK_LEN]-sysinfo_old[SEND_TCP_SYN_ACK_LEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "UDP", sysinfo_new[SEND_UDP_PKT],sysinfo_new[SEND_UDP_PKT_LEN],(sysinfo_new[SEND_UDP_PKT]-sysinfo_old[SEND_UDP_PKT]),(sysinfo_new[SEND_UDP_PKT_LEN]-sysinfo_old[SEND_UDP_PKT_LEN]));
	fprintf(fp,"%-10s %12llu %12llu %12llu %12llu\n", "SEND-ERR", sysinfo_new[SEND_PKT_ERR], sysinfo_new[SEND_PKT_ERR_LEN], (sysinfo_new[SEND_PKT_ERR]-sysinfo_old[SEND_PKT_ERR]), sysinfo_new[SEND_PKT_ERR_LEN]-sysinfo_old[SEND_PKT_ERR_LEN]);

	fprintf(fp,"\n%-10s %12s %12s\n", "TUNNEL", "total_pkt", "total_len");	
	fprintf(fp,"%-10s %12llu %12llu\n", "6over4", sysinfo_new[TUNNEL_6OVER4], sysinfo_new[TUNNEL_6OVER4_LEN]); 
	fprintf(fp,"%-10s %12llu %12llu\n","teredo",sysinfo_new[TUNNEL_TEREDO], sysinfo_new[TUNNEL_TEREDO_LEN]);
	fprintf(fp,"%-10s %12llu %12llu\n","GTP",sysinfo_new[TUNNEL_GTP], 0LLU);


	fprintf(fp,"\n%-10s %12s\n", "DROP", "total_pkt");
	fprintf(fp,"%-10s %12ld\n", "app", packet_io_get_app_drop_num_tot());
	fprintf(fp,"%-10s %12ld\n\n", "lib", packet_io_get_lib_drop_num());

	if(cap_mode == CAP_MODEL_MARSIOV4)
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

	fprintf(fp,"\n------------------------------- TCP statistics detail -----------------------------\n");
	fprintf(fp,"%3s %-27s %-19s %-27s\n", "", "|-----------Current---------|", "|------Realtime-----|", "|--------From-of-startup---------|");
	fprintf(fp,"%3s %8s %9s %10s %10s %10s %10s %9s %13s\n", "tid", "link-syn", "link-data", "link-nouse", "link-new/s", "link-del/s", "stream-num", "reset-num", "hash-list-max");
	for(i = 0; i < g_packet_io_thread_num; i++){	
		fprintf(fp, "%3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13llu\n", 
				i, 
				g_SysInputInfo[i][SYS_TCP_LINK_SYN], 
				g_SysInputInfo[i][SYS_TCP_LINK_DATA],
				g_SysInputInfo[i][SYS_TCP_LINK_NOUSE], 
				(g_SysInputInfo[i][SYS_TCP_LINK_NEW]-g_SysInputInfo_old[i][SYS_TCP_LINK_NEW]), 
				(g_SysInputInfo[i][SYS_TCP_LINK_DEL]-g_SysInputInfo_old[i][SYS_TCP_LINK_DEL]),
				g_SysInputInfo[i][SYS_TCP_LINK_NEW],
				g_SysInputInfo[i][SYS_TCP_LINK_RESET],
				g_SysInputInfo[i][SYS_HASH_LIST_MAX]);
	}

	fprintf(fp,"\n-------------------------- UDP statistics detail ------------------------\n");
	fprintf(fp,"%3s %-27s %-19s %-20s\n", "  ", "|-----------Current---------|", "|------Realtime-----|", "|--From-of-startup--|");
	fprintf(fp,"%3s %8s %9s %10s %10s %10s %10s %9s\n", "tid", "link-one", "link-two", "link-more", "link-new/s", "link-del/s", "stream-num", "reset-num");
	for(i = 0; i < g_packet_io_thread_num; i++){	
		fprintf(fp, "%3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu\n", 
				i, 
				g_SysInputInfo[i][SYS_UDP_LINK_ONE], 
				g_SysInputInfo[i][SYS_UDP_LINK_TWO],
				g_SysInputInfo[i][SYS_UDP_LINK_MORE], 
				(g_SysInputInfo[i][SYS_UDP_LINK_NEW]-g_SysInputInfo_old[i][SYS_UDP_LINK_NEW]), 
				(g_SysInputInfo[i][SYS_UDP_LINK_DEL]-g_SysInputInfo_old[i][SYS_UDP_LINK_DEL]),
				g_SysInputInfo[i][SYS_UDP_LINK_NEW],
				g_SysInputInfo[i][SYS_UDP_LINK_RESET]);
	}
	
	fprintf(fp,"*****************************************************************\n\n");
	fprintf(fp,"################# \033[41m%s\033[0m --- is same as above! #########\n", "sysinfo humanly");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n", "RCV-PKT", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","Ethernet",sysinfo_new[PKT_ETHERNET],byte_convert_human(sysinfo_new[PKT_ETHERNET_LEN],1 ,1,s1),(sysinfo_new[PKT_ETHERNET]-sysinfo_old[PKT_ETHERNET]),byte_convert_human((sysinfo_new[PKT_ETHERNET_LEN]-sysinfo_old[PKT_ETHERNET_LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","IPv4",sysinfo_new[PKT_IP],byte_convert_human(sysinfo_new[PKT_IPLEN],1 ,1,s1),(sysinfo_new[PKT_IP]-sysinfo_old[PKT_IP]),byte_convert_human((sysinfo_new[PKT_IPLEN]-sysinfo_old[PKT_IPLEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","IPv6",sysinfo_new[PKT_IPV6],byte_convert_human(sysinfo_new[PKT_IPV6LEN],1,1,s1),(sysinfo_new[PKT_IPV6]-sysinfo_old[PKT_IPV6]),byte_convert_human((sysinfo_new[PKT_IPV6LEN]-sysinfo_old[PKT_IPV6LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","TCP",sysinfo_new[PKT_TCP],byte_convert_human(sysinfo_new[PKT_TCPLEN],1,1,s1),(sysinfo_new[PKT_TCP]-sysinfo_old[PKT_TCP]),byte_convert_human((sysinfo_new[PKT_TCPLEN]-sysinfo_old[PKT_TCPLEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","UDP",sysinfo_new[PKT_UDP],byte_convert_human(sysinfo_new[PKT_UDPLEN],1,1,s1),(sysinfo_new[PKT_UDP]-sysinfo_old[PKT_UDP]),byte_convert_human((sysinfo_new[PKT_UDPLEN]-sysinfo_old[PKT_UDPLEN]),1,8,s2));	
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n","Unknown",sysinfo_new[PKT_UNKNOWN],byte_convert_human(sysinfo_new[PKT_UNKNOWN_LEN],1,1,s1),(sysinfo_new[PKT_UNKNOWN]-sysinfo_old[PKT_UNKNOWN]),byte_convert_human((sysinfo_new[PKT_UNKNOWN_LEN]-sysinfo_old[PKT_UNKNOWN_LEN]),1,8,s2));
	fprintf(fp,"#################################################################\n");
	fprintf(fp,"%-10s %12s %12s %12s %12s\n","SND-PKT", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "TCP_RST", sysinfo_new[SEND_TCP_RST], byte_convert_human(sysinfo_new[SEND_TCP_RST_LEN], 1, 1, s1),(sysinfo_new[SEND_TCP_RST]-sysinfo_old[SEND_TCP_RST]), byte_convert_human((sysinfo_new[SEND_TCP_RST_LEN]-sysinfo_old[SEND_TCP_RST_LEN]), 1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "TCP_S/A", sysinfo_new[SEND_TCP_SYN_ACK], byte_convert_human(sysinfo_new[SEND_TCP_SYN_ACK_LEN], 1, 1, s1),(sysinfo_new[SEND_TCP_SYN_ACK]-sysinfo_old[SEND_TCP_SYN_ACK]), byte_convert_human((sysinfo_new[SEND_TCP_SYN_ACK_LEN]-sysinfo_old[SEND_TCP_SYN_ACK_LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "UDP", sysinfo_new[SEND_UDP_PKT], byte_convert_human(sysinfo_new[SEND_UDP_PKT_LEN],1,1,s1),(sysinfo_new[SEND_UDP_PKT]-sysinfo_old[SEND_UDP_PKT]), byte_convert_human((sysinfo_new[SEND_UDP_PKT_LEN]-sysinfo_old[SEND_UDP_PKT_LEN]),1,8,s2));
	fprintf(fp,"%-10s %12llu %12s %12llu %12s\n", "SEND-ERR", sysinfo_new[SEND_PKT_ERR], byte_convert_human(sysinfo_new[SEND_PKT_ERR_LEN],1,1,s1),(sysinfo_new[SEND_PKT_ERR]-sysinfo_old[SEND_PKT_ERR]), byte_convert_human((sysinfo_new[SEND_PKT_ERR_LEN]-sysinfo_old[SEND_PKT_ERR_LEN]),1,8,s2));

	fprintf(fp,"#################################################################\n");

    fprintf(fp,"%-10s %12s %12s\n","TCP_LINK", "total_link", "link/s");
    fprintf(fp,"%-10s %12llu %12llu\n", "TCP_NEW", sysinfo_new[SYS_TCP_LINK_NEW],
            sysinfo_new[SYS_TCP_LINK_NEW] - sysinfo_old[SYS_TCP_LINK_NEW]);
    //fprintf(fp,"%-10s %12llu %12llu\n", "TCP_DATA", sysinfo_new[SYS_TCP_LINK_DATA],
    //        sysinfo_new[SYS_TCP_LINK_DATA] - sysinfo_old[SYS_TCP_LINK_DATA]);
    fprintf(fp,"%-10s %12llu %12llu\n", "TCP_DEL", sysinfo_new[SYS_TCP_LINK_DEL],
            sysinfo_new[SYS_TCP_LINK_DEL] - sysinfo_old[SYS_TCP_LINK_DEL]);
    fprintf(fp,"%-10s %12llu %12llu\n", "TCP_DOU", sysinfo_new[LINK_DOUBLE],
            sysinfo_new[LINK_DOUBLE] - sysinfo_old[LINK_DOUBLE]);
    fprintf(fp,"%-10s %12llu %12llu\n", "TCP_C2S", sysinfo_new[LINK_SINGLE_C2S],
            sysinfo_new[LINK_SINGLE_C2S] - sysinfo_old[LINK_SINGLE_C2S]);
    fprintf(fp,"%-10s %12llu %12llu\n", "TCP_S2C", sysinfo_new[LINK_SINGLE_S2C],
            sysinfo_new[LINK_SINGLE_S2C] - sysinfo_old[LINK_SINGLE_S2C]);

    fprintf(fp,"#################################################################\n\n");

	/* 2018-08-29 lijia add field statsd */
#if 0	
	sapp_statsd_add_para("Ethernet_pps", sysinfo_new[PKT_ETHERNET]-sysinfo_old[PKT_ETHERNET]);
	sapp_statsd_add_para("Ethernet_bps", 8 *( sysinfo_new[PKT_ETHERNET_LEN]-sysinfo_old[PKT_ETHERNET_LEN]));
	
	sapp_statsd_add_para("IPv4_pps", sysinfo_new[PKT_IP]-sysinfo_old[PKT_IP]);
	sapp_statsd_add_para("IPv4_bps", 8 *(sysinfo_new[PKT_IPLEN]-sysinfo_old[PKT_IPLEN]));

	sapp_statsd_add_para("IPv6_pps", sysinfo_new[PKT_IPV6]-sysinfo_old[PKT_IPV6]);
	sapp_statsd_add_para("IPv6_bps", 8 *(sysinfo_new[PKT_IPV6LEN]-sysinfo_old[PKT_IPV6LEN]));

	sapp_statsd_add_para("TCP_pps", sysinfo_new[PKT_TCP]-sysinfo_old[PKT_TCP]);
	sapp_statsd_add_para("TCP_bps", 8 *(sysinfo_new[PKT_TCPLEN]-sysinfo_old[PKT_TCPLEN]));
	sapp_statsd_add_para("UDP_pps", sysinfo_new[PKT_UDP]-sysinfo_old[PKT_UDP]);	
	sapp_statsd_add_para("UDP_bps", 8 *(sysinfo_new[PKT_UDPLEN]-sysinfo_old[PKT_UDPLEN]));
	
	sapp_statsd_add_para("TCP_LINK_NEW",sysinfo_new[SYS_TCP_LINK_NEW]-sysinfo_old[SYS_TCP_LINK_NEW]);
	sapp_statsd_add_para("TCP_LINK_DEL", sysinfo_new[SYS_TCP_LINK_DEL]-sysinfo_old[SYS_TCP_LINK_DEL]);

	sapp_statsd_add_para("TCP_RST_SEND",  sysinfo_new[SEND_TCP_RST]-sysinfo_old[SEND_TCP_RST]);
	sapp_statsd_add_para("TCP_S/A_SEND",  sysinfo_new[SEND_TCP_SYN_ACK]-sysinfo_old[SEND_TCP_SYN_ACK]);
	sapp_statsd_add_para("UDP_SEND",  sysinfo_new[SEND_UDP_PKT]-sysinfo_old[SEND_UDP_PKT]);

	sapp_statsd_flush_buf(); /* statsd输出, 最后无论缓存是否满, 强制刷新一次 */
#elif 0
	sapp_fs2_update(PKT_ETHERNET, sysinfo_new[PKT_ETHERNET]-sysinfo_old[PKT_ETHERNET]);
	sapp_fs2_update(PKT_ETHERNET_LEN, 8 *( sysinfo_new[PKT_ETHERNET_LEN]-sysinfo_old[PKT_ETHERNET_LEN]));
	
	sapp_fs2_update(PKT_IP, sysinfo_new[PKT_IP]-sysinfo_old[PKT_IP]);
	sapp_fs2_update(PKT_IPLEN, 8 *(sysinfo_new[PKT_IPLEN]-sysinfo_old[PKT_IPLEN]));

	sapp_fs2_update(PKT_IPV6, sysinfo_new[PKT_IPV6]-sysinfo_old[PKT_IPV6]);
	sapp_fs2_update(PKT_IPV6LEN, 8 *(sysinfo_new[PKT_IPV6LEN]-sysinfo_old[PKT_IPV6LEN]));

	sapp_fs2_update(PKT_TCP, sysinfo_new[PKT_TCP]-sysinfo_old[PKT_TCP]);
	sapp_fs2_update(PKT_TCPLEN, 8 *(sysinfo_new[PKT_TCPLEN]-sysinfo_old[PKT_TCPLEN]));
	sapp_fs2_update(PKT_UDP, sysinfo_new[PKT_UDP]-sysinfo_old[PKT_UDP]);	
	sapp_fs2_update(PKT_UDPLEN, 8 *(sysinfo_new[PKT_UDPLEN]-sysinfo_old[PKT_UDPLEN]));
	
	sapp_fs2_update(SYS_TCP_LINK_NEW,sysinfo_new[SYS_TCP_LINK_NEW]-sysinfo_old[SYS_TCP_LINK_NEW]);
	sapp_fs2_update(SYS_TCP_LINK_DEL, sysinfo_new[SYS_TCP_LINK_DEL]-sysinfo_old[SYS_TCP_LINK_DEL]);

	sapp_fs2_update(SEND_TCP_RST,  sysinfo_new[SEND_TCP_RST]-sysinfo_old[SEND_TCP_RST]);
	sapp_fs2_update(SEND_TCP_SYN_ACK,  sysinfo_new[SEND_TCP_SYN_ACK]-sysinfo_old[SEND_TCP_SYN_ACK]);
	sapp_fs2_update(SEND_UDP_PKT,  sysinfo_new[SEND_UDP_PKT]-sysinfo_old[SEND_UDP_PKT]);
#else
	sapp_fs2_update(PKT_ETHERNET, sysinfo_new[PKT_ETHERNET]);
	sapp_fs2_update(PKT_ETHERNET_LEN, 8 *( sysinfo_new[PKT_ETHERNET_LEN]));
	
	sapp_fs2_update(PKT_IP, sysinfo_new[PKT_IP]);
	sapp_fs2_update(PKT_IPLEN, 8 *(sysinfo_new[PKT_IPLEN]));

	sapp_fs2_update(PKT_IPV6, sysinfo_new[PKT_IPV6]);
	sapp_fs2_update(PKT_IPV6LEN, 8 *(sysinfo_new[PKT_IPV6LEN]));

	sapp_fs2_update(PKT_TCP, sysinfo_new[PKT_TCP]);
	sapp_fs2_update(PKT_TCPLEN, 8 *(sysinfo_new[PKT_TCPLEN]));
	sapp_fs2_update(PKT_UDP, sysinfo_new[PKT_UDP]);	
	sapp_fs2_update(PKT_UDPLEN, 8 *(sysinfo_new[PKT_UDPLEN]));
	
	sapp_fs2_update(SYS_TCP_LINK_NEW,sysinfo_new[SYS_TCP_LINK_NEW]);
	sapp_fs2_update(SYS_TCP_LINK_DEL, sysinfo_new[SYS_TCP_LINK_DEL]);
	sapp_fs2_update(SYS_TCP_LINK_DATA, sysinfo_new[SYS_TCP_LINK_DATA]);

	sapp_fs2_update(LINK_DOUBLE,sysinfo_new[LINK_DOUBLE]);
	sapp_fs2_update(LINK_SINGLE_C2S, sysinfo_new[LINK_SINGLE_C2S]);
	sapp_fs2_update(LINK_SINGLE_S2C, sysinfo_new[LINK_SINGLE_S2C]);

	sapp_fs2_update(SEND_TCP_RST,  sysinfo_new[SEND_TCP_RST]);
	sapp_fs2_update(SEND_TCP_SYN_ACK,  sysinfo_new[SEND_TCP_SYN_ACK]);
	sapp_fs2_update(SEND_UDP_PKT,  sysinfo_new[SEND_UDP_PKT]);
#endif

	memcpy(sysinfo_old,sysinfo_new,sizeof(unsigned long long)*COUNTER_NUM);
	memcpy(g_SysInputInfo_old, (void *)g_SysInputInfo, sizeof(g_SysInputInfo));

	fclose(fp);

	return ;
}


void *time_event_thread(void *arg)
{
	time_t last_log_time;

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 480) /* 版本判断, 很多旧系统无法编译 */
#ifdef _GNU_SOURCE
	pthread_setname_np(pthread_self(), "sapp_time_event");
#endif
#endif

	TO_KB = 1024UL;
	TO_MB = 1024 * 1024UL;
	TO_GB = 1024 * 1024 * 1024UL;
	TO_TB = (unsigned long long)1024 * 1024 * 1024 * 1024UL;

	last_log_time = time(NULL);
	
	while(1)
	{
		g_CurrentTime = time(NULL);

		/*
			NOTE:
			为什么用下面这种方式, 而不是do_something(); sleep(1);

			因为do_something()函数因写硬盘, 本身可能就消耗几十ms, 再加上sleep(1)也并不是精确的休眠1秒, 会略微大于1秒,
			最后造成统计延时间隔实际比1秒大很多, 长时间运行后, 误差就会累积越来越大.
		*/
		if(g_CurrentTime > last_log_time){
			last_log_time = g_CurrentTime;
			sysinfo_output();
			pkt_runtime_output();
		}
		
		usleep(1000);
	}
	
	return NULL;
}

#ifdef __cplusplus
}
#endif
