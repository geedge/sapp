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
#include <errno.h>

#define STATS_STR_LEN	(32)

volatile int update_packet_io_status_sw = 1;

static unsigned long long sysinfo_old[COUNTER_NUM] = {0};
static unsigned long long TO_KB = 1024;
static unsigned long long TO_MB = 1024 * 1024;
static unsigned long long TO_GB = 1024 * 1024 * 1024UL;
static unsigned long long TO_TB;

extern volatile unsigned long long sysinfo_new[COUNTER_NUM];

extern int g_packet_io_thread_num;
extern void pkt_runtime_output(void);

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
	int i;
	FILE* fp;
	
	static unsigned long long g_SysInputInfo_old[MAX_THREAD_NUM][COUNTER_NUM];
	char s1[STATS_STR_LEN], s2[STATS_STR_LEN];

	if(0 == update_packet_io_status_sw){
		return;
	}

	memset((void *)sysinfo_new, 0, sizeof(sysinfo_new));

	for(i=0;i<g_packet_io_thread_num;i++)
	{
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

		sysinfo_new[SEND_TCP_RST] += g_SysInputInfo[i][SEND_TCP_RST];
		sysinfo_new[SEND_TCP_RST_LEN] += g_SysInputInfo[i][SEND_TCP_RST_LEN];

		sysinfo_new[SEND_TCP_SYN_ACK] += g_SysInputInfo[i][SEND_TCP_SYN_ACK];
		sysinfo_new[SEND_TCP_SYN_ACK_LEN] += g_SysInputInfo[i][SEND_TCP_SYN_ACK_LEN];

		sysinfo_new[SEND_UDP_PKT] += g_SysInputInfo[i][SEND_UDP_PKT];
		sysinfo_new[SEND_UDP_PKT_LEN] += g_SysInputInfo[i][SEND_UDP_PKT_LEN];		
	}

	fp = fopen("./sysinfo.log","w+");
	if(fp == NULL)
	{
		printf(" fopen sysinfo.log error, %s!\n", strerror(errno));
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


	fprintf(fp,"\n%-10s %12s %12s\n", "TUNNEL", "total_pkt", "total_len");	
	fprintf(fp,"%-10s %12llu %12llu\n", "6over4", sysinfo_new[TUNNEL_6OVER4], sysinfo_new[TUNNEL_6OVER4_LEN]); 
	fprintf(fp,"%-10s %12llu %12llu\n","teredo",sysinfo_new[TUNNEL_TEREDO], sysinfo_new[TUNNEL_TEREDO_LEN]);

#if (0 == SAPP_AS_TARGET_SO) /* 做为.so运行时, 无底层IO库支持, 不需调用丢包统计 */
	fprintf(fp,"\n%-10s %12s\n", "DROP", "total_pkt");
	fprintf(fp,"%-10s %12ld\n", "app", packet_io_get_app_drop_num_tot());
	fprintf(fp,"%-10s %12ld\n\n", "lib", packet_io_get_lib_drop_num());
#endif

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

	fprintf(fp,"#################################################################\n\n");
	
	memcpy((void *)sysinfo_old, (void *)sysinfo_new,sizeof(unsigned long long)*COUNTER_NUM);
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
			为什么用下面这种方式, 而不是do_something() + sleep(1) ??

			因为do_something()函数因写硬盘, 本身可能就消耗几十ms, 再加上sleep(1)也并不是精确的休眠1秒, 造成统计延时间隔实际比1秒大很多.
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
