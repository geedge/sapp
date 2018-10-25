#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include "MESA_path_trace.h"


#define MESA_TRACE_LOG	"./log/MESA_path_trace.log"

/*
	参数说明:
		dstip_net_order: 数据包目标IP地址, 网络序;
		dstport_net_order: 数据包目标端口, 网络序;
		payload: 执向udp负载的指针;
		payload_len: udp负载长度;

	返回值:
		0: 不是MESA_trace包;
		1: 是MESA_trace包;
*/
static int MESA_path_trace_identify(MESA_path_trace_addr_t *dstip, 
									char *payload, int payload_len)
{
	MESA_path_trace_t *ptrace_data;
	unsigned int random_rl, random_rr;
	int ip_addr_type, i;

	ptrace_data = (MESA_path_trace_t *)payload;
	random_rl = rol32(ptrace_data->random_shift, (ptrace_data->random_shift&0xE) + 1);  /* 靠random_shift左移生成, 用于异或magic1, dst_ip_net_order */
	random_rr = ror32(ptrace_data->random_shift, ((ptrace_data->random_shift&0xE) >> 4) + 1);  /* 靠random_shift右移生成, 用于异或magic2 */

	ip_addr_type = ptrace_data->ip_addr_type ^ random_rl;
	if((MESA_TRACE_IPV4 != ip_addr_type) && (MESA_TRACE_IPV6 != ip_addr_type)){
		return 0;
	}

	if(MESA_PATH_TRACE_MAGIC != (ptrace_data->magic1 ^ random_rl)){
		return 0;
	}

	if(MESA_PATH_TRACE_MAGIC != (ptrace_data->magic2 ^ random_rr)){
		return 0;
	}

	if(MESA_TRACE_IPV4 == ip_addr_type){
		unsigned int *ipv4 = (unsigned int *)ptrace_data->dst_ip_net_order;
		if(dstip->ipv4_dst != (*ipv4 ^ random_rr)){
			return 0;
		}
	}else{
		unsigned int *ipv6_payload = (unsigned int *)ptrace_data->dst_ip_net_order;
		unsigned int *ipv6_net = (unsigned int *)&dstip->ipv6_dst;

		for(i = 0; i < 4; i++){
			if(*ipv6_net != (*ipv6_payload ^ random_rr)){
				return 0;
			}
		}
	}
	
	return 1;
}

static const char *MESA_trace_get_time_now(char *time_res, int len)
{
	time_t cur;
	struct tm *date_loc;

	if(time_res && (len < 64)){
	    strcpy(time_res, "");
        return "";
	}
	
	time(&cur);
	date_loc = localtime(&cur);
	snprintf(time_res, 64, "%04d-%02d-%02d %02d:%02d:%02d", date_loc->tm_year+1900, date_loc->tm_mon+1,date_loc->tm_mday, 
		date_loc->tm_hour, date_loc->tm_min, date_loc->tm_sec);
    
	return time_res;
}

static void MESA_trace_write_log(struct streaminfo *a_udp)
{
	FILE *fp;
	time_t tm_now;
	char time_str[64];
	char ip_src_str[64], ip_dst_str[64];
	unsigned short sport, dport;

	fp = fopen(MESA_TRACE_LOG, "a+");
	if(fp == NULL){
		return;
	}
	if(ADDR_TYPE_IPV4==a_udp->addr.addrtype){
		inet_ntop(AF_INET, &a_udp->addr.tuple4_v4->saddr, ip_src_str, 64);
		inet_ntop(AF_INET, &a_udp->addr.tuple4_v4->daddr, ip_dst_str, 64);
		sport = ntohs(a_udp->addr.tuple4_v4->source);
		dport = ntohs(a_udp->addr.tuple4_v4->dest);
	}else{
		inet_ntop(AF_INET6, a_udp->addr.tuple4_v6->saddr, ip_src_str, 64);
		inet_ntop(AF_INET6, a_udp->addr.tuple4_v6->daddr, ip_dst_str, 64);
		sport = ntohs(a_udp->addr.tuple4_v6->source);
		dport = ntohs(a_udp->addr.tuple4_v6->dest);
	}
	
	tm_now = time(NULL);
	
	fprintf(fp, "%s, recv MESA trace packet: %s.%u ---> %s.%u\n",  
		  MESA_trace_get_time_now(time_str, 64), 
			ip_src_str, sport,
			ip_dst_str, dport);

	fclose(fp);
}

char MESA_path_trace_entry(struct streaminfo *a_udp,  void **pme, int thread_seq,void *a_packet)
{
	MESA_path_trace_addr_t dip_in_net;

	if((NULL == a_udp->pudpdetail->pdata) 
	  || (0 == a_udp->pudpdetail->datalen)
	  || (a_udp->pudpdetail->datalen < sizeof(MESA_path_trace_t))){
		return APP_STATE_DROPME;
	}

	if(ADDR_TYPE_IPV4 ==  a_udp->addr.addrtype){
		if((MESA_PATH_TRACE_SRC_PORT != a_udp->addr.tuple4_v4->source)
		||(MESA_PATH_TRACE_DST_PORT != a_udp->addr.tuple4_v4->dest)){
			return APP_STATE_DROPME;
		}
		dip_in_net.ip_addr_type = MESA_TRACE_IPV4;
		dip_in_net.ipv4_dst = a_udp->addr.tuple4_v4->daddr;
	}
	else if(ADDR_TYPE_IPV6 ==  a_udp->addr.addrtype){
		if((MESA_PATH_TRACE_SRC_PORT != a_udp->addr.tuple4_v6->source)
		||(MESA_PATH_TRACE_DST_PORT != a_udp->addr.tuple4_v6->dest)){
			return APP_STATE_DROPME;
		}
		dip_in_net.ip_addr_type = MESA_TRACE_IPV6;
		memcpy(&dip_in_net.ipv6_dst, a_udp->addr.tuple4_v6->daddr, IPV6_ADDR_LEN);
	}else{
		return APP_STATE_DROPME;
	}

	if(MESA_path_trace_identify(&dip_in_net, a_udp->pudpdetail->pdata, a_udp->pudpdetail->datalen) != 0){
		MESA_trace_write_log(a_udp);
	}

	return APP_STATE_GIVEME;
}

int CHAR_INIT(void)
{
	int demo_plugid = 52;

//  函数实现自定义
//  只要求函数返回值为插件ID；
	
	return demo_plugid;
}

#if 1
int main(void)
{
	int result, times = 0;
	char buf[1024];
	MESA_path_trace_addr_t test_addr;
	
	while(1){
		test_addr.ip_addr_type = 4;
		test_addr.ipv4_dst = 0x12345678;
		MESA_path_trace_build_payload(&test_addr, buf, 1024, rand());

		if(times & 1){
			buf[0] = 0; /* 故意修改数据 */
			buf[1] = 1;
		}
		
		result = MESA_path_trace_identify(&test_addr, buf, 1024);

		printf("ipv4 result is:%d\n", result);


		test_addr.ip_addr_type = 6;
		inet_pton(AF_INET6, "2002:1234:10:0:6:229", &test_addr.ipv6_dst);
		MESA_path_trace_build_payload(&test_addr, buf, 1024, rand());

		if(times & 1){
			buf[0] = 0; /* 故意修改数据 */
			buf[1] = 1;
		}
		
		result = MESA_path_trace_identify(&test_addr, buf, 1024);

		printf("ipv6 result is:%d\n", result);


		sleep(1);
		times++;
	}
	return 0;
}
#endif

#ifdef __cplusplus
}
#endif
