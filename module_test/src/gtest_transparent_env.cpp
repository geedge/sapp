#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include "mesa_net.h"
#include "gtest_sapp_fun.h"

/*
	本文件用于测试sapp的双臂透明transparent模式功能,
	创建两个TAP虚拟网卡, 用于模拟inline模式的回流/回注口, 
	通过此TAP向sapp注入数据包, 根据不同的测试用例, sapp会回注、丢弃、注入新数据包等动作, 
	本模块再从TAP收包, 判断sapp的动作是否符合预期行为.
*/
int g_slient_mode = 1;
static pcap_t *g_transparent_pcap_handle;
static void *g_transparent_env_log_handle;
static unsigned char *g_transparent_pcap_file_md5sum[64];
static int gtest_transparent_result_flag = GTEST_SAPP_ERR; /* 0:success; -1:error */
static volatile int g_transparent_timer_ms = 1000 * 10;  

static int g_transparent_to_sapp_up_fd = -1; /* 通过TAP向sapp注入数据包, up方向 */
static int g_transparent_to_sapp_down_fd = -1; /* 通过TAP向sapp注入数据包, down方向 */

#if (1 == GTEST_SAPP_COMM_MODE)
static struct sockaddr_un g_transparent_to_gtest_sockaddr;
#else
static struct sockaddr_in g_transparent_to_gtest_sockaddr;
#endif

static int g_transparent_to_gtest_fd = -1; /* UNIX socket, 发送检查结果 */


static int transparent_sendto_test_result(int res)
{
	int ret;

	if(GTEST_RESULT_NONE == res){
		printf("test over, result is GTEST_RESULT_NONE, ignore!\n");
		return 0;
	}

	printf("test over, send result:%x\n", res);
	
	ret = sendto(g_transparent_to_gtest_fd, &res, sizeof(int), 0, 
	            (const sockaddr*)&g_transparent_to_gtest_sockaddr, sizeof(g_transparent_to_gtest_sockaddr));
	if(ret < 0){
		printf("send result error:%s!\n", strerror(errno));
	}

	return 0;
}


/* 
   自造轮子, 一个非常简单的定时器, 
   因为不像sapp -d读包模式可以自动退出,
   用于read()阻塞模式无法超时返回, 一定时间后自动发送结果然后结束进程!
*/
static void *transparent_thread_timer(void *arg)
{
	while(1){
		if(g_transparent_timer_ms > 0){
			usleep(g_transparent_timer_ms * 1000);
			if(gtest_transparent_result_flag != GTEST_RESULT_NONE){
				MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "transparent_timer", "timeout, result is:0x%x, send and exit!\n", gtest_transparent_result_flag);
				transparent_sendto_test_result(gtest_transparent_result_flag);
			}
			usleep(1000);
			exit(1);
		}else{
			usleep(1000);
		}
	}

	return NULL;
}


static void transparent_sig_handler(int signo)
{
	printf("recv sig: %d\n", signo);
}


static void transparent_env_usage(const char *prog_name)
{
	printf("Usage: %s <pcap_filename> [timeout(s)]\n", prog_name);
	exit(1);
}


/*
	TODO:
		之前有个mrzcpd驱动双臂模式的BUG, 测试环境比较少, 也不好复现.
		使用本文件加上fake_marsio模块, 可以自测试mrzcpd + transparent模式的功能.
*/
static int transparent_env_init(char *argv[])
{
	g_transparent_to_sapp_up_fd = tuntap_dev_create((char *)GTEST_TAP_UP_DEV_NAME, IFF_TAP | IFF_NO_PI);
	if(g_transparent_to_sapp_up_fd < 0){
		printf("tuntap_dev_create() %s error!\n", GTEST_TAP_UP_DEV_NAME);
		return -1;
	}

	g_transparent_to_sapp_down_fd = tuntap_dev_create((char *)GTEST_TAP_DOWN_DEV_NAME, IFF_TAP | IFF_NO_PI);
	if(g_transparent_to_sapp_down_fd < 0){
		printf("tuntap_dev_create() %s error!\n", GTEST_TAP_DOWN_DEV_NAME);
		return -1;
	}
	
#if (1 == GTEST_SAPP_COMM_MODE)	
	g_transparent_to_gtest_fd = socket(AF_UNIX,SOCK_DGRAM,0);
#else
	g_transparent_to_gtest_fd = socket(AF_INET,SOCK_DGRAM,0);
#endif
	if(g_transparent_to_gtest_fd < 0){
		printf("socket error!\n");
		exit(1);
	}

	memset(&g_transparent_to_gtest_sockaddr, 0, sizeof(g_transparent_to_gtest_sockaddr));
#if (1 == GTEST_SAPP_COMM_MODE)	
	g_transparent_to_gtest_sockaddr.sun_family = AF_UNIX;
	strcpy(g_transparent_to_gtest_sockaddr.sun_path, UNIX_SOCKET_NAME);
#else
	g_transparent_to_gtest_sockaddr.sin_family = AF_INET;
	g_transparent_to_gtest_sockaddr.sin_port = htons(UDP_SERVER_BIND_PORT);	//host to network hostshort
	g_transparent_to_gtest_sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");		
#endif
	g_transparent_pcap_handle = pcap_dumpfile_init(argv[1]);
	if(NULL == g_transparent_pcap_handle){
		printf("pcap_init() error!\n");
		return -1;
	}

	return 0;
}

static void __arp_flow_forward_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char test_pcap_smac[ETH_ALEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
	const struct ethhdr *ehdr;
	static int arp_forward_pkt_num = 0;

	ret = write(g_transparent_to_sapp_up_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "arp_flow_forward","\033[1;31;40msend packet to sapp up tap error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_DEBUG, "arp_flow_forward","sendto tap device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:

	ret = read(g_transparent_to_sapp_down_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "arp_flow_forward","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	/* 测试流量的源mac是00:01:02:03:04:05, 不是测试流量则丢弃, 此处不能再判断广播或组播地址了!! */
	ehdr = (struct ethhdr *)pkt_buf;
	if(memcmp(ehdr->h_source, test_pcap_smac, ETH_ALEN) != 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "arp_flow_forward","\033[1;31;40mrecv from device:'%s', but src mac is not 00:01:02:03:04:05\033[0m\n", GTEST_TAP_DOWN_DEV_NAME);
		goto read_again;
	}

	arp_forward_pkt_num++;

	if(3 == arp_forward_pkt_num){
		/* 测试pcap一共三个包, 正确收到则说明正常 */
		gtest_transparent_result_flag = GTEST_TRANSPARENT_TO_SAPP_SUCC;	
		transparent_sendto_test_result(GTEST_TRANSPARENT_TO_SAPP_SUCC);
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "arp_flow_forward","\033[32mrecv 3 sapp forward packet, check success!\033[0m\n");
	}
}


static void __transparent_common_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const struct ethhdr *raw_ehdr;
	int replay_device_fd, recv_device_fd;

	raw_ehdr = (struct ethhdr *)data;

	if(memcmp(raw_ehdr->h_dest, raw_ehdr->h_source, ETH_ALEN) >= 0){
		replay_device_fd = g_transparent_to_sapp_up_fd;
		recv_device_fd = g_transparent_to_sapp_down_fd; /* 收包卡反向 */
	}else{
		replay_device_fd = g_transparent_to_sapp_down_fd;
		recv_device_fd = g_transparent_to_sapp_up_fd;  /* 收包卡反向 */
	}

	ret = write(replay_device_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "transparent_env","\033[1;31;40msend packet to tap device error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_DEBUG, "transparent_env","send packet to tap device succ, pkt len:%d\n", ret);
	}

read_again:

	ret = read(recv_device_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "transparent_env", "\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

}


static void __tcp_simple_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char test_pcap_smac[ETH_ALEN] = {0x76, 0xfc, 0xca, 0xef, 0x29, 0x28};
	const unsigned char test_pcap_dmac[ETH_ALEN] = {0x00, 0x30, 0x64, 0x4b, 0x58, 0x64};
	const struct ethhdr *rcv_ehdr, *raw_ehdr;
	static int forward_pkt_num = 0;
	int replay_device_fd, recv_device_fd;

	raw_ehdr = (struct ethhdr *)data;

	if(memcmp(test_pcap_smac, raw_ehdr->h_source, ETH_ALEN) == 0){
		replay_device_fd = g_transparent_to_sapp_up_fd;
		recv_device_fd = g_transparent_to_sapp_down_fd; /* 收包卡反向 */
	}else if(memcmp(test_pcap_dmac, raw_ehdr->h_source, ETH_ALEN) == 0){
		replay_device_fd = g_transparent_to_sapp_down_fd;
		recv_device_fd = g_transparent_to_sapp_up_fd;  /* 收包卡反向 */
	}else{
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "tcp_simple_cb", "\033[1;31;40mrecv not test sample pcap packet, eth_proto:0x%x\033[0m\n", ntohs(raw_ehdr->h_proto));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}

	ret = write(replay_device_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "tcp_simple_cb","\033[1;31;40msend packet to tap device error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_DEBUG, "tcp_simple_cb","send packet to tap device succ, pkt len=%d", hdr->caplen);
	}

read_again:

	ret = read(recv_device_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "tcp_simple_cb","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 不是测试流量则丢弃 */
	rcv_ehdr = (struct ethhdr *)pkt_buf;
	if((memcmp(rcv_ehdr->h_source, test_pcap_smac, ETH_ALEN) != 0)
	 &&(memcmp(rcv_ehdr->h_dest, test_pcap_smac, ETH_ALEN) != 0)){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "tcp_simple_cb","\033[1;31;40mrecv packet, but mac is not sample packet, drop it.\033[0m\n");
		goto read_again;
	}

	forward_pkt_num++;

	if(68 == forward_pkt_num){
		/* 测试pcap一共68个包, 正确收到则说明正常 */
		gtest_transparent_result_flag = GTEST_TRANSPARENT_TO_SAPP_SUCC;	
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "tcp_simple_cb","\033[32mrecv sapp forward packet:%d, check success!\033[0m\n", forward_pkt_num);

		/* transparent env只监测错误, 正确结果在plug的entry里发送 */
	}
}

static void __tcp_drop_and_rst_c2s_trigger_by_c2s_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char test_pcap_smac[ETH_ALEN] = {0x76, 0xfc, 0xca, 0xef, 0x29, 0x28};
	//const unsigned char test_pcap_dmac[ETH_ALEN] = {0x00, 0x30, 0x64, 0x4b, 0x58, 0x64};
	const unsigned int test_pcap_sip = 0xC0A80AFA;
	const unsigned int test_pcap_dip = 0xC0A80AEA;
	const struct ethhdr *rcv_ehdr;
	const struct ip* ip4hdr;
	const struct tcphdr *thdr;
	static int c2s_c2s_forward_pkt_num = 0;
	//int replay_device_fd, recv_device_fd;

	ret = write(g_transparent_to_sapp_up_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40msend packet to tap device error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	while(1){
		/* 测试同向发包, 从up网卡注入sapp, 从down网卡收sapp同向注入的包 */
		ret = read(g_transparent_to_sapp_down_fd, pkt_buf, GTEST_DEV_MTU);
		if(ret < 0){
			if(EINTR == errno){
				continue;
			}
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	

		/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 不是测试流量则丢弃 */
		rcv_ehdr = (struct ethhdr *)pkt_buf;
		if((memcmp(rcv_ehdr->h_source, test_pcap_smac, ETH_ALEN) != 0)
		 &&(memcmp(rcv_ehdr->h_dest, test_pcap_smac, ETH_ALEN) != 0)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv packet, but mac is not sample packet, drop it.\033[0m\n");
			continue;
		}

		c2s_c2s_forward_pkt_num++;
		ip4hdr = (struct ip*)(pkt_buf + sizeof(struct ethhdr));
		if(ip4hdr->ip_p != IPPROTO_TCP){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv packet, but is not TCP!\033[0m\n");
			continue;
		}
		if((ntohl(ip4hdr->ip_src.s_addr) != test_pcap_sip)
		 ||(ntohl(ip4hdr->ip_dst.s_addr) != test_pcap_dip)){
		 	MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv ip pkt, but address is not 192.168.10.250 or 192.168.10.234 \033[0m\n");
			continue;
		}

		thdr = (struct tcphdr *)(pkt_buf + sizeof(struct ethhdr) + ip4hdr->ip_hl*4);
		if((ntohs(ip4hdr->ip_id) == 0x4879) && (ntohs(thdr->check) == 0xe28f)){ /* 收到了原始包, 没有被丢弃 */
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv tcp pkt, but is raw pcap pkt, is not be dropped!\033[0m\n");
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
		
		if(thdr->rst != 1){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv tcp pkt, but rst flag is 0\033[0m\n");
			continue;
		}

		if((ntohs(thdr->source) != 58725) || (ntohs(thdr->dest) != 22)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv rst pkt, but src port is not 58725, or dst port is not 22!\033[0m\n");
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}

		/* 执行到此刻, 是符合预期的, 设置检查结果为SUCC,
			为了防止drop不生效, 还是继续收包, 理论上不应该收到任何数据包了, 直到超时为止.
		*/
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_rst_c2s_trigger_by_c2s","\033[32m[Notice]test OK! set result = SUCC. \033[0m\n");
		gtest_transparent_result_flag = GTEST_TRANSPARENT_TO_SAPP_SUCC;	
		
		if(c2s_c2s_forward_pkt_num > 1){ /* 原始包被丢弃, 只能收到一个C2S方向的rst包 */
			gtest_transparent_result_flag = GTEST_SAPP_ERR;	
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_c2s_trigger_by_c2s","\033[1;31;40mrecv pkt num:%d, expect only 1\033[0m\n", c2s_c2s_forward_pkt_num);
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
	}

}

static void __tcp_drop_and_rst_s2c_trigger_by_c2s_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char test_pcap_smac[ETH_ALEN] = {0x76, 0xfc, 0xca, 0xef, 0x29, 0x28};
	//const unsigned char test_pcap_dmac[ETH_ALEN] = {0x00, 0x30, 0x64, 0x4b, 0x58, 0x64};
	const unsigned int test_pcap_sip = 0xC0A80AFA;
	const unsigned int test_pcap_dip = 0xC0A80AEA;
	const struct ethhdr *rcv_ehdr;
	const struct ip* ip4hdr;
	const struct tcphdr *thdr;
	static int s2c_c2s_forward_pkt_num = 0;
	//int replay_device_fd, recv_device_fd;

	ret = write(g_transparent_to_sapp_up_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mtcp_drop_and_rst_s2c_trigger_by_c2s_cb(): send packet to tap device error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	while(1){
		ret = read(g_transparent_to_sapp_up_fd, pkt_buf, GTEST_DEV_MTU);
		if(ret < 0){
			if(EINTR == errno){
				continue;
			}
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	

		/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 不是测试流量则丢弃 */
		rcv_ehdr = (struct ethhdr *)pkt_buf;
		if((memcmp(rcv_ehdr->h_source, test_pcap_smac, ETH_ALEN) != 0)
		 &&(memcmp(rcv_ehdr->h_dest, test_pcap_smac, ETH_ALEN) != 0)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mrecv packet, but mac is not sample packet, drop it.\033[0m\n");
			continue;
		}

		s2c_c2s_forward_pkt_num++;
		ip4hdr = (struct ip*)(pkt_buf + sizeof(struct ethhdr));
		if(ip4hdr->ip_p != IPPROTO_TCP){
			continue;
		}
		if((ntohl(ip4hdr->ip_src.s_addr) != test_pcap_dip)
		 ||(ntohl(ip4hdr->ip_dst.s_addr) != test_pcap_sip)){
		 	MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mrecv ip pkt, but address is not 192.168.10.250 or 192.168.10.234 \033[0m\n");
			continue;
		}

		thdr = (struct tcphdr *)(pkt_buf + sizeof(struct ethhdr) + ip4hdr->ip_hl*4);
		if((ntohs(ip4hdr->ip_id) == 0x4879) && (ntohs(thdr->check) == 0xe28f)){ /* 收到了原始包, 没有被丢弃 */
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mrecv tcp pkt, but is raw pcap pkt, is not be dropped!\033[0m\n");
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
		
		if(thdr->rst != 1){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mrecv tcp pkt, but rst flag is 0\033[0m\n");
			continue;
		}

		if((ntohs(thdr->source) != 22) || (ntohs(thdr->dest) != 58725)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mrecv rst pkt, but dst port is not 58725, or src port is not 22!\033[0m\n");
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);			
		}

		/* 执行到此刻, 是符合预期的, 设置检查结果为SUCC,
			为了防止drop不生效, 还是继续收包, 理论上不应该收到任何数据包了, 直到超时为止,
			最终在transparent_thread_timer()发送结果.
		*/
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_rst_s2c_trigger_by_c2s", "\033[32m[Notice]tcp_drop_and_rst_s2c_trigger_by_c2s test OK! set result = SUCC. \033[0m\n");
		gtest_transparent_result_flag = GTEST_TRANSPARENT_TO_SAPP_SUCC;	
		
		if(s2c_c2s_forward_pkt_num > 1){ /* 反向注入, 只能收到一个S2C方向的rst包 */
			gtest_transparent_result_flag = GTEST_SAPP_ERR;	
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_rst_s2c_trigger_by_c2s","\033[1;31;40mrecv pkt num:%d, expect only 1\033[0m\n", s2c_c2s_forward_pkt_num);
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
	}

}

static void __tcp_drop_and_inject_c2s_trigger_by_c2s_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char test_pcap_smac[ETH_ALEN] = {0x76, 0xfc, 0xca, 0xef, 0x29, 0x28};
	//const unsigned char test_pcap_dmac[ETH_ALEN] = {0x00, 0x30, 0x64, 0x4b, 0x58, 0x64};
	const unsigned int test_pcap_sip = 0xC0A80AFA;
	const unsigned int test_pcap_dip = 0xC0A80AEA;
	const struct ethhdr *rcv_ehdr;
	const struct ip* ip4hdr;
	const struct tcphdr *thdr;
	static int c2s_c2s_inject_pkt_num = 0;
	//int replay_device_fd, recv_device_fd;

	ret = write(g_transparent_to_sapp_up_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40msend packet to tap device error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	while(1){
		/* 测试同向发包, 从up网卡注入sapp, 从down网卡收sapp同向注入的包 */
		ret = read(g_transparent_to_sapp_down_fd, pkt_buf, GTEST_DEV_MTU);
		if(ret < 0){
			if(EINTR == errno){
				continue;
			}
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	

		/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 不是测试流量则丢弃 */
		rcv_ehdr = (struct ethhdr *)pkt_buf;
		if((memcmp(rcv_ehdr->h_source, test_pcap_smac, ETH_ALEN) != 0)
		 &&(memcmp(rcv_ehdr->h_dest, test_pcap_smac, ETH_ALEN) != 0)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40mrecv packet, but mac is not sample packet, drop it.\033[0m\n");
			continue;
		}

		c2s_c2s_inject_pkt_num++;
		ip4hdr = (struct ip*)(pkt_buf + sizeof(struct ethhdr));
		if(ip4hdr->ip_p != IPPROTO_TCP){
			continue;
		}
		if((ntohl(ip4hdr->ip_src.s_addr) != test_pcap_sip)
		 ||(ntohl(ip4hdr->ip_dst.s_addr) != test_pcap_dip)){
		 	MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40mrecv ip pkt, but address is not 192.168.10.250 or 192.168.10.234 \033[0m\n");
			continue;
		}

		if(ntohs(ip4hdr->ip_id) != 0x1234){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40mrecv ip pkt, but ipid is:%x, expect:0x1234!\033[0m\n", ntohs(ip4hdr->ip_id));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);			
		}

		if(ntohs(ip4hdr->ip_sum) != 0x912A){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40mrecv ip pkt, but ipid is:%x, expect:0x912A!\033[0m\n", ntohs(ip4hdr->ip_sum));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);			
		}

		thdr = (struct tcphdr *)(pkt_buf + sizeof(struct ethhdr) + ip4hdr->ip_hl*4);
		if((ntohs(thdr->source) != 58725) || (ntohs(thdr->dest) != 22)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40mrecv rst pkt, but src port is not 58725, or dst port is not 22!\033[0m\n");
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);			
		}

		/* 执行到此刻, 是符合预期的, 设置检查结果为SUCC,
			为了防止drop不生效, 还是继续收包, 理论上不应该收到任何数据包了, 直到超时为止.
			最终在transparent_thread_timer()发送结果.
		*/
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_inject_c2s_trigger_by_c2s","\033[32m[Notice]tcp_drop_and_inject_c2s_trigger_by_c2s test OK! set result = SUCC. \033[0m\n");
		gtest_transparent_result_flag = GTEST_TRANSPARENT_TO_SAPP_SUCC;	
		
		if(c2s_c2s_inject_pkt_num > 1){ /* 原始包被丢弃, 只能收到一个C2S方向的包 */
			gtest_transparent_result_flag = GTEST_SAPP_ERR;	
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_c2s","\033[1;31;40mrecv pkt num:%d, expect only 1\033[0m\n", c2s_c2s_inject_pkt_num);
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
	}

}


static void __tcp_drop_and_inject_c2s_trigger_by_s2c_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char test_pcap_smac[ETH_ALEN] = {0x76, 0xfc, 0xca, 0xef, 0x29, 0x28};
	//const unsigned char test_pcap_dmac[ETH_ALEN] = {0x00, 0x30, 0x64, 0x4b, 0x58, 0x64};
	const unsigned int test_pcap_sip = 0xC0A80AFA; /* 10.250 */
	const unsigned int test_pcap_dip = 0xC0A80AEA; /* 10.234 */
	const struct ethhdr *rcv_ehdr;
	const struct ip* ip4hdr;
	const struct tcphdr *thdr;
	static int c2s_s2c_inject_pkt_num = 0;
	//int replay_device_fd, recv_device_fd;

	ret = write(g_transparent_to_sapp_down_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40msend packet to tap device error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	while(1){
		/* 测试反向发包, 从down网卡注入sapp, 还是从down网卡收sapp注入的包 */
		ret = read(g_transparent_to_sapp_down_fd, pkt_buf, GTEST_DEV_MTU);
		if(ret < 0){
			if(EINTR == errno){
				continue;
			}
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	

		/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 不是测试流量则丢弃 */
		rcv_ehdr = (struct ethhdr *)pkt_buf;
		if((memcmp(rcv_ehdr->h_source, test_pcap_smac, ETH_ALEN) != 0)
		 &&(memcmp(rcv_ehdr->h_dest, test_pcap_smac, ETH_ALEN) != 0)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40mrecv packet, but mac is not sample packet, drop it.\033[0m\n");
			continue;
		}

		c2s_s2c_inject_pkt_num++;
		ip4hdr = (struct ip*)(pkt_buf + sizeof(struct ethhdr));
		if(ip4hdr->ip_p != IPPROTO_TCP){
			continue;
		}
		if((ntohl(ip4hdr->ip_src.s_addr) != test_pcap_sip)
		 ||(ntohl(ip4hdr->ip_dst.s_addr) != test_pcap_dip)){
		 	MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40mrecv ip pkt, but address is not 192.168.10.250 or 192.168.10.234 \033[0m\n");
			continue;
		}

		if(ntohs(ip4hdr->ip_id) != 0x1234){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40mrecv ip pkt, but ipid is:%x, expect:0x1234!\033[0m\n", ntohs(ip4hdr->ip_id));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);			
		}

		if(ntohs(ip4hdr->ip_sum) != 0x912A){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40mrecv ip pkt, but ipid is:%x, expect:0x912A!\033[0m\n", ntohs(ip4hdr->ip_sum));
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);			
		}

		thdr = (struct tcphdr *)(pkt_buf + sizeof(struct ethhdr) + ip4hdr->ip_hl*4);
		if((ntohs(thdr->source) != 58725) || (ntohs(thdr->dest) != 22)){
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40mrecv rst pkt, but src port is not 58725, or dst port is not 22!\033[0m\n");
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);			
		}

		/* 执行到此刻, 是符合预期的, 设置检查结果为SUCC,
			为了防止drop不生效, 还是继续收包, 理论上不应该收到任何数据包了, 直到超时为止.
			最终在transparent_thread_timer()发送结果.
		*/
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_and_inject_c2s_trigger_by_s2c","\033[32m[Notice]tcp_drop_and_inject_c2s_trigger_by_s2c test OK! set result = SUCC. \033[0m\n");
		gtest_transparent_result_flag = GTEST_TRANSPARENT_TO_SAPP_SUCC;	
		
		if(c2s_s2c_inject_pkt_num > 1){ /* 原始包被丢弃, 只能收到一个C2S方向的包 */
			gtest_transparent_result_flag = GTEST_SAPP_ERR;	
			MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_and_inject_c2s_trigger_by_s2c","\033[1;31;40mrecv pkt num:%d, expect only 1\033[0m\n", c2s_s2c_inject_pkt_num);
			transparent_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
	}

}


static void __drop_current_packet_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char test_pcap_smac[ETH_ALEN] = {0x76, 0xfc, 0xca, 0xef, 0x29, 0x28};
	const unsigned char test_pcap_dmac[ETH_ALEN] = {0x00, 0x30, 0x64, 0x4b, 0x58, 0x64};
	const struct ethhdr *rcv_ehdr, *raw_ehdr;
	static int drop_cur_pkt_num = 0;
	int replay_device_fd, recv_device_fd;

	raw_ehdr = (struct ethhdr *)data;

	if(memcmp(test_pcap_smac, raw_ehdr->h_source, ETH_ALEN) == 0){
		replay_device_fd = g_transparent_to_sapp_up_fd;
		recv_device_fd = g_transparent_to_sapp_down_fd; /* 收包卡反向 */
	}else if(memcmp(test_pcap_dmac, raw_ehdr->h_source, ETH_ALEN) == 0){
		replay_device_fd = g_transparent_to_sapp_down_fd;
		recv_device_fd = g_transparent_to_sapp_up_fd;  /* 收包卡反向 */
	}else{
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_current_packet","\033[1;31;40mrecv not test sample pcap packet, eth_proto:0x%x\033[0m\n", ntohs(raw_ehdr->h_proto));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}

	/* 一共三个包, 每个都正常注入, 但是ipid为0x487A的包会被插件DROP, 不应该收到 */
	ret = write(replay_device_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_current_packet","\033[1;31;40msend packet to tap device error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

read_again:

	ret = read(recv_device_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_current_packet","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		transparent_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 不是测试流量则丢弃 */
	rcv_ehdr = (struct ethhdr *)pkt_buf;
	if((memcmp(rcv_ehdr->h_source, test_pcap_smac, ETH_ALEN) != 0)
	 &&(memcmp(rcv_ehdr->h_dest, test_pcap_smac, ETH_ALEN) != 0)){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_current_packet","\033[1;31;40mrecv packet, but mac is not sample packet, drop it.\033[0m\n");
		goto read_again;
	}
	
	const struct ip *ip4hdr = (struct ip *)(data + sizeof(struct ethhdr));

	if(0x487A == ntohs(ip4hdr->ip_id)){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_current_packet","\033[1;31;40mrecv from sapp pkt, ipid=0x478A, but it should be droped!\033[0m\n");
		transparent_sendto_test_result(GTEST_SAPP_ERR);		
	}else if(0x4879 == ntohs(ip4hdr->ip_id)){
		drop_cur_pkt_num++;
	}else if(0x487F == ntohs(ip4hdr->ip_id)){
		drop_cur_pkt_num++;
	}else{
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "drop_current_packet","\033[1;31;40mrecv from sapp pkt, is not read from pcap:%s\033[0m\n", "drop_currrent_xxx.pcap");
		transparent_sendto_test_result(GTEST_SAPP_ERR);		
	}

	if(2 == drop_cur_pkt_num){
		/* 测试pcap一共3个包, 插件丢掉中间的一个, 正确收到2个, 且没有ipid=0x487A的包, 则说明正常 */
		gtest_transparent_result_flag = GTEST_TRANSPARENT_TO_SAPP_SUCC;	
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "drop_current_packet","\033[32mrecv sapp forward packet:%d, check success!\033[0m\n", drop_cur_pkt_num);
	}

}


/*
	不同的数据包对应不同的测试用例, 使用一个数组来保存数据包md5和相关处理函数的对应关系.

	TODO:
		这些函数大同小异, 都是检查某个数据包某个字段是什么值, 使用sapp_benchmark模式, 与tshark json对比.
*/
static pcap_md5_tuple_t g_transparent_pcap_md5_tuple[] = 
{
	{"0898b506eddfce273a970aa9d69370a4",GTEST_SAPP_ERR,	__arp_flow_forward_cb,			"测试arp,组播,广播基本转发功能"}, /* for_gtest_only/transparent/broadcast_and_multicast.pcap */
	{"df138740a6a22ca9c977052f21f7a470",GTEST_SAPP_ERR,	__tcp_simple_cb,				"测试tcp包基本转发功能, route dir方向"},
	{"8e95cfbe797756b35e4771ecc7b1ad8a",GTEST_SAPP_ERR,	__tcp_drop_and_rst_c2s_trigger_by_c2s_cb,		"注入一个C2S方向的tcp包, 测试丢弃当前包, 并追加发送一个C2S方向的rst包功能"},
	{"0f65d93dece662dc982c3f193e5fe80e",GTEST_SAPP_ERR,	__tcp_drop_and_rst_s2c_trigger_by_c2s_cb,		"注入一个C2S方向的tcp包, 测试丢弃当前包, 并追加发送一个S2C方向的rst包功能"},
	{"b369a07c6425ba3f15c64caeebaba57a",GTEST_SAPP_ERR, __tcp_drop_and_inject_c2s_trigger_by_c2s_cb,	"注入一个C2S方向的tcp包, 测试丢弃当前包, 并追加发送一个C2S方向的IP包功能"},
	{"7bf11e398e4dc0993843d1364fbe701d",GTEST_SAPP_ERR, __tcp_drop_and_inject_c2s_trigger_by_s2c_cb,	"注入一个C2S方向的tcp包, 测试丢弃当前包, 并追加发送一个S2C方向的IP包功能"},
	{"687e907fc50d2dae52e14168c179d4df",GTEST_TRANSPARENT_TO_SAPP_SUCC, __drop_current_packet_cb,		"测试接口 MSO_DROP_CURRENT_PKT 丢弃当前包"},
	{"4023b9c75003711f8d1e7bdbfb8cf799",GTEST_TRANSPARENT_TO_SAPP_SUCC, __drop_current_packet_cb,		"测试接口 MSO_DROP_CURRENT_PKT 丢弃当前包"},
	{NULL, GTEST_RESULT_NONE, NULL, NULL}
};


static void transparent_test_run(void)
{
	int i;

	for(i = 0; g_transparent_pcap_md5_tuple[i].pcap_file_md5 != NULL; i++){
		if(strncasecmp((char *)g_transparent_pcap_file_md5sum, (char *)g_transparent_pcap_md5_tuple[i].pcap_file_md5, strlen(g_transparent_pcap_md5_tuple[i].pcap_file_md5)) == 0){
			gtest_transparent_result_flag = g_transparent_pcap_md5_tuple[i].default_check_result;
			pcap_loop(g_transparent_pcap_handle, -1, g_transparent_pcap_md5_tuple[i].pcap_callback, NULL);
			break;
		}
	}

	/* 不关心串联返回包情况的插件, 只注入数据包即可 */
	if(NULL == g_transparent_pcap_md5_tuple[i].pcap_file_md5){
		gtest_transparent_result_flag = GTEST_RESULT_NONE;
		pcap_loop(g_transparent_pcap_handle, -1, __transparent_common_cb, NULL);
	}	

	transparent_sendto_test_result(gtest_transparent_result_flag);
}


int main(int argc, char *argv[])
{
	pthread_t pid;
	
	if(argc < 2){
		transparent_env_usage(argv[0]);
	}

	if(argc >= 3){
		g_transparent_timer_ms = atoi(argv[2]) * 1000; /* cmd args单位是秒, 转换成毫秒 */
	}

	MESA_handle_runtime_log_creation("./etc/sapp_log.conf");
	g_transparent_env_log_handle = MESA_create_runtime_log_handle("./log/gtest_transparent_env.log", RLOG_LV_DEBUG);
	MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_INFO, "transparent_env", "--------------------main() starting -------------------\n");

	if(transparent_env_init(argv) < 0){
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_FATAL, "transparent_env","inline_env_init() error!\n");
		return -1;
	}

	gtest_file_md5sum(argv[1], (char *)g_transparent_pcap_file_md5sum, sizeof(g_transparent_pcap_file_md5sum));

	gtest_transparent_result_flag = GTEST_RESULT_NONE;

	signal(SIGPIPE, transparent_sig_handler);
	pthread_create(&pid, NULL, transparent_thread_timer, NULL);

	while(1){
		if(wait_for_sapp_running() == 1){
			break;
		}
		usleep(1000 * 500);
		MESA_handle_runtime_log(g_transparent_env_log_handle, RLOG_LV_DEBUG, "transparent_env","sapp is not running, waiting...\n");
	}
	sleep(1); //测试发现, 立即回放包, sapp可能还没真正运行起来, 此处先sleep一会. TODO!!
	transparent_test_run();

	while(1){
		pause();
	}

	return 0;
}


