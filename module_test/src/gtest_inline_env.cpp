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
	本文件用于测试sapp的inline模式功能,
	创建一个TAP虚拟网卡, 用于模拟inline模式的回流/回注口, 
	通过此TAP向sapp注入数据包, 根据不同的测试用例, sapp会回注、丢弃、注入新数据包等动作, 
	本模块再从TAP收包, 判断sapp的动作是否符合预期行为.
*/

static void *g_inline_env_log_handle;
static int g_replay_pkt_to_sapp_fd = -1; /* 通过TAP向sapp注入数据包 */
static int g_result_to_sapp_fd = -1; 
int g_slient_mode = 1;

#if (1 == GTEST_SAPP_COMM_MODE)
static struct sockaddr_un g_result_to_sapp_sockaddr;
#else
static struct sockaddr_in g_result_to_sapp_sockaddr;
#endif

static pcap_t *g_pcap_handle;
static unsigned char *g_pcap_file_md5sum[64];
static int gtest_inline_mode_result_flag = GTEST_SAPP_ERR; /* 0:success; -1:error */
static volatile int g_timer_ms = 1000 * 10;  

extern int check_vxlan_private_pkt_equal(const void *raw_net_hdr, const void *inject_net_hdr, struct layer_addr_vxlan_private *raw_vxlan_addr, struct layer_addr_vxlan_private *inject_vxlan_addr, int reverse_dir);;

static void inline_sig_handler(int signo)
{
	printf("recv sig: %d\n", signo);
}

static int inline_sendto_test_result(int res)
{
	int ret;

	if(GTEST_RESULT_NONE == res){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG,"inline_env","test over, result is GTEST_RESULT_NONE, ignore!\n");
		return 0;
	}	
	
	ret = sendto(g_result_to_sapp_fd, &res, sizeof(int), 0, 
	            (const sockaddr*)&g_result_to_sapp_sockaddr, sizeof(g_result_to_sapp_sockaddr));
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"inline_env","inline_sendto_test_result error:%s!\n", strerror(errno));
	}else{
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG,"inline_env","inline_sendto_test_result:0x%x succ, fd=%d, fd address is:%p\n", res, g_result_to_sapp_fd, &g_result_to_sapp_fd);
	}

	return 0;
}

/* 
   自造轮子, 一个非常简单的定时器, 
   因为不像sapp -d读包模式可以自动退出,
   用于read()阻塞模式无法超时返回, 一定时间后自动发送结果然后结束进程!
*/
static void *inline_thread_timer(void *arg)
{
	while(1){
		if(g_timer_ms > 0){
			usleep(g_timer_ms * 1000);
			if(gtest_inline_mode_result_flag != GTEST_RESULT_NONE){
				MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"inline_env","timeout, result is:%x, exit!\n", gtest_inline_mode_result_flag);
				inline_sendto_test_result(gtest_inline_mode_result_flag);
			}
			exit(1);
		}else{
			usleep(1);
		}
	}

	return NULL;
}


static int check_vxlan_pkt_equal(const inline_vxlan_hdr_t *vxlanhdr1, const inline_vxlan_hdr_t *vxlanhdr2, int reverse_dir)
{
	int ret;
	char tmp_vxlan_addr[sizeof(inline_vxlan_hdr_t)];
	inline_vxlan_hdr_t *vxlanhdr_reverse = (inline_vxlan_hdr_t *)tmp_vxlan_addr;
	
	if(0 == reverse_dir){
		ret = memcmp(vxlanhdr1, vxlanhdr2, sizeof(inline_vxlan_hdr_t));
	}else{
		memcpy(tmp_vxlan_addr, vxlanhdr1, sizeof(inline_vxlan_hdr_t));
		vxlanhdr_reverse->dir ^= 1; /* 只变换了方向, 其他值都不能变 */
		ret = memcmp(tmp_vxlan_addr, vxlanhdr2, sizeof(inline_vxlan_hdr_t));
	}

	return ret;
}


static void inline_env_usage(const char *prog_name)
{
	printf("Usage: %s <pcap_filename> [timeout]\n", prog_name);
	exit(1);
}


/*
	创建一个TAP虚拟网卡, 作为sapp.tom的捕包和收包卡, 
	可以自由控制向此网卡注入的数据包, 以及读取sapp回注的数据包.
*/
static int inline_env_init(char *argv[])
{
	g_replay_pkt_to_sapp_fd = tuntap_dev_create((char *)GTEST_TAP_UP_DEV_NAME, IFF_TAP | IFF_MULTI_QUEUE | IFF_NO_PI);
	if(g_replay_pkt_to_sapp_fd < 0){
		printf("tuntap_dev_create() %s error!\n", GTEST_TAP_UP_DEV_NAME);
		return -1;
	}
	
#if (1 == GTEST_SAPP_COMM_MODE)
	g_result_to_sapp_fd = socket(AF_UNIX,SOCK_DGRAM,0);
#else
	g_result_to_sapp_fd = socket(AF_INET,SOCK_DGRAM,0);
#endif
	if(g_result_to_sapp_fd < 0){
		printf("AF_UNIX socket error!\n");
		return -1;
	}

	memset(&g_result_to_sapp_sockaddr, 0, sizeof(g_result_to_sapp_sockaddr));
#if (1 == GTEST_SAPP_COMM_MODE)
	g_result_to_sapp_sockaddr.sun_family = AF_UNIX;
	strcpy(g_result_to_sapp_sockaddr.sun_path, UNIX_SOCKET_NAME);
#else
	g_result_to_sapp_sockaddr.sin_family = AF_INET;
	g_result_to_sapp_sockaddr.sin_port = htons(UDP_SERVER_BIND_PORT);	//host to network hostshort
	g_result_to_sapp_sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");	
#endif
	g_pcap_handle = pcap_dumpfile_init(argv[1]);
	if(NULL == g_pcap_handle){
		printf("pcap_init() error!\n");
		return -1;
	}

	return 0;
}

static void __inline_pkt_common_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "gtest_inline_env", "send packet to sapp error:%s", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG, "gtest_inline_env", "write to device:%s succ, len=%d", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}
}


static void __inline_pkt_drop_test_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	const unsigned char raw_pcap_dmac[ETH_ALEN] = {0xe4, 0x95, 0x6e, 0x20, 0x0d, 0x0a};
	const unsigned char raw_pcap_smac[ETH_ALEN] = {0x00, 0x1e, 0x73, 0x6c, 0xfa, 0x43};

	gtest_inline_mode_result_flag = GTEST_INLINE_TO_SAPP_SUCC; /* 如果超时了, 说明没收到sapp的返回包, 在thread_timer()函数里返回结果是正确 */

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"__inline_pkt_drop_test_cb","\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		printf("\033[32mwrite to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:
	
	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"__inline_pkt_drop_test_cb","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{	
		/* 收到与原始pcap包mac地址一样的回注数据包是错误的 */
		if(memcmp(pkt_buf, raw_pcap_dmac, ETH_ALEN) == 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"__inline_pkt_drop_test_cb","\033[1;31;40mrecv from sapp! but expect action is DROP!\033[0m\n");
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
		if(memcmp(pkt_buf+6, raw_pcap_smac, ETH_ALEN) == 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"__inline_pkt_drop_test_cb","\033[1;31;40mrecv from sapp! but expect action is DROP!\033[0m\n");
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}		
	}
}



static void __tcp_flow_forward_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	int inner_payload_offset;
	int inner_payload_len;
	unsigned int this_pcap_src_ip_addr;
	const struct ip *ip4hdr;
	const struct ethhdr *ehdr;
	const inline_mode_pcap_md5_tuple_t *this_pcap_md5_tuple = (inline_mode_pcap_md5_tuple_t *)user;

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		printf("\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		printf("\033[32mwrite to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:

	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		printf("\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	ehdr = (struct ethhdr *)pkt_buf;
	if(ETH_P_IP != ntohs(ehdr->h_proto)){
		printf("\033[1;31;40mrecv from device:'%s', but eth protocol is not IP\033[0m\n", GTEST_TAP_UP_DEV_NAME);
		goto read_again;
	}

	inet_pton(AF_INET, this_pcap_md5_tuple->keepalive_ip, &this_pcap_src_ip_addr);
	ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		printf("\033[1;31;40mrecv from %s, but src ip address is: %s, ecpect: %s\033[0m\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again;
	}

	if(ret != (int)hdr->caplen){
		printf("\033[1;31;40mcheck pkt error, send len:%d is diff with recv len:%d\033[0m\n", hdr->caplen, ret);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}

	/* 从vxlan开始的内层数据不变, 外层mac, ip颠倒方向, udp层不变 */
	inner_payload_offset = sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr);
	inner_payload_len = hdr->caplen - inner_payload_offset;
	
	if(memcmp(data+inner_payload_offset, pkt_buf+inner_payload_offset, inner_payload_len) != 0){
		printf("\033[1;31;40mcheck inner packet payload error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);			  
	}

	ret = check_ethernet_pkt_equal((struct ethhdr *)(data), (struct ethhdr *)(pkt_buf), 1);
	if(ret < 0){
	  printf("\033[1;31;40methernet layer check error!\033[0m\n");
	  inline_sendto_test_result(GTEST_SAPP_ERR);
	  exit(1);		  
	}   

	ret = check_ip_pkt_equal((struct ip *)(data+sizeof(struct ethhdr)), (struct ip *)(pkt_buf+sizeof(struct ethhdr)), 1, 1);
	if(ret < 0){
		printf("\033[1;31;40mip layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/* udp端口不变 */
	ret = check_udp_pkt_equal((struct udphdr *)(data+sizeof(struct ethhdr)+sizeof(struct ip)), (struct udphdr *)(pkt_buf+sizeof(struct ethhdr)+sizeof(struct ip)), 0, 1);
	if(ret < 0){
		printf("\033[1;31;40mudp layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	printf("\033[32mrecv sapp reinject packet, check success!\033[0m\n");
}

/*
	TODO:
		这些函数大同小异, 都是检查某个数据包某个字段是什么值, 使用sapp_benchmark模式, 与tshark json对比.	
*/
static void __tcp_snd_c2s_rst_trigger_by_c2s_pkt_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	unsigned int this_pcap_src_ip_addr;
	const struct ip *ip4hdr;
	const struct ethhdr *ehdr;
	const inline_mode_pcap_md5_tuple_t *this_pcap_md5_tuple = (inline_mode_pcap_md5_tuple_t *)user;

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s", "\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG, "c2s_rst_trigger_by_c2s", "write to device:%s succ, len=%d\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:

	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	ehdr = (struct ethhdr *)pkt_buf;
	if(ETH_P_IP != ntohs(ehdr->h_proto)){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "c2s_rst_trigger_by_c2s","\033[1;31;40mrecv from device:'%s', but eth protocol is not IP\033[0m\n", GTEST_TAP_UP_DEV_NAME);
		goto read_again;
	}

	inet_pton(AF_INET, this_pcap_md5_tuple->keepalive_ip, &this_pcap_src_ip_addr);
	ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "c2s_rst_trigger_by_c2s","\033[1;31;40mrecv from %s, but src ip address is: %s, ecpect: %s\033[0m\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again;
	}

	/******* vxlan开始的外层mac, ip颠倒方向, udp层不变 *********/
//	inner_payload_offset = sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr);
	//inner_payload_len = hdr->caplen - inner_payload_offset;

	ret = check_ethernet_pkt_equal((struct ethhdr *)(data), (struct ethhdr *)(pkt_buf), 1);
	if(ret < 0){
	  MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40mOuter ethernet layer check error!\033[0m\n");
	  inline_sendto_test_result(GTEST_SAPP_ERR);
	  exit(1);		  
	}   

	ret = check_ip_pkt_equal((struct ip *)(data+sizeof(struct ethhdr)), (struct ip *)(pkt_buf+sizeof(struct ethhdr)), 1, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40mOuter ip layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/* udp端口不变 */
	ret = check_udp_pkt_equal((struct udphdr *)(data+sizeof(struct ethhdr)+sizeof(struct ip)), (struct udphdr *)(pkt_buf+sizeof(struct ethhdr)+sizeof(struct ip)), 0, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40mOuter udp layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/******* 检查内层协议, 即实际会发送到公网的数据包地址 *********/
	const inline_vxlan_hdr_t *raw_vxlan_hdr = (inline_vxlan_hdr_t *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	const inline_vxlan_hdr_t *snd_vxlan_hdr = (inline_vxlan_hdr_t *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	ret = check_vxlan_pkt_equal(raw_vxlan_hdr, snd_vxlan_hdr, 0); /* 触发包是C2S方向, 发送的RST包是C2S方向  */
	if(ret < 0){ 
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40mvxlan hdr dir error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}
	const struct ethhdr *raw_eth_hdr = (struct ethhdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	const struct ethhdr *snd_eth_hdr = (struct ethhdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	ret = check_ethernet_pkt_equal(raw_eth_hdr, snd_eth_hdr, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40minner ethernet layer check error, raw_src:%02x-%02x-%02x-%02x-%02x-%02x, raw_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 raw_eth_hdr->h_source[0],raw_eth_hdr->h_source[1],raw_eth_hdr->h_source[2],raw_eth_hdr->h_source[3],raw_eth_hdr->h_source[4],raw_eth_hdr->h_source[5],
			 raw_eth_hdr->h_dest[0],raw_eth_hdr->h_dest[1],raw_eth_hdr->h_dest[2],raw_eth_hdr->h_dest[3],raw_eth_hdr->h_dest[4],raw_eth_hdr->h_dest[5]);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40minner ethernet layer check error, snd_src:%02x-%02x-%02x-%02x-%02x-%02x, snd_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 snd_eth_hdr->h_source[0],snd_eth_hdr->h_source[1],snd_eth_hdr->h_source[2],snd_eth_hdr->h_source[3],snd_eth_hdr->h_source[4],snd_eth_hdr->h_source[5],
			 snd_eth_hdr->h_dest[0],snd_eth_hdr->h_dest[1],snd_eth_hdr->h_dest[2],snd_eth_hdr->h_dest[3],snd_eth_hdr->h_dest[4],snd_eth_hdr->h_dest[5]);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	
	const struct ip *raw_ip4_hdr = (struct ip *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr));
	const struct ip *snd_ip4_hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr));	
	ret = check_ip_pkt_equal(raw_ip4_hdr, snd_ip4_hdr, 0, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40minner IP layer check error, raw_src:%x, raw_dst:%x\033[0m\n", 
						raw_ip4_hdr->ip_src.s_addr, raw_ip4_hdr->ip_dst.s_addr);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40minner IP layer check error, snd_src:%x, snd_dst:%x\033[0m\n", 
						snd_ip4_hdr->ip_src.s_addr, snd_ip4_hdr->ip_dst.s_addr);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	/** inner tcp layer **/
	const struct mesa_tcp_hdr *raw_tcp_hdr = (struct mesa_tcp_hdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip));
	const struct mesa_tcp_hdr *snd_tcp_hdr = (struct mesa_tcp_hdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip));	
	int tcp_payload_len = ntohs(raw_ip4_hdr->ip_len) - raw_ip4_hdr->ip_hl*4 - raw_tcp_hdr->th_off*4;
	
	ret = check_tcp_pkt_equal(raw_tcp_hdr, snd_tcp_hdr, 0x14, htonl(ntohl(raw_tcp_hdr->th_seq) + tcp_payload_len),  raw_tcp_hdr->th_ack,  0); /* 同向发送, snd.seq = raw.seq+raw.len, snd.ack=raw.ack */
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "c2s_rst_trigger_by_c2s","\033[1;31;40minner TCP layer check error, raw_src:%u, raw_dst:%u, snd_src:%u, snd_dst:%u, snd_flags:0x%x\033[0m\n",
				ntohs(raw_tcp_hdr->th_sport), ntohs(raw_tcp_hdr->th_dport), ntohs(snd_tcp_hdr->th_sport), ntohs(snd_tcp_hdr->th_dport), snd_tcp_hdr->th_flags);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	
	
	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "c2s_rst_trigger_by_c2s","\033[32mrecv sapp reinject C2S packet, check success!\033[0m\n");
	inline_sendto_test_result(GTEST_INLINE_TO_SAPP_SUCC);
	exit(0);
	return ;
}

/*
	TODO:
		这些函数大同小异, 都是检查某个数据包某个字段是什么值, 使用sapp_benchmark模式, 与tshark json对比.	
*/
static void __tcp_snd_s2c_rst_trigger_by_s2c_pkt_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	unsigned int this_pcap_src_ip_addr;
	const struct ip *ip4hdr;
	const struct ethhdr *ehdr;
	const inline_mode_pcap_md5_tuple_t *this_pcap_md5_tuple = (inline_mode_pcap_md5_tuple_t *)user;

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG, "s2c_rst_trigger_by_s2c","\033[32mwrite to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:

	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "s2c_rst_trigger_by_s2c","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	ehdr = (struct ethhdr *)pkt_buf;
	if(ETH_P_IP != ntohs(ehdr->h_proto)){
		printf("\033[1;31;40mrecv from device:'%s', but eth protocol is not IP\033[0m\n", GTEST_TAP_UP_DEV_NAME);
		goto read_again;
	}

	inet_pton(AF_INET, this_pcap_md5_tuple->keepalive_ip, &this_pcap_src_ip_addr);
	ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		printf("\033[1;31;40mrecv from %s, but src ip address is: %s, ecpect: %s\033[0m\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again;
	}

	/******* vxlan开始的外层mac, ip颠倒方向, udp层不变 *********/
	//inner_payload_offset = sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr);
	//inner_payload_len = hdr->caplen - inner_payload_offset;

	ret = check_ethernet_pkt_equal((struct ethhdr *)(data), (struct ethhdr *)(pkt_buf), 1);
	if(ret < 0){
	  MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40mOuter ethernet layer check error!\033[0m\n");
	  inline_sendto_test_result(GTEST_SAPP_ERR);
	  exit(1);		  
	}   

	ret = check_ip_pkt_equal((struct ip *)(data+sizeof(struct ethhdr)), (struct ip *)(pkt_buf+sizeof(struct ethhdr)), 1, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40mOuter ip layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/* udp端口不变 */
	ret = check_udp_pkt_equal((struct udphdr *)(data+sizeof(struct ethhdr)+sizeof(struct ip)), (struct udphdr *)(pkt_buf+sizeof(struct ethhdr)+sizeof(struct ip)), 0, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40mOuter udp layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/******* 检查内层协议, 即实际会发送到公网的数据包地址 *********/
	const inline_vxlan_hdr_t *raw_vxlan_hdr = (inline_vxlan_hdr_t *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	const inline_vxlan_hdr_t *snd_vxlan_hdr = (inline_vxlan_hdr_t *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	ret = check_vxlan_pkt_equal(raw_vxlan_hdr, snd_vxlan_hdr, 0); /* 触发包是C2S方向, 发送的RST包是C2S方向  */
	if(ret < 0){ 
		printf("\033[1;31;40mvxlan hdr dir error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}
	const struct ethhdr *raw_eth_hdr = (struct ethhdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	const struct ethhdr *snd_eth_hdr = (struct ethhdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	ret = check_ethernet_pkt_equal(raw_eth_hdr, snd_eth_hdr, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40minner ethernet layer check error, raw_src:%02x-%02x-%02x-%02x-%02x-%02x, raw_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 raw_eth_hdr->h_source[0],raw_eth_hdr->h_source[1],raw_eth_hdr->h_source[2],raw_eth_hdr->h_source[3],raw_eth_hdr->h_source[4],raw_eth_hdr->h_source[5],
			 raw_eth_hdr->h_dest[0],raw_eth_hdr->h_dest[1],raw_eth_hdr->h_dest[2],raw_eth_hdr->h_dest[3],raw_eth_hdr->h_dest[4],raw_eth_hdr->h_dest[5]);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40minner ethernet layer check error, snd_src:%02x-%02x-%02x-%02x-%02x-%02x, snd_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 snd_eth_hdr->h_source[0],snd_eth_hdr->h_source[1],snd_eth_hdr->h_source[2],snd_eth_hdr->h_source[3],snd_eth_hdr->h_source[4],snd_eth_hdr->h_source[5],
			 snd_eth_hdr->h_dest[0],snd_eth_hdr->h_dest[1],snd_eth_hdr->h_dest[2],snd_eth_hdr->h_dest[3],snd_eth_hdr->h_dest[4],snd_eth_hdr->h_dest[5]);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	
	const struct ip *raw_ip4_hdr = (struct ip *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr));
	const struct ip *snd_ip4_hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr));	
	ret = check_ip_pkt_equal(raw_ip4_hdr, snd_ip4_hdr, 0, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40minner IP layer check error, raw_src:%x, raw_dst:%x\033[0m\n", raw_ip4_hdr->ip_src.s_addr, raw_ip4_hdr->ip_dst.s_addr);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40minner IP layer check error, snd_src:%x, snd_dst:%x\033[0m\n", snd_ip4_hdr->ip_src.s_addr, snd_ip4_hdr->ip_dst.s_addr);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}
	
	const struct mesa_tcp_hdr *raw_tcp_hdr = (struct mesa_tcp_hdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip));
	const struct mesa_tcp_hdr *snd_tcp_hdr = (struct mesa_tcp_hdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip));	
	int tcp_payload_len = ntohs(raw_ip4_hdr->ip_len) - raw_ip4_hdr->ip_hl*4 - raw_tcp_hdr->th_off*4;
	
	ret = check_tcp_pkt_equal(raw_tcp_hdr, snd_tcp_hdr, 0x14, htonl(ntohl(raw_tcp_hdr->th_seq) + tcp_payload_len),  raw_tcp_hdr->th_ack,  0); /* 同向发送, snd.seq = raw.seq+raw.len, snd.ack=raw.ack */
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "s2c_rst_trigger_by_s2c","\033[1;31;40minner TCP layer check error, raw_src:%u, raw_dst:%u, snd_src:%u, snd_dst:%u, snd_flags:0x%x\033[0m\n",
				ntohs(raw_tcp_hdr->th_sport), ntohs(raw_tcp_hdr->th_dport), ntohs(snd_tcp_hdr->th_sport), ntohs(snd_tcp_hdr->th_dport), snd_tcp_hdr->th_flags);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	
	
	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "s2c_rst_trigger_by_s2c","\033[32mrecv sapp reinject S2C packet, check success!\033[0m\n");
	inline_sendto_test_result(GTEST_INLINE_TO_SAPP_SUCC);
	exit(0);

	return ;
}

/*
	TODO:
		这些函数大同小异, 都是检查某个数据包某个字段是什么值, 使用sapp_benchmark模式, 与tshark json对比.	
*/
static void __tcp_snd_s2c_rst_trigger_by_c2s_pkt_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	unsigned int this_pcap_src_ip_addr;
	const struct ip *ip4hdr;
	const struct ethhdr *ehdr;
	const inline_mode_pcap_md5_tuple_t *this_pcap_md5_tuple = (inline_mode_pcap_md5_tuple_t *)user;

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s", "\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG, "s2c_rst_trigger_by_c2s","\033[32mwrite to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:

	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	ehdr = (struct ethhdr *)pkt_buf;
	if(ETH_P_IP != ntohs(ehdr->h_proto)){
		printf("\033[1;31;40mrecv from device:'%s', but eth protocol is not IP\033[0m\n", GTEST_TAP_UP_DEV_NAME);
		goto read_again;
	}

	inet_pton(AF_INET, this_pcap_md5_tuple->keepalive_ip, &this_pcap_src_ip_addr);
	ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		printf("\033[1;31;40mrecv from %s, but src ip address is: %s, ecpect: %s\033[0m\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again;
	}

	/******* vxlan开始的外层mac, ip颠倒方向, udp层不变 *********/
	//inner_payload_offset = sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr);
	//inner_payload_len = hdr->caplen - inner_payload_offset;

	ret = check_ethernet_pkt_equal((struct ethhdr *)(data), (struct ethhdr *)(pkt_buf), 1);
	if(ret < 0){
	  MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40mOuter ethernet layer check error!\033[0m\n");
	  inline_sendto_test_result(GTEST_SAPP_ERR);
	  exit(1);		  
	}   

	ret = check_ip_pkt_equal((struct ip *)(data+sizeof(struct ethhdr)), (struct ip *)(pkt_buf+sizeof(struct ethhdr)), 1, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40mOuter ip layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/* vxlan udp端口不变 */
	ret = check_udp_pkt_equal((struct udphdr *)(data+sizeof(struct ethhdr)+sizeof(struct ip)), (struct udphdr *)(pkt_buf+sizeof(struct ethhdr)+sizeof(struct ip)), 0, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40mOuter udp layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/******* 检查内层协议, 即实际会发送到公网的数据包地址 *********/
	const inline_vxlan_hdr_t *raw_vxlan_hdr = (inline_vxlan_hdr_t *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	const inline_vxlan_hdr_t *snd_vxlan_hdr = (inline_vxlan_hdr_t *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	ret = check_vxlan_pkt_equal(raw_vxlan_hdr, snd_vxlan_hdr, 1); /* 触发包是C2S方向, 发送的RST包是S2C方向  */
	if(ret < 0){ 
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40mvxlan hdr dir error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}
	const struct ethhdr *raw_eth_hdr = (struct ethhdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	const struct ethhdr *snd_eth_hdr = (struct ethhdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	ret = check_ethernet_pkt_equal(raw_eth_hdr, snd_eth_hdr, 1);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40minner ethernet layer check error, raw_src:%02x-%02x-%02x-%02x-%02x-%02x, raw_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 raw_eth_hdr->h_source[0],raw_eth_hdr->h_source[1],raw_eth_hdr->h_source[2],raw_eth_hdr->h_source[3],raw_eth_hdr->h_source[4],raw_eth_hdr->h_source[5],
			 raw_eth_hdr->h_dest[0],raw_eth_hdr->h_dest[1],raw_eth_hdr->h_dest[2],raw_eth_hdr->h_dest[3],raw_eth_hdr->h_dest[4],raw_eth_hdr->h_dest[5]);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40minner ethernet layer check error, snd_src:%02x-%02x-%02x-%02x-%02x-%02x, snd_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 snd_eth_hdr->h_source[0],snd_eth_hdr->h_source[1],snd_eth_hdr->h_source[2],snd_eth_hdr->h_source[3],snd_eth_hdr->h_source[4],snd_eth_hdr->h_source[5],
			 snd_eth_hdr->h_dest[0],snd_eth_hdr->h_dest[1],snd_eth_hdr->h_dest[2],snd_eth_hdr->h_dest[3],snd_eth_hdr->h_dest[4],snd_eth_hdr->h_dest[5]);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	
	const struct ip *raw_ip4_hdr = (struct ip *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr));
	const struct ip *snd_ip4_hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr));	
	ret = check_ip_pkt_equal(raw_ip4_hdr, snd_ip4_hdr, 1, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40minner IP layer check error, raw_src:%x, raw_dst:%x\033[0m\n", raw_ip4_hdr->ip_src.s_addr, raw_ip4_hdr->ip_dst.s_addr);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40minner IP layer check error, snd_src:%x, snd_dst:%x\033[0m\n", snd_ip4_hdr->ip_src.s_addr, snd_ip4_hdr->ip_dst.s_addr);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}
	
	const struct mesa_tcp_hdr *raw_tcp_hdr = (struct mesa_tcp_hdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip));
	const struct mesa_tcp_hdr *snd_tcp_hdr = (struct mesa_tcp_hdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip));	
	int tcp_payload_len = ntohs(raw_ip4_hdr->ip_len) - raw_ip4_hdr->ip_hl*4 - raw_tcp_hdr->th_off*4;
	
	ret = check_tcp_pkt_equal(raw_tcp_hdr, snd_tcp_hdr, 0x14, raw_tcp_hdr->th_ack, htonl(ntohl(raw_tcp_hdr->th_seq) + tcp_payload_len), 1); /* 反向发送, snd.seq = raw.ack, snd.ack=raw.seq+len */
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL,"s2c_rst_trigger_by_c2s","\033[1;31;40minner TCP layer check error, raw_src:%u, raw_dst:%u, snd_src:%u, snd_dst:%u, snd_flags:0x%x\033[0m\n",
				ntohs(raw_tcp_hdr->th_sport), ntohs(raw_tcp_hdr->th_dport), ntohs(snd_tcp_hdr->th_sport), ntohs(snd_tcp_hdr->th_dport), snd_tcp_hdr->th_flags);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	
	
	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO,"s2c_rst_trigger_by_c2s","\033[32mrecv sapp reinject S2C packet, check success!\033[0m\n");
	inline_sendto_test_result(GTEST_INLINE_TO_SAPP_SUCC);
	exit(0);

	return ;
}

static void __tcp_snd_c2s_rst_trigger_by_s2c_pkt_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	__tcp_snd_s2c_rst_trigger_by_c2s_pkt_cb(user, hdr, data);
}

/*
	TODO:
		这些函数大同小异, 都是检查某个数据包某个字段是什么值, 使用sapp_benchmark模式, 与tshark json对比.	
*/
static void __inline_inject_common_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	unsigned int this_pcap_src_ip_addr;
	const struct ip *ip4hdr;
	const struct ethhdr *ehdr;
	static int __inject_pkt_num = 0;
	const inline_mode_pcap_md5_tuple_t *this_pcap_md5_tuple = (inline_mode_pcap_md5_tuple_t *)user;
	int offset_to_inner_ip_layer;

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "inline_inject_common", "\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG, "inline_inject_common","write to device:%s succ, len=%d\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:

	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "inline_inject_common","\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	ehdr = (struct ethhdr *)pkt_buf;
	if(ETH_P_IP != ntohs(ehdr->h_proto)){
		printf("\033[1;31;40mrecv from device:'%s', but eth protocol is not IP\033[0m\n", GTEST_TAP_UP_DEV_NAME);
		goto read_again;
	}

	inet_pton(AF_INET, this_pcap_md5_tuple->keepalive_ip, &this_pcap_src_ip_addr);
	ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		printf("\033[1;31;40mrecv from %s, but src ip address is: %s, ecpect: %s\033[0m\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again;
	}

	__inject_pkt_num++;

	/******* vxlan开始的外层mac, ip颠倒方向, udp层不变 *********/
	ret = check_ethernet_pkt_equal((struct ethhdr *)(data), (struct ethhdr *)(pkt_buf), 1);
	if(ret < 0){
	 MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "inline_inject_common","\033[1;31;40mOuter ethernet layer check error!\033[0m\n");
	  inline_sendto_test_result(GTEST_SAPP_ERR);
	  exit(1);		  
	}	

	/* vxlan 外层ip地址颠倒 */
	ret = check_ip_pkt_equal((struct ip *)(data+sizeof(struct ethhdr)), (struct ip *)(pkt_buf+sizeof(struct ethhdr)), 1, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "inline_inject_common","\033[1;31;40mOuter ip layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/* vxlanudp端口不变 */
	ret = check_udp_pkt_equal((struct udphdr *)(data+sizeof(struct ethhdr)+sizeof(struct ip)), (struct udphdr *)(pkt_buf+sizeof(struct ethhdr)+sizeof(struct ip)), 0, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "inline_inject_common","\033[1;31;40mOuter udp layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	
	const void *raw_vxlan_net_hdr =  (void *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	const void *snd_vxlan_net_hdr =  (void *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	struct layer_addr_vxlan_private raw_mem_hdr, inject_mem_hdr;
	ret = check_vxlan_private_pkt_equal(raw_vxlan_net_hdr, snd_vxlan_net_hdr, &raw_mem_hdr, &inject_mem_hdr, this_pcap_md5_tuple->inject_reverse); 
	if(ret < 0){ 
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40mvxlan hdr check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	/******* 检查内层协议, 即实际会发送到公网的数据包地址 *********/
	if(0 == raw_mem_hdr.addr_public.C2S_vxlan_addr.link_type){ //ethernet
		const struct ethhdr *raw_eth_hdr = (struct ethhdr *)((char *)raw_vxlan_net_hdr + raw_mem_hdr.actual_total_len);
		const struct ethhdr *snd_eth_hdr = (struct ethhdr *)((char *)snd_vxlan_net_hdr + inject_mem_hdr.actual_total_len);
		ret = check_ethernet_pkt_equal(raw_eth_hdr, snd_eth_hdr, this_pcap_md5_tuple->inject_reverse);
		if(ret < 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40minner ethernet layer check error, raw_src:%02x-%02x-%02x-%02x-%02x-%02x, raw_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
				 raw_eth_hdr->h_source[0],raw_eth_hdr->h_source[1],raw_eth_hdr->h_source[2],raw_eth_hdr->h_source[3],raw_eth_hdr->h_source[4],raw_eth_hdr->h_source[5],
				 raw_eth_hdr->h_dest[0],raw_eth_hdr->h_dest[1],raw_eth_hdr->h_dest[2],raw_eth_hdr->h_dest[3],raw_eth_hdr->h_dest[4],raw_eth_hdr->h_dest[5]);
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40minner ethernet layer check error, snd_src:%02x-%02x-%02x-%02x-%02x-%02x, snd_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
				 snd_eth_hdr->h_source[0],snd_eth_hdr->h_source[1],snd_eth_hdr->h_source[2],snd_eth_hdr->h_source[3],snd_eth_hdr->h_source[4],snd_eth_hdr->h_source[5],
				 snd_eth_hdr->h_dest[0],snd_eth_hdr->h_dest[1],snd_eth_hdr->h_dest[2],snd_eth_hdr->h_dest[3],snd_eth_hdr->h_dest[4],snd_eth_hdr->h_dest[5]);
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	
		offset_to_inner_ip_layer = sizeof(inline_vxlan_hdr_t) + sizeof(struct ethhdr);
	}else if(0x08 == raw_mem_hdr.addr_public.C2S_vxlan_addr.link_type){ //PPP
		const struct layer_ppp_hdr * raw_ppp_hdr = (struct layer_ppp_hdr *)((char *)raw_vxlan_net_hdr + sizeof(inline_vxlan_hdr_t));
		const struct layer_ppp_hdr * snd_ppp_hdr = (struct layer_ppp_hdr *)((char *)snd_vxlan_net_hdr + sizeof(inline_vxlan_hdr_t));
		if(memcmp((void *)raw_ppp_hdr, (void *)snd_ppp_hdr, sizeof(struct layer_ppp_hdr)) != 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40mvxlan PPP layer check error!\033[0m\n");
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);				
		}
		offset_to_inner_ip_layer = sizeof(inline_vxlan_hdr_t) + sizeof(struct layer_ppp_hdr);
	}else if(0x0C == raw_mem_hdr.addr_public.C2S_vxlan_addr.link_type){ //HDLC
		const struct hdlc_net_hdr * raw_hdlc_hdr = (struct hdlc_net_hdr *)((char *)raw_vxlan_net_hdr + sizeof(inline_vxlan_hdr_t));
		const struct hdlc_net_hdr * snd_hdlc_hdr = (struct hdlc_net_hdr *)((char *)snd_vxlan_net_hdr + sizeof(inline_vxlan_hdr_t));
		if(memcmp((void *)raw_hdlc_hdr, (void *)snd_hdlc_hdr, sizeof(struct hdlc_net_hdr)) != 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40mvxlan HDLC layer check error!\033[0m\n");
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);				
		}
		offset_to_inner_ip_layer = sizeof(inline_vxlan_hdr_t) + sizeof(struct hdlc_net_hdr);
	}

	const unsigned char *raw_inner_ip_layer_hdr = ((unsigned char *)raw_vxlan_net_hdr + offset_to_inner_ip_layer);
	const unsigned char *snd_inner_ip_layer_hdr = ((unsigned char *)snd_vxlan_net_hdr + offset_to_inner_ip_layer);
	int ip_layer_hdr_offset;
	int ip_layer_payload_len;
	int ip_protocol;
	if(0x40 == (*raw_inner_ip_layer_hdr & 0xF0)){
		const struct ip *raw_ip4_hdr = (struct ip *)((char *)raw_vxlan_net_hdr + offset_to_inner_ip_layer);
		const struct ip *snd_ip4_hdr = (struct ip *)((char *)snd_vxlan_net_hdr + offset_to_inner_ip_layer);	
		ret = check_ip_pkt_equal(raw_ip4_hdr, snd_ip4_hdr, this_pcap_md5_tuple->inject_reverse, 0); //此处如果是发送rst, 不能和原始包比长度字段
		if(ret < 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40minner IP layer check error, raw_src:%x, raw_dst:%x\033[0m\n", raw_ip4_hdr->ip_src.s_addr, raw_ip4_hdr->ip_dst.s_addr);
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40minner IP layer check error, snd_src:%x, snd_dst:%x\033[0m\n", snd_ip4_hdr->ip_src.s_addr, snd_ip4_hdr->ip_dst.s_addr);
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
		ip_layer_hdr_offset = raw_ip4_hdr->ip_hl * 4;
		ip_layer_payload_len = ntohs(raw_ip4_hdr->ip_len) - raw_ip4_hdr->ip_hl*4;
		ip_protocol = raw_ip4_hdr->ip_p;
	}else{
		const struct ip6_hdr *raw_ip6_hdr = (struct ip6_hdr *)((char *)raw_vxlan_net_hdr + offset_to_inner_ip_layer);
		const struct ip6_hdr *snd_ip6_hdr = (struct ip6_hdr *)((char *)snd_vxlan_net_hdr + offset_to_inner_ip_layer);	
		ret = check_ipv6_pkt_equal(raw_ip6_hdr, snd_ip6_hdr, this_pcap_md5_tuple->inject_reverse, 0); //此处如果是发送rst, 不能和原始包比长度字段
		if(ret < 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40minner IPv6 layer check error, raw_src:, raw_dst:\033[0m\n");
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40minner IPv6 layer check error, snd_src:, snd_dst:\033[0m\n");
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}		
		ip_layer_hdr_offset = sizeof(struct ip6_hdr);
		ip_layer_payload_len = ntohs(raw_ip6_hdr->ip6_plen);
		ip_protocol = raw_ip6_hdr->ip6_nxt;
	}

	if(IPPROTO_TCP == ip_protocol){
		const struct mesa_tcp_hdr *raw_tcp_hdr = (struct mesa_tcp_hdr *)((char *)raw_inner_ip_layer_hdr + ip_layer_hdr_offset);
		const struct mesa_tcp_hdr *snd_tcp_hdr = (struct mesa_tcp_hdr *)((char *)snd_inner_ip_layer_hdr + ip_layer_hdr_offset);	
		int tcp_payload_len = ip_layer_payload_len - raw_tcp_hdr->th_off*4;
		int tcp_flags_plus_seq = 0;

		tcp_flags_plus_seq += tcp_payload_len;

		if((TH_SYN|TH_FIN) & raw_tcp_hdr->th_flags){
			tcp_flags_plus_seq += 1; //syn, fin是要多占一个序号的
		}
		
		if(0 == this_pcap_md5_tuple->inject_reverse){
			ret = check_tcp_pkt_equal(raw_tcp_hdr, snd_tcp_hdr, 0, ntohl(htonl(raw_tcp_hdr->th_seq)+tcp_flags_plus_seq), raw_tcp_hdr->th_ack, this_pcap_md5_tuple->inject_reverse); /* 同向发送, snd.seq = raw.ack, snd.ack=raw.seq+len */
		}else{
			ret = check_tcp_pkt_equal(raw_tcp_hdr, snd_tcp_hdr, 0, raw_tcp_hdr->th_ack, htonl(ntohl(raw_tcp_hdr->th_seq) + tcp_payload_len), this_pcap_md5_tuple->inject_reverse); /* 反向发送, snd.seq = raw.ack, snd.ack=raw.seq+len */
		}	
		if(ret < 0){
			MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40minner TCP layer check error, raw_src:%u, raw_dst:%u, snd_src:%u, snd_dst:%u, snd_flags:0x%x\033[0m\n",
					ntohs(raw_tcp_hdr->th_sport), ntohs(raw_tcp_hdr->th_dport), ntohs(snd_tcp_hdr->th_sport), ntohs(snd_tcp_hdr->th_dport), snd_tcp_hdr->th_flags);
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	
	}else{
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inline_inject_common","\033[1;31;40m inject common not support inner udp check!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}

	if(__inject_pkt_num >= this_pcap_md5_tuple->inject_pkt_trigger_threshold){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "inline_inject_common","\033[32m inject common check success!\033[0m\n");
		inline_sendto_test_result(GTEST_INLINE_TO_SAPP_SUCC);
		__inject_pkt_num = 0;
		exit(0);	
	}

}


static void __tcp_inject_rst_reverse_gre_v0(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	unsigned int this_pcap_src_ip_addr;
	const struct ip *ip4hdr;
	const struct ethhdr *ehdr;
	static int pkt_count = 0;
	int check_reverse;
	const inline_mode_pcap_md5_tuple_t *this_pcap_md5_tuple = (inline_mode_pcap_md5_tuple_t *)user;

	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0", "\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		printf("\033[32mwrite to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, hdr->caplen);
	}

read_again:

	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0", "\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	ehdr = (struct ethhdr *)pkt_buf;
	if(ETH_P_IP != ntohs(ehdr->h_proto)){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "__tcp_inject_rst_reverse_gre_v0","recv from device:'%s', but eth protocol is not IP\n", GTEST_TAP_UP_DEV_NAME);
		goto read_again;
	}

	pkt_count++;
	if(pkt_count <= 3){
		/* 对于pcap包gre_v0_reverse_inject.pcap来说, 前三个是回流回注, 同向检查;
		   第4个包才会触发一个反向RST */
		check_reverse = 0;
	}else{
		check_reverse = 1;
	}
	
	inet_pton(AF_INET, this_pcap_md5_tuple->keepalive_ip, &this_pcap_src_ip_addr);
	ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "__tcp_inject_rst_reverse_gre_v0","recv from %s, but src ip address is: %s, ecpect: %s\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again;
	}

	/******* vxlan开始的外层mac, ip颠倒方向, udp层不变 *********/
	//inner_payload_offset = sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr);
	//inner_payload_len = hdr->caplen - inner_payload_offset;

	ret = check_ethernet_pkt_equal((struct ethhdr *)(data), (struct ethhdr *)(pkt_buf), 1);
	if(ret < 0){
	 MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40mOuter ethernet layer check error!\033[0m\n");
	  inline_sendto_test_result(GTEST_SAPP_ERR);
	  exit(1);		  
	}	

	ret = check_ip_pkt_equal((struct ip *)(data+sizeof(struct ethhdr)), (struct ip *)(pkt_buf+sizeof(struct ethhdr)), 1, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40mOuter ip layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/* vxlan udp端口不变 */
	ret = check_udp_pkt_equal((struct udphdr *)(data+sizeof(struct ethhdr)+sizeof(struct ip)), (struct udphdr *)(pkt_buf+sizeof(struct ethhdr)+sizeof(struct ip)), 0, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40mOuter udp layer check error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);		
	}	

	/******* 检查内层协议, 即实际会发送到公网的数据包地址 *********/
	const inline_vxlan_hdr_t *raw_vxlan_hdr = (inline_vxlan_hdr_t *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	const inline_vxlan_hdr_t *snd_vxlan_hdr = (inline_vxlan_hdr_t *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr));
	ret = check_vxlan_pkt_equal(raw_vxlan_hdr, snd_vxlan_hdr, check_reverse); /* 触发包是C2S方向, 发送的RST包是S2C方向  */
	if(ret < 0){ 
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40mvxlan hdr dir error!\033[0m\n");
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}
	const struct ethhdr *raw_eth_hdr = (struct ethhdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	const struct ethhdr *snd_eth_hdr = (struct ethhdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t));
	ret = check_ethernet_pkt_equal(raw_eth_hdr, snd_eth_hdr, check_reverse);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40minner ethernet layer check error, raw_src:%02x-%02x-%02x-%02x-%02x-%02x, raw_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 raw_eth_hdr->h_source[0],raw_eth_hdr->h_source[1],raw_eth_hdr->h_source[2],raw_eth_hdr->h_source[3],raw_eth_hdr->h_source[4],raw_eth_hdr->h_source[5],
			 raw_eth_hdr->h_dest[0],raw_eth_hdr->h_dest[1],raw_eth_hdr->h_dest[2],raw_eth_hdr->h_dest[3],raw_eth_hdr->h_dest[4],raw_eth_hdr->h_dest[5]);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40minner ethernet layer check error, snd_src:%02x-%02x-%02x-%02x-%02x-%02x, snd_dst:%02x-%02x-%02x-%02x-%02x-%02x \033[0m\n",
			 snd_eth_hdr->h_source[0],snd_eth_hdr->h_source[1],snd_eth_hdr->h_source[2],snd_eth_hdr->h_source[3],snd_eth_hdr->h_source[4],snd_eth_hdr->h_source[5],
			 snd_eth_hdr->h_dest[0],snd_eth_hdr->h_dest[1],snd_eth_hdr->h_dest[2],snd_eth_hdr->h_dest[3],snd_eth_hdr->h_dest[4],snd_eth_hdr->h_dest[5]);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	
	const struct ip *raw_ip4_hdr = (struct ip *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr));
	const struct ip *snd_ip4_hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)); 
	ret = check_ip_pkt_equal(raw_ip4_hdr, snd_ip4_hdr, check_reverse, 0);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40minner IP layer check error, raw_src:%x, raw_dst:%x\033[0m\n", raw_ip4_hdr->ip_src.s_addr, raw_ip4_hdr->ip_dst.s_addr);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40minner IP layer check error, snd_src:%x, snd_dst:%x\033[0m\n", snd_ip4_hdr->ip_src.s_addr, snd_ip4_hdr->ip_dst.s_addr);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}

	/* skip gre header */
	const struct mesa_tcp_hdr *raw_tcp_hdr = (struct mesa_tcp_hdr *)(data + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip)+4/*grev0*/+sizeof(struct ip));
	const struct mesa_tcp_hdr *snd_tcp_hdr = (struct mesa_tcp_hdr *)(pkt_buf + sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct udphdr)+sizeof(inline_vxlan_hdr_t)+sizeof(struct ethhdr)+sizeof(struct ip)+4/*grev0*/+sizeof(struct ip));
	
	if(0 == check_reverse){
		ret = check_tcp_pkt_equal(raw_tcp_hdr, snd_tcp_hdr, 0, raw_tcp_hdr->th_seq, raw_tcp_hdr->th_ack, check_reverse); /* 反向发送, snd.seq = raw.ack, snd.ack=raw.seq+len */
	}else{
		ret = check_tcp_pkt_equal(raw_tcp_hdr, snd_tcp_hdr, 0, raw_tcp_hdr->th_ack, htonl(ntohl(raw_tcp_hdr->th_seq) + 20/*payload len*/), check_reverse); /* 反向发送, snd.seq = raw.ack, snd.ack=raw.seq+len */
	}
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "__tcp_inject_rst_reverse_gre_v0","\033[1;31;40minner TCP layer check error, raw_src:%u, raw_dst:%u, snd_src:%u, snd_dst:%u, snd_flags:0x%x\033[0m\n",
				ntohs(raw_tcp_hdr->th_sport), ntohs(raw_tcp_hdr->th_dport), ntohs(snd_tcp_hdr->th_sport), ntohs(snd_tcp_hdr->th_dport), snd_tcp_hdr->th_flags);
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	if(pkt_count >= 4){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "__tcp_inject_rst_reverse_gre_v0","\033[32minject_rst_reverse_gre_v0, check success!\033[0m\n");
		inline_sendto_test_result(GTEST_INLINE_TO_SAPP_SUCC);
		pkt_count = 0;
		exit(0);
	}
	
	return ;
}



/* 回放的数据包: for_gtest_only/performance/sapp_perf_test.pcap  */
#define PERF_TEST_PKT_NUM 168  
#define PERF_VOID_MAX_PKT_NUM  1000000
#define PERF_CONCURRENT_STREAM_NUM 10000
static int sapp_perf_init_flag = 0;
static void *sapp_perf_inject_pkt_array[PERF_TEST_PKT_NUM]; /* 每个包的内存指针 */
static int sapp_perf_inject_pkt_len_array[PERF_TEST_PKT_NUM]; /* 每个包的长度 */
static int sapp_perf_test_cur_num = 0; /* 当前收到的数据包数量 */

typedef struct{
	int pkt_seq; /* 当前队列回放到第几个包了, 即数组sapp_perf_inject_pkt_array[]下标 */
	unsigned sport;
	unsigned dport;
}pkt_modify_para_t;

static pkt_modify_para_t perf_test_concurrent_queue[PERF_CONCURRENT_STREAM_NUM];


static int __sapp_perf_gen_pkt_init(void)
{
	int i, j;

	for(i = 0; i < PERF_CONCURRENT_STREAM_NUM; i++){
		perf_test_concurrent_queue[i].pkt_seq = 0;
		perf_test_concurrent_queue[i].sport = (unsigned short)(1 + i);
		for(j = 0; j < PERF_CONCURRENT_STREAM_NUM/65535 + 1; i++, j++){ /* 如果超过了65535, 就得靠不同的dport区分了 */
			perf_test_concurrent_queue[i].dport = (unsigned short)(1 + j);
		}
	}
	
	return 0;
}
static void __sapp_perf_gen_pkt_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int i;
	int this_queue_index;
	int this_queue_pkt_seq;
	void *this_pkt_data;
	int this_pkt_len;
	struct tcphdr *thdr;

	if(0 == sapp_perf_init_flag){
		__sapp_perf_gen_pkt_init();
		sapp_perf_init_flag = 1;
	}

	sapp_perf_inject_pkt_array[sapp_perf_test_cur_num] = malloc(hdr->caplen);
	sapp_perf_inject_pkt_len_array[sapp_perf_test_cur_num] = hdr->caplen;
	memcpy(sapp_perf_inject_pkt_array[sapp_perf_test_cur_num], data, hdr->caplen);

	sapp_perf_test_cur_num++;
	
	if(sapp_perf_test_cur_num < PERF_TEST_PKT_NUM-1){
		return;
	}

	/* 循环回放PERF_VOID_MAX_PKT_NUM个数据包 */
	for(i = 0; i < PERF_VOID_MAX_PKT_NUM; i++){
		/* 并发流量每次发出的流四元组不一样且随机, 模拟真实环境, 
		   而不是一个流完全结束后再处理下一个流 */
		this_queue_index = rand() % PERF_CONCURRENT_STREAM_NUM;
		if(perf_test_concurrent_queue[this_queue_index].pkt_seq > PERF_TEST_PKT_NUM-1){
			perf_test_concurrent_queue[this_queue_index].pkt_seq = 0; /* 重新从0开始 */
		}
		
		this_queue_pkt_seq = perf_test_concurrent_queue[this_queue_index].pkt_seq;
		this_pkt_data = sapp_perf_inject_pkt_array[this_queue_pkt_seq];
		this_pkt_len = sapp_perf_inject_pkt_len_array[this_queue_pkt_seq];

		thdr = (struct tcphdr *)((char *)this_pkt_data + sizeof(struct ethhdr) + sizeof(struct ip));

		/* 每次重新修改数据包的端口为当前队列的初始特定值, 其他属性不变 */
		thdr->source = perf_test_concurrent_queue[this_queue_index].sport;
		thdr->dest = perf_test_concurrent_queue[this_queue_index].dport;

		write(g_replay_pkt_to_sapp_fd, this_pkt_data, this_pkt_len);
		
		perf_test_concurrent_queue[this_queue_index].pkt_seq++;
	}
	printf("\033[32mwrite to device:%s succ, tot pkt num:%d\033[0m\n", GTEST_TAP_UP_DEV_NAME, PERF_VOID_MAX_PKT_NUM);

	/* 循环结束, 要把所有队列的包都清空 */
	for(i = 0; i < PERF_CONCURRENT_STREAM_NUM;i++){
		while(perf_test_concurrent_queue[i].pkt_seq != PERF_TEST_PKT_NUM-1){
			this_queue_pkt_seq = perf_test_concurrent_queue[i].pkt_seq;
			this_pkt_data = sapp_perf_inject_pkt_array[this_queue_pkt_seq];
			this_pkt_len = sapp_perf_inject_pkt_len_array[this_queue_pkt_seq];	
			thdr = (struct tcphdr *)((char *)this_pkt_data + sizeof(struct ethhdr) + sizeof(struct ip));
			thdr->source = perf_test_concurrent_queue[i].sport;
			thdr->dest = perf_test_concurrent_queue[i].dport;			
			write(g_replay_pkt_to_sapp_fd, this_pkt_data, this_pkt_len);
			perf_test_concurrent_queue[i].pkt_seq++;
		}
	}
	
	printf("\033[32mclear all pkt queue.\033[0m\n");
}


static void reinject_sapp_send_pkt(char *pkt_buf, int pkt_len)
{
	struct ethhdr *outer_ehdr;
	struct ip *outer_ip4hdr;
	int ret;
	char no_used_buf[GTEST_DEV_MTU];

	/* dup测试插件会注入一个数据包, 负载内容:"test_inject_dup_payload string",  此时再将sapp注入的包给sapp, 造成注入数据包有重复流量的假象 */
	if(memmem(pkt_buf, GTEST_DEV_MTU, "test_inject_dup_payload string", strlen("test_inject_dup_payload string")) != NULL){
		/* 将外层mac, ip地址翻转, 否则inline模式下不符合规范 */
		unsigned char mactmp[ETH_ALEN];
		outer_ehdr = (struct ethhdr *)pkt_buf;
		outer_ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
		
		memcpy(mactmp, outer_ehdr->h_source, ETH_ALEN);
		memcpy(outer_ehdr->h_source, outer_ehdr->h_dest, ETH_ALEN);
		memcpy(outer_ehdr->h_dest, mactmp, ETH_ALEN);
		
		unsigned int iptmp = outer_ip4hdr->ip_src.s_addr;
		outer_ip4hdr->ip_src.s_addr = outer_ip4hdr->ip_dst.s_addr;
		outer_ip4hdr->ip_dst.s_addr = iptmp;

		ret = write(g_replay_pkt_to_sapp_fd, pkt_buf, pkt_len);
		if(ret < 0){
			printf("\033[1;31;40msend inject packet to sapp error: %s\033[0m\n", strerror(errno));
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}else{
			printf("\033[32mwrite inject pkt to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, ret);
		}	

read_again:

		ret = read(g_replay_pkt_to_sapp_fd, no_used_buf, GTEST_DEV_MTU);
		if(ret < 0){
			if(EINTR == errno){
				goto read_again;
			}
			printf("\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
			inline_sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	
	
	}

}


static void __inject_dup_pkt_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int ret;
	char pkt_buf[GTEST_DEV_MTU];
	unsigned int this_pcap_src_ip_addr;
	struct ip *outer_ip4hdr;
	const inline_mode_pcap_md5_tuple_t *this_pcap_md5_tuple = (inline_mode_pcap_md5_tuple_t *)user;

	inet_pton(AF_INET, this_pcap_md5_tuple->keepalive_ip, &this_pcap_src_ip_addr);
	
	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "inject_dup_pkt", "\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		printf("\033[32mwrite to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, ret);
	}

	usleep(10000); /* 避免此处回放包太快, sapp还没来得及注入包 */
read_again:

	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again;
		}
		printf("\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	outer_ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(outer_ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &outer_ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		printf("\033[1;31;40mrecv from %s, but src ip address is: %s, ecpect: %s\033[0m\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again;
	}
	

	reinject_sapp_send_pkt(pkt_buf, ret);
		

	/* 每个包重复注入两次, 让sapp以为有重复流量 */
	ret = write(g_replay_pkt_to_sapp_fd, data, hdr->caplen);
	if(ret < 0){
		printf("\033[1;31;40msend packet to sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}else{
		printf("\033[32mwrite to device:%s succ, len=%d!\033[0m\n", GTEST_TAP_UP_DEV_NAME, ret);
	}

	usleep(10000); /* 避免此处回放包太快, sapp还没来得及注入包 */
	
read_again2:
	/* 每个包重复注入两次, 让sapp以为有重复流量, 此处也要重复读两次 */
	ret = read(g_replay_pkt_to_sapp_fd, pkt_buf, GTEST_DEV_MTU);
	if(ret < 0){
		if(EINTR == errno){
			goto read_again2;
		}
		printf("\033[1;31;40mrecv from sapp error: %s\033[0m\n", strerror(errno));
		inline_sendto_test_result(GTEST_SAPP_ERR);
		exit(1);
	}	

	outer_ip4hdr = (struct ip *)(pkt_buf + sizeof(struct ethhdr));
	/* 新的tap设备创建后, 有可能会收到一些广播、组播等包, IPv6 router solicitation等包, 丢弃 */
	if(outer_ip4hdr->ip_src.s_addr != this_pcap_src_ip_addr){
		char tmp_ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &outer_ip4hdr->ip_src.s_addr, tmp_ip_str, sizeof(tmp_ip_str));
		printf("\033[1;31;40mrecv from %s, but src ip address is: %s, ecpect: %s\033[0m\n", 
				GTEST_TAP_UP_DEV_NAME, tmp_ip_str, this_pcap_md5_tuple->keepalive_ip);
		goto read_again2;
	}
	
	reinject_sapp_send_pkt(pkt_buf, ret);

}


/*
	不同的数据包对应不同的测试用例, 使用一个数组来保存数据包md5和相关处理函数的对应关系.

	TODO:
		这些函数大同小异, 都是检查某个数据包某个字段是什么值, 使用sapp_benchmark模式, 与tshark json对比.	
*/
static inline_mode_pcap_md5_tuple_t pcap_md5_tuple[] = 
{
	{"e588fef2066daa25ffe0e61ab5586728","172.26.70.1",  0, 1,GTEST_RESULT_NONE,			__inline_inject_common_cb, 					"测试基本的inline模式注入包, HDLC"},
	{"509e6213660f2c33964db8dd7c348917","172.26.70.1",  0, 1,GTEST_RESULT_NONE,			__inline_inject_common_cb, 					"测试基本的inline模式注入包, PPP"},
	{"ff0aac8961b4cd660894304fd38d7d71","192.168.1.14", 1, 1,GTEST_RESULT_NONE,			__inline_inject_common_cb,					"测试基本的inline模式注入包, ipv6"},
	{"2d930e391d57b8e4e930eec5a234aaba","10.3.36.1",	0,1,GTEST_RESULT_NONE, 			__tcp_flow_forward_cb,						"测试tcp基本回流回注功能"},
	{"508e10b7af3ad4bac49868d9610d550b","10.3.36.1",	0,1,GTEST_RESULT_NONE, 			__tcp_snd_c2s_rst_trigger_by_c2s_pkt_cb,	"测试C2S包触发的tcp c2s rst注入功能,默认是SUCC,如果失败,业务插件会发出错误结果"},
	{"a53c8674fbe467b86256b9911c66361f","10.3.36.1",	0,1,GTEST_RESULT_NONE, 			__tcp_snd_s2c_rst_trigger_by_s2c_pkt_cb, 	"测试S2C包触发的tcp s2c rst注入功能"},
	{"8da13608354898e2af3f34547a0d54fa","10.3.36.1",	1,1,GTEST_RESULT_NONE, 			__tcp_snd_s2c_rst_trigger_by_c2s_pkt_cb,	"测试C2S包触发的tcp s2c rst注入功能"},
	{"25a94fb48a2cdb568a5561d60a2f72b3","10.3.36.1",	1,1,GTEST_RESULT_NONE, 			__tcp_snd_c2s_rst_trigger_by_s2c_pkt_cb,	"测试S2C包触发的tcp c2s rst注入功能"},
	{"48126d760155589618c523050148475d","10.3.36.1",	0,1,GTEST_INLINE_TO_SAPP_SUCC, __inline_pkt_drop_test_cb,					"测试插件返回DROP动作是否正确"},
	{"3153c45408e8b18b49ffda62b08e341e","10.3.36.1",	0,1,GTEST_RESULT_NONE, 		   __tcp_flow_forward_cb,						"测试插件字节数统计, 复用基本回流回注函数,此处不发送结果,在sapp plug中发送检查结果"},
	{"24fd87627aa8c240530982cdeb1b40ab","10.3.36.1",	0,1,GTEST_RESULT_NONE,			__tcp_flow_forward_cb,						"测试vxlan头部各个字段的解析功能"	},
	{"87f99936b70f415b81e665204a841ac3","10.3.36.1",	0,1,GTEST_RESULT_NONE, 			__inline_pkt_common_cb,						"测试polling接口的无包超时淘汰功能"	},
	{"abbaa9255a5df0573e41eec1477a11eb","10.3.36.1",	0,1,GTEST_RESULT_NONE,			__sapp_perf_gen_pkt_cb, 					"测试sapp处理性能"},
	{"ba1aaa9eefc8e026509ce185369ee8c9","10.3.36.1",	0,1,GTEST_RESULT_NONE,			__tcp_flow_forward_cb, 						"测试非对称vxlan外层地址处理功能,要判断插件返回值的,此处默认结果为NONE"},
	{"2808e7b99ed7680b22f370aa6621da2a","10.3.36.1",	0,1,GTEST_RESULT_NONE,			__inject_dup_pkt_cb,						"测试注入数据包重复流量功能, ipv4_tcp"},
	{"8c66d7544a6c931d956c15249f401923","10.3.36.1",	0,1,GTEST_RESULT_NONE,			__inject_dup_pkt_cb,						"测试注入数据包重复流量功能, ipv6_tcp"},
	{"0f6dbdc4f65b98c7fd2e95c812b26d87","10.3.36.1",	0,1,GTEST_RESULT_NONE,			__inject_dup_pkt_cb,						"测试注入数据包重复流量功能, ipv4_udp"},
	{"f109d211904245ea55a0ba8b92fd7233","10.3.36.1",	0,1,GTEST_RESULT_NONE,			__inject_dup_pkt_cb,						"测试注入数据包重复流量功能, ipv6_udp"},
	{"6f24d4d3f3c13c925afae812f0114626","192.168.1.10",	1,1,GTEST_SAPP_ERR, 			__tcp_inject_rst_reverse_gre_v0,			"测试GREv0反向发送RST包功能, 有可能发送失败, 默认结果是ERR"},
	{NULL, NULL, 0,0,GTEST_RESULT_NONE, NULL, NULL}
};

static void inline_test_run(const char *pcap_filename)
{
	int i;

	for(i = 0; pcap_md5_tuple[i].pcap_file_md5 != NULL; i++){
		if(strncasecmp((char *)g_pcap_file_md5sum, (char *)pcap_md5_tuple[i].pcap_file_md5, strlen(pcap_md5_tuple[i].pcap_file_md5)) == 0){
			gtest_inline_mode_result_flag = pcap_md5_tuple[i].default_check_result;
			pcap_loop(g_pcap_handle, -1, pcap_md5_tuple[i].pcap_callback, (unsigned char *)&pcap_md5_tuple[i]);
			break;
		}
	}

	/* 不关心串联返回包情况的插件, 只注入数据包即可 */
	if(NULL == pcap_md5_tuple[i].pcap_file_md5){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "gtest_inline_env", "not found pcap file:%s in md5 table, use default function: __inline_pkt_common_cb() ", pcap_filename);
		gtest_inline_mode_result_flag = GTEST_RESULT_NONE;
		pcap_loop(g_pcap_handle, -1, __inline_pkt_common_cb, (unsigned char *)&pcap_md5_tuple[i]);
	}

	if(gtest_inline_mode_result_flag != GTEST_RESULT_NONE){
		inline_sendto_test_result(gtest_inline_mode_result_flag);
	}

	/* 回放包完成后, 可能sapp还没来得及处理, 稍等一会再退出 */
	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "gtest_inline_env", "inline env process sleep for %dms", g_timer_ms);
	usleep(g_timer_ms * 1000);
	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "gtest_inline_env", "inline env process exited!");
	exit(0);
}



int main(int argc, char *argv[])
{
	pthread_t pid;
	
	MESA_handle_runtime_log_creation("./etc/sapp_log.conf");
	g_inline_env_log_handle = MESA_create_runtime_log_handle("./log/gtest_inline_env.log", RLOG_LV_DEBUG);
	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "gtest_inline_env", "--------------------main() starting -------------------\n");
	
	if(argc > 3 || argc <= 1){
		inline_env_usage(argv[0]);
	}

	if(argc == 3){
		g_timer_ms = atoi(argv[2]) * 1000;
	}else{
		g_timer_ms = 1000 * 10;
	}

	srand(time(NULL));

	if(inline_env_init(argv) < 0){
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_FATAL, "gtest_inline_env", "inline_env_init() error!");
		printf("inline_env_init() error!\n");
		return -1;
	}

	gtest_file_md5sum(argv[1], (char *)g_pcap_file_md5sum, sizeof(g_pcap_file_md5sum));

	gtest_inline_mode_result_flag = GTEST_SAPP_ERR;

	signal(SIGPIPE, inline_sig_handler);
	pthread_create(&pid, NULL, inline_thread_timer, NULL);

	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "gtest_inline_env", "init success, wait sapp starting....");
	
	while(1){
		if(wait_for_sapp_running() == 1){
			break;
		}
		usleep(1000 * 100);
		MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_DEBUG, "gtest_inline_env", "sapp not running, waiting....");
	}
	sleep(1);//测试发现, 立即回放包, sapp可能还没真正运行起来, 此处先sleep一会. TODO!!
	MESA_handle_runtime_log(g_inline_env_log_handle, RLOG_LV_INFO, "gtest_inline_env", "program starting, pcap_file:%s, timeout is %dms", argv[1], g_timer_ms);
	inline_test_run(argv[1]);

	return 0;
}

