#include "sapp_api.h"
#include "sapp_private_api.h"
#include "support/MESA_socket_wrap.h"

/*
	2015-04-15 , LiJia.
	新增cycle_pkt_dump功能, 
	   	可以实时循环存储数据包，目的是解决在线环境程序意外挂掉，只留下一个core, 但BUG无法重现问题.
		sapp意外coredump后， 'pkt_dump_file_root_dir'目录会存储最近一段时间收到的包, 
		再用读包模式重现，极有可能发现BUG真正根源，
		如果还不能重现，将pkt_dump_file_max_size适当调大一些.
	   
	main.conf中新增1个新的section和5个独立配置项:
	    [pkt_dump]
	    pkt_dump_switch=0                 //总开关 
	    pkt_dump_total_size=1000		 //root_dir总计.pcap文件的大小, 单位:MB, 防止程序因贫富从起而写满硬盘
	    pkt_dump_file_max_size=200        //pcap文件每个线程可用最大值, 单位:MB.
	    pkt_dump_file_root_dir=/dev/shm  //pcap存储路径,  推荐/dev/shm, 比硬盘速度快很多 
	    pkt_dump_thread_seq=0,2,4,6,8    //每个线程的开关，因为在线流量可能巨大，无法全部存储，那就碰碰运气，只启用部分线程的dump功能 , all=全开启
	
*/

#ifdef __cplusplus
extern "C" {
#endif


#define UNIX_DOMAIN_SOCKET_NAME	"/tmp/.pktdump"
#define PKT_DUMP_PROCESS_NAME	"sapp_pkt_dump"

extern iknow_handle PLATFORM_IHANDLE;

#if DEBUG
#include "iknow.h"

typedef struct{
	unsigned long long total_pkt_num;
	unsigned long long total_pkt_bytes;
	unsigned long long discard_pkt_num;
	unsigned long long discard_pkt_bytes;
	char __pad__[32]; /* 64字节cache对齐 */
}pkt_dump_status_t;
static pkt_dump_status_t PKT_DISCARD_STAT[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM]; /* 独立发包线程, tcpdump_mesa模式为INJECT时也要捕包 */

#endif

const int tcpdump_mesa_version_VERSION_20190820 = 20190820;

extern int g_use_MESA_sleep_sw;
extern void MESA_sleep(void);
extern int MESA_mkdir_p(const char *pathname, mode_t mode);
//extern time_t g_CurrentTime;
//extern int g_packet_io_thread_num;
//extern int g_iThreadNum; /* for dual_stack, start */
static char G_PKT_DUMP_ROOT_DIR[PATH_MAX]; /* 可以指定为/dev/shm, 速度快 */
static long G_PKT_DUMP_FILE_SIZE = 104857600; /* 默认100MB, 单线程 */
int G_PKT_DUMP_SW = 0; /* 默认关闭 */
int G_PKT_DUMP_MODE = PKT_DUMP_LOCAL_FILE; /* 默认是写到本地文件 */
static int G_PKT_DUMP_PER_THREAD_SW[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM];

static int pkt_dump_thread_num = 1;

static FILE *G_PKT_DUMP_FP[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM];
static int G_FILENAME_INDEX[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM];
static long G_PCAP_SIZE[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM];
static char G_PKT_DUMP_FILTER_STR[PATH_MAX];

static struct bpf_program G_PKT_DUMP_BPF_FILTER[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM];
static unsigned short pkt_dump_data_offset = 0; /* 捕包时可指定偏移量, 用于vxlan环境下捕获内层数据包 */
static unsigned short pkt_dump_tcp_bind_port = 12345; /* 默认TCP监听端口, 用于接收外部tcpdump命令 */
static int pkt_dump_tcp_cmd_sd = -1;/* TCP fd,  用于接收外部tcpdump命令 */
static volatile int pkt_dump_udp_socket_peer_alive = 0; /* 外部tcpdump是否存活 */
static int pkt_dump_udp_pkt_sd[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM]; /* UDP发送数据包fd */
static struct sockaddr_in udp_recv_addr;
static int tcpdump_perceptive_flag = 0; /* 明察秋毫模式, 可以发现丢包数量 */	
static int greedy_seek_flag = 0; /* 偏移到最内层IP, 便于隧道模式下查找BUG */
static int tcpdump_mesa_pkt_classify = PKT_CLASSIFY_IN;
static int pkt_classify_watermark_flag = 0; /* 保存捕包来源值到dmac, 便于分别数据包来源 */

static unsigned char phony_mac_hdr[14] = 
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0x12, 0x23, 0x34, 0x56, 0x67, 0x78,
	0x08, 0x00
};


/* 在线大流量环境下, 未指定过滤条件, 会通过sendto发送大量数据包, 引发sapp丢包, 所以设置采样比率 */
typedef struct{
	int sample_pkt_num;
	unsigned int perceptive_mode_pkt_seq;
	char __cache_alignment[56];
}pkt_dump_mthread_t;

static pkt_dump_mthread_t pkt_dump_mthread_info[MAX_THREAD_NUM+INDEPENDENT_SEND_QUEUE_MAX_NUM];

static int raw_cfg_pkt_dump_ratio = 30; /* 全局默认捕包采样率, 表示每隔N个包捕获一次, 防止大流量下tcpdump_mesa导致平台丢包 */
static int cur_conn_pkt_dump_ratio = 30; /* 当前连接的捕包采样率, 如果设置了host, port等bpf参数, 则为全捕包模式, debug排错用 */


typedef struct  {
	unsigned int magic;
	unsigned short version_major;
	unsigned short version_minor;
	unsigned int thiszone;	/* gmt to local correction */
	unsigned int sigfigs;	/* accuracy of timestamps */
	unsigned int snaplen;	/* max length saved portion of each pkt */
	unsigned int linktype;	/* data link type (LINKTYPE_*) */
}pkt_dump_file_hdr_t;

struct pkt_dump_timeval {
	unsigned int tv_sec;     /* seconds */
	unsigned int tv_usec;    /* microseconds */
};

typedef struct {
	struct pkt_dump_timeval ts;	/* time stamp */
	unsigned int caplen;	/* length of portion present */
	unsigned int len;	/* length this packet (off wire) */
}pkt_dump_pkt_hdr_t;

typedef struct{
	enum addr_type_t low_layer_type;	/* 原始包最底层协议的类型, 可能是MAC(pcap捕包), 也可能是IPv4(pag捕包) */
	int raw_pkt_len;		/* 原始包总长度 */
	//char pkt_data[];
}pkt_dump_pipe_t;


static const pkt_dump_file_hdr_t pfile_hdr = 
{
	0xA1B2C3D4,
	0x0002, 
	0x0004,
	0,
	0,
	0xFFFF,
	1
};

/* reliable read */
static inline ssize_t Rread(int fd, void *buf, size_t expect_count)
{
	ssize_t ret;
	void *save_ptr = buf;
	size_t left_count = expect_count;
	
	while(left_count > 0){
retry:
		ret = read(fd, save_ptr, left_count);
		if(ret < 0){
			switch(errno){
				case EAGAIN:
					if(0 == g_use_MESA_sleep_sw){
						sapp_usleep(1);
					}else{
						MESA_sleep();
					}	
					/* no break here!!!  no break here!!! no break here!!!*/
				case EINTR:
					goto retry;
				break;

				default:
					sapp_runtime_log(20, "pkt dump, read error:%s, ptr=%p, expect_count=%lu, left_count=%lu\n", 
						  strerror(errno), save_ptr, expect_count, left_count);
				break;
			}
		}else if(0 == ret){
			return 0; /* peer close */
		}else{
			save_ptr = (char *)save_ptr + ret;
			left_count -= ret;
		}
	}

	return expect_count - left_count;
}

/* reliable write */
static inline ssize_t Rwrite(int fd, const void *buf, size_t expect_count)
{
	ssize_t ret;
	const void *real_ptr = buf;
	size_t left_count = expect_count;

	while(left_count > 0){
retry:
		ret = write(fd, real_ptr, left_count);
		if(ret < 0){
			switch(errno){
				case EINTR:
					goto retry;
				break;

				default:
					sapp_runtime_log(20, "pkt dump, write error:%s\n", strerror(errno));
					/* 写端如果因空间不足, 不能重试, 否则会影响正常包处理流程 */
				break;
			}		
		}else{
			real_ptr = (const char *)real_ptr + ret;
			left_count -= ret;
		}
	}

	return expect_count - left_count;
}

#if 0
static void *cycle_pkt_dump_check_father(void *arg)
{
	while(1){
		if(1 == getppid()){ /* 父进程变为init, 说明主进程已经退出 */
			exit(1);
		}else{
			sapp_usleep(100000);
		}
	}

	return NULL;
}


static void *cycle_pkt_dump_thread(void *arg)
{
	int thread_seq = *((int *)arg);
	FILE *fp;
	int file_name_post_prefix = 0, ret, pfile_hdr_flag = 0;
	long tot_pcap_file_len = 0;
	char pkt_buf[65536];
	char dump_file_name[PATH_MAX];
	pkt_dump_pkt_hdr_t *ppkt_hdr;
	int pkt_len;
	int skip_pkt_hdr_len; /* 预留包头部空间长度, 根据捕包模式不同, 可能会包含Eth层 */

	snprintf(dump_file_name, PATH_MAX, "%s/pid_%d.tid_%d.%d.pcap", 
			G_PKT_DUMP_ROOT_DIR, getpid(), thread_seq, file_name_post_prefix);
	fp = fopen(dump_file_name, "w+"); 		
	if(NULL == fp){
		printf("fopen %s error!\n", dump_file_name);
		goto done;
	}
	ppkt_hdr = (pkt_dump_pkt_hdr_t *)pkt_buf;
	ppkt_hdr->ts.tv_usec = 0;
#ifdef CAPTURE_MODE_PAG
	memcpy(pkt_buf+sizeof(pkt_dump_pkt_hdr_t), phony_mac_hdr, 14);
	skip_pkt_hdr_len = sizeof(pkt_dump_pkt_hdr_t) + 14;
#else
	skip_pkt_hdr_len = sizeof(pkt_dump_pkt_hdr_t);
#endif
	while(1){
		/* 将pcap包头部空间预留, 这样只需一次fwrite, 就将头部和数据一次写入 */
		pkt_len = read(G_UNIX_DOMAIN_SD[thread_seq], (char *)pkt_buf+skip_pkt_hdr_len, 2048);
		if(0 == pkt_len){
			goto done;
		}else if(pkt_len < 0){
			continue;
		}

		/* pcap file header, first time */
		if(0 == pfile_hdr_flag){
			fwrite(&pfile_hdr, sizeof(pkt_dump_file_hdr_t), 1, fp);
			tot_pcap_file_len += sizeof(pkt_dump_file_hdr_t);
			pfile_hdr_flag = 1;
		}
		/* 更新包长度, 时间戳 */
		ppkt_hdr->ts.tv_sec = (unsigned int )g_CurrentTime;
#ifdef CAPTURE_MODE_PAG
		ppkt_hdr->caplen = pkt_len+14;
		ppkt_hdr->len = pkt_len+14;
#else
		ppkt_hdr->caplen = pkt_len;
		ppkt_hdr->len = pkt_len;
#endif

		fwrite(pkt_buf, pkt_len+skip_pkt_hdr_len, 1, fp);
		tot_pcap_file_len += pkt_len+skip_pkt_hdr_len;

		/* 超过最大限制, 循环写文件 */
		if(tot_pcap_file_len >= G_PKT_DUMP_FILE_SIZE){
			fclose(fp);
			file_name_post_prefix = file_name_post_prefix ^ 1;
			snprintf(dump_file_name, PATH_MAX, "%s/pid_%d.tid_%d.%d.pcap", 
					G_PKT_DUMP_ROOT_DIR, getpid(), thread_seq, file_name_post_prefix);
			fp = fopen(dump_file_name, "w+"); /* cycle write two files */
			if(NULL == fp){
				printf("fopen %s error!\n", dump_file_name);
				goto done;	
			}
			tot_pcap_file_len = 0;
			pfile_hdr_flag = 0;
		}
	}
	
done:

	return NULL;
}
#endif

static inline int cycle_pkt_dump_sample_by_ratio(int thread_seq)
{
	if(pkt_dump_mthread_info[thread_seq].sample_pkt_num++ >= cur_conn_pkt_dump_ratio){
		pkt_dump_mthread_info[thread_seq].sample_pkt_num = 0;
		return 1;
	}

	return 0;
}

extern char *timet_to_str(time_t timet, char *time_str, int time_str_len);
static char udp_start_time_str[64];
static long long tot_udp_send_succ_num = 0; /* sendto成功数量 */
static long long tot_udp_send_err_num = 0; /* 发送错误数量, 如缓存满等原因 */
static long long tot_udp_send_willful_discard_num = 0; /* 主动丢弃数量 */


/* 
	为了DEBUG方便, 支持过滤最内层的四元组, 但tcpdump -w 存储的包还是整个带隧道完整的数据包.
	
	return value:
		>=0: 符合条件, 输出给tcpdump_mesa;
		 <0: 不符合bpf条件, 或不符合采样条件, 丢弃.
*/
static int cycle_pkt_dump_seek_to_inner_ip(char *pkt_buf, int pktlen, int thread_seq)
{
	struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)pkt_buf;
	char *first_ip_layer = NULL;
	struct mesa_ip4_hdr *ip4hdr_greedy;
	struct mesa_ip6_hdr *ip6hdr_greedy;
	int bpf_match_pkt_len = -1;
	int bpf_match_ipv4 = 0, bpf_match_ipv6 = 0;

	if(ETHERTYPE_IP == ntohs(ehdr->ether_type)){
		first_ip_layer = pkt_buf + sizeof(struct mesa_ethernet_hdr);
	}else if(ETHERTYPE_IPv6 == ntohs(ehdr->ether_type)){
		first_ip_layer = pkt_buf + sizeof(struct mesa_ethernet_hdr);
	}else{
		first_ip_layer = NULL;
	}
	
	ip4hdr_greedy = (struct mesa_ip4_hdr *)MESA_net_jump_to_layer_greedy(pkt_buf, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V4);
	if(ip4hdr_greedy){
		if((char *)ip4hdr_greedy == first_ip_layer){
			bpf_match_pkt_len = pktlen; /* 最内层和第一层IP一样, 说明是标准ethernet->IPv4包, 无需memmove操作 */
		}else{
			if(pktlen <= ((char *)ip4hdr_greedy - pkt_buf)){
				return -1; /* 因各种不明原因, 跳转的内层包头溢出了, 错误!! */
			}				
			memmove(pkt_buf + sizeof(struct mesa_ethernet_hdr),
			        ip4hdr_greedy,
			        pktlen - ((char *)ip4hdr_greedy - pkt_buf));
			bpf_match_pkt_len = pktlen - ((char *)ip4hdr_greedy - pkt_buf) + sizeof(struct mesa_ethernet_hdr);
			ehdr->ether_type = htons(ETHERTYPE_IP); /* 第一层可能不是IPV4, 比如MPLS, VLAN等, 需要改成IP, 以便bpf过滤器能正确执行 */
		}

		if(bpf_match_pkt_len <= 0){
			sapp_runtime_log(20, "cycle_pkt_dump_seek_to_inner_ip() length error!\n");
			return -1;
		}
		
		/* 如果有正确的过滤条件, 不设采样率, 保证捕包尽量全, 符合调用者意图;
	       如果没有过滤条件, 即全捕包模式, 为了尽量不影响包处理线程, 根据采样率只捕一部分包.
		*/
		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
			bpf_match_ipv4 = bpf_filter(G_PKT_DUMP_BPF_FILTER[thread_seq].bf_insns, 
						    (const unsigned char *)pkt_buf, (unsigned int)bpf_match_pkt_len, (unsigned int)bpf_match_pkt_len);
		}
	}else{
		bpf_match_ipv4 = 0;
	}

	ip6hdr_greedy = (struct mesa_ip6_hdr *)MESA_net_jump_to_layer_greedy(pkt_buf, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V6);
	if(ip6hdr_greedy){
		if((char *)ip6hdr_greedy == first_ip_layer){
			bpf_match_pkt_len = pktlen; /* 最内层和第一层IP一样, 说明是标准ethernet->IPv6包, 无需memmove操作 */
		}else{
			if(pktlen <= ((char *)ip4hdr_greedy - pkt_buf)){
				return -1; /* 因各种不明原因, 跳转的内层包头溢出了, 错误!! */
			}			
			memmove(pkt_buf + sizeof(struct mesa_ethernet_hdr),
			        ip6hdr_greedy,
			        pktlen - ((char *)ip6hdr_greedy - pkt_buf));
			bpf_match_pkt_len = pktlen - ((char *)ip4hdr_greedy - pkt_buf) + sizeof(struct mesa_ethernet_hdr);
			ehdr->ether_type = htons(ETHERTYPE_IPv6); /* 第一层可能不是IPV6, 比如MPLS, VLAN等,需要改成IP,以便bpf过滤器能正确执行 */
		}

		if(bpf_match_pkt_len <= 0){
			sapp_runtime_log(20, "cycle_pkt_dump_seek_to_inner_ip() length error!\n");
			return -1;
		}
		

		/* 如果有正确的过滤条件, 不设采样率, 保证捕包尽量全, 符合调用者意图;
	       如果没有过滤条件, 即全捕包模式, 为了尽量不影响包处理线程, 根据采样率只捕一部分包.
		*/
		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
			bpf_match_ipv6 = bpf_filter(G_PKT_DUMP_BPF_FILTER[thread_seq].bf_insns, 
						    (const unsigned char *)pkt_buf, (unsigned int)bpf_match_pkt_len, (unsigned int)bpf_match_pkt_len);
		}
		
	}else{
		bpf_match_ipv6 = 0;
	}	

	if(bpf_match_ipv4 || bpf_match_ipv6){
		return 1; /* 任意头部命中即可输出给tcpdump_mesa */ 
	}else{
		if(cur_conn_pkt_dump_ratio > 0){
			if(0 == cycle_pkt_dump_sample_by_ratio(thread_seq)){
				tot_udp_send_willful_discard_num++;
				return -1;
			}
		}
	}

	return 1;
}


static void pkt_dump_with_watermark(int tid, const void *rawpkt, int pktlen, enum _pkt_classify class_val)
{	
	int ret;
	char temp_pkt_buf[MTU_MAX];
	struct mesa_ethernet_hdr *ehdr;
	unsigned char watermaker = 'I';

	if(pktlen > MTU_MAX){
		tot_udp_send_err_num++;
		return;
	}

	memcpy(temp_pkt_buf, rawpkt, pktlen);

	ehdr = (struct mesa_ethernet_hdr *)temp_pkt_buf;
	
	switch(class_val){
		case PKT_CLASSIFY_IN:
			watermaker = 'I';
		break;

		case PKT_CLASSIFY_FORWARD:
			watermaker = 'F';
		break;

		case PKT_CLASSIFY_INJECT:
			watermaker = 'J';
		break;

		case PKT_CLASSIFY_DROP:
			watermaker = 'D';
		break;		
		
		case PKT_CLASSIFY_ERROR:
			watermaker = 'E';
		break;		
		
		case PKT_CLASSIFY_REPEAT:
			watermaker = 'R';
		break;		
	}

	memset(ehdr->ether_shost, watermaker, ETH_ALEN);
	memset(ehdr->ether_dhost, watermaker, ETH_ALEN);

	/* bingo, match filter, sendto */
	ret = sendto(pkt_dump_udp_pkt_sd[tid], 
			(void *)ehdr,  /* 过滤时使用内层数据包头, 但要发送整个原始包 */
			pktlen,   	 /* 过滤时使用内层数据包头, 但要发送整个原始包 */
		  	MSG_DONTWAIT,
		  	(const struct sockaddr *)&udp_recv_addr,
		  	sizeof(udp_recv_addr));	
		  	
	if(ret < 0){
		tot_udp_send_err_num++;
	}else{
		tot_udp_send_succ_num ++;
	}		
	
}


static void __do_cycle_pkt_dump_udp_socket(int thread_seq, const raw_pkt_t *p_raw_pkt, enum _pkt_classify class_val)
{
	const unsigned char *pktdata, *for_bpf_filter_data;
	int pktlen, for_bpf_filter_len, ret;
	char modify_pkt_buf[2048]; /* 需要修改原始包, 先copy到临时缓冲区 */
	struct perceptive_info *pperceptive_info;
	const sapp_config_tools_pktdump_t *pktdump_cfg = &sapp_global_val->config.tools.pkt_dump;

	if(likely(0 == pkt_dump_udp_socket_peer_alive)){	
		return;
	}
	if(0 == G_PKT_DUMP_PER_THREAD_SW[thread_seq]){
		return;
	}
	/* 原始包跳过偏离量后, 还不满一个Ethernet帧, 跳过 */
	if(pkt_dump_data_offset + 14 > p_raw_pkt->raw_pkt_len){
		return;
	}

	if (p_raw_pkt->low_layer_type != (enum addr_type_t)CAP_LEVEL_MAC)
	{
		pktdata = (const unsigned char *)p_raw_pkt->raw_pkt_data - 14 + pkt_dump_data_offset;
		for_bpf_filter_data = pktdata;
		pktlen = p_raw_pkt->raw_pkt_len + 14 - pkt_dump_data_offset;
		for_bpf_filter_len = pktlen;
	}
	else
	{
		pktdata = (const unsigned char *)p_raw_pkt->raw_pkt_data + pkt_dump_data_offset;
		pktlen = p_raw_pkt->raw_pkt_len - pkt_dump_data_offset;
		for_bpf_filter_len = pktlen;
		for_bpf_filter_data = pktdata;
	}
	if(0 == greedy_seek_flag){


		/* 如果有正确的过滤条件, 不设采样率, 保证捕包尽量全, 符合调用者意图;
	       如果没有过滤条件, 即全捕包模式, 为了尽量不影响包处理线程, 根据采样率只捕一部分包.
		*/
		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
			if(0 == bpf_filter(G_PKT_DUMP_BPF_FILTER[thread_seq].bf_insns, 
						    (const unsigned char *)for_bpf_filter_data, for_bpf_filter_len, for_bpf_filter_len)){
				return;
			}
		}else{
			if(cur_conn_pkt_dump_ratio > 0){
				if(0 == cycle_pkt_dump_sample_by_ratio(thread_seq)){
					tot_udp_send_willful_discard_num++;
					return;
				}
			}
		}
	
	}else{
		struct mesa_ip4_hdr *ip4hdr_greedy;
		struct mesa_ip6_hdr *ip6hdr_greedy;
		int inner_pkt_len;
		const unsigned char *inner_iphdr = NULL;
		ip4hdr_greedy = (struct mesa_ip4_hdr *)MESA_net_jump_to_layer_greedy(for_bpf_filter_data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V4);
		if (ip4hdr_greedy)
		{
			inner_iphdr = (const unsigned char *)ip4hdr_greedy;
			inner_pkt_len = for_bpf_filter_len - ((const u_char *)ip4hdr_greedy - for_bpf_filter_data);
		}
		else
		{
			ip6hdr_greedy = (struct mesa_ip6_hdr *)MESA_net_jump_to_layer_greedy(for_bpf_filter_data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V6);
			if (ip6hdr_greedy)
			{
				inner_iphdr = (const unsigned char *)ip6hdr_greedy;
				inner_pkt_len = for_bpf_filter_len - ((const u_char *)ip6hdr_greedy - for_bpf_filter_data);
			}
			else
			{
				return;
			}
		}
		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
			if(0 == bpf_filter(G_PKT_DUMP_BPF_FILTER[thread_seq].bf_insns, 
						    (const unsigned char *)inner_iphdr, inner_pkt_len, inner_pkt_len)){
				return;
			}
		}else{
			if(cur_conn_pkt_dump_ratio > 0){
				if(0 == cycle_pkt_dump_sample_by_ratio(thread_seq)){
					tot_udp_send_willful_discard_num++;
					return;
				}
			}
		}
	}

	if(tcpdump_perceptive_flag > 0){ /* 丢包检测 */
		memcpy(modify_pkt_buf, pktdata, pktlen>2048?2048:pktlen);
		pperceptive_info = (struct perceptive_info *)&modify_pkt_buf[6]; /* 存于源MAC地址 */
		pperceptive_info->thread_id = thread_seq;
		pperceptive_info->pkt_seq = htonl(pkt_dump_mthread_info[thread_seq].perceptive_mode_pkt_seq);
		pkt_dump_mthread_info[thread_seq].perceptive_mode_pkt_seq++;
		pktdata = (unsigned char *)modify_pkt_buf;
		pktlen = pktlen>2048?2048:pktlen;
	}

	if(pkt_classify_watermark_flag){
		return pkt_dump_with_watermark(thread_seq, pktdata, pktlen, class_val);
	}
	
	/* bingo, match filter, sendto */
	ret = sendto(pkt_dump_udp_pkt_sd[thread_seq], 
			pktdata,//(char *)p_raw_pkt->raw_pkt_data, /* 过滤时使用内层数据包头, 但要发送整个原始包 */
			pktlen,//p_raw_pkt->raw_pkt_len, 		 /* 过滤时使用内层数据包头, 但要发送整个原始包 */
		  	MSG_DONTWAIT,
		  	(const struct sockaddr *)&udp_recv_addr,
		  	sizeof(udp_recv_addr));
	if((ret < 0) && (EINTR == errno)){
		/* 优先保证sapp处理流程, 因中断造成的发包失败只重试一次, 其他错误不重试 */
		ret = sendto(pkt_dump_udp_pkt_sd[thread_seq], 
				pktdata,///(char *)p_raw_pkt->raw_pkt_data, 
				pktlen,///p_raw_pkt->raw_pkt_len, 
			  	MSG_DONTWAIT,
			  	(const struct sockaddr *)&udp_recv_addr,
			  	sizeof(udp_recv_addr));
	}
	
	if(ret < 0){
		tot_udp_send_err_num++;
	}else{
		tot_udp_send_succ_num ++;
	}

}

static void __do_cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt, enum _pkt_classify class_val)
{
	int ret;
	/* 定义为pcap_hdr[2]数组,是一个小小的trick, 数组[0]表示pcap包头部信息,
		数组[1]表示在PAG模式下, 存储的etherhdr, pkt_dump_pkt_hdr_t为16字节, 正好可以放一个完整的ether hdr.
	*/
	pkt_dump_pkt_hdr_t pcap_hdr[2];
	int write_hdr_len;
	char dump_file_name[PATH_MAX];	
	const sapp_config_tools_pktdump_t *pktdump_cfg = &sapp_global_val->config.tools.pkt_dump;

	if(PKT_DUMP_LOCAL_FILE == G_PKT_DUMP_MODE){
		if(0 == G_PKT_DUMP_PER_THREAD_SW[thread_seq]){
			return;
		}
	}else{
		__do_cycle_pkt_dump_udp_socket(thread_seq, p_raw_pkt, class_val);
		return;
	}

	if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
		if(g_packet_io_cap_level != (enum addr_type_t)CAP_LEVEL_MAC){
			if(0 == bpf_filter(G_PKT_DUMP_BPF_FILTER[thread_seq].bf_insns, 
						    (const unsigned char *)p_raw_pkt->raw_pkt_data-14, 
			       		    p_raw_pkt->raw_pkt_len+14, p_raw_pkt->raw_pkt_len+14)){
				return;
			}
		}else{
			if(0 == bpf_filter(G_PKT_DUMP_BPF_FILTER[thread_seq].bf_insns, 
						    (const unsigned char *)p_raw_pkt->raw_pkt_data, 
			       		    p_raw_pkt->raw_pkt_len, p_raw_pkt->raw_pkt_len)){
				return;
			}
		}
	}

	if(unlikely(NULL == G_PKT_DUMP_FP[thread_seq])){
		snprintf(dump_file_name, PATH_MAX, "%s/pid_%d.tid_%d.%d.pcap", 
				pktdump_cfg->storge_path, getpid(), thread_seq, G_FILENAME_INDEX[thread_seq]);
		G_PKT_DUMP_FP[thread_seq] = fopen(dump_file_name, "wb+"); 		
		if(NULL == G_PKT_DUMP_FP[thread_seq]){
			printf("open dump file:%s error!\n", dump_file_name);
			return;
		}
		/* pcap file header, first time */
		fwrite(&pfile_hdr, sizeof(pkt_dump_file_hdr_t), 1, G_PKT_DUMP_FP[thread_seq]);
	}

	/* 更新包长度, 时间戳 */
	pcap_hdr[0].ts.tv_sec = (unsigned int )g_CurrentTime;	

	if(p_raw_pkt->low_layer_type != CAP_LEVEL_MAC){
		pcap_hdr[0].caplen = p_raw_pkt->raw_pkt_len+14;
		pcap_hdr[0].len = p_raw_pkt->raw_pkt_len+14;
		memcpy(&pcap_hdr[1], phony_mac_hdr, 14);
		write_hdr_len = sizeof(pkt_dump_pkt_hdr_t) + 14;
	}else{
		pcap_hdr[0].caplen = p_raw_pkt->raw_pkt_len;
		pcap_hdr[0].len = p_raw_pkt->raw_pkt_len;
		write_hdr_len = sizeof(pkt_dump_pkt_hdr_t);
	}

	ret = fwrite(&pcap_hdr[0], write_hdr_len, 1, G_PKT_DUMP_FP[thread_seq]);
	if(unlikely(ret < 1)){
		return;
	}
	ret = fwrite(p_raw_pkt->raw_pkt_data, p_raw_pkt->raw_pkt_len, 1, G_PKT_DUMP_FP[thread_seq]);
	if(unlikely(ret < 1)){
		/* 如果只写了头部, 但写数据出现错误, 回滚 */
		fseek(G_PKT_DUMP_FP[thread_seq], (int)0-(int)sizeof(pkt_dump_pkt_hdr_t), SEEK_CUR);
		return;
	} 

	/* 超过最大限制, 循环写文件 */
	G_PCAP_SIZE[thread_seq]  += write_hdr_len + p_raw_pkt->raw_pkt_len;
	if(unlikely(G_PCAP_SIZE[thread_seq] >= G_PKT_DUMP_FILE_SIZE)){
		fclose(G_PKT_DUMP_FP[thread_seq]);
		G_FILENAME_INDEX[thread_seq] ^= 1;
		snprintf(dump_file_name, PATH_MAX, "%s/pid_%d.tid_%d.%d.pcap", 
				G_PKT_DUMP_ROOT_DIR, getpid(), thread_seq, G_FILENAME_INDEX[thread_seq]);
		G_PKT_DUMP_FP[thread_seq] = fopen(dump_file_name, "wb+"); 		
		if(NULL == G_PKT_DUMP_FP[thread_seq]){
			printf("open dumpfile: %s error!\n", dump_file_name);
			return;
		}
		/* pcap file header, first time */
		fwrite(&pfile_hdr, sizeof(pkt_dump_file_hdr_t), 1, G_PKT_DUMP_FP[thread_seq]);
		G_PCAP_SIZE[thread_seq] = 0;
	}	
	
	return;
}

void cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt)
{
	if(likely(0 == G_PKT_DUMP_SW)){
		return;
	}

	__do_cycle_pkt_dump(thread_seq, p_raw_pkt, PKT_CLASSIFY_IN);

}

/*
	TODO: 如果一个包有多个标签, 比如重复数据包REPEAT, 同时肯定是FORWARD,
	      遇到ddos时, BYPASS的包其实也是FORWARD,
	      使用多个标志位表示, 但物理包仅发送一次, 可以节约一些CPU和IO资源.
*/
void cycle_pkt_dump_by_classify(int thread_seq, const raw_pkt_t *p_raw_pkt, enum _pkt_classify class_val)
{
	if(0 == G_PKT_DUMP_SW){
		return;
	}

	if(0 == (class_val & tcpdump_mesa_pkt_classify)){
		return;
	}

	__do_cycle_pkt_dump(thread_seq, p_raw_pkt, class_val);

}


void cycle_pkt_dump_old(int thread_seq, const void *ippkt, int ippktlen)
{
	raw_pkt_t raw_pkt;

	raw_pkt.raw_pkt_data = ippkt;
	raw_pkt.raw_pkt_len = ippktlen;

	cycle_pkt_dump(thread_seq, &raw_pkt);
}

#if 0 
static int cycle_pkt_dump_child_init(void)
{
	int i, ret;
	struct sockaddr_un father_pro_addr;
	int addr_len;
	char test_buf[1024];
	int buf_len = 0;
	socklen_t opt_len;	

	for(i = 0; i < g_packet_io_thread_num; i++){
		G_UNIX_DOMAIN_SD[i] = socket(AF_UNIX,SOCK_DGRAM,0);
		if(G_UNIX_DOMAIN_SD[i] < 0){
			printf("socket error: %s\n", strerror(errno));
			return -1;
		}
		
		addr_len = sizeof(father_pro_addr);
		father_pro_addr.sun_family=AF_UNIX;
		snprintf(father_pro_addr.sun_path, sizeof(father_pro_addr.sun_path), "%s%d", UNIX_DOMAIN_SOCKET_NAME, i);

		unlink(father_pro_addr.sun_path);
		if(bind(G_UNIX_DOMAIN_SD[i], (struct sockaddr *)&father_pro_addr, addr_len) < 0){
			printf("bind %s error: %s\n", father_pro_addr.sun_path, strerror(errno));
			return -1;
		}

		listen(G_UNIX_DOMAIN_SD[i], 10);
	}

	sapp_usleep(10000);

	for(i = 0; i < g_packet_io_thread_num; i++){
		ret = read(G_UNIX_DOMAIN_SD[i], test_buf, 1024); /* 阻塞等待捕包进程的数据, 正确返回说明连接正常 */
		if(ret <= 0){
			printf("socket read error:%s\n", strerror(errno));
			return -1;
		}
	}
	
	return 0;
}
#endif


#if 0
static long ifuncb_show_pktdump_summary(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	int i;
	unsigned long long discard_pkt_sum = 0, discard_byte_sum = 0;
	unsigned long long tot_pkt_sum = 0, tot_byte_sum = 0;

	for(i = 0; i < g_packet_io_thread_num; i++){
		tot_pkt_sum += PKT_DISCARD_STAT[i].total_pkt_num;
		tot_byte_sum += PKT_DISCARD_STAT[i].total_pkt_bytes;
		discard_pkt_sum += PKT_DISCARD_STAT[i].discard_pkt_num;
		discard_byte_sum += PKT_DISCARD_STAT[i].discard_pkt_bytes;
	}
	//iprintf(ihandle, iconn,"NOTE: unit of byte for total is 'byte', for realtime is 'bps, bit per second'!\n");
	iprintf(ihandle, iconn, "%8s %8s %13s\n", "", "packet", "byte");
	iprintf(ihandle, iconn, "%8s %8llu %13llu\n",  "total", tot_pkt_sum, tot_byte_sum);
	iprintf(ihandle, iconn, "%8s %8llu %13llu\n",  "DROP", discard_pkt_sum, discard_byte_sum);

	return 0;
}

#endif

#if 0
static int cycle_pkt_dump_father_init(void)
{
	int i;
	struct sockaddr_un child_pro_addr;
	int addr_len;
	char test_buf[1024] = "I am father";
	int buf_len = 0;
	socklen_t opt_len;
		
	for(i = 0; i < g_packet_io_thread_num; i++){
		G_UNIX_DOMAIN_SD[i] = socket(AF_UNIX,SOCK_DGRAM,0);
		if(G_UNIX_DOMAIN_SD[i] < 0){
			printf("socket error: %s\n", strerror(errno));
			return -1;
		}
		
		addr_len = sizeof(child_pro_addr);
		child_pro_addr.sun_family=AF_UNIX;
		snprintf(child_pro_addr.sun_path, sizeof(child_pro_addr.sun_path), "%s%d", UNIX_DOMAIN_SOCKET_NAME, i);

		if(connect(G_UNIX_DOMAIN_SD[i], (struct sockaddr*)&child_pro_addr, addr_len) < 0){
			printf("connect %s error: %s\n", child_pro_addr.sun_path, strerror(errno));
			return -1;
		}
	}

	for(i = 0; i < g_packet_io_thread_num; i++){
		write(G_UNIX_DOMAIN_SD[i], test_buf, 1024);
	}

	unlink(child_pro_addr.sun_path);
#if DEBUG
	iknow_register_cmd(PLATFORM_IHANDLE, "show pktdump summary", "display packet dump status", 
					ifuncb_show_pktdump_summary, NULL, 0, NULL);
#endif

	return 0;
}
#endif

#if 0
static void cycle_pkt_dump_clear_last_status(void)
{
	char cmd_buf[128];

	snprintf(cmd_buf, 128, "killall %s", PKT_DUMP_PROCESS_NAME);

	system(cmd_buf);
}


static void cycle_pkt_dump_exec(int argc, char *argv[])
{
	int i;
	pid_t pid;
	pthread_t check_ppid, thread_id[MAX_THREAD_NUM];
	static int thread_seq[MAX_THREAD_NUM];

	cycle_pkt_dump_clear_last_status();	

	pid = fork();
	if(0 == pid){ /* 子进程, 即捕包进程 */
		if(cycle_pkt_dump_child_init() < 0){
			printf("cycle pkt dump init error!\n");
			exit(1);
		}		
		prctl(PR_SET_NAME, PKT_DUMP_PROCESS_NAME, 0, 0, 0);
	}else if(pid > 0){
		sapp_usleep(50000);
		if(cycle_pkt_dump_father_init() < 0){
			printf("cycle pkt dump init error!\n");
			exit(1);
		}
		return; /* 父进程返回, 即sapp主进程 */
	}else{
		printf("cycle_pkt_dump fork error!\n");
		exit(0);
	}

	for(i = 0; i < pkt_dump_thread_num; i++){
		if(G_PKT_DUMP_PER_THREAD_SW[i] != 0){
			thread_seq[i] = i;
			pthread_create(&thread_id[i], NULL, cycle_pkt_dump_thread, &thread_seq[i]);
			sapp_usleep(100);
		}
	}

	pthread_create(&check_ppid, NULL, cycle_pkt_dump_check_father, NULL);

	/* 子进程的主线程阻塞等待 */	
	for(i = 0; i < pkt_dump_thread_num; i++){
		if(G_PKT_DUMP_PER_THREAD_SW[i] != 0){
			pthread_join(thread_id[i], NULL);
		}
	}

	exit(0);
}
#endif

static void cycle_pkt_dump_set_thread_num(int thread_num)
{
	pkt_dump_thread_num = thread_num;
}

#if 0
static int cycle_pkt_dump_get_core_num(void)
{
	FILE *fp;
	char line_buf[PATH_MAX] = {0};
	int core_num = 0;

	fp = popen("ls -l core.* | wc -l", "r");
	if(NULL == fp){
		return -1;
	}

	fgets(line_buf, PATH_MAX, fp);

	core_num = atoi(line_buf);

	pclose(fp);
	return core_num;
}


/* config is like: "0,1,2,3,4,5" */
static int cycle_pkt_dump_parse_per_thread_switch(char *config_str)
{
	char *parse_config = config_str;
	char *save_ptr;
	char *token;
	int i, thread_seq;

	if(strncasecmp("all", config_str, 3) == 0){ /* all thread is enable */
		for(i = 0; i < pkt_dump_thread_num; i++){
			G_PKT_DUMP_PER_THREAD_SW[i] = 1;
		}
		return 0;
	}

	while((token = strtok_r(parse_config, ", \t", &save_ptr)) != NULL){
		thread_seq = atoi(token);
		if(thread_seq < 0 || thread_seq >= pkt_dump_thread_num){
			printf("'pkt_dump_thread_seq' config invalid, threadnum=%d!\n", pkt_dump_thread_num);
			return -1;
		}
		G_PKT_DUMP_PER_THREAD_SW[thread_seq] = 1;
		parse_config = NULL;
	}

	return 0;
}
#endif


static long cycle_pkt_dump_get_cur_files_size(void)
{
	FILE *fp;
	long cur_files_size;
	char cmd_str[PATH_MAX], tmp_str[1024];

	snprintf(cmd_str, PATH_MAX, "du -scb %s | grep %s  | awk {'print $1'}", G_PKT_DUMP_ROOT_DIR, G_PKT_DUMP_ROOT_DIR);

	fp = popen(cmd_str, "r");
	if(NULL == fp){
		return -1;
	}

	if(NULL == fgets(tmp_str, 1024, fp)){
		return -1;
	}
	cur_files_size = (long)strtol(tmp_str, NULL, 10);

	pclose(fp);

	return cur_files_size;
}

static int cycle_pkt_dump_get_cur_enable_thread(void)
{
	int i, sum = 0;
	const sapp_config_tools_pktdump_t *pktdump_cfg = &sapp_global_val->config.tools.pkt_dump;

	for(i = 0; i < MAX_THREAD_NUM; i++){
		if(G_PKT_DUMP_PER_THREAD_SW != 0){
			sum++;
		}
	}

	return sum;
}
/*
	total_files_size: 此目录下总的.pcap包大小, 单位:Byte;
	file_size_per_thread_by_conf: 单个线程最大文件大小, 单位:Byte;

	最终的实际file_size_per_thread值, 取决于当前已有的.pcap文件大小和total_files_size的关系;
	如果当前已有的.pcap文件已超过total_files_size, 则不再写新的文件.
*/
static int cycle_pkt_dump_set_file_size(long total_files_size, long file_size_per_thread_by_conf)
{
	long cur_files_size;
	int cur_enable_thread_num = 0;
	long file_size_per_thread_by_calc; /* 根据实际计算得出的每个线程最大文件大小 */

	cur_files_size = cycle_pkt_dump_get_cur_files_size();
	if(cur_files_size < 0 || cur_files_size >= total_files_size){
		printf("\033[33m[Warning]pkt_dump is enable, but current files size is more than 'pkt_dump_total_size', disable pktdump!\033[0m\n");
		sapp_usleep(1000);
		G_PKT_DUMP_SW = 0;
		return -1;
	}

	cur_enable_thread_num = cycle_pkt_dump_get_cur_enable_thread();
	if(0 == cur_enable_thread_num){
		printf("\033[33m[Warning]pkt_dump is enable, but enable thread number is 0, disable pktdump!\033[0m\n");
		sapp_usleep(1000);
		return -1;
	}

	file_size_per_thread_by_calc = (total_files_size-cur_files_size)/cur_enable_thread_num/2; 

	/* 两者取最小 */
	G_PKT_DUMP_FILE_SIZE = (file_size_per_thread_by_calc < file_size_per_thread_by_conf?file_size_per_thread_by_calc:file_size_per_thread_by_conf);
	if(G_PKT_DUMP_FILE_SIZE < 2048){
		printf("\033[33m[Warning]pkt_dump is enable, but current files size is more than 'pkt_dump_total_size'!\033[0m\n");
		return -1;
	}

	return 0;
}

static void pkt_dump_sig_ignore(int sig)
{
	return;
}

static void pkt_dump_sig_handle(int sig)
{
	signal(SIGSEGV, pkt_dump_sig_ignore); /* SIGSEGV不允许忽略, 用一个虚假的中断处理函数骗过系统 */
	sync(); /* 将缓冲区内未写到磁盘的数据强制写完 */
	abort(); /* 终止程序, 保存core文件 */
}

static void pkt_dump_set_default_opt(void)
{
	int i;
	const sapp_config_tools_pktdump_t *pktdump_cfg = &sapp_global_val->config.tools.pkt_dump;
	udp_recv_addr.sin_family = AF_INET;
	udp_recv_addr.sin_addr.s_addr = htonl(0x7f000001);
	udp_recv_addr.sin_port = htons(12345);

	/* 将原始配置复制一份, 因为udp模式下, 可能会输入-k参数改变此值 */
	for(i = 0; i < MAX_THREAD_NUM; i++){
		G_PKT_DUMP_PER_THREAD_SW[i] = pktdump_cfg->dump_thread_id_mask[i];
	}	

	if(pktdump_cfg->bpf_filter != NULL){
		strncpy(G_PKT_DUMP_FILTER_STR, pktdump_cfg->bpf_filter, sizeof(G_PKT_DUMP_FILTER_STR)-1);
	}
}

static void pkt_dump_parse_opt_rcv_port(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	unsigned short *rcv_port = (unsigned short *)opt_val;

	udp_recv_addr.sin_port = *rcv_port; /* 此处直接使用网络序 */
}

static void pkt_dump_parse_opt_bpf_filter(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	if(ntohs(cmd_opt->opt_len) >= sizeof(G_PKT_DUMP_FILTER_STR)){
		printf("bpf filter string is too long: %s\n", opt_val);
		return;
	}
	memcpy(G_PKT_DUMP_FILTER_STR, opt_val, ntohs(cmd_opt->opt_len)); /* 已包含了EOF */
}

static void pkt_dump_parse_opt_dump_offset(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	unsigned short *toffset = (unsigned short *)opt_val;
	pkt_dump_data_offset = ntohs(*toffset);
}

/*
	tcpdump_mesa命令发出以char数组为单位的若干thread_id, 比如长度是3, 内容是[1,3,5],
	表示第1,3,5线程开启捕包功能.
*/
static void pkt_dump_parse_opt_thread_index(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	int i;
	unsigned short opt_len = ntohs(cmd_opt->opt_len);
	unsigned char *thread_index = (unsigned char *)opt_val;

	/* 默认值是1, 此处根据命令行输入参数, 只开启特定线程 */
	memset(G_PKT_DUMP_PER_THREAD_SW, 0,  sizeof(G_PKT_DUMP_PER_THREAD_SW));
	
	for(i = 0; i < opt_len; i++){
		if(thread_index[i] >= MAX_THREAD_NUM){
			continue;
		}
		G_PKT_DUMP_PER_THREAD_SW[thread_index[i]] = 1;
	}

	return;
}

static void pkt_dump_parse_opt_classify(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	unsigned short opt_len = ntohs(cmd_opt->opt_len);
	const unsigned short *classify_opt = (unsigned short *)opt_val;

	tcpdump_mesa_pkt_classify = ntohs(*classify_opt);

	sapp_runtime_log(RLOG_LV_DEBUG, "recv tcpdump_mesa classify option: 0x%x", tcpdump_mesa_pkt_classify);

	return;
}

static int pkt_dump_reply_ack(int connfd)
{
	char send_buf[128];
	struct pkt_dump_handshake *pkt_hdr;
	struct pkt_dump_opt *ack_opt;

	pkt_hdr = (struct pkt_dump_handshake *)&send_buf[0];
	ack_opt = (struct pkt_dump_opt *)(send_buf + sizeof(struct pkt_dump_handshake));

	pkt_hdr->magic = htonl(PKT_DUMP_HDR_MAGIC);
	pkt_hdr->version = htonl(20180119);
	pkt_hdr->opt_num = htonl(1);

	ack_opt->opt_type = htons(PKT_DUMP_OPT_ACK);
	ack_opt->opt_len = 0;

	int ret = MESA_sock_force_write(connfd, send_buf, sizeof(struct pkt_dump_handshake)+sizeof(struct pkt_dump_opt), 0);

	return ret;
}

static void cycle_pkt_dump_command_parse(int connfd)
{
	char cmd_buf[1024];
	unsigned int i;
	int ret;
	struct pkt_dump_handshake pkt_hdr;
	struct pkt_dump_opt cmd_opt;
	
	/* tcpdump_mesa先发送固定头部, 用于判定magic, 选项数量, 版本号之类的 */
	ret = MESA_sock_greedy_read(connfd,  &pkt_hdr, sizeof(pkt_hdr), -1);
	if(0 == ret){
		goto err_exit;
	}else if(ret < 0){
		printf("sock read error, %s\n", strerror(errno));
		goto err_exit;
	}

	if(ntohl(pkt_hdr.magic) != PKT_DUMP_HDR_MAGIC){
		printf("Remote tcpdump_mesa is not recognized!\n");
		goto err_exit;
	}

    /* 暂不严格限定对端tcpdump_mesa版本号, 只打印警告信息 */
#if 0    
	if(ntohl(pkt_hdr.version) != (unsigned int)tcpdump_mesa_version_VERSION_20181114){
		printf("Remote tcpdump_mesa version is incompatible!\n");
		sapp_runtime_log(20, "Remote tcpdump_mesa version is incompatible!\n");
	}
#endif	

	pkt_dump_set_default_opt();

	for(i = 0; i < ntohl(pkt_hdr.opt_num); i++){
		/* get opt hdr */
		ret = MESA_sock_greedy_read(connfd,  &cmd_opt, sizeof(cmd_opt), -1);
		if(0 == ret){
			goto err_exit;
		}else if(ret < 0){
			printf("sock read error, %s\n", strerror(errno));
			goto err_exit;
		}
		/* get opt value if exist */
		if(ntohs(cmd_opt.opt_len) > 0){
			ret = MESA_sock_greedy_read(connfd,  cmd_buf, ntohs(cmd_opt.opt_len), -1);
			if(0 == ret){
				goto err_exit;
			}else if(ret < 0){
				printf("sock read error, %s\n", strerror(errno));
				goto err_exit;
			}
		}
		
		switch(ntohs(cmd_opt.opt_type)){
			case PKT_DUMP_OPT_RCV_PORT:
				pkt_dump_parse_opt_rcv_port(&cmd_opt, cmd_buf);
			break;

			case PKT_DUMP_OPT_BPF_FILTER:
				pkt_dump_parse_opt_bpf_filter(&cmd_opt, cmd_buf);
			break;

			case PKT_DUMP_OPT_DATA_OFFSET:
				pkt_dump_parse_opt_dump_offset(&cmd_opt, cmd_buf);
			break;

			case PKT_DUMP_OPT_THREAD_INDEX:
				pkt_dump_parse_opt_thread_index(&cmd_opt, cmd_buf);
			break;

			case PKT_DUMP_OPT_PERCEPTIVE:
				tcpdump_perceptive_flag = 1;
			break;

			case PKT_DUMP_OPT_GREEDY_SEEK:
				greedy_seek_flag = 1;
			break;

			case PKT_DUMP_OPT_CLASSIFY:
				pkt_dump_parse_opt_classify(&cmd_opt, cmd_buf);
			break;

			case PKT_DUMP_OPT_CLASSIFY_WATERMARK:
				pkt_classify_watermark_flag = 1;
			break;

			default:
				/* 未知选项跳过不处理 */
				break;
		}
	}
	int pcap_link_type = DLT_EN10MB;
	if(greedy_seek_flag == 1)pcap_link_type = DLT_RAW;
	for(i = 0; i < (unsigned int )g_packet_io_thread_num + sapp_global_val->config.cpu.send_only_threads_max_num; i++){

		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){ /* 允许没有filter, 即全捕包 */
			if(pcap_compile_nopcap(65535, pcap_link_type, &G_PKT_DUMP_BPF_FILTER[i], G_PKT_DUMP_FILTER_STR, 100, 0) < 0){                
				printf("Compile pcap filter '%s' error\n", G_PKT_DUMP_FILTER_STR);                
				goto err_exit;    
			}
			/* 如果有正确的过滤条件, 不设采样率, 保证捕包尽量符合调用者意图 */
			cur_conn_pkt_dump_ratio = 0;			
		}
	}

	pkt_dump_udp_socket_peer_alive = 1;

	if(pkt_dump_reply_ack(connfd) < 0 ){
		goto err_exit;
	}

	timet_to_str(time(NULL),  udp_start_time_str, 64);

	/* 与tcpdump_mesa建立连接以后不再处理任何命令, 阻塞读取但不做任何解析, 直到对端tcpdump_mesa连接结束 */
	while(MESA_sock_greedy_read(connfd,  cmd_buf, sizeof(cmd_buf), -1) != 0);

	MESA_handle_runtime_log(g_sapp_log_handle, 20, "tcpdump_mesa", "capture start at %s, send pkt succ: %lld, error: %lld, willful discard:%lld!",
						   udp_start_time_str,
						   tot_udp_send_succ_num,
						   tot_udp_send_err_num,
						   tot_udp_send_willful_discard_num);

err_exit:
	/* 恢复各种变量的默认值 */
	pkt_dump_udp_socket_peer_alive = 0; /* NOTE: 命令连接中断后, 第一步先关闭捕包开关 */
	tot_udp_send_succ_num = 0; /* sendto成功数量 */
	tot_udp_send_err_num = 0; /* 发送错误数量, 如缓存满等原因 */
	tot_udp_send_willful_discard_num = 0; /* 主动丢弃数量 */
	tcpdump_perceptive_flag = 0;
	greedy_seek_flag = 0;
	pkt_classify_watermark_flag = 0;
	tcpdump_mesa_pkt_classify = PKT_CLASSIFY_IN;
	
	memset(G_PKT_DUMP_FILTER_STR, 0, sizeof(G_PKT_DUMP_FILTER_STR));
	pkt_dump_data_offset = 0;
	cur_conn_pkt_dump_ratio = raw_cfg_pkt_dump_ratio;
	
	/* 可单独按线程指定捕包, 每次恢复默认值 */
	memset(G_PKT_DUMP_PER_THREAD_SW, 0,  sizeof(G_PKT_DUMP_PER_THREAD_SW));
	sapp_usleep(1000 * 500); /* 延时释放, 避免有线程正在使用BPF过滤器 */
	for(i = 0; i <  (unsigned int )g_packet_io_thread_num + sapp_global_val->config.cpu.send_only_threads_max_num; i++){
		pcap_freecode(&G_PKT_DUMP_BPF_FILTER[i]);
		pkt_dump_mthread_info[i].sample_pkt_num = 0;
		pkt_dump_mthread_info[i].perceptive_mode_pkt_seq = 0;
	}	
	close(connfd);
	return;
}

static void * cycle_pkt_dump_udp_socket_daemon_thread(void *arg)
{
	socklen_t cliaddr_len;
	struct sockaddr_in cliaddr;
	int connfd;
#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 480) /* 版本判断, 很多旧系统无法编译 */	
#ifdef _GNU_SOURCE
	pthread_setname_np(pthread_self(), "sapp_pkt_dump");
#endif
#endif
	printf("\033[32m[Notice]'%s'is ready, port %d.\033[0m\n", "tcpdump_mesa",
	        pkt_dump_tcp_bind_port);
	
	while(1){
		cliaddr_len = sizeof(cliaddr);
		connfd = accept(pkt_dump_tcp_cmd_sd, (struct sockaddr *) &cliaddr, &cliaddr_len);
		if(connfd > 0){
			//cycle_pkt_dump_command_parse(connfd);
			cycle_pkt_dump_command_parse(connfd);
		}
	}

	return NULL;
}

static int cycle_pkt_dump_socket_init(void)
{
	pthread_t pid;
	int i, opt;
	struct sockaddr_in sockadd;
	
	pkt_dump_tcp_cmd_sd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	opt = 1;
	setsockopt(pkt_dump_tcp_cmd_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

	memset(&sockadd, 0, sizeof(sockadd));
	sockadd.sin_family = AF_INET;
	sockadd.sin_addr.s_addr = htonl(INADDR_ANY);
	sockadd.sin_port = htons(pkt_dump_tcp_bind_port);

	if(bind(pkt_dump_tcp_cmd_sd, (struct sockaddr *) &sockadd, sizeof(sockadd)) < 0){
		printf("pkt dump bind cmd port %u error, %s!\n", pkt_dump_tcp_bind_port, strerror(errno));
		return -1;
	}
	listen(pkt_dump_tcp_cmd_sd,  1); /* 不支持并发, 暂时只支持一个客户端捕包 */

	for(i = 0; i < g_packet_io_thread_num + sapp_global_val->config.cpu.send_only_threads_max_num; i++){
		pkt_dump_udp_pkt_sd[i] = socket(AF_INET, SOCK_DGRAM, 0);
	}
	
	pthread_create(&pid, NULL, cycle_pkt_dump_udp_socket_daemon_thread, NULL);

	return 0;
}

int cycle_pkt_dump_init(int argc, char *argv[])
{
	int i, ret = 0;
	int int_tmp, total_files_size, core_num;
	char per_thread_sw[PATH_MAX];
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	const sapp_config_tools_pktdump_t *pktdump_cfg = &sapp_global_val->config.tools.pkt_dump;

	if(0 == pktdump_cfg->enabled){
		return 0;
	}

	G_PKT_DUMP_SW = pktdump_cfg->enabled;
	pkt_dump_tcp_bind_port = (unsigned short)pktdump_cfg->command_port;
	cur_conn_pkt_dump_ratio = pktdump_cfg->pkt_dump_ratio;
	cur_conn_pkt_dump_ratio = pktdump_cfg->pkt_dump_ratio;
	G_PKT_DUMP_MODE = pktdump_cfg->mode_bin;

	/* 将原始配置复制一份, 因为udp模式下, 可能会输入-k参数改变此值 */
	for(i = 0; i < MAX_THREAD_NUM; i++){
		G_PKT_DUMP_PER_THREAD_SW[i] = pktdump_cfg->dump_thread_id_mask[i];
	}
	if(pktdump_cfg->bpf_filter != NULL){
		strncpy(G_PKT_DUMP_FILTER_STR, pktdump_cfg->bpf_filter, sizeof(G_PKT_DUMP_FILTER_STR)-1);
	}
	if(PKT_DUMP_LOCAL_FILE == G_PKT_DUMP_MODE){
		cycle_pkt_dump_set_thread_num(g_packet_io_thread_num + sapp_global_val->config.cpu.send_only_threads_max_num);

		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
			for(i = 0; i < g_packet_io_thread_num + sapp_global_val->config.cpu.send_only_threads_max_num; i++){
				if(pcap_compile_nopcap(65535,DLT_EN10MB, &G_PKT_DUMP_BPF_FILTER[i], G_PKT_DUMP_FILTER_STR, 100, 0) < 0){                
					sapp_log(30, 1, 1, "Compile pcap filter '%s' error\n", pktdump_cfg->bpf_filter);                
					return -1;        
				}		
			}
		}

		if(MESA_mkdir_p(pktdump_cfg->storge_path, 0755) < 0){
			sapp_log(30, 1, 1, "tools.pkt_dump.storage mkdir '%s' error!\n", pktdump_cfg->storge_path);				  
			return -1;	
		}

		G_PKT_DUMP_FILE_SIZE = pktdump_cfg->file_size_max_per_thread * 1024 * 1024 ;
#if 0		
		MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_total_size", &total_files_size, 1000);
		if(total_files_size < 1 || (unsigned int)total_files_size >= 1024*1000 /* 1000GB */){
			printf("pkt_dump_total_size  invalid!\n");
			return -1;
		}
		
		MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_file_max_size", &int_tmp, 100);
		if(int_tmp < 2 || (unsigned int)int_tmp >= 1024*1000 /* 1000GB */){
			printf("pkt_dump_file_max_size  invalid!\n");
			return -1;
		}
		/* 每个线程需要循环写2个文件, 所以需要将pkt_dump_file_max_size的实际值再除以2 */
		if(cycle_pkt_dump_set_file_size((long)total_files_size*1024*1024, (long)int_tmp*1024*512) < 0){
			return 0;
		}
#endif		
		signal(SIGPIPE, SIG_IGN);
		/* 捕获SIGSEGV信号, 保证程序异常终止时, 最后一个触发BUG的pcap包真正能写到硬盘 */
		if((SIG_ERR == signal(SIGSEGV, pkt_dump_sig_handle))){
			printf("Catch SIGSEGV error!\n");	
		}

		sapp_log(20, 1, 1, "tools.pkt_dump enable, this maybe encumber performance!\n");
	}else{
		ret = cycle_pkt_dump_socket_init();
	}
	
	return ret;
}


#ifdef __cplusplus
}
#endif



