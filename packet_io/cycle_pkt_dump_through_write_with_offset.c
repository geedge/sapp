#include "packet_io.h"
#include "stream_internal.h"
#include "stream_manage.h"
#include "mesa_net.h"
#include "sendpacket.h"
#include "MESA_prof_load.h"
#include "MESA_sleep.h"
#include "MESA_socket_wrap.h"
#include "iknow.h"
#include "mesa_pkt_dump.h"
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <execinfo.h>
#include <pcap/pcap.h>

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

enum dump_mode{
	PKT_DUMP_LOCAL_FILE		=	1, /* 写本地文件 */
	PKT_DUMP_UDP_SOCKET		=	2, /* 写到UDP 某个端口 */
};

#if DEBUG
#include "iknow.h"

typedef struct{
	unsigned long long total_pkt_num;
	unsigned long long total_pkt_bytes;
	unsigned long long discard_pkt_num;
	unsigned long long discard_pkt_bytes;
	char __pad__[32]; /* 64字节cache对齐 */
}pkt_dump_status_t;
static pkt_dump_status_t PKT_DISCARD_STAT[MAX_THREAD_NUM];

#endif

extern int g_packet_io_cap_level;
extern int g_use_MESA_sleep_sw;
extern int MESA_mkdir_p(const char *pathname, mode_t mode);
//extern time_t g_CurrentTime;
extern int g_packet_io_thread_num;
extern int g_iThreadNum; /* for dual_stack, start */
static char G_PKT_DUMP_ROOT_DIR[PATH_MAX]; /* 可以指定为/dev/shm, 速度快 */
static long G_PKT_DUMP_FILE_SIZE = 104857600; /* 默认100MB, 单线程 */
int G_PKT_DUMP_SW = 0; /* 默认关闭 */
int G_PKT_DUMP_MODE = PKT_DUMP_LOCAL_FILE; /* 默认是写到本地文件 */
static int G_PKT_DUMP_PER_THREAD_SW[MAX_THREAD_NUM];

static int pkt_dump_thread_num = 1;

static FILE *G_PKT_DUMP_FP[MAX_THREAD_NUM];
static int G_FILENAME_INDEX[MAX_THREAD_NUM];
static long G_PCAP_SIZE[MAX_THREAD_NUM];
static char G_PKT_DUMP_FILTER_STR[PATH_MAX];
static struct bpf_program G_PKT_DUMP_BPF_FILTER[MAX_THREAD_NUM];
static pcap_t *phony_pcap_handle[MAX_THREAD_NUM]; /* 仅用于BPF过滤时使用 */
static unsigned short pkt_dump_data_offset = 0; /* 捕包时可指定偏移量, 用于vxlan环境下捕获内层数据包 */
static unsigned short pkt_dump_tcp_bind_port = 12345; /* 默认TCP监听端口, 用于接收外部tcpdump命令 */
static int pkt_dump_tcp_cmd_sd = -1;/* TCP fd,  用于接收外部tcpdump命令 */
static volatile int pkt_dump_udp_socket_peer_alive = 0; /* 外部tcpdump是否存活 */
static int pkt_dump_udp_pkt_sd[MAX_THREAD_NUM]; /* UDP发送数据包fd */
static struct sockaddr_in udp_recv_addr;

static unsigned char phony_mac_hdr[14] = 
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0x12, 0x23, 0x34, 0x56, 0x67, 0x78,
	0x08, 0x00
};
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
						usleep(1);
					}else{
						MESA_sleep();
					}	
					/* no break here!!!  no break here!!! no break here!!!*/
				case EINTR:
					goto retry;
				break;

				default:
					printf("pkt dump, read error:%s, ptr=%p, expect_count=%lu, left_count=%lu\n", 
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
					printf("pkt dump, write error:%s\n", strerror(errno));
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
			usleep(100000);
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

static void __do_cycle_pkt_dump_udp_socket(int thread_seq, const raw_pkt_t *p_raw_pkt)
{
	const mesa_ethernet_hdr *ehdr;
	const unsigned char *pktdata;
	int pktlen;

	if(1 == pkt_dump_udp_socket_peer_alive){
		/* 原始包跳过偏离量后, 还不满一个Ethernet帧, 跳过 */
		if(pkt_dump_data_offset + 14 > p_raw_pkt->raw_pkt_len){
			return;
		}
		
		if(g_packet_io_cap_level != CAP_LEVEL_MAC){
			pktdata =  (const unsigned char *)p_raw_pkt->raw_pkt_data-14 + pkt_dump_data_offset, 
			pktlen = p_raw_pkt->raw_pkt_len+14 - pkt_dump_data_offset;
			ehdr = (const mesa_ethernet_hdr *)pktdata;
		}else{
			pktdata =  (const unsigned char *)p_raw_pkt->raw_pkt_data + pkt_dump_data_offset, 
			pktlen = p_raw_pkt->raw_pkt_len - pkt_dump_data_offset;
			ehdr = (const mesa_ethernet_hdr *)pktdata;
		}

		/* 2017-01-06 lijia add, 非常规Ethernet包不处理 */
		switch(ntohs(ehdr->ether_type)){
			case ETHERTYPE_IP:
			case ETHERTYPE_IPv6:
			case ETHERTYPE_VLAN:
			case ETHERTYPE_ARP:
			break;

			default:
			return;
		}
	
		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
			if(0 == bpf_filter(G_PKT_DUMP_BPF_FILTER[thread_seq].bf_insns, 
						    (const unsigned char *)pktdata, pktlen, pktlen)){
				return;
			}
		}
		
		/* bingo, match filter, sendto */
		sendto(pkt_dump_udp_pkt_sd[thread_seq], 
				(char *)pktdata, 
				pktlen, 
			  	MSG_DONTWAIT,
			  	(const struct sockaddr *)&udp_recv_addr,
			  	sizeof(udp_recv_addr));
	}
}

static void __do_cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt)
{
	int ret;
	/* 定义为pcap_hdr[2]数组,是一个小小的trick, 数组[0]表示pcap包头部信息,
		数组[1]表示在PAG模式下, 存储的etherhdr, pkt_dump_pkt_hdr_t为16字节, 正好可以放一个完整的ether hdr.
	*/
	pkt_dump_pkt_hdr_t pcap_hdr[2];
	int write_hdr_len;
	char dump_file_name[PATH_MAX];	

	if(PKT_DUMP_LOCAL_FILE == G_PKT_DUMP_MODE){
		if(0 == G_PKT_DUMP_PER_THREAD_SW[thread_seq]){
			return;
		}
	}else{
		__do_cycle_pkt_dump_udp_socket(thread_seq, p_raw_pkt);
		return;
	}

	if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
		if(g_packet_io_cap_level != CAP_LEVEL_MAC){
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
				G_PKT_DUMP_ROOT_DIR, getpid(), thread_seq, G_FILENAME_INDEX[thread_seq]);
		G_PKT_DUMP_FP[thread_seq] = fopen(dump_file_name, "wb+"); 		
		if(NULL == G_PKT_DUMP_FP[thread_seq]){
			printf("fopen %s error!\n", dump_file_name);
			return;
		}
		/* pcap file header, first time */
		fwrite(&pfile_hdr, sizeof(pkt_dump_file_hdr_t), 1, G_PKT_DUMP_FP[thread_seq]);
	}

	/* 更新包长度, 时间戳 */
	pcap_hdr[0].ts.tv_sec = (unsigned int )g_CurrentTime;	

	if(g_packet_io_cap_level != CAP_LEVEL_MAC){
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
			printf("fopen %s error!\n", dump_file_name);
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

	__do_cycle_pkt_dump(thread_seq, p_raw_pkt);
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

	usleep(10000);

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


#if DEBUG
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
		usleep(50000);
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
			usleep(100);
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

	for(i = 0; i < MAX_THREAD_NUM; i++){
		if(G_PKT_DUMP_PER_THREAD_SW[i] > 0){
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
		usleep(100000);
		G_PKT_DUMP_SW = 0;
		return -1;
	}

	cur_enable_thread_num = cycle_pkt_dump_get_cur_enable_thread();
	if(0 == cur_enable_thread_num){
		printf("\033[33m[Warning]pkt_dump is enable, but enable thread number is 0, disable pktdump!\033[0m\n");
		usleep(100000);
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
	udp_recv_addr.sin_family = AF_INET;
	udp_recv_addr.sin_addr.s_addr = htonl(0x7f000001);
	udp_recv_addr.sin_port = htons(12345);
	
	memset(G_PKT_DUMP_FILTER_STR, 0, sizeof(G_PKT_DUMP_FILTER_STR));
	pkt_dump_data_offset = 0;
}

static void pkt_dump_parse_opt_rcv_port(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	unsigned short *rcv_port = (unsigned short *)opt_val;

	udp_recv_addr.sin_port = *rcv_port; /* 此处直接使用网络序 */
}

static void pkt_dump_parse_opt_bpf_filter(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	memcpy(G_PKT_DUMP_FILTER_STR, opt_val, ntohs(cmd_opt->opt_len)); /* 已包含了EOF */
}

static void pkt_dump_parse_opt_dump_offset(const struct pkt_dump_opt *cmd_opt, const char *opt_val)
{
	unsigned short *toffset = (unsigned short *)opt_val;
	pkt_dump_data_offset = ntohs(*toffset);
}

static void cycle_pkt_dump_command_parse(int connfd)
{
	char cmd_buf[1024];
	unsigned int i;
	int ret;
	struct pkt_dump_handshake pkt_hdr;
	struct pkt_dump_opt cmd_opt;
	
	/* 先发送2个字节tcpdump UDP接收端口 */
	ret = MESA_sock_greedy_read(connfd,  &pkt_hdr, sizeof(pkt_hdr), -1);
	if(0 == ret){
		goto err_exit;
	}else if(ret < 0){
		printf("sock read error, %s\n", strerror(errno));
		goto err_exit;
	}

	if(ntohl(pkt_hdr.magic) != PKT_DUMP_HDR_MAGIC){
		printf("Remote tcpdump is not recognized\n");
		goto err_exit;
	}

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
		/* get opt value */
		ret = MESA_sock_greedy_read(connfd,  cmd_buf, ntohs(cmd_opt.opt_len), -1);
		if(0 == ret){
			goto err_exit;
		}else if(ret < 0){
			printf("sock read error, %s\n", strerror(errno));
			goto err_exit;
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

			default:
				/* 未知选项跳过不处理 */
				break;
		}
	}

	for(i = 0; i < (unsigned int )g_packet_io_thread_num; i++){
		phony_pcap_handle[i] = pcap_open_dead(DLT_EN10MB, 65535);
		if(NULL == phony_pcap_handle[i]){
			goto err_exit;
		}		

		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){ /* 允许没有filter */
			if(pcap_compile(phony_pcap_handle[i], &G_PKT_DUMP_BPF_FILTER[i], G_PKT_DUMP_FILTER_STR, 100, 0) < 0){                
				printf("Compile pcap filter '%s' error:%s\n", G_PKT_DUMP_FILTER_STR, pcap_geterr(phony_pcap_handle[i]));                
				goto err_exit;    
			}
		}
	}

	pkt_dump_udp_socket_peer_alive = 1;

	/* 以后不再动态接收任何命令, 直到连接结束 */
	while(MESA_sock_greedy_read(connfd,  cmd_buf, sizeof(cmd_buf), -1)  != 0);

err_exit:
	pkt_dump_udp_socket_peer_alive = 0;
	usleep(1000 * 500); /* 延时释放, 避免有线程正在使用BPF过滤器 */
	for(i = 0; i <  (unsigned int )g_packet_io_thread_num; i++){
		pcap_freecode(&G_PKT_DUMP_BPF_FILTER[i]);
	}
	memset(G_PKT_DUMP_FILTER_STR, 0, sizeof(G_PKT_DUMP_FILTER_STR));
	pkt_dump_data_offset = 0;
	close(connfd);
	return;
}

static void * cycle_pkt_dump_udp_socket_daemon_thread(void *arg)
{
	socklen_t cliaddr_len;
	struct sockaddr_in cliaddr;
	int connfd;
#ifdef _GNU_SOURCE
	pthread_setname_np(pthread_self(), "sapp_pkt_dump");
#endif
	
	while(1){
		cliaddr_len = sizeof(cliaddr);
		connfd = accept(pkt_dump_tcp_cmd_sd, (struct sockaddr *) &cliaddr, &cliaddr_len);
		if(connfd > 0){
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
	
	pkt_dump_tcp_cmd_sd = socket(AF_INET, SOCK_STREAM, 0);

	opt = 1;
	setsockopt(pkt_dump_tcp_cmd_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family = AF_INET;
	sockadd.sin_addr.s_addr = htonl(INADDR_ANY);
	sockadd.sin_port = htons(pkt_dump_tcp_bind_port);

	if(bind(pkt_dump_tcp_cmd_sd, (struct sockaddr *) &sockadd, sizeof(sockadd)) < 0){
		printf("pkt dump bind cmd port %u error, %s!\n", pkt_dump_tcp_bind_port, strerror(errno));
		return -1;
	}
	listen(pkt_dump_tcp_cmd_sd,  1); /* 暂时只支持一个客户端捕包 */

	for(i = 0; i < g_packet_io_thread_num; i++){
		pkt_dump_udp_pkt_sd[i] = socket(AF_INET, SOCK_DGRAM, 0);
	}
	
	pthread_create(&pid, NULL, cycle_pkt_dump_udp_socket_daemon_thread, NULL);

	return 0;
}

int cycle_pkt_dump_init(int argc, char *argv[])
{
	int i, ret;
	int int_tmp, total_files_size, core_num;
	char per_thread_sw[PATH_MAX];
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_switch", &G_PKT_DUMP_SW, 0);

	if(0 == G_PKT_DUMP_SW){
		return 0;
	}

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_mode", &G_PKT_DUMP_MODE, 1);
	if((G_PKT_DUMP_MODE != PKT_DUMP_LOCAL_FILE) && (G_PKT_DUMP_MODE != PKT_DUMP_UDP_SOCKET)){
		printf("\n\033[41mError! pkt_dump_mode only support 1 or 2!\033[0m\n");
		return -1;
	}

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_cmd_port", &int_tmp, 12345);
	if((int_tmp <=0) || (int_tmp > 65535)){
		printf("\n\033[41mError! pkt_dump_cmd_port invalid, %d!\033[0m\n", int_tmp);
		return -1;
	}
	pkt_dump_tcp_bind_port = (unsigned short)int_tmp;
	
#if 0 == CYCLE_PKT_DUMP
	printf("\n\033[33m[Warning]pkt_dump is enable, but sapp is not compile correct, please use debug=2.\033[0m\n");
	sleep(1);
#endif

	if(PKT_DUMP_LOCAL_FILE == G_PKT_DUMP_MODE){
		cycle_pkt_dump_set_thread_num(g_packet_io_thread_num);

		core_num = cycle_pkt_dump_get_core_num();
		if(core_num < 0 || core_num > 10){
			printf("\033[33m[Warning]core.* number is more than 10, pkt dump is auto disabled!\n");
			G_PKT_DUMP_SW = 0;
			return 0;
		}

		MESA_load_profile_string_def((char *)"conf/main.conf",(char *)"pkt_dump", (char *)"pkt_dump_bpf_filter", G_PKT_DUMP_FILTER_STR, PATH_MAX, (char *)"");
		if(G_PKT_DUMP_FILTER_STR[0] != '\0'){
			for(i = 0; i < g_packet_io_thread_num; i++){
				phony_pcap_handle[i] = pcap_open_dead(DLT_EN10MB, 65535);
				if(NULL == phony_pcap_handle[i]){
					printf("pcap_open %s error, %s\n", "lo", pcap_errbuf);
					printf("\n\033[41mpkt_dump_bpf_filter is not enable!\033[0m\n");
					goto skip_bpf_filter;
				}		
				if(pcap_compile(phony_pcap_handle[i], &G_PKT_DUMP_BPF_FILTER[i], G_PKT_DUMP_FILTER_STR, 100, 0) < 0){                
					printf("Compile pcap filter '%s' error:%s\n", G_PKT_DUMP_FILTER_STR, pcap_geterr(phony_pcap_handle[i]));                
					return -1;        
				}		
			}
		}

	skip_bpf_filter:

		MESA_load_profile_string_def((char *)"conf/main.conf",(char *)"pkt_dump", (char *)"pkt_dump_file_root_dir", G_PKT_DUMP_ROOT_DIR, PATH_MAX, (char *)"/tmp/pkt_dump");
		MESA_mkdir_p(G_PKT_DUMP_ROOT_DIR, 0755);

		MESA_load_profile_string_nodef((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_thread_seq", per_thread_sw, PATH_MAX);
		if(cycle_pkt_dump_parse_per_thread_switch(per_thread_sw) < 0){
			return 0;
		}
		
		MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_total_size", &total_files_size, 1000);
		if(total_files_size < 1 || (unsigned int)total_files_size >= 1024*100 /* 100GB */){
			printf("pkt_dump_total_size  invalid!\n");
			return -1;
		}
		
		MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_file_max_size", &int_tmp, 100);
		if(int_tmp < 2 || (unsigned int)int_tmp >= 1024*100 /* 100GB */){
			printf("pkt_dump_file_max_size  invalid!\n");
			return -1;
		}
		/* 每个线程需要循环写2个文件, 所以需要将pkt_dump_file_max_size的实际值再除以2 */
		if(cycle_pkt_dump_set_file_size((long)total_files_size*1024*1024, (long)int_tmp*1024*512) < 0){
			return 0;
		}
		
		signal(SIGPIPE, SIG_IGN);
		/* 捕获SIGSEGV信号, 保证程序异常终止时, 最后一个触发BUG的pcap包真正能写到硬盘 */
		if((SIG_ERR == signal(SIGSEGV, pkt_dump_sig_handle))){
			printf("Catch SIGSEGV error!\n");	
		}

#if DEBUG
		iknow_register_cmd(PLATFORM_IHANDLE, "show pkt dump summary", "display pkt dump summary", 
						  ifuncb_show_pktdump_summary, NULL, 0, NULL);
#endif	
		printf("\n\033[33m[Warning]pkt dump enable, this maybe encumber performance.\033[0m\n");
		sleep(1);
	}else{
		ret = cycle_pkt_dump_socket_init();
	}
	
	return ret;
}


#ifdef __cplusplus
}
#endif



