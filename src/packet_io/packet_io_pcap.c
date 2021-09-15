#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include <pcap/pcap.h>
#include <sys/types.h>


#define PROCESS_BAR_SW 		(1)

int g_pcap_version_VERSION_20210722; 
static int g_pcap_version_internal = 20210907;

#define PCAP_SNAPLEN_MAX	(65535)

typedef struct{
	int raw_eth_fd; /* 仅用于发送Ethernet原始报文 */
	int thread_num; 
	struct sockaddr saddr_up;
	struct sockaddr saddr_down;
	UINT8 pcap_send_buf[SENDPACKET_BUF_LEN];
}pcap_send_handle;

/* 分流模式, 按内层二元组还是外层二元组, TODO:按需求开发, 以后可以支持四元组 */
typedef enum{ 
	PCAP_DISTMODE_INNER_TUPLE2,
	PCAP_DISTMODE_OUTER_TUPLE2,
}pcap_distmode_t;

#define PCAP_MALLOC(size)		malloc(size)
#define PCAP_FREE(ptr)			free(ptr)

static char g_pcap_up_dev_name[DEV_NAME_STR_LEN] = "dumpfile"; /* if in parallel mode, use this arg */
static char g_pcap_down_dev_name[DEV_NAME_STR_LEN];
static char g_pcap_cap_filter[CAP_FILTER_STR_LEN];
static int g_pcap_buf_queue_num = 10000;
static int g_pcap_cap_mode = CAP_MODEL_PCAP_ONLINE;
static int g_pcap_topology_mode = NET_CONN_PARALLEL;
static int g_pcap_cap_level = CAP_LEVEL_MAC; /* 本库捕包起始位置,默认MAC层 */
static int g_pcap_work_thread_num = 1;
static pcap_t *pcap_up_handle; /* if in parallel mode, use this arg */
static pcap_t *pcap_down_handle;
static PACKET_IO_CB_T g_pcap_work_fun;
static PACKET_IO_EXIT_CB_T g_pcap_exit_cb_fun;
static volatile long pcap_app_drop_num[MAX_THREAD_NUM];
static volatile int get_pcap_lib_drop_flag = 0;
static volatile long pcap_lib_drop_up_num = 0; /* 并联模式默认使用此变量存储 */
static volatile long pcap_lib_drop_down_num = 0;
static struct mesa_ethernet_hdr *raw_pkt_hdr[MAX_THREAD_NUM]; /* 记录原始包头指针, 用于发包获取MAC地址用 */
static unsigned char raw_pkt_route_dir[MAX_THREAD_NUM]; /* 记录原始包方向, 用于发送数据包 */
static unsigned long long tot_up_rcv_pkt_num, tot_down_rcv_pkt_num;
static int pcap_device_up_mtu = 1500;
static int pcap_device_down_mtu = 1500;
static pcap_distmode_t g_pcap_distmode = PCAP_DISTMODE_OUTER_TUPLE2;

extern sapp_global_t *sapp_global_val;
extern int g_PollingFunNum;
extern int g_use_MESA_sleep_sw;
extern void MESA_sleep(void);
extern void timestamp_record(enum timestamp_level level, const raw_pkt_t *raw_pkt, int thread_seq);
extern void timestamp_record_lib(const raw_pkt_t *raw_pkt);
/*

	注册控制命令,
	"set timestamp record minimum xxx",
	即超时最小是xxx时才显示.
	超时分为如下几个级别:

	硬件时间戳--->最底层拿到包-->IPv4层入口-->befor_stream_process()->after_stream_process()

	分别在__pkt_handle, ipv4_entry, stream_process()函数前后记录时间:
	"netdev--xxx---libentry---xxx---IPv4_entry---xxx---Before_call_plug---xxx---After_call_plug

	或者每次只打印时间值, 不要提示符, 
	"0 -- 1 -- 4 -- 10 -- 20"
*/


/* 2014-12-01 lijia add */
#define PCAP_OP_FLAG_PKT			(0x01)
#define PCAP_OP_FLAG_EOF			(0x02)
#define PCAP_OP_FLAG_IDLE_POLLING	(0x03)


typedef struct{
	raw_pkt_t raw_pkt;
	//unsigned char *data;
	//int data_len;
	//unsigned char route_dir;
	char op_flag; /* 2014-12-01 lijia add */
}pkt_queue_t;

typedef struct {
	pthread_t work_tid;
	short thread_num;
	volatile short op_status; /* 2014-12-01 lijia add */
	int sd_raw_eth;
	struct sockaddr sock_addr_up;
	struct sockaddr sock_addr_down;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	MESA_lqueue_head pkt_queue;
}pcap_work_thread_t;

static pcap_work_thread_t work_thread_pool[MAX_THREAD_NUM];

#if PROCESS_BAR_SW /* 2013-12-04 LiJia add, for 读大包进度实时显示 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


static const char *dumpfile_name;
static unsigned long dumpfile_total_size;
static unsigned long dumpfile_read_size = 0;
static unsigned long  dump_times;
static char process_bar[100][101];
static unsigned long PKTps = 500000;
static int dumpfile_according_timestamp = 0;
static long long dumpfile_timestamp_diff_with_start = 0; /* 当前进程启动时间与收到第一个包的时间戳的差值 */

static long long __get_current_time_in_ms(void)
{
	struct timeval t;
	long long tms;

	gettimeofday(&t, NULL);

	tms = t.tv_sec * 1000 + t.tv_usec/1000;

	return tms;
}
	
static unsigned long __get_file_length(const char *file_name)
{
	struct stat file_stat;
	
	if(stat(file_name, &file_stat) == 0)
	{
		return file_stat.st_size;
	}
	return 0;
}

/* return value:
   byte/ms.
*/
static double process_bar_calc_byte_per_sec(void)
{
	static struct timeval __last_time = {0,0};
	struct timeval __this_time = {0,0};
	static unsigned long __last_read_size = 0;
	double byte_per_sec = 0;
	double time_diff_ms;

	if(0 == __last_time.tv_sec){
		gettimeofday(&__last_time, NULL);
	}
	
	gettimeofday(&__this_time, NULL);

	time_diff_ms = ((double)__this_time.tv_sec*1000.0 + (double)__this_time.tv_usec/1000.0) 
			 - ((double)__last_time.tv_sec*1000.0 + (double)__last_time.tv_usec/1000.0);

	if(time_diff_ms > 0){
		byte_per_sec = 1000.0 * ((double) (dumpfile_read_size - __last_read_size)/(double)time_diff_ms);
	}

	__last_read_size = dumpfile_read_size;
	__last_time = __this_time;

	return (double)byte_per_sec;
}


/* 根据以往的速率, 计算一个平均值 */
static double process_bar_calc_byte_per_sec_average(void)
{
	double __pass_bpms = 0.0;
	double __this_bpms;
	double __pass_num = 0.0;

	__this_bpms = process_bar_calc_byte_per_sec();	

	__pass_bpms += __this_bpms;
	__pass_num += 1.0;

	return __pass_bpms/__pass_num;
}

#if 0
static unsigned long process_bar_get_pps(void)
{
	static time_t __last_time = 0;
	time_t __this_time = 0;
	static unsigned long __last_read_size = 0;
	unsigned long byte_per_sec = 0;
	static int times = 0;

	if(0 == __last_time){
		__last_time = time(NULL);
	}
	
	if(times++ < 200){
		return 0;
	}

	__this_time = time(NULL);

	if(__this_time > __last_time){
		byte_per_sec =  dumpfile_read_size - __last_read_size;
		__last_read_size = dumpfile_read_size;
	}

	times = 0;

	return byte_per_sec;
}
#endif

static void process_bar_print(int len)
{
	double percent;
	double bytes_per_sec, remain_time;
	FILE *fp;
	char dumpfile_proc_log_absolute[PATH_MAX];

	if(CAP_MODEL_PCAP_DUMPFILE != g_pcap_cap_mode){
		return;
	}
	dumpfile_read_size += len + sizeof(struct pcap_pkthdr);
	
	//if((dump_times % (dumpfile_total_size/10000)) == 0){
	if(dump_times > PKTps){
		snprintf(dumpfile_proc_log_absolute, PATH_MAX, "%s/%s", sapp_global_val->config.data_file_path.data_files_root_dir, "dumpfile_progress.log");
		fp = fopen(dumpfile_proc_log_absolute, "w+");
		
		if(dumpfile_read_size < dumpfile_total_size){
			percent = ((double)dumpfile_read_size/(double)dumpfile_total_size) * 100;
		}else{
			percent = 100.00;
		}

		/* 猜测剩余时间 */
		bytes_per_sec = process_bar_calc_byte_per_sec_average();
		if((percent < 99.0) && (bytes_per_sec > 100000.0) && (dumpfile_total_size-dumpfile_read_size > 100000)){
			remain_time = ((double)(dumpfile_total_size-dumpfile_read_size)/bytes_per_sec);
			//printf("dumpfile-progress:%s \033[41m%0.2f%% \033[0m\n", process_bar[index], percent);
			printf("dumpfile-progress: %s\n", process_bar[(int)percent]);
			printf("dumpfile-progress: \033[41m%0.2f%% \033[0m, I guess, process dumpfile over need time almost: \033[41m %0.1fsec  \033[0m \n",  percent, remain_time);	
			if(fp){
				fprintf(fp, "dumpfile-progress: %s\n", process_bar[(int)percent]);
				fprintf(fp, "dumpfile-progress: \033[41m%0.2f%% \033[0m, I guess, process dumpfile over need time almost: \033[41m %0.1fsec  \033[0m \n",  percent, remain_time);
			}
		}else{
			printf("dumpfile-progress: \033[41m%0.2f%% \033[0m\n",  percent);
			if(fp){
				fprintf(fp, "dumpfile-progress: \033[41m%0.2f%% \033[0m\n",  percent);	
			}
		}

		dump_times = 0;
		if(fp){
			fclose(fp);
		}
	}


#if 0
	/* 预估读完包的时间 */
	bytes_per_sec = process_bar_get_pps();
	if(bytes_per_sec > 0){
		printf("^_^ I guess,  read file dumpfile over need time: \033[41m %fs  \033[0m \n", (float)(dumpfile_total_size-dumpfile_read_size)/(float)bytes_per_sec);
	}
#endif

	dump_times++;
}

void process_bar_prt_all(void)
{
	int i;
	for(i = 0; i < 100; i++){
		printf("%s\n", process_bar[i]);
	}
}

int process_bar_prt_init(void)
{
	int i, j;
	
	dumpfile_total_size = __get_file_length(dumpfile_name);

	for(i = 0; i < 100; i++){
		for(j = 0; j < 100; j++){
			if(j <= i){
				process_bar[i][j] = '>';
			}else{
				process_bar[i][j] = '.';
			}
		}
		process_bar[i][100] = '\0'; 
	}

	return 0;
}
#else
inline void process_bar_print(int len)
{
	return;
}
#endif

/*
	TODO, 
	此功能要再抽象一下, 仅对内层tcp包做拆分, 且MTU由配置文件控制, 不能写死!
	外层可以是其他隧道协议, 或vxlan等等, 
	仅保证大的数据包能被拆分发出(不是IP分片), 而不保证网络传输的可靠性.
*/
static int sendpacket_tcp_offload(char *raw_data, int raw_datalen, int fd, const struct sockaddr *sa)
{
#define TCP_TSO_SPLIT_MTU 1400
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
	char tmp_send_buf[MTU_MAX];
	
	const struct sendpacket_ethernet_hdr *raw_eth_hdr = (const struct sendpacket_ethernet_hdr *)raw_data;
	const struct sendpacket_ip_hdr *raw_ip_hdr = (const struct sendpacket_ip_hdr *)((char *)raw_eth_hdr + sizeof(struct sendpacket_ethernet_hdr));
	const struct mesa_tcp_hdr *raw_tcp_hdr = (const struct mesa_tcp_hdr *)((char *)raw_ip_hdr + raw_ip_hdr->ip_hl * 4);
	struct sendpacket_ip_hdr *send_ip_hdr;
	struct mesa_tcp_hdr *send_tcp_hdr;
	char *data;
	int leftlen;
	int this_send_len;
	int ret = 0;
	unsigned int send_seq;
	int local_errno;
	int retry_times = 0;
	int fix_hdr_len;

	if(ETHERTYPE_IP != ntohs(raw_eth_hdr->ether_type)){
		sendto(fd, raw_data, raw_datalen, 0, (struct sockaddr *)sa, sizeof(struct sockaddr));
		sapp_runtime_log(RLOG_LV_FATAL,"sendpacket","MTU more than %d, but protocol is not ip!\n", TCP_TSO_SPLIT_MTU);
		return -1;
	}

	if(raw_ip_hdr->ip_p != IPPROTO_TCP){
		sendto(fd, raw_data, raw_datalen, 0, (struct sockaddr *)sa, sizeof(struct sockaddr));
		sapp_runtime_log(RLOG_LV_FATAL,"sendpacket","MTU more than %d, but protocol is not tcp!\n", TCP_TSO_SPLIT_MTU);
		return -1;
	}
#if 0 //for test	
	if((ntohl(raw_ip_hdr->ip_dst.s_addr) & 0xc0a80000) != 0xc0a80000){
		sendto(fd, raw_data, raw_datalen, 0, (struct sockaddr *)sa, sizeof(struct sockaddr));
		return -1;
	}
#endif

	fix_hdr_len = sizeof(struct sendpacket_ethernet_hdr) + raw_ip_hdr->ip_hl * 4 + raw_tcp_hdr->th_off * 4; /* 固定头部长度, 可能有选项 */

	memcpy(tmp_send_buf, raw_data, fix_hdr_len);
	send_seq = ntohl(raw_tcp_hdr->th_seq);
	leftlen = ntohs(raw_ip_hdr->ip_len) - raw_ip_hdr->ip_hl * 4 - raw_tcp_hdr->th_off * 4; /* 剩余的纯TCP负载部分长度 */
	data = raw_data + fix_hdr_len;
	send_ip_hdr = (struct sendpacket_ip_hdr *)(tmp_send_buf+ sizeof(struct sendpacket_ethernet_hdr));
	send_tcp_hdr = (struct mesa_tcp_hdr *)(tmp_send_buf+ sizeof(struct sendpacket_ethernet_hdr) + send_ip_hdr->ip_hl*4);
	
	while(leftlen > 0){
		retry_times = 0;
		this_send_len = MIN(leftlen, TCP_TSO_SPLIT_MTU);

		memcpy(tmp_send_buf + fix_hdr_len, data, this_send_len); /* 需要计算校验和, 不能修改原始包, copy到临时缓冲区 */
		send_ip_hdr->ip_len = htons(raw_ip_hdr->ip_hl * 4 + raw_tcp_hdr->th_off * 4 + this_send_len);
		send_tcp_hdr->th_seq = htonl(send_seq); /* 拆分TCP负载, 序号依次后移, ACK不变 */
		/* NOTE:
			注意, 此处不能使用固定长度sizeof(struct sendpacket_tcp_hdr),
			因为实际包头中可能包含选项, 要使用原始包的实际长度: raw_tcp_hdr->th_off * 4.
		*/
		sendpacket_do_checksum((unsigned char *)send_ip_hdr, IPPROTO_TCP, raw_tcp_hdr->th_off*4 + this_send_len);
		sendpacket_do_checksum((unsigned char *)send_ip_hdr, IPPROTO_IP, raw_ip_hdr->ip_hl * 4);

send_again:		
		ret = sendto(fd, tmp_send_buf, this_send_len+fix_hdr_len, 0, (struct sockaddr *)sa, sizeof(struct sockaddr));
    		if(ret < 0){
    			local_errno = errno;
			if((EAGAIN == local_errno) 
			  || (EINTR == local_errno) 
			  || (EWOULDBLOCK==local_errno)
			  || (ENOBUFS==local_errno)
			  || (ENOMEM==local_errno))
	  		{
	  			if(retry_times++ < 3){
					sapp_usleep(1);
					goto send_again;
	       		}else{
					sapp_runtime_log(RLOG_LV_FATAL,"sendpacket","retry more than %d times, %s\n", retry_times, strerror(local_errno));
					return -1;
	       		}
		    }
		    	else
		    	{
				sapp_runtime_log(RLOG_LV_FATAL,"sendpacket","%s\n", strerror(local_errno));
				return -1;
			}			
		}
		data += this_send_len;
		leftlen -= this_send_len;
		send_seq += this_send_len;
	}

	return ret;
}


/************************  funcitons for dynamic link *************************/
int pcap_dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_pcap_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int pcap_dl_io_set_cap_level(int cap_level)
{
	g_pcap_cap_level = cap_level;

#if PCAP_CAP_FROM_IP
	g_pcap_cap_level = CAP_LEVEL_IPV4;
#endif

	return 0;
}

int pcap_dl_io_set_cap_mode(int cap_mode)
{
	g_pcap_cap_mode = cap_mode;

	return 0;
}

int pcap_dl_io_set_capdev_parallel(const char *cap_dev)
{
	int len;

	len = snprintf(g_pcap_up_dev_name, DEV_NAME_STR_LEN, "%s", cap_dev);
	if(len >= DEV_NAME_STR_LEN){
		return -1;
	}

	return 0;
}

int pcap_dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	int len;

	len = snprintf(g_pcap_up_dev_name, DEV_NAME_STR_LEN, "%s", up_dev);
	if(len >= DEV_NAME_STR_LEN){
		return -1;
	}
	
	len = snprintf(g_pcap_down_dev_name, DEV_NAME_STR_LEN, "%s", down_dev);
	if(len >= DEV_NAME_STR_LEN){
		return -1;
	}
	
	return 0;
	
}

int pcap_dl_io_set_capture_filter(const char *filter_rule)
{
	int len;
	
	len = snprintf(g_pcap_cap_filter, CAP_FILTER_STR_LEN, "%s", filter_rule);
	if(len >= CAP_FILTER_STR_LEN){
		return -1;
	}
	
	return 0;	
}

int pcap_dl_io_set_cap_buf_queue(int queue_num_max)
{
	g_pcap_buf_queue_num = queue_num_max;

	return 0;
}

int pcap_dl_io_set_work_thread_num(int thread_num_max)
{
	if(thread_num_max > MAX_THREAD_NUM){
		return -1;
	}
	g_pcap_work_thread_num = thread_num_max;

	return 0;
}

/* 此接口针对pag模式发送rst, 数据和日志, pcap模式不区别 */
int pcap_dl_io_set_send_type(int send_type)
{
	return 0;
}


long pcap_dl_io_get_app_drop_num(int thread_num)
{
	return pcap_app_drop_num[thread_num];
}

long pcap_dl_io_get_lib_drop_num(void)
{
	get_pcap_lib_drop_flag = 1;
	
	return pcap_lib_drop_down_num + pcap_lib_drop_up_num;
}

void * pcap_dl_io_device_alias(unsigned int target_id, char *device_args)
{
	/* 对于pcap模式来说, 就是设备名称 eth1, eth2, etc. */
	return (void *)sapp_strdup(device_args);
}

int pcap_dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_pcap_work_fun = fun;

	return 0;
}


int pcap_dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun)
{
	g_pcap_exit_cb_fun = exit_fun;

	return 0;
}

unsigned char *pcap_dl_io_get_sendbuf(void *phandle, int thread_num)
{
	pcap_send_handle *send_handle = (pcap_send_handle *)phandle;
	
	return send_handle->pcap_send_buf;
}

void pcap_dl_io_free_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	
	/* PCAP模式无需释放 */
	return;
}

void *pcap_dl_io_get_send_handle(int thread_seq)
{
	pcap_send_handle *send_handle = (pcap_send_handle *)calloc(1, sizeof(pcap_send_handle));

	send_handle->raw_eth_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if(send_handle->raw_eth_fd < 0){
		printf("socket error: %s\n", strerror(errno));
		goto err_exit;
	}
	send_handle->thread_num = thread_seq;
	strncpy(send_handle->saddr_up.sa_data, g_pcap_up_dev_name, sizeof(struct sockaddr));
	strncpy(send_handle->saddr_down.sa_data, g_pcap_down_dev_name, sizeof(struct sockaddr));
	send_handle->saddr_up.sa_family = PF_INET;
	send_handle->saddr_down.sa_family = PF_INET;

	return send_handle;

err_exit:
	free(send_handle);
	return NULL;
}

void pcap_dl_io_free_send_handle(int thread_seq, void *_handle)
{
	pcap_send_handle *send_handle = (pcap_send_handle *)_handle;

	if(NULL == _handle){
		return;
	}

	if(send_handle->raw_eth_fd > 0){
		close(send_handle->raw_eth_fd);
		send_handle->raw_eth_fd = -1;
	}

	free(_handle);
}

int pcap_dl_io_get_version(void)
{
	return g_pcap_version_internal;
}

int pcap_dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num, unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	pcap_send_handle *send_handle = (pcap_send_handle *)phandle;
	int ret;
	struct sockaddr snd_addr;
	send_raw_args_t *snd_raw_args;
	int retry_times = 0;

	snd_raw_args = (send_raw_args_t *)arg;
	strncpy(snd_addr.sa_data, snd_raw_args->dev_name, sizeof(snd_addr.sa_data));	
	snd_addr.sa_family = PF_INET;

/* 2017-02-28 lijia add, for tcp offload sendback, 某些乱七八糟的破网卡, GRO, GSO等特性关不掉, 导致串联模式大包丢包 */
	//TODO, 此处功能要移到sapp的上层发包接口, 不再这么底层的接口做offload, 因为还可能涉及到marsio模式
    //根据发包网卡的MTU自动判断, 是否需要offload.
#if 0 
	if(datalen > 1514){
		if(sapp_global_single.cfg_send_tcp_offload_sw){
			sapp_runtime_log(10, "send pkt len is:%d, more than 1514,  send packet by tcp_offload,  the slice pkt maybe different with raw pkt !\n", datalen);
			ret = sendpacket_tcp_offload((char *)data, datalen, send_handle->raw_eth_fd, (struct sockaddr *)&snd_addr);
			return ret;		
		}

		sapp_runtime_log(30, "send pkt len is:%d, moren than 1514,  but main.conf->send_tcp_offload is disable !\n", datalen);
		return -1;
	}
#endif

send_again:
	ret = sendto(send_handle->raw_eth_fd, data, datalen, 0, (struct sockaddr *)&snd_addr, sizeof(struct sockaddr));
	if(ret < 0){
		if(EINTR == errno){
			goto send_again; /* 因中断或缓存满导致发送失败, 重试 */
		}else if((EAGAIN == errno) || (ENOBUFS == errno)){
			if(retry_times++ < 5){
				goto send_again; 
			}else{
				sapp_runtime_log(30, "sendto error! %s\n", strerror(errno));
				return -1;
			}
		}else{
			sapp_runtime_log(30, "sendto error! %s\n", strerror(errno));
			return -1;
		}
	}	

	sapp_pkt_dump_by_raw_pkt(thread_num, data, datalen, 1, 0, PKT_CLASSIFY_INJECT);

	return ret;
}


int pcap_dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num,const raw_pkt_t *raw_pkt)
{
	pcap_send_handle *send_handle = (pcap_send_handle *)phandle;
	int dir_reverse, ret;
	struct sockaddr *snd_addr;

	/* 2018-07-26 lijia add, 增加了插件自己创建的线程发包功能, 但是必须发送完整的ethernet包, 底层mac驱动层无法填充 */
	if(thread_num >= g_pcap_work_thread_num){
		sapp_runtime_log(30, "\033[1;31;40m send thread_seq is:%d, bigger than total thread num(%d) !\033[0m\n", thread_num, g_pcap_work_thread_num);
		return -1;
	}
	
	//if(dir != raw_pkt_route_dir[thread_num]){
	//	dir_reverse = 1;
	//}else{
	//	dir_reverse = 0;
	//}

	if(NET_CONN_SERIAL_GDEV == g_pcap_topology_mode){
		snd_addr = &send_handle->saddr_up;
	}else{/* transparent */
		if((DIR_ROUTE_DOWN & dir) == DIR_ROUTE_DOWN){
			snd_addr = &send_handle->saddr_up;
		}else{
			snd_addr = &send_handle->saddr_down;
		}
	}

	//net_common_build_send_mac(data, raw_pkt_hdr[thread_num], eth_carry_layer_addr_type, dir_reverse,g_pcap_topology_mode);
	/* delete by lijia 2014-12-10, datalen已经包含了mac地址长度 */
	//datalen += sizeof(struct mesa_ethernet_hdr); 

	packet_io_hook_sendto(raw_pkt, dir, data, NULL);

send_again:
	ret = sendto(send_handle->raw_eth_fd, data, datalen, 0, (struct sockaddr *)snd_addr, sizeof(struct sockaddr));
	if(ret < 0){
		if((EAGAIN == errno) || (EINTR == errno) ){
			goto send_again;
		}else{
			return -1;
		}
	}	

	sapp_pkt_dump_by_raw_pkt(thread_num, data, datalen, 1, 0, PKT_CLASSIFY_INJECT);

	return ret;
}


/************************  funcitons for dynamic link *************************/


static int pcap_set_filter(pcap_t *handle, const char *filter_str)
{
	struct bpf_program bpf_filter;

	if((NULL == handle) || (NULL == filter_str) || ('\0' == *filter_str)){
		return 0;
	}
	
	if(pcap_compile(handle, &bpf_filter, (char *)filter_str, 1, 0) < 0)
	{
		printf("Compile pcap filter '%s' error:%s\n", filter_str, pcap_geterr(handle));
		return -1;
	}

	if(pcap_setfilter(handle, &bpf_filter) < 0){
		printf("Set pcap filter '%s' error:%s\n", filter_str, pcap_geterr(handle));
		return -1;
	}

	return 0;
}


extern void packet_io_clean_thread_context(int thread_seq);
extern void bind_thread_to_cpuid(int thread_id);

static int pcap_forward_pkt(int thread_num, const unsigned char *data,int data_len,unsigned char dir)
{
	int ret;
	struct sockaddr *sock_addr;

	if(NET_CONN_SERIAL_GDEV == g_pcap_topology_mode){
		/* 特种设备模式, 收发使用同一块网卡 */
		sock_addr = &work_thread_pool[thread_num].sock_addr_up;
#if 0	//2020-12-25 , v4.2版本在	packet_io_hook_output_vxlan()函数已经修改了各层地址, 此处直接转发即可.
		net_common_adjust_forward_mac((struct mesa_ethernet_hdr *)data, g_pcap_topology_mode);
#endif		
	}else{	
		if((DIR_ROUTE_DOWN & dir) == DIR_ROUTE_DOWN){
			sock_addr = &work_thread_pool[thread_num].sock_addr_up; /* the opposite device */
		}else{
			sock_addr = &work_thread_pool[thread_num].sock_addr_down;
		}
	}

send_again:
	ret = sendto(work_thread_pool[thread_num].sd_raw_eth, data, data_len, 0, 
			   sock_addr, sizeof(struct sockaddr));
	if(ret < 0){
		if((EAGAIN == errno) || (EINTR == errno)){
		 	goto send_again;
		}else{
			//printf("sendto error, %s\n", strerror(errno));
			return -1;
		}	
	}

	return (ret);	
}
static void *__pcap_work_thread(void *arg)
{
	int thread_num = (int)(*((short *)arg));
	pkt_queue_t pkt_queue_node;
	long recv_len;
	int ret;
	int total_call_times = 0, rcv_pkt_tims = 0, polling_work_times = 0;

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 480) /* 版本判断, 很多旧系统无法编译 */
#ifdef _GNU_SOURCE
	pthread_setname_np(pthread_self(), "sapp_pkt_process");
#endif
#endif

	set_current_thread_cpu_affinity(thread_num);
	sapp_global_val->individual_fixed.cpu_bind_core_id_per_thread[thread_num] = get_current_thread_cpu_affinity_id();
	sapp_global_val->individual_fixed.thread_tid[thread_num] = syscall(SYS_gettid);

	while(SAPP_STATE_PROCESSING != sapp_get_current_state()){
		sapp_usleep(1000);
	}

	/* for perf optimize
	   频繁调用stream_process_polling()等函数, 此处先在函数外部判断一下是否需要调用.
	*/
	int polling_enabled = sapp_global_val->config.packet_io.polling_enabled;

	while(SAPP_STATE_PROCESSING == sapp_get_current_state()){
		sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_FETCH_PKT]++;
		
		if(0 == MESA_lqueue_get_count(work_thread_pool[thread_num].pkt_queue)){
			if(polling_enabled && (stream_process_polling(thread_num) & POLLING_STATE_WORK)){
				polling_work_times++;
			}
			if(polling_enabled && (polling_stream_timeout(thread_num) & POLLING_STATE_WORK)){
				polling_work_times++;
			}
			total_call_times++;

			if(total_call_times >= 100){
				total_call_times = 0;
				rcv_pkt_tims = 0;
				polling_work_times = 0;
				sapp_usleep(1);
			}
			continue;
		}	
		pthread_mutex_lock(&work_thread_pool[thread_num].mutex);
		recv_len = sizeof(pkt_queue_t);
		ret = MESA_lqueue_get_head(work_thread_pool[thread_num].pkt_queue, &pkt_queue_node, &recv_len);
		pthread_mutex_unlock(&work_thread_pool[thread_num].mutex);
		if(ret < 0){
			continue;
		}

		total_call_times++;
		if(total_call_times >= sapp_global_val->config.packet_io.polling_priority){
			/* 如果流量巨大, 一直有包时, 每隔polling_priority个包也要调用polling接口 */
			if(polling_enabled && (stream_process_polling(thread_num) & POLLING_STATE_WORK )){
				polling_work_times++;
			}
		}
		if(total_call_times >= 100){
			total_call_times = 0;
			rcv_pkt_tims = 0;
			polling_work_times = 0;
			sapp_usleep(1);
		}

		if(PCAP_OP_FLAG_IDLE_POLLING == pkt_queue_node.op_flag){
			idle_polling_call(thread_num);
			polling_stream_timeout(thread_num);		
			continue;
		}else if(PCAP_OP_FLAG_EOF == pkt_queue_node.op_flag){
			libsapp_destroy_env_per_thread(thread_num);
			printf("[Info]free_thread_context success, tid:%d\n", thread_num);
			work_thread_pool[thread_num].op_status = PCAP_OP_FLAG_EOF;
			goto exit;
		}

		raw_pkt_hdr[thread_num] = (struct mesa_ethernet_hdr *)pkt_queue_node.raw_pkt.__lib_raw_pkt_data;
		raw_pkt_route_dir[thread_num] =  pkt_queue_node.raw_pkt.route_dir;

#if DEBUG
		timestamp_record(TS_LEVEL_WORK, &(pkt_queue_node.raw_pkt), thread_num);
#endif		
		ret = (*g_pcap_work_fun)(&(pkt_queue_node.raw_pkt), pkt_queue_node.raw_pkt.route_dir, thread_num);
		/* 串联模式且返回值为PASS, 需要转发包 */
		if((g_pcap_topology_mode & __NET_CONN_SERIAL) && (PASS == ret)){
			pcap_forward_pkt(thread_num, (unsigned char *)pkt_queue_node.raw_pkt.__lib_raw_pkt_data, 
						pkt_queue_node.raw_pkt.__lib_raw_pkt_len, pkt_queue_node.raw_pkt.route_dir);
		}

		PCAP_FREE((void *)(pkt_queue_node.raw_pkt.__lib_raw_pkt_data));
	}

exit:
	return NULL;
}

static int pcap_create_work_thread(void)
{
	int i, ret;

	for(i = 0; i < g_pcap_work_thread_num; i++)
	{
		work_thread_pool[i].thread_num = i;
		pthread_cond_init (&work_thread_pool[i].cond, NULL);
		pthread_mutex_init (&work_thread_pool[i].mutex, NULL);		
		work_thread_pool[i].sd_raw_eth = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
		if(work_thread_pool[i].sd_raw_eth < 0){
			printf("pcap_create_work_thread(), socket raw eth error, %s\n", strerror(errno));
			assert(0);
		}
		ret = snprintf(work_thread_pool[i].sock_addr_up.sa_data, 
					sizeof(work_thread_pool[i].sock_addr_up.sa_data), 
					"%s", g_pcap_up_dev_name);
		if(ret >= 	(int)sizeof(work_thread_pool[i].sock_addr_up.sa_data)){
			printf("cap device name is too long!\n");
			assert(0);
		}
		ret = snprintf(work_thread_pool[i].sock_addr_down.sa_data, 
					sizeof(work_thread_pool[i].sock_addr_down.sa_data), 
					"%s", g_pcap_down_dev_name);
		if(ret >= 	(int)sizeof(work_thread_pool[i].sock_addr_down.sa_data)){
			printf("cap device name is too long!\n");
			assert(0);
		}
		work_thread_pool[i].op_status = PCAP_OP_FLAG_PKT;
		/* 注意:此处不用MESA_lqueue自带的线程安全锁, 为了实现__pcap_work_thread()的cond_wait功能. */
		work_thread_pool[i].pkt_queue = MESA_lqueue_create(0, g_pcap_buf_queue_num+1);

		ret = pthread_create(&work_thread_pool[i].work_tid, NULL, __pcap_work_thread, &work_thread_pool[i].thread_num);
		assert(ret == 0);
		sapp_global_val->individual_fixed.thread_obtain_id[i] = work_thread_pool[i].work_tid;
	}

	return 0;
}

static inline unsigned int __rol32( unsigned int word,  unsigned int shift) 
{
	return (word << shift) | (word >> (32 - shift));
}

#define __pcap_dispatch_hash(a, b, c) {    \
	c ^= b; c -= __rol32(b, 14);        \
	a ^= c; a -= __rol32(c, 11);        \
	b ^= a; b -= __rol32(a, 25);        \
	c ^= b; c -= __rol32(b, 16);        \
	a ^= c; a -= __rol32(c, 4);        \
	b ^= a; b -= __rol32(a, 14);        \
	c ^= b; c -= __rol32(b, 24);        \
}

static unsigned int pcap_dispatch_hash(unsigned int a, unsigned int b, unsigned int c) 
{
	__pcap_dispatch_hash(a, b, c);

	return c;
}


static unsigned int __pcap_dispatch_thread(const u_char *data)
{
	const void *res;
	unsigned int hash = 0;
	unsigned char *disp_arg1, *disp_arg2;
	int disp_addrlen;
	const struct ip *ipv4_hdr;
	const struct ip6_hdr *ipv6_hdr;

	if(PCAP_DISTMODE_OUTER_TUPLE2 == g_pcap_distmode){
		res = MESA_jump_layer((const void *)data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V4);
	}else{
		res = MESA_jump_layer_greedy((const void *)data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V4);
	}
	
	if(res){
		ipv4_hdr = (const struct ip *)res;
		if(memcmp(&ipv4_hdr->ip_src.s_addr, &ipv4_hdr->ip_dst.s_addr, sizeof(int)) >= 0){
			disp_arg1 = (unsigned char *)&ipv4_hdr->ip_src.s_addr;
			disp_arg2 = (unsigned char *)&ipv4_hdr->ip_dst.s_addr;
		}else{
			disp_arg1 = (unsigned char *)&ipv4_hdr->ip_dst.s_addr;
			disp_arg2 = (unsigned char *)&ipv4_hdr->ip_src.s_addr;
		}
		disp_addrlen = sizeof(int);
		goto disp;
	}

	if(PCAP_DISTMODE_OUTER_TUPLE2 == g_pcap_distmode){
		res = MESA_jump_layer((const void *)data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V6);
	}else{
		res = MESA_jump_layer_greedy((const void *)data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V6);
	}
	if(res){
		ipv6_hdr = (const struct ip6_hdr *)res;
		/* 只使用IPv6地址的一部分 */
		if(memcmp(&ipv6_hdr->ip6_src.s6_addr32[3], &ipv6_hdr->ip6_dst.s6_addr32[3], sizeof(int)) >= 0){
			disp_arg1 = (unsigned char *)&ipv6_hdr->ip6_src;
			disp_arg2 = (unsigned char *)&ipv6_hdr->ip6_dst;
		}else{
			disp_arg1 = (unsigned char *)&ipv6_hdr->ip6_dst;
			disp_arg2 = (unsigned char *)&ipv6_hdr->ip6_src;
		}
		disp_addrlen = sizeof(struct in6_addr);
		goto disp;
	}

	/* 非IPv4, 非IPv6协议, 暂时返回0, 固定用一个线程处理.
		to do: 识别尽可能多的已知协议类型, 计算一个hash值.
	*/
	return 0;

disp:
	//hash = pcap_dispatch_hash(disp_arg1, disp_arg2, 0xFEEDBEAF); 
	hash = dpdk_rte_ip_hash(disp_arg1, disp_arg2, disp_addrlen);
	hash %=  g_pcap_work_thread_num;

	return hash;
}

static void __pcap_nodify_work_thread(char op_flag)
{
	pkt_queue_t pkt_queue_node;
	int i, ret;

	for(i = 0; i < g_pcap_work_thread_num; i++){
		pkt_queue_node.op_flag = op_flag;
retry:		
		pthread_mutex_lock(&work_thread_pool[i].mutex);
		ret = MESA_lqueue_join_tail(work_thread_pool[i].pkt_queue, &pkt_queue_node, sizeof(pkt_queue_t));
		pthread_mutex_unlock(&work_thread_pool[i].mutex);		
		if(0 == ret){
			pthread_cond_signal(&work_thread_pool[i].cond);
		}else{
			sapp_usleep(1);
			//MESA_sleep();
			goto retry;
		}
	}
}

static inline int pcap_raw_pkt_check(const struct pcap_pkthdr *hdr, u_char *user)
{
	if(0 == (*user & DIR_ROUTE_DOWN)){
		if(hdr->caplen > pcap_device_up_mtu){
			if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode){
				sapp_runtime_log(20, "pcap recv pkt from %s, but length is %d, you should be disable GRO, GSO,TSO, etc.\n", g_pcap_up_dev_name, hdr->caplen);
			}
		}
	}else{
		if(hdr->caplen > pcap_device_down_mtu){
			if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode){
				sapp_runtime_log(20, "pcap recv pkt from %s, but length is %d, you should be disable GRO, GSO,TSO, etc.\n", g_pcap_down_dev_name, hdr->caplen);
			}
		}
	}

	if(hdr->caplen <= 14){
		return -1;
	}

	return 0;
}


static void dumpfile_wait_according_timestamp(const struct pcap_pkthdr *hdr)
{
	long long cur_time_ms;
	long long pkt_time_ms;

	pkt_time_ms = hdr->ts.tv_sec * 1000 + hdr->ts.tv_usec / 1000;
	cur_time_ms = __get_current_time_in_ms() - dumpfile_timestamp_diff_with_start;

	while(pkt_time_ms > cur_time_ms){
		sapp_usleep(100);
		cur_time_ms = __get_current_time_in_ms() - dumpfile_timestamp_diff_with_start;	
	}
}


static int gen_route_dir_for_dumpfile_mode(const u_char *data)
{
	int datalink_type = pcap_datalink(pcap_up_handle);
	int route_dir = 0;
	const struct mesa_ip4_hdr *ihdr4;
	const struct mesa_ip6_hdr *ihdr6;
	int raw_layer_type = ADDR_TYPE_MAC;

	if(DLT_EN10MB == datalink_type){
		raw_layer_type = ADDR_TYPE_MAC;
	}else if(DLT_RAW == datalink_type){
		raw_layer_type = ADDR_TYPE_IPV4;
	}

	ihdr4 = (struct mesa_ip4_hdr *)MESA_jump_layer(data, raw_layer_type, ADDR_TYPE_IPV4);
	if(NULL == ihdr4){
		ihdr6 = (struct mesa_ip6_hdr *)MESA_jump_layer(data, raw_layer_type, ADDR_TYPE_IPV6);
		if(NULL == ihdr6){
			return 0;
		}else{
			if(memcmp(&ihdr6->ip6_src, &ihdr6->ip6_dst, sizeof(struct in6_addr)) > 0){
				route_dir = 1;
			}else{
				route_dir = 0;
			}
		}
	}else{
		if(memcmp(&ihdr4->ip_src.s_addr, &ihdr4->ip_dst.s_addr, sizeof(int)) > 0){
			route_dir = 1;
		}else{
			route_dir = 0;
		}
	}

	/* 
		todo, 两个IP地址一样怎么办? 比如127.0.0.1本机通信, 再比端口.
	*/

	return route_dir;
}

static void __pcap_pkt_handle(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	pkt_queue_t pkt_queue_node = {};
	int thread_num, ret;

	if(CAP_MODEL_PCAP_ONLINE == g_pcap_cap_mode){
		if(pcap_raw_pkt_check(hdr, user) < 0){
			return;
		}
	}

	thread_num = __pcap_dispatch_thread(data);

	if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode){
#if PROCESS_BAR_SW	
		process_bar_print(hdr->caplen);	
#endif		
		if((dumpfile_according_timestamp != 0)){
			if(0 == dumpfile_timestamp_diff_with_start){ /* first time */
				dumpfile_timestamp_diff_with_start = __get_current_time_in_ms() - (hdr->ts.tv_sec * 1000 + hdr->ts.tv_usec / 1000);
			}

			dumpfile_wait_according_timestamp(hdr);
		}
	}

#if 0
retry:	
	if(MESA_lqueue_get_count(work_thread_pool[thread_num].pkt_queue) < g_pcap_buf_queue_num){
		pkt_queue_node.data = (unsigned char *)PCAP_MALLOC(hdr->len);
		memcpy(pkt_queue_node.data, data, hdr->len);
		pkt_queue_node.data_len = hdr->len;
		pkt_queue_node.route_dir = *((unsigned char *)user);
		
		pthread_mutex_lock(&work_thread_pool[thread_num].mutex);
		MESA_lqueue_join_tail(work_thread_pool[thread_num].pkt_queue, &pkt_queue_node, sizeof(pkt_queue_t));
		pthread_cond_signal(&work_thread_pool[thread_num].cond);
		pthread_mutex_unlock(&work_thread_pool[thread_num].mutex);
	}else{
		if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode){
			sapp_usleep(1);
			goto retry;  /* 在读包模式下, 保证不因队列满而丢包 */
		}
		pcap_app_drop_num[thread_num]++;
	}
#else
	pkt_queue_node.raw_pkt.__lib_raw_pkt_data = PCAP_MALLOC(hdr->caplen);

#if PCAP_CAP_FROM_IP	
	const struct mesa_ethernet_hdr *p_eth_hdr = (struct mesa_ethernet_hdr *)data;
	if(ntohs(p_eth_hdr->ether_type) != ETHERTYPE_IP){
		return;
	}

	pkt_queue_node.raw_pkt.raw_pkt_data = (char *)pkt_queue_node.raw_pkt.__lib_raw_pkt_data + 14;
	pkt_queue_node.raw_pkt.raw_pkt_len = hdr->caplen - 14;
#else
	pkt_queue_node.raw_pkt.raw_pkt_data = pkt_queue_node.raw_pkt.__lib_raw_pkt_data;
	pkt_queue_node.raw_pkt.raw_pkt_len = hdr->caplen;
#endif
	memcpy((void *)(pkt_queue_node.raw_pkt.__lib_raw_pkt_data), data, hdr->caplen);
	//pkt_queue_node.raw_pkt.raw_pkt_len = hdr->len;
	/* 2015-09-28 lijia modify,
		此处要使用caplen, 因为可能由于没有加-s0选项, 实际捕包与理论包长不一致!
	*/
	pkt_queue_node.raw_pkt.__lib_raw_pkt_len = hdr->caplen;
	
	/* pcap包头的timestamp可能是32bit的, 使用单独赋值语句 */
	pkt_queue_node.raw_pkt.raw_pkt_ts.tv_sec = hdr->ts.tv_sec;
	pkt_queue_node.raw_pkt.raw_pkt_ts.tv_usec = hdr->ts.tv_usec;
	pkt_queue_node.raw_pkt.low_layer_type = (enum addr_type_t)g_pcap_cap_level;
	pkt_queue_node.raw_pkt.magic_num = RAW_PKT_MAGIC_NUM; /* 2014-12-11 lijia add */
	pkt_queue_node.raw_pkt.hd_hash = 0; /* 2016-05-05 lijia add, pcap模式不支持硬件HASH */
	pkt_queue_node.raw_pkt.io_lib_pkt_reference = pkt_queue_node.raw_pkt.__lib_raw_pkt_data; /* 兼容dpdk模式, 将此变量赋值 */
	pkt_queue_node.raw_pkt.vlan_flipping_couple[0] = 0;
	pkt_queue_node.raw_pkt.vlan_flipping_couple[1] = 0;
	pkt_queue_node.raw_pkt.mac_flipping_enable = 0;
	pkt_queue_node.raw_pkt.diagnose_error_to_dump = 0;
	pkt_queue_node.raw_pkt.overlay_layer_bytes = 0;
	pkt_queue_node.raw_pkt.drop_current_pkt_flag = 0;

	if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode){
		/* 读包模式下本来没有routedir的概念, 为了便于测试上层业务, 使用最底层地址比较算出一个routedir */
		pkt_queue_node.raw_pkt.route_dir = gen_route_dir_for_dumpfile_mode(data);
	}else{
		pkt_queue_node.raw_pkt.route_dir = *((unsigned char *)user);
	}

	pkt_queue_node.op_flag = PCAP_OP_FLAG_PKT;
#if DEBUG
	timestamp_record_lib(&pkt_queue_node.raw_pkt);
#endif	
retry:		
	pthread_mutex_lock(&work_thread_pool[thread_num].mutex);
	ret = MESA_lqueue_join_tail(work_thread_pool[thread_num].pkt_queue, &pkt_queue_node, sizeof(pkt_queue_t));
	pthread_mutex_unlock(&work_thread_pool[thread_num].mutex);
	
	if(MESA_QUEUE_RET_OK == ret){	
		pthread_cond_signal(&work_thread_pool[thread_num].cond);
	}else{
		if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode){
			if(0 == g_use_MESA_sleep_sw){
				sapp_usleep(1);
			}else{
				MESA_sleep();
			}
			goto retry;  /* 在读包模式下, 保证不因队列满而丢包, 要不断重试 */
		}else{
			pcap_app_drop_num[thread_num]++; /* 在线模式记录丢包数 */
			PCAP_FREE((void *)(pkt_queue_node.raw_pkt.__lib_raw_pkt_data));
		}	
	}
#endif

	if(get_pcap_lib_drop_flag != 0){
		struct pcap_stat pcap_st = {};
		if(0 == (DIR_ROUTE_DOWN & *((unsigned char *)user))){
			if(pcap_stats(pcap_up_handle, &pcap_st) == 0){
				pcap_lib_drop_up_num = pcap_st.ps_drop + pcap_st.ps_ifdrop;
			}
		}else{
			if(pcap_stats(pcap_down_handle, &pcap_st) == 0){
				pcap_lib_drop_down_num = pcap_st.ps_drop + pcap_st.ps_ifdrop;
			}
		}
		get_pcap_lib_drop_flag = 0;	
	}

	if(0 == (DIR_ROUTE_DOWN & *((unsigned char *)user))){
		tot_up_rcv_pkt_num++;
	}else{
		tot_down_rcv_pkt_num++;
	}

	return;
}

extern void packet_io_exit(void);
extern volatile int update_packet_io_status_sw;
static void wait_all_work_thread(void)
{
	//pkt_queue_t pkt_queue_node;
	int i;
	long tot_empty_num = 0;

	do{
		tot_empty_num = 0;
		for(i = 0; i < g_pcap_work_thread_num; i++){
#if 0	
			while(1){	
				len = sizeof(pkt_queue_t);
				pthread_mutex_lock(&work_thread_pool[i].mutex);
				ret = MESA_lqueue_read_head(work_thread_pool[i].pkt_queue, &pkt_queue_node, &len);		
				pthread_mutex_unlock(&work_thread_pool[i].mutex);
				if(ret < 0){
					tot_empty_num++;
					break;
				}
			}
#else
			if(PCAP_OP_FLAG_EOF == work_thread_pool[i].op_status){
				tot_empty_num++;
			}
#endif
		}
	}while(tot_empty_num != g_pcap_work_thread_num);


	if(1 == update_packet_io_status_sw){
		sysinfo_output(); /* 最后一次写统计信息, 关闭标志位, 因为流表将被清空, 再写就没意义了 */
		update_packet_io_status_sw = 0;
	}
	
	printf("[Info]clear all context success.\n");

	//packet_io_exit();
	(*g_pcap_exit_cb_fun)();

	return;
}


static pcap_t *pcap_open_dumpfile_mode(const char *filename)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;

	if((pcap_handle = pcap_open_offline(filename, pcap_errbuf)) == NULL)
	{
		printf("\033[1;31;40m[Error]Can't open file:'%s', %s\033[0m\n", filename, pcap_errbuf);
		return NULL;
	}

	pcap_set_filter(pcap_handle, g_pcap_cap_filter);

	return pcap_handle;
}


static void pcap_io_dumpfile_list(void)
{
	pcap_t *pcap_handle;
	int pcap_file_num = 0;
	unsigned char route_dir = DIR_ROUTE_UP;
	struct timeval start_time, end_time;
	
	while(sapp_global_val->cla.dumpfie_list_array[pcap_file_num] != NULL){
		pcap_handle = pcap_open_dumpfile_mode(sapp_global_val->cla.dumpfie_list_array[pcap_file_num]);
		if(pcap_handle){
			pcap_up_handle = pcap_handle;
			gettimeofday(&start_time, NULL);
			pcap_loop(pcap_handle, -1, __pcap_pkt_handle, (unsigned char *)&route_dir);
			gettimeofday(&end_time, NULL);

			sapp_log(20, 1, 1, "pcap file '%s' processing finished, takes time: %ldus", 
					sapp_global_val->cla.dumpfie_list_array[pcap_file_num],
					(end_time.tv_sec-start_time.tv_sec)*1000*1000 + (end_time.tv_usec-start_time.tv_usec));
			pcap_close(pcap_handle);
			pcap_up_handle = NULL;

			dumpfile_timestamp_diff_with_start = 0; /* 每个pcap包的时间戳都不一样, 处理完后重置相对时间戳 */
		}
		pcap_file_num++;
	}

	__pcap_nodify_work_thread(PCAP_OP_FLAG_EOF);
	wait_all_work_thread();

	return;
}

static void *pcap_io_thread(void *arg)
{
	long route_dir_arg = (long)arg; /* 逃过编译器precision检查 */
	unsigned char route_dir = (unsigned char)route_dir_arg;
	pcap_t *handle;
	int pcap_ret;
	char *no_use;

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 480) /* 版本判断, 很多旧系统无法编译 */
#ifdef _GNU_SOURCE
	pthread_setname_np(pthread_self(), "sapp");
#endif
#endif

	if(sapp_get_cla_raw("dumpfile-list", &no_use) >= 0){
		pcap_io_dumpfile_list();
		exit(0);
	}

	if(0 == (DIR_ROUTE_DOWN & route_dir)){
		handle = pcap_up_handle;
	}else{
		handle = pcap_down_handle;
	}

	while(SAPP_STATE_PROCESSING != sapp_get_current_state()){
		sapp_usleep(1000);
	}

	while(1){

		if(1){
			pcap_ret = pcap_loop(handle, -1, __pcap_pkt_handle, (unsigned char *)&route_dir);
		}else{
			pcap_ret = pcap_dispatch(handle, -1, __pcap_pkt_handle, (unsigned char *)&route_dir);
		}
		if(0 == pcap_ret){
			if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode){
				printf("\033[32m[Notice]process dumpfile over!\033[0m\n");
				__pcap_nodify_work_thread(PCAP_OP_FLAG_EOF);
				wait_all_work_thread();
				return NULL;
			}else{
				__pcap_nodify_work_thread(PCAP_OP_FLAG_IDLE_POLLING);
			}		
		}else if(pcap_ret < 0){
			printf("pcap err, %s\n", pcap_geterr(handle));
			sapp_set_current_state(SAPP_STATE_READY_TO_EXIT);
			exit(1);
		}
	}

	return NULL;
}


int pcap_dl_io_init(int argc, char *argv[])
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	int opt_len;
	char *no_use;

#if PCAP_CAP_FROM_IP	
	printf("\033[41m Warning! 'PCAP_CAP_FROM_IP' is enable!. \033[0m\n");
#endif

	if(CAP_MODEL_PCAP_DUMPFILE == g_pcap_cap_mode) /* pcap本地读包模式 */	
	{
		if(g_pcap_topology_mode & __NET_CONN_SERIAL){
			printf("\033[1;31;40m[Error]cap_mode is %d, but topology is serial!\033[0m\n", g_pcap_cap_mode);
			return -1;
		}
		
		if(sapp_get_cla_raw("dumpfile-list", &no_use) >= 0){
			;//读列表模式, 无需此处打开dumpfile文件
		}else{
			if((pcap_up_handle = pcap_open_offline(sapp_global_val->config.packet_io.pcap_dumpfile_name, pcap_errbuf)) == NULL)
			{
				printf("\033[1;31;40m[Error]Can't open file:'%s', %s\033[0m\n", sapp_global_val->config.packet_io.pcap_dumpfile_name, pcap_errbuf);
				return -1;
			}
		}
#if PROCESS_BAR_SW
		dumpfile_name = "dumpfile";
#endif
		pcap_down_handle = NULL;

#if PROCESS_BAR_SW
		process_bar_prt_init();
#endif
		pcap_set_filter(pcap_up_handle, g_pcap_cap_filter);
		//g_pcap_topology_model = NET_CONN_PARA_NOSEND; /* 本地读包模式，网络拓扑模式设为并联不发包 */
	}
	else /* 网络抓包模式 */
	{
		if((strncasecmp(sapp_global_val->config.packet_io.depolyment_mode_str, "transparent", strlen("transparent")) == 0)
		  && (strstr(sapp_global_val->config.packet_io.pcap_capture_direction, "out") != NULL)){
			printf("\033[1;31;40m[Error]in transparent mode, pcap_capture_direction must set 'in'![0m\n");
			return -1;
		}
		pcap_up_handle = pcap_open_live(g_pcap_up_dev_name, PCAP_SNAPLEN_MAX,1,1,pcap_errbuf);
		if(NULL == pcap_up_handle)
		{
			printf("\033[1;31;40m[Error]Can't open device:'%s', %s\033[0m\n", g_pcap_up_dev_name, pcap_errbuf);
			return -1;
		}

		pcap_set_filter(pcap_up_handle, g_pcap_cap_filter);
		if(strncasecmp(sapp_global_val->config.packet_io.pcap_capture_direction, "inout", 5) == 0){
			pcap_setdirection(pcap_up_handle, PCAP_D_INOUT);
		}else if(strncasecmp(sapp_global_val->config.packet_io.pcap_capture_direction, "out", 3) == 0){
			pcap_setdirection(pcap_up_handle, PCAP_D_OUT);
		}else{
			pcap_setdirection(pcap_up_handle, PCAP_D_IN);
		}
		
		opt_len = sizeof(int);
		sapp_get_device_opt(g_pcap_up_dev_name, SDO_MTU, &pcap_device_up_mtu, &opt_len);	
		if(pcap_device_up_mtu < 1500){
			printf("\033[41m Warning! '%s' MTU is %d!. \033[0m\n", g_pcap_up_dev_name, pcap_device_up_mtu);
		}
		pcap_device_up_mtu += sizeof(struct mesa_ethernet_hdr); /* MTU不含ethernet层长度, 但pcap捕包是包括的, 需要加上这个头部 */
		
		if(NET_CONN_SERIAL_2CARD == g_pcap_topology_mode) /* 双网卡串联模式 */	
		{
			pcap_down_handle = pcap_open_live(g_pcap_down_dev_name, PCAP_SNAPLEN_MAX,1,1,pcap_errbuf);
			if(NULL == pcap_down_handle)
			{
				printf("\033[1;31;40m[Error]Can't open device:'%s', %s\033[0m\n", g_pcap_down_dev_name, pcap_errbuf);
				return -1;
			}

			opt_len = sizeof(int);
			sapp_get_device_opt(g_pcap_down_dev_name, SDO_MTU, &pcap_device_down_mtu, &opt_len);	
			if(pcap_device_down_mtu < 1500){
				printf("\033[41m Warning! '%s' MTU is %d!. \033[0m\n", g_pcap_down_dev_name, pcap_device_down_mtu);
			}
			pcap_device_down_mtu += sizeof(struct mesa_ethernet_hdr); /* MTU不含ethernet层长度, 但pcap捕包是包括的, 需要加上这个头部 */
			pcap_set_filter(pcap_down_handle, g_pcap_cap_filter);
			pcap_setdirection(pcap_down_handle, PCAP_D_IN);
		}
	}
	
	pcap_create_work_thread();
	
#if 0 /* version3.0 */
	MESA_load_profile_string_def("conf/main.conf", "Module", "dumpfile_speed", cfg_buf, sizeof(cfg_buf), "topspeed");
	if(strncasecmp(cfg_buf, "timestamp", strlen("timestamp")) == 0){
		dumpfile_according_timestamp = 1;	
	}
#else
	char *dumpfile_speed_mode;
	if(sapp_get_cla_raw("dumpfile-speed", &dumpfile_speed_mode) < 0){
		dumpfile_according_timestamp = 0; /* default is top-speed */	
	}else{
		if(strncasecmp(dumpfile_speed_mode, "timestamp", strlen("timestamp")) == 0){
			dumpfile_according_timestamp = 1;	
		}
	}
#endif

	char conf_pcap_distmode[NAME_MAX];
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"pcap_distmode", conf_pcap_distmode, sizeof(conf_pcap_distmode), "inner_tuple2");
	if(strncasecmp(conf_pcap_distmode, "inner_tuple2", strnlen("inner_tuple2", NAME_MAX)) == 0){
		g_pcap_distmode = PCAP_DISTMODE_INNER_TUPLE2;
	}else if(strncasecmp(conf_pcap_distmode, "outer_tuple2", strnlen("outer_tuple2", NAME_MAX)) == 0){
		g_pcap_distmode = PCAP_DISTMODE_OUTER_TUPLE2;
	}else{
		printf("\033[1;31;40m[Error]invalid [packet_io.feature]->pcap_distmode:'%s', only support [\"inner_tuple2\", \"outer_tuple2\"].\033[0m\n", conf_pcap_distmode);
		return -1;
	}

	return 0;
}

void pcap_dl_io_destroy(void)
{
	if(pcap_up_handle){
		pcap_close(pcap_up_handle);
		pcap_up_handle = NULL;
	}
	if(pcap_down_handle){
		pcap_close(pcap_down_handle);
		pcap_down_handle = NULL;
	}	
}

/* not return except some error occur. */
void pcap_dl_io_run(void)
{
	pthread_t tid_up, tid_down;
	long dir_up = DIR_ROUTE_UP;
	long dir_down = DIR_ROUTE_DOWN;
	
	pthread_create(&tid_up, NULL, pcap_io_thread, (void *)dir_up);

	if(NET_CONN_SERIAL_2CARD == g_pcap_topology_mode){ /* 双网卡串联模式 */	
		pthread_create(&tid_down, NULL, pcap_io_thread, (void *)dir_down);
	}

	return;
}


#ifdef __cplusplus
}
#endif

