#include <stdlib.h>
#include <stdint.h>
#include <linux/stddef.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include "sapp_limits.h"
#include "stream.h"
#include "stream_internal.h"


/* sapp性能测试, 使用tap虚网卡模式获取数据包
   读包只有个pcap, 读入内存后, 
   随机修改四元组地址, 但是内容不变, 伪造出有成千上万个流的效果.
*/


/*
	将函数 __sapp_perf_gen_pkt_cb 移植到此处,
	并发N个线程, 每个线程有N个队列, 

	使用readdir命令, 读取一个perf test pcap包的目录,
	将里面所有的pcap包, 比如准备一些混合流量, tcp, udp, http, dns等等吧, 
	每个队列里暂存每个物理pcap包, 这些pcap的数量保存一个Index, 每次发完一个然后递增, 到最后一个包再归零,

	每个线程内的并发连接并不是真正构造那么多pcap包, 

	每个队列初始化时选择一个物理原始pcap包, 然后就不再改了, 
	并发队列和物理队列的关系是NtoM, 随机挑选, 只要并发流数足够多, 物理pcap也基本会平均的分散到每个队列.
	只是修改sip,dip地址, 也不用重新计算校验和, 用来模拟N个连接, 但实际的数据负载是一样的,
	此种测试方法对业务插件不太好使, 但sapp只关心tcp/udp流还原层面, 是可以的.

	发包时, 先随机选择队列index, 模拟多个连接并发的感觉, 而不是一个pcap包一次就全部发送完, 
	也模拟了sapp缓存不命中的问题, 即当前包是正序的tcp, 下一个就是udp, 下一个又是tcp乱序包, 每次函数栈不一样.

	然后对于一个队列内的pcap包, 每次全部发完一次, 更新一个全局sip,dip的偏移量, 记住这个偏移量, 然后依次发送.
	
	可以通过配置文件设置每个pcap包所占比例, 1-100, 比如:
	tcp_short_payload.pcap  20
	tcp_lost.pcap	 5
	udp_dns.pcap	 3
	tcp_long_payload.pcap 10
	tcp_syn_flood.pcap 1
	icmp.pcap 		1
*/

static const char *sapp_pf_version = "2021.06.01";
static int SAPP_IO_THREAD_NUM = 1;
static int SAPP_CONCURRENT_STREAM  = 1000;
static int g_sapp_pf_modify_port = 0;

#define SAPP_PT_PCAP_FILE_LIST  "./perf_test_pcap.list"
char **g_sapp_pt_pcap_file_list;
static int g_sapp_pt_pcap_file_num;
static char g_raw_pcap_file_name[PATH_MAX] = "dumpfile";


typedef struct{
	int pkt_num; /* 这个pcap包里一共多少个数据包 */
	int *pkt_len; /* pcap每个eth包的长度 */
	const struct ethhdr **pkt_data; /* 存储pcap包内容的指针数组 */
}sapp_pt_pcap_file_image_t;


typedef struct{
	const sapp_pt_pcap_file_image_t  *raw_pcap_image;
	int pkt_seq; /* 当前队列回放到第几个包了, 即数组sapp_perf_inject_pkt_array[]下标 */
	unsigned int ip_pad;
	unsigned int port_pad;
}sapp_pt_pkt_modify_para_t;


static int g_pcap_image_num; /* 测试目录共有多少个pcap文件 */
static sapp_pt_pcap_file_image_t **g_pcap_image_array; /* 存储原始pcap包镜像的指针数组 */

typedef struct{
	unsigned int ip_pad; /* 原始包的sip和dip地址偏移量, 为了不区别方向, 两边的地址同时偏移一个值,保证四元组是对的 */
	unsigned short port_pad; /* 原始包的端口偏移量 */	
}sapp_ip_pad_t;

static sapp_ip_pad_t g_sapp_ip_pad[128]; /* 每个线程独立且起始值随机 */


extern int libsapp_setup_env(int argc, char *argv[]);

static inline void update_pkt_ip_port(struct ethhdr *ehdr, unsigned int ip_pad, unsigned short port_pad)
{
	struct ip *iph4 = (struct ip *)((char *)ehdr + sizeof(struct ethhdr));
	struct tcphdr *tcph;
	struct udphdr *udph;
	
	iph4->ip_src.s_addr += ip_pad;
	iph4->ip_dst.s_addr += ip_pad;

	if(g_sapp_pf_modify_port){
		if(IPPROTO_TCP == iph4->ip_p){
			tcph = (struct tcphdr *)((char *)iph4 + iph4->ip_hl * 4);
			tcph->source += port_pad;
			tcph->dest += port_pad;
		}else if(IPPROTO_UDP == iph4->ip_p){
			udph = (struct udphdr *)((char *)iph4 + iph4->ip_hl * 4);
			udph->source += port_pad;
			udph->dest += port_pad;		
		}
	}
}


static sapp_pt_pcap_file_image_t* pkt_image_hard_dup(const sapp_pt_pcap_file_image_t *raw_image)
{
	int i;
	sapp_pt_pcap_file_image_t *new_image = (sapp_pt_pcap_file_image_t *)malloc(sizeof(sapp_pt_pcap_file_image_t));
	new_image->pkt_data = (const struct ethhdr **)malloc(sizeof(void *) * raw_image->pkt_num);
	new_image->pkt_len = (int *)malloc(sizeof(int) * raw_image->pkt_num);

	for( i = 0; i < raw_image->pkt_num; i++){
		new_image->pkt_data[i] = malloc(raw_image->pkt_len[i]);
		new_image->pkt_len[i] = raw_image->pkt_len[i];
		memcpy((void *)new_image->pkt_data[i], raw_image->pkt_data[i], raw_image->pkt_len[i]);
	}

	new_image->pkt_num = raw_image->pkt_num;

	return new_image;
}


static void update_local_replay_concurrent_stream_array(long thread_index, sapp_pt_pkt_modify_para_t *local_replay_pkt_array, int array_max_num)
{
	int i;
	int rand_index;
	
	memset(local_replay_pkt_array, 0, sizeof(sapp_pt_pkt_modify_para_t) * SAPP_CONCURRENT_STREAM);

	for(i = 0; i < SAPP_CONCURRENT_STREAM; i++){
		rand_index = rand() % g_pcap_image_num;
		local_replay_pkt_array[i].raw_pcap_image = pkt_image_hard_dup(g_pcap_image_array[rand_index]);
		local_replay_pkt_array[i].pkt_seq = 0;

		printf("thread:%ld build concurrent stream:%d succ...\n", thread_index, i);
	}
}

			
/*
	sapp也会自己创建线程, 此时的线程其实是假的,不是真正的packet_io线程, 
	但是线程id符合sapp的编号, 把数据包直接注入到eth_entry, 所以能骗过sapp.
*/
static void *fake_sapp_io_thread(void *arg)
{
	long thread_index = (long )arg;
	raw_pkt_t fake_raw_pkt;
	unsigned long long rand_seed_1 = random() ^ 1; /* 保证是个单数 */
	unsigned long long rand_seed_2 = random() & 0xFFFFFFFEL; /* 保证是个偶数 */
	unsigned long long rand_seed_3 = random() ^ 1; /* 保证是个单数 */
	unsigned long long tot_times = 0;
	int stream_index;
	sapp_pt_pkt_modify_para_t *cur_replay_stream;
	
	sapp_pt_pkt_modify_para_t *local_replay_pkt_array = (sapp_pt_pkt_modify_para_t *)malloc(sizeof(sapp_pt_pkt_modify_para_t) * SAPP_CONCURRENT_STREAM);

	/* 
		每个线程的N个并发流预先从全局g_pcap_image_array选择一个pcap包, 第一次选定后, 以后只改地址,但不改内容, 
		这样在一个线程内, 可以不用为了修改地址而临时memcpy包, 提升性能.
	*/
	printf("simulate concurrent stream number:%d\n", SAPP_CONCURRENT_STREAM);
	printf("thread:%ld copy pcap file to memory, please waitting......\n", thread_index);
	update_local_replay_concurrent_stream_array(thread_index, local_replay_pkt_array, SAPP_CONCURRENT_STREAM);
	printf("thread:%ld copy pcap file to memory succ, starting pkt replay......\n", thread_index);
	
	memset(&fake_raw_pkt, 0, sizeof(raw_pkt_t));
	/* 固定不变的参数预先设置 */
	fake_raw_pkt.low_layer_type = (enum addr_type_t)ADDR_TYPE_MAC;
	fake_raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	fake_raw_pkt.offset_to_raw_pkt_hdr = 0;
	fake_raw_pkt.route_dir = 0;		
	fake_raw_pkt.io_lib_pkt_reference = (void *)0x12345678;

	while(1){
		/* 调用rand(), 或者clock_gettime()取当前时间用来获取随机数太耗CPU了, 此处用个非常简单的办法取个伪随机数就行了
			实测这种方式运行一会, 获取的随机数可以将 SAPP_CONCURRENT_STREAM 数组元素 全部遍历一遍, 不会有空洞, 功能没有问题!!
		*/
		tot_times++;
		rand_seed_1 += 1; /* 单数累加单数 */
		rand_seed_2 += 2; /* 偶数累加偶数 */
		rand_seed_3 += 3; /* 单数累加单数 */

		if(tot_times){
			stream_index = (rand_seed_1 ^ rand_seed_2) % SAPP_CONCURRENT_STREAM; /* 单数异或偶数肯定还是单数 */
		}else{
			stream_index = (rand_seed_1 ^ rand_seed_3) % SAPP_CONCURRENT_STREAM; /* 单数异或单数肯定是偶数 */
		}
		///printf("stream_index:%d\n", stream_index);
		cur_replay_stream = &local_replay_pkt_array[stream_index];

		if((NULL == cur_replay_stream->raw_pcap_image)
		|| (cur_replay_stream->pkt_seq >= cur_replay_stream->raw_pcap_image->pkt_num)){ /* 第一次回放, 或者是已经完整的回放完一个pcap包, 需要更新当前流引用的原始pcap镜像地址 */
			cur_replay_stream->pkt_seq = 0;
			cur_replay_stream->ip_pad = g_sapp_ip_pad[thread_index].ip_pad++; /* 每个并发流只更新一次地址, 保证用相同的四元组完整回放一个流, 回放完成后再更新ip_addr */
			cur_replay_stream->port_pad = g_sapp_ip_pad[thread_index].port_pad++; /* 每个并发流只更新一次地址, 保证用相同的四元组完整回放一个流, 回放完成后再更新port_addr */
		}

		fake_raw_pkt.__lib_raw_pkt_data = cur_replay_stream->raw_pcap_image->pkt_data[cur_replay_stream->pkt_seq];
		fake_raw_pkt.raw_pkt_data = fake_raw_pkt.__lib_raw_pkt_data;
		fake_raw_pkt.__lib_raw_pkt_len = cur_replay_stream->raw_pcap_image->pkt_len[cur_replay_stream->pkt_seq];
		fake_raw_pkt.raw_pkt_len = fake_raw_pkt.__lib_raw_pkt_len;

		update_pkt_ip_port((struct ethhdr * )cur_replay_stream->raw_pcap_image->pkt_data[cur_replay_stream->pkt_seq], cur_replay_stream->ip_pad, cur_replay_stream->port_pad);
		
		eth_entry(NULL,cur_replay_stream->raw_pcap_image->pkt_data[cur_replay_stream->pkt_seq],thread_index, DIR_ROUTE_UP, &fake_raw_pkt, 0);
		cur_replay_stream->pkt_seq++;
	}

	return NULL;
}


static int insert_to_global_pkt_image(sapp_pt_pcap_file_image_t *new_pkt_image)
{
	g_pcap_image_array = (sapp_pt_pcap_file_image_t **)realloc(g_pcap_image_array, (g_pcap_image_num + 1)*sizeof(void *));

	g_pcap_image_array[g_pcap_image_num] = new_pkt_image;
	g_pcap_image_num++;
	
	return 0;
}


static void pcap_copy_to_mem_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	sapp_pt_pcap_file_image_t **pp_mem_image = (sapp_pt_pcap_file_image_t **)user;
	sapp_pt_pcap_file_image_t *p_mem_image = *pp_mem_image;
	const struct ethhdr *one_eth_pkt;

	one_eth_pkt = (struct ethhdr *)malloc(hdr->caplen);
	memcpy((void *)one_eth_pkt, data, hdr->caplen);
	
	p_mem_image->pkt_data = (const struct ethhdr **)realloc(p_mem_image->pkt_data, (p_mem_image->pkt_num+1)*sizeof(void *));
	p_mem_image->pkt_len = (int *)realloc(p_mem_image->pkt_len, (p_mem_image->pkt_num+1)*sizeof(int));

	p_mem_image->pkt_data[p_mem_image->pkt_num] = one_eth_pkt;
	p_mem_image->pkt_len[p_mem_image->pkt_num] = hdr->caplen;
	p_mem_image->pkt_num++;
	
	*pp_mem_image = p_mem_image;
}


/*
	将磁盘文件中的pcap, 读取到内层sapp_pt_pcap_file_image_t中.
*/
static sapp_pt_pcap_file_image_t *get_pkts_from_one_pcap(const char *pcap_filename)
{
	pcap_t *pcap_handle;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	sapp_pt_pcap_file_image_t *pcap_mem_image;

	pcap_handle = pcap_open_offline(pcap_filename, pcap_errbuf);
	if(NULL == pcap_handle){
		printf("pcap_open_offline: %s error, %s\n", pcap_filename, pcap_errbuf );
		exit(1);
	}

	pcap_mem_image = (sapp_pt_pcap_file_image_t *)calloc(1, sizeof(sapp_pt_pcap_file_image_t));
	pcap_mem_image->pkt_num = 0;
	pcap_mem_image->pkt_data = NULL;

	pcap_loop(pcap_handle, -1, pcap_copy_to_mem_cb, (u_char *)&pcap_mem_image);

	pcap_close(pcap_handle);

	insert_to_global_pkt_image(pcap_mem_image);

	printf("process pcap file:%s, tot inner eth pkts:%d\n", pcap_filename, pcap_mem_image->pkt_num );
	
	return pcap_mem_image;
}


static void get_pkts_from_dir(char* relative_path) {
	DIR *pdir = NULL;
	struct dirent *dp = NULL; /* readdir函数的返回值就存放在这个结构体中 */
	struct stat file_st;    
	char absolute_path[PATH_MAX] = {0};
	
	if(stat(relative_path, &file_st) < 0 || !S_ISDIR(file_st.st_mode)) {
		printf("invalid relative_path: %s\n", relative_path);
		return;
	}

	if(!(pdir = opendir(relative_path))) {
		printf("opendir[%s] error: %m\n", relative_path);
		return;
	}

	while((dp = readdir(pdir)) != NULL) {
		/* 把当前目录.，上一级目录..及隐藏文件都去掉，避免死循环遍历目录 */
		if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
			continue;

		snprintf(absolute_path, sizeof(absolute_path) - 1, "%s/%s", relative_path, dp->d_name);
		stat(absolute_path, &file_st);
		if(!S_ISDIR(file_st.st_mode)) {
			if(strstr(dp->d_name, "pcap") != NULL){
				//printf("%s\n", dp->d_name);
				get_pkts_from_one_pcap(absolute_path);
			}
		} else {
			//printf("%s/\n", dp->d_name);
			get_pkts_from_dir(absolute_path);
		}
	}
	closedir(pdir);

	return;
}



static void pf_test_usage(const char *progname)
{
	printf("Usage: \n"); 
	printf("%6s %11s\n", "option", "description");
	printf("%6s %11s\n", "-h", "show help message");
	printf("%6s %11s\n", "-v", "show version");
	printf("%6s %11s\n", "-p", "modify transport layer port, default is disable, only modify ip address");
	printf("%6s %11s\n", "-n <>", "emulate concurrent stream number, default is 1000");
	printf("%6s %11s\n", "-r <>", "raw pcap file or directory name, default is ./dumpfile");
	exit(1);
}


static int update_sapp_config_file(const char *filename, const char *param, const char *value)
{
	char cmd_buf[1024];
	int ret;

	snprintf(cmd_buf, 1024, "sed 's/^[ \t]*%s=.*/%s=%s/g' -i %s", param, param, value, filename);

	ret = system(cmd_buf);

	return ret;
}

static int update_sapp_config_file_by_anchor(const char *filename, const char *lastline, int N, const char *param, const char *value)
{
	char cmd_buf[1024] = {};
	int ret;
	const char *sed_n_line = "n";
	

	switch(N){
		case 1:
			sed_n_line = "n";
		break;

		case 2:
			sed_n_line = "n;n";
		break;

		case 3:
			sed_n_line = "n;n;n";
		break;

		case 4:
			sed_n_line = "n;n;n;n";
		break;

		case 5:
			sed_n_line = "n;n;n;n;n";
		break;		

		default:
			printf("max support N is:%d\n", 5);
		break;
	}	

	//snprintf(cmd_buf, 1024, "sed '/%s/{%s;s/^%s=.*/%s=%s/;}' -i %s", lastline, sed_n_line, param, param, value, filename);
	snprintf(cmd_buf, 1024, "sed '/%s/{%s;s/%s=.*/%s=%s/;}' -i %s", lastline, sed_n_line, param, param, value, filename);

	ret = system(cmd_buf);

	return ret;
}


/* 静态只读全局变量可以放在任何代码段, 无需在sapp_global_val里 */
static const char *sapp_pf_short_options = "vphn:r:";

/* 静态只读全局变量可以放在任何代码段, 无需在sapp_global_val里 */
static const struct option sapp_pf_long_options[] = 
{
	{"help",			no_argument,      	NULL,      'h'},
	{"version",			no_argument,      	NULL,      'v'},
	{"modify-port", 	no_argument,		NULL,	   'p'},
	{"concurrent-stream-num", required_argument,	NULL,	   'n'},
	{NULL,          	0,      			NULL,      0}
};


static int parse_cmd_args(int argc, char *argv[])
{
	int c, opt_index;
	
	while(1){
		c = getopt_long(argc, argv, sapp_pf_short_options, sapp_pf_long_options, &opt_index);
		if(c == -1){
			break;	
		}

		switch(c){
			case 'h':
				pf_test_usage(argv[0]);
				exit(1);
			break;

			case 'v':
				printf("Version: %s\n", sapp_pf_version);
				exit(1);
			break;	

			case 'r':
				strcpy(g_raw_pcap_file_name, optarg);
			break;

			case 'n':
				SAPP_CONCURRENT_STREAM = atoi(optarg);
				if(SAPP_CONCURRENT_STREAM <= 0 || SAPP_CONCURRENT_STREAM > 1000000){
					printf("concurrent-stream-number %d out of range!\n", SAPP_CONCURRENT_STREAM);
					pf_test_usage(argv[0]);
				}
			break;
			

			case 'p':
				g_sapp_pf_modify_port = 1;
			break;

			case '?': /* invalid or unknown option */
				return -1;
			break;			
		}
	}

	return 0;
}


int main(int argc, char *argv[])
{
	long i;
	pthread_t pid[128];
	struct stat file_st; 

	if(parse_cmd_args(argc, argv) < 0){
		pf_test_usage(argv[0]);

		return -1;
	}

	stat(g_raw_pcap_file_name, &file_st);

	if(S_ISDIR(file_st.st_mode)) {
		get_pkts_from_dir(g_raw_pcap_file_name);
	}else{
		get_pkts_from_one_pcap(g_raw_pcap_file_name);
	}

	/* 性能测试模式一定要关闭sapp的polling和真正的收发包线程,
	   因为sapp_perf_test进程启动的线程不是真正的sapp IO线程, 只是用0-N的线程id欺骗了sapp而已, 
	   如果同时开了polling, 会启用超时流淘汰功能, 就冲突了! 
	   为了不让sapp真正能从网卡收到包, 故意写一个不可能命中的bpf过滤条件!

	   为了保证手误或忘了修改, 此处直接用程序修改测试目录的sapp.toml文件.
	 */
	update_sapp_config_file_by_anchor("etc/sapp.toml", "packet_io.polling",1, "enabled", "0");

	/* 
		16进制 字符
		0x22   "
		0x2F   /
	*/	
	update_sapp_config_file("./etc/sapp.toml", "BSD_packet_filter", "\\x22host 255.255.255.255 and port 65535\\x22");


	if(libsapp_setup_env(1, NULL) < 0){
		return -1;
	}	

	srand(time(NULL));

	int optlen = sizeof(int);
	int ret = sapp_get_platform_opt(SPO_THREAD_COUNT, &SAPP_IO_THREAD_NUM, &optlen);
	if(ret < 0){
		printf("sapp_get_platform_opt->SPO_THREAD_COUNT error!\n");
		exit(1);
	}
	for(i = 0; i < SAPP_IO_THREAD_NUM; i++){
		g_sapp_ip_pad[i].ip_pad = rand();
		g_sapp_ip_pad[i].port_pad = rand();
	}

	for(i = 0; i < SAPP_IO_THREAD_NUM; i++){
		pthread_create(&pid[i], NULL, fake_sapp_io_thread, (void *)i);
	}

	while(1){
		pause();
	}
	
	return 0;
}


