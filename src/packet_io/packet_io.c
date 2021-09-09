#include "sapp_api.h"
#include "sapp_private_api.h"
#include "support/MESA_feedback.h"
/*
2015-04-15
   平台实时捕获最近的数据包, 按size指定大小, 如最近的100MB,
   每个线程分为两个文件, 循环写入,
	文件名规则:
		pid.thread_seq.[0-1].pcap,
		
   0文件超过100MB后停止, 转而开始写1文件, 1文件也超过100MB后, 返回来覆盖写0文件.

   通过总开关控制此功能是否开启, 并查看当前目录有几个core, 超过后则不写, 防止硬盘满!

   debug_pkt_dump_switch=1
   debug_pkt_dump_max_num=5 //类似core文件
   debug_pkt_dump_max_size_per_thread=100 // 单位MB

   另起一个进程, 如debug_pkt_dump,

   sapp初始化时按线程数, 创建THREAD_NUM个管道, 然后fork自身, 子进程变为debug_pkt_dump,
   父进程继续运行sapp,

   在mesa_default_pkt_cb函数中, 将收到的包通过管道发往debug_pkt_dump进程.

   debug_pkt_dump进程, 也同样用相同的线程数接收数据, 写文件.
*/

#ifdef __cplusplus
extern "C" {
#endif


int gdev_init(void);
extern int packet_io_status_init(void);
extern MESA_send_handle g_send_handle[MAX_THREAD_NUM];
char g_send_dev_name[DEV_NAME_STR_LEN]; /* 发包网卡名 */
//unsigned char g_send_dev_mac[MAC_ADDR_LEN];
//unsigned char g_send_gateway_mac[MAC_ADDR_LEN]; /* 通过手工配置或查询路由表和ARP表得到 */
unsigned char g_send_gateway_mac_table[64][16][18];
static int G_SND_ROUTE_INFO_NUM = 0;

unsigned char g_send_gdev_ip_table[64][32];
static int G_SND_GDEV_INFO_NUM = 0;

char g_up_dev_name[DEV_NAME_STR_LEN]; /* 并联模式默认捕包网卡 */
char g_down_dev_name[DEV_NAME_STR_LEN];
//static char g_cap_filter[CAP_FILTER_STR_LEN];
//static int g_cap_buf_queue_num = 10000; /* IO线程和处理线程之间的缓冲队列长度 */
//int g_topology_config_raw_mode = 1;/* main.conf 配置文件的原始值 */
//int g_topology_mode = NET_CONN_PARALLEL; /* 通过topology_mode_convert()转换后的平台内部值 */
//int g_packet_io_cap_mode = CAP_MODEL_PCAP_ONLINE;
///int g_packet_io_cap_level = CAP_LEVEL_MAC; /* 捕包起始位置,默认MAC层 */
//int g_packet_io_thread_num = 1;
int g_app_send_rst_type;
//extern int g_timestamp_record_sw;
int g_encapsulate_with_ddp = 0; /* 使用DDP协议封装的原始包 */
int g_encapsulate_with_L2E = 0; /* 使用DDP协议封装的x27原始IP包 */
 /* 
 	2015-12-10 lijia add, 跳过eth层, 无需处理MAC地址, 无需创建流时COPY到流结构体 ,
 	原始包从IP层开始.
 */
int g_skip_ethernet_layer_sw = 0;
void *g_packet_dl_send_handle[MAX_THREAD_NUM];/* 动态IO库的发包句柄 */
//static int g_packet_io_dir; /* 用于记录当前来包方向, 构造包时使用 */
//int G_SKIP_NOT_IP_LAYER = 0; /* 跳过非IP协议的层, 用于双栈并联特殊环境下, RST包发送 */
static int mesa_default_pkt_cb(const raw_pkt_t *p_raw_pkt, unsigned char dir, int thread_num);
PACKET_IO_CB_T G_DEFAULT_PKT_CB = mesa_default_pkt_cb;

dl_io_fun_list_t dl_io_fun_list;
static int use_custom_pkt_cb = 0; /* 是否定义了新的callback函数 */
long long g_timedelay_threshold = 10000000; /* 单位CPU周期数, 非时间 */

int g_use_MESA_sleep_sw = 0;
int g_raw_pkt_broken_check = 0; /* 检测原始包是否被修改 */
static UINT8 *g_send_buf_pool[MAX_THREAD_NUM];

#define MAX_RAW_PKT_TARGET_NUM		(128)

typedef struct{
	unsigned int target_id;	/* 目标ID */
	send_raw_args_t send_args[__CAP_MODEL_MAX];
}send_raw_pkt_info_t;

static send_raw_pkt_info_t G_SND_RAW_PKT_INFO[MAX_RAW_PKT_TARGET_NUM];
static int G_SND_RAW_PKT_INFO_NUM = 0;

extern int G_PKT_DUMP_SW;

void packet_io_exit(void);
int packet_io_lib_load(int cap_mode);
void del_last_rn(char *data, int max_len);
int parse_send_route_conf(const char *profile_path);
int parse_send_gdev_ip_conf(const char *profile_path);
extern void cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt);
extern char *MESA_MD5_sum_bin(unsigned char *raw_data, unsigned int raw_data_len, char result[16]);
extern void timestamp_region_update(int tid, long long cpu_cycle);
void pptp_exit(void);
extern void ipv4_frag_per_thread_exit(int thread_seq);
extern void ipv6_frag_per_thread_exit(int thread_seq);
extern void pptp_per_thread_exit(int thread_seq);
extern void __timestamp_print_max_tuple4(const raw_pkt_t *raw_pkt, long timedelay, int tid);
extern int packet_io_device_alias_init(void);
extern void sapp_fs2_set_latency(int thead_seq, long long time_cost);
extern void plugctrl_destroy_all_plug(void);

static const unsigned char phony_feedback_eth_hdr_ip4[ETHERNET_HDR_LEN] = 
			{0x50, 0x48, 0x4F, 0x4E, 0x59, 0x5F, 0x4D, 0x41, 0x43, 0x41, 0x44, 0x44, 0x08, 0x00}; /* PHONY_MACADD + ipv4 */
static const unsigned char phony_feedback_eth_hdr_ip6[ETHERNET_HDR_LEN] = 
			{0x50, 0x48, 0x4F, 0x4E, 0x59, 0x5F, 0x4D, 0x41, 0x43, 0x41, 0x44, 0x44, 0x86, 0xDD}; /* PHONY_MACADD + ipv6*/

int packet_io_set_ipv6_module_enable(int op_switch)
{
	g_ipv6_decapsulation_enabled = op_switch;
	return 0;
}

int packet_io_set_ipv6_raw_socket_enable(int op_switch)
{
	g_ipv6_send_packet_enabled = op_switch;
	return 0;
}

int packet_io_register_cb(PACKET_IO_CB_T fun)
{
	int ret = 0;
	
	use_custom_pkt_cb = 1;
	if(dl_io_fun_list.dl_io_register_cb){
		ret = dl_io_fun_list.dl_io_register_cb(fun);
	}else{
		printf("Warning, packet io library not support 'dl_io_register_cb'!\n");
	}

	return ret;
}

int packet_io_set_cap_level(int cap_level)
{
	int ret = 0;
	g_packet_io_cap_level = cap_level;

	if(dl_io_fun_list.dl_io_set_cap_level){
		ret = dl_io_fun_list.dl_io_set_cap_level(cap_level);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_cap_level'!\n");
	}

	return ret;
}

int packet_io_set_work_thread_num(int thread_num)
{
	int ret = 0;

	if(dl_io_fun_list.dl_io_set_work_thread_num){
		ret = dl_io_fun_list.dl_io_set_work_thread_num(thread_num);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_work_thread_num'!\n");
	}

	//g_packet_io_thread_num = thread_num;

	return ret;
}

int packet_io_set_cap_mode(int cap_mode)
{
	int ret = 0;

	if(dl_io_fun_list.dl_io_set_cap_mode){
		ret = dl_io_fun_list.dl_io_set_cap_mode(cap_mode);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_cap_mode'!\n");
	}

	return ret;
}

/* 
	为了方便用户配置，配置文件中的值比较简单，即0，1，2，3等，
	内存中的值定义比较复杂，需要此函数转换一下.
*/
static int topology_mode_convert(int config_value)
{
	int private_value;
	
	switch(config_value)
	{
		case 0:
			private_value = NET_CONN_PARA_NOSEND;
		break;
		
		case 1:
			private_value = NET_CONN_PARALLEL;
		break;
		
		case 2:
			private_value = NET_CONN_SERIAL_2CARD;
		break;
		
		case 3:
			private_value = NET_CONN_SERIAL_GDEV;
		break;

		default:
			private_value = -1;
		break;
	}

	return private_value;
}

int packet_io_set_topology_mode(int user_topology_mode)
{
	int private_top_mode, ret = -1;

	private_top_mode = topology_mode_convert(user_topology_mode);
	if(private_top_mode < 0){
		return -1;
	}

	//g_topology_config_raw_mode = user_topology_mode;
	//g_topology_mode = private_top_mode;

	if(dl_io_fun_list.dl_io_set_topology_mode){
		ret =  dl_io_fun_list.dl_io_set_topology_mode(private_top_mode);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_topology_mode'!\n");
	}

	return ret;
}

int packet_io_set_capdev_parallel(const char *cap_dev)
{
	int ret = 0;

	if(dl_io_fun_list.dl_io_set_capdev_parallel){
		ret = dl_io_fun_list.dl_io_set_capdev_parallel(cap_dev);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_capdev_parallel'!\n");
	}

	strncpy(g_up_dev_name, cap_dev, DEV_NAME_STR_LEN);

	return ret;
}

int packet_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	int ret = 0;

	if(dl_io_fun_list.dl_io_set_capdev_serial){
		ret = dl_io_fun_list.dl_io_set_capdev_serial(up_dev, down_dev);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_capdev_serial'!\n");
	}

	strncpy(g_up_dev_name, up_dev, DEV_NAME_STR_LEN);
	strncpy(g_down_dev_name, down_dev, DEV_NAME_STR_LEN);
	
	return ret;
}
#if 0

int packet_io_set_send_dev(const char *send_dev)
{
	int ret;

	ret = snprintf(g_send_dev_name, DEV_NAME_STR_LEN, "%s", send_dev);
	if(ret >= DEV_NAME_STR_LEN){
		printf("send device name is too long!\n");
		return -1;
	}
	
	return ret;
}


int packet_io_set_gateway_mac(const char *gateway_mac)
{
	if(MESA_mac_pton(gateway_mac, ':', (char *)g_send_gateway_mac) < 0){
		printf("error, gateway mac:%s is not correct, for example:00:11:22:33:44:55\n", gateway_mac);
		return -1;
	}
	
	return 0;
}
#endif

int packet_io_set_capture_filter(const char *filter_rule)
{
	int ret = 0;

	if(dl_io_fun_list.dl_io_set_capture_filter){
		ret = dl_io_fun_list.dl_io_set_capture_filter(filter_rule);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_capture_filter'!\n");
	}
	
	return ret;
}


long packet_io_get_app_drop_num(int thread_num)
{
	long ret = 0;

	if(dl_io_fun_list.dl_io_get_app_drop_num){
		ret = dl_io_fun_list.dl_io_get_app_drop_num(thread_num);
	}else{
		//printf("Warning, packet io library not support 'dl_io_get_app_drop_num'!\n");
		ret = 0;
	}
	
	return ret;
}


long packet_io_get_app_drop_num_tot(void)
{
	int i;
	long ret = 0;

	for(i = 0; i < g_packet_io_thread_num; i++){
		ret += packet_io_get_app_drop_num(i);
	}

	return 0;
}

long packet_io_get_lib_drop_num(void)
{
	long ret = 0;

	if(dl_io_fun_list.dl_io_get_lib_drop_num){
		ret = dl_io_fun_list.dl_io_get_lib_drop_num();
	}else{
		//printf("Warning, packet io library not support 'dl_io_get_lib_drop_num'!\n");
		ret = 0;
	}
	
	return ret;
}

int packet_io_set_cap_buf_queue(int queue_num_max)
{
	int ret = 0;

	if(dl_io_fun_list.dl_io_set_cap_buf_queue){
		ret = dl_io_fun_list.dl_io_set_cap_buf_queue(queue_num_max);
	}else{
		printf("Warning, packet io library not support 'dl_io_set_cap_buf_queue'!\n");
	}
	
	return ret;
}

int packet_io_send_only_thread_init(void)
{
	int ret = 0;
	if(dl_io_fun_list.dl_io_send_only_thread_init != NULL){
		ret = dl_io_fun_list.dl_io_send_only_thread_init();
	}

	return ret;
}

static int packet_io_process_ddp_pkt(const MESA_feedback_raw_pkt_t *ddp_fix_hdr,
			int ddp_payload_len, raw_pkt_t *p_raw_pkt, unsigned char dir, int thread_num)
{
	const char *ddp_payload;
	//int pkt_index = 1; //所以暂不支持DDP聚合原始包	
	if(MESA_FEEDBACK_HDR_MAGIC != ddp_fix_hdr->property_hdr.magic){
		return PASS;
	}

	if(0 != ddp_fix_hdr->property_hdr.stream){
		return PASS;
	}

	if((MESA_FEEDBACK_DTYPE_IPv4 != ddp_fix_hdr->property_hdr.data_type)
	 && (MESA_FEEDBACK_DTYPE_IPv6 != ddp_fix_hdr->property_hdr.data_type)){
		return PASS;
	}

	ddp_payload = (const char *)((char *)ddp_fix_hdr + sizeof(MESA_feedback_raw_pkt_t));

#if 0 /* 因网卡自动填充0, 通过IP头获取的包长度与实际不符, 而且也不支持VLAN, PPPOE等数据包, 所以暂不支持DDP聚合原始包, 一个DDP包只取一个原始包 */
	while(ddp_payload_len > 0)
	{
		p_raw_pkt->raw_pkt_len = get_pkt_len_from_eth_hdr((const struct mesa_ethernet_hdr *)ddp_payload);
		if(p_raw_pkt->raw_pkt_len < 0){
			sapp_runtime_log(30, "ddp raw pkt parse error, pkt index:%d\n", pkt_index);
			break;
		}
#else
	{
		p_raw_pkt->raw_pkt_len = ddp_payload_len;
#endif
		p_raw_pkt->raw_pkt_data = (char *)ddp_payload;
#if CYCLE_PKT_DUMP
		/* 2017-10-09 lijia add, for tcpdump_mesa capture ddp inner packet */
		cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_IN);
#endif
		eth_entry(NULL, p_raw_pkt->raw_pkt_data, thread_num, dir, p_raw_pkt, 0);

#if 0
		ddp_payload += p_raw_pkt->raw_pkt_len;
		ddp_payload_len -= p_raw_pkt->raw_pkt_len;
		if(ddp_payload_len < 0){
			sapp_runtime_log(30, "ddp raw pkt parse error, pkt index:%d\n", pkt_index);
			break;
		}
		pkt_index++;
#endif
	}

	return PASS;
}

static int packet_io_strip_ddp_hdr(const raw_pkt_t *p_raw_pkt, unsigned char dir, int thread_num)
{
	int ret;
	const MESA_feedback_raw_pkt_t *ddp_raw_pkt_hdr = NULL;
	int ddp_payload_len = p_raw_pkt->raw_pkt_len; /* DDP数据长度, 包含所有内层包的ddp头部和负载 */
	
	switch(p_raw_pkt->low_layer_type){
		case CAP_LEVEL_MAC:
		{
			const struct mesa_ethernet_hdr *ethh = (const struct mesa_ethernet_hdr *)p_raw_pkt->raw_pkt_data;
			if(ETHERTYPE_IP == ntohs(ethh->ether_type)){
				const struct mesa_ip4_hdr *ip4h = (const struct mesa_ip4_hdr  *)((char *)ethh + sizeof(struct mesa_ethernet_hdr));
				ddp_raw_pkt_hdr = (const MESA_feedback_raw_pkt_t *)((char *)ip4h + ip4h->ip_hl * 4 + sizeof(struct mesa_udp_hdr));
				ddp_payload_len -= sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ip4_hdr) +  sizeof(struct mesa_udp_hdr) + sizeof(MESA_feedback_raw_pkt_t);
			}else{
				/* 暂不支持其他方式的DDP原始包回传 */
				sapp_runtime_log(30, "ddp raw pkt parse error, unknown ether_type:0x%x\n", ntohs(ethh->ether_type));
				return PASS;
			}
		}
		break;

		case CAP_LEVEL_IPV4:
		{
			const struct mesa_ip4_hdr *ip4h = (const struct mesa_ip4_hdr  *)p_raw_pkt->raw_pkt_data;
			ddp_raw_pkt_hdr = (const MESA_feedback_raw_pkt_t *)((char *)ip4h + ip4h->ip_hl * 4 + sizeof(struct mesa_udp_hdr));		
			ddp_payload_len -= sizeof(struct mesa_ip4_hdr) +  sizeof(struct mesa_udp_hdr) + sizeof(MESA_feedback_raw_pkt_t);
		}
		break;

		default:
			return PASS;
		break;
	}

	ret = packet_io_process_ddp_pkt(ddp_raw_pkt_hdr, ddp_payload_len, (raw_pkt_t *)p_raw_pkt, dir, thread_num);

	return ret;
}


#if 1 /* for xx7 接口 */

typedef struct {
     uint32_t     magic_num;
     uint8_t      version;
     uint8_t      msg_type;
     uint16_t     flag;
     uint32_t     cont_len; /* 不含本头部的12字节! */
}L2E_msg_header_t; /*sizeof = 12B */



typedef struct  {
	uint16_t  data_len;  /* 包括本头部的4字节 */
	uint16_t  data_type;    
	uint8_t  data_value[0]; 
}L2E_data_small_block_hdr_t;

struct __msg_small_body_t{
	uint32_t cap_ip;			// 前端节点IP
	uint32_t data_id;	    // 该命中结果的唯一编号
	uint16_t unit_num;       //小数据块的个数
	L2E_data_small_block_hdr_t small_unit[0];  //小数据块内容
}__attribute__((packed));
typedef struct __msg_small_body_t L2E_msg_small_body_hdr_t;


#endif

/*
	3x7项目回传的原始包头部.
*/
static int packet_io_strip_L2E_hdr(raw_pkt_t *p_raw_pkt, unsigned char dir, int thread_num)
{
	int ret;
#define L2E_HDR_TOTAL_LEN (78)
#define L2E_PKT_HDR_MAGIC  0xD0BADABA
	const struct mesa_ethernet_hdr *ethh = (const struct mesa_ethernet_hdr *)p_raw_pkt->raw_pkt_data;
	//const unsigned int *l2e_hdr_magic;
	unsigned char *L2E_payload;
	int L2E_len;
	const L2E_msg_header_t *L2E_msg_hdr;
	const L2E_data_small_block_hdr_t *small_block_hdr;
	const L2E_msg_small_body_hdr_t *small_block_body;
	int i;

	/* 一些错误检测 */
	if(ntohs(ethh->ether_type) != ETHERTYPE_IP){
		return PASS;
	}

	const struct mesa_ip4_hdr *ip4h = (const struct mesa_ip4_hdr  *)((char *)p_raw_pkt->raw_pkt_data + sizeof(struct mesa_ethernet_hdr));
	if(ip4h->ip_p != IPPROTO_UDP){
		return PASS;
	}

	if(ntohs(ip4h->ip_len) < sizeof(struct mesa_ip4_hdr)/* 最外层ip头 */  + sizeof(struct mesa_udp_hdr)/* 外层udp头 */ + L2E_HDR_TOTAL_LEN + sizeof(struct mesa_ip4_hdr)/* 内层IP包头 */){
		return PASS;
	}

	L2E_payload = (unsigned char *)p_raw_pkt->raw_pkt_data + sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_udp_hdr);
	L2E_len = p_raw_pkt->raw_pkt_len - sizeof(struct mesa_ethernet_hdr) - sizeof(struct mesa_ip4_hdr) - sizeof(struct mesa_udp_hdr);

	while(L2E_len > 0){
		L2E_msg_hdr = (L2E_msg_header_t *)L2E_payload;
		if(L2E_msg_hdr->magic_num != L2E_PKT_HDR_MAGIC){
			sapp_runtime_log(20, "L2E hdr error, magic is:%x\n", L2E_msg_hdr->magic_num);
			return PASS;
		}

		L2E_payload += sizeof(L2E_msg_header_t);
		L2E_len -=  sizeof(L2E_msg_header_t);
		
		if(L2E_len < (int)L2E_msg_hdr->cont_len ){
			sapp_runtime_log(20, "L2E hdr error, left payload len is %d,  smaller than hdr declare len:%d!\n", L2E_len, L2E_msg_hdr->cont_len);
			return PASS;
		}

		if(L2E_msg_hdr->msg_type != 2){ /* 1:meta data;  2:small block; 3:big block,  只关心小块数据中的IP包, 其他跳过不处理! */
			L2E_payload += L2E_msg_hdr->cont_len;
			L2E_len -= L2E_msg_hdr->cont_len;
			continue;
		}
	
		small_block_body = (L2E_msg_small_body_hdr_t *)L2E_payload;
		L2E_payload += sizeof(L2E_msg_small_body_hdr_t);
		L2E_len -= sizeof(L2E_msg_small_body_hdr_t);

		for(i  = 0; i < small_block_body->unit_num; i++){
			small_block_hdr = (L2E_data_small_block_hdr_t *)L2E_payload;
			if(small_block_hdr->data_type != 0x0002){ /* 0x0002: 原始IP包 */
				L2E_payload += small_block_hdr->data_len;
				L2E_len -= small_block_hdr->data_len;
				continue;
			}
			
			/* 更新raw_pkt指针 */
			p_raw_pkt->raw_pkt_data = L2E_payload + sizeof(L2E_data_small_block_hdr_t);
			p_raw_pkt->raw_pkt_len = small_block_hdr->data_len - sizeof(L2E_data_small_block_hdr_t);
			p_raw_pkt->low_layer_type = ADDR_TYPE_IPV4;
#if CYCLE_PKT_DUMP
			/* for tcpdump_mesa capture ddp inner packet */
			cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_IN);
#endif			
			ret = ipv4_entry(NULL, p_raw_pkt->raw_pkt_data, thread_num, dir, p_raw_pkt, 0);
		
			L2E_payload += small_block_hdr->data_len;
			L2E_len -= small_block_hdr->data_len;			
		}
	}

	return ret;
}

extern void sapp_fs2_set_latency(int thead_seq, long long time_cost);
extern char (*g_platform_action_cb_fun)(int net_conn_mode, char plug_action);


static int mesa_default_pkt_cb(const raw_pkt_t *p_raw_pkt, unsigned char dir, int thread_num)
{
	int ret = PASS;
	//long long before_call = 0, after_call;
	long long timecost;
	struct timespec start, end;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	local_sys_stat->count[SAPP_STAT_RCV_LINE]++;
	local_sys_stat->length[SAPP_STAT_RCV_LINE] += p_raw_pkt->raw_pkt_len;	

	sapp_global_val->mthread_volatile[thread_num]->raw_pkt = p_raw_pkt;
	
	if(DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin){
		ret = packet_io_hook_input((raw_pkt_t *)p_raw_pkt, dir, thread_num);
		if(ret < 0){
			cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_DROP);
			return DROP;
		}
	}else if(DEPOLYMENT_MODE_MIRROR == sapp_global_val->config.packet_io.depolyment_mode_bin){
		if(sapp_global_val->config.packet_io.extract_linkdir_from_mac_enabled != 0){
			packet_io_hook_input_mirror((raw_pkt_t *)p_raw_pkt, dir, thread_num);
		}
	}

	local_sys_stat->count[SAPP_STAT_RCV_RAW]++;
	local_sys_stat->length[SAPP_STAT_RCV_RAW] += ((unsigned long long)p_raw_pkt->raw_pkt_len - p_raw_pkt->overlay_layer_bytes);

	if (p_raw_pkt->route_dir == sapp_global_val->config.packet_io.inbound_route_dir)
	{
		local_sys_stat->count[SAPP_STAT_RAW_INBOUND]++;
		local_sys_stat->length[SAPP_STAT_RAW_INBOUND] += ((unsigned long long)p_raw_pkt->raw_pkt_len - p_raw_pkt->overlay_layer_bytes);
	}
	else
	{
		local_sys_stat->count[SAPP_STAT_RAW_OUTBOUND]++;
		local_sys_stat->length[SAPP_STAT_RAW_OUTBOUND] += ((unsigned long long)p_raw_pkt->raw_pkt_len - p_raw_pkt->overlay_layer_bytes);
	}

	if(unlikely(g_timestamp_record_sw))
	{
		clock_gettime(CLOCK_MONOTONIC, &start);
		//before_call = sapp_get_cpu_cycle();
	}
#if DEBUG
	char raw_pkt_md5_before[16];
	char raw_pkt_md5_after[16];

	if(unlikely(g_raw_pkt_broken_check != 0)){
		MESA_MD5_sum_bin((unsigned char *)p_raw_pkt->raw_pkt_data, p_raw_pkt->raw_pkt_len, raw_pkt_md5_before);
	}
#endif

	if(unlikely(g_encapsulate_with_ddp)){
		/* 开启ddp解封装功能后, 在packet_io_process_ddp_pkt()函数中捕获DDP负载数据 */
		ret = packet_io_strip_ddp_hdr(p_raw_pkt, p_raw_pkt->route_dir, thread_num);
	} else if(unlikely(g_encapsulate_with_L2E)){
		ret = packet_io_strip_L2E_hdr((raw_pkt_t *)p_raw_pkt, p_raw_pkt->route_dir, thread_num);
	}else{

#if CYCLE_PKT_DUMP
		cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_IN);
#endif
		switch(p_raw_pkt->low_layer_type){
			case CAP_LEVEL_MAC:
				ret = eth_entry(NULL,p_raw_pkt->raw_pkt_data,thread_num,p_raw_pkt->route_dir, p_raw_pkt, 0);
			break;

			case CAP_LEVEL_IPV4:
				ret = ipv4_entry(NULL,(void *)p_raw_pkt->raw_pkt_data,thread_num,p_raw_pkt->route_dir, p_raw_pkt, 0);
			break;

			case CAP_LEVEL_IPV6:
				ret = ipv6_entry(NULL,(void *)p_raw_pkt->raw_pkt_data,thread_num,p_raw_pkt->route_dir, p_raw_pkt, 0);
			break;

			default:
				return PASS;
			break;
		}
	}

	//after_call = sapp_get_cpu_cycle();
	//timecost = after_call - before_call;
	if(unlikely(g_timestamp_record_sw))
    {
		clock_gettime(CLOCK_MONOTONIC, &end);
    	timecost = (end.tv_sec*1000000000 +end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);

		//timestamp_region_update(thread_num,  timecost);
		if(sapp_global_val->config.profiling.pkt_latency_accurate_enable != 0){
			sapp_fs2_set_latency(thread_num,  timecost);
		}else{
			sapp_fs2_fuzzy_latency_update_per_thread(thread_num,  timecost);
		}
	}
#if DEBUG
	//if(unlikely(g_timestamp_record_sw)){
		//if(timecost > g_timedelay_threshold){
		//	__timestamp_print_max_tuple4(p_raw_pkt, timecost, thread_num);
		//}
	//}	
	
	if(unlikely(g_raw_pkt_broken_check != 0)){
		MESA_MD5_sum_bin((unsigned char *)p_raw_pkt->raw_pkt_data, p_raw_pkt->raw_pkt_len, raw_pkt_md5_after);

		if(memcmp(raw_pkt_md5_before, raw_pkt_md5_after, 16) != 0){
			printf("\033[41mraw packet is broken involuntarily! If you don't care, please disable 'raw_pkt_broken_check' in main.conf!\033[0m\n");
			abort();
		}
	}	
#endif

	if(g_platform_action_cb_fun != NULL){
		ret = g_platform_action_cb_fun(sapp_global_val->config.packet_io.depolyment_mode_bin, ret);
	}

	if(p_raw_pkt->diagnose_error_to_dump){
		cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_ERROR);
	}

	/* drop_current_pkt_flag优先级高于函数返回值 */
	if(p_raw_pkt->drop_current_pkt_flag != 0){
		ret = DROP;
	}

	if(DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin){ 
		if((p_raw_pkt->is_overlay_pkt)&& (PASS == ret)){
			cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_FORWARD);
			packet_io_hook_forward((raw_pkt_t *)p_raw_pkt, p_raw_pkt->route_dir, thread_num);
		}else{
			/* inline模式下, 非原始链路中的包, 即使插件返回了PASS, 也不能注入链路 */
			ret = DROP;
			cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_DROP);
		}
	}else if(DEPOLYMENT_MODE_TRANSPARENT == sapp_global_val->config.packet_io.depolyment_mode_bin){
		if(PASS == ret){
			cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_FORWARD);
		}else{
			cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_DROP);
		}
	}else{
		/* mirror模式下, 没有forward, 仅有drop,虽然drop也没实际意义,但是可以用于观察哪些包被插件返回了DROP */
		if(DROP == ret){
			cycle_pkt_dump_by_classify(thread_num, p_raw_pkt, PKT_CLASSIFY_DROP);
		}		
	}

	return ret;
}


extern int g_StreamTcpAllFunNum;
extern int g_Ipv6FunNum;
extern  int app_function_rationality_check(void);
 /* not return until error, or use 'CAP_MODEL_PCAP_DUMPFILE' mode */
void packet_io_run(void)
{		
	if(NULL == dl_io_fun_list.dl_io_run){
		printf("Error, packet io library must support 'dl_io_run' !\n");
		sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: Error, packet io library must support 'dl_io_run' !\n", __FILE__, __LINE__);
		assert(0);
	}

	app_function_rationality_check();
	
	pthread_create(&sapp_global_val->individual_fixed.thread_timer_event_id, NULL, sapp_time_event_thread ,NULL);

	packet_io_under_ddos_run();
	
	dl_io_fun_list.dl_io_run();
}

extern volatile int update_packet_io_status_sw;



MESA_send_handle *packet_io_get_send_handle(int thread_id)
{
	return &g_send_handle[thread_id];
}


unsigned char *packet_io_get_sendbuf(int type, int thread_num)
{
	if(g_topology_mode & __NET_CONN_PARALLEL){
		return g_send_buf_pool[thread_num];
	}

	return dl_io_fun_list.dl_io_get_sendbuf(g_packet_dl_send_handle[thread_num], thread_num);
}

void packet_io_free_sendbuf(int type, int thread_num)
{
	if(g_topology_mode & __NET_CONN_PARALLEL){
		return; /* use static global variable, do nothing */
	}
	
	dl_io_fun_list.dl_io_free_sendbuf(g_packet_dl_send_handle[thread_num], thread_num);
	return;
}


static int packet_io_calc_ethernet_offset_to_ip(const unsigned char *sendbuf)
{
	int offset;
	const struct mesa_ethernet_hdr *outer_ehdr;
	///const struct mesa_ethernet_hdr *inner_ehdr;

	if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_GDEV){
		sendbuf += VXLAN_HDR_RESERVED_LEN; /* vxlan模式下预留了vxlan和外层mac,ip,udp头部, 跳转到内层mac头 */
	}
	
    switch(g_packet_io_cap_level){
        case CAP_LEVEL_IPV4:
			offset = 0;
        break;
        
        case CAP_LEVEL_MAC:
			offset =  sizeof(struct mesa_ethernet_hdr);
        break;

        default:
        	offset = -1;
        	sapp_runtime_log(RLOG_LV_FATAL, "MESA_kill_tcp: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		return -1;
    }

	return offset;
}

/*
	输入原始包指针, 需要转换成raw_pkt结构, 传递给cycle_pkt_dump模块.
	has_layer2_hdr: 是否包括ethernet头部, 
	                如果没有, 比如sys_route发包模式, 需要临时copy一份并补充一个虚假mac头, 否则外部tcpdump_mesa会解析失败.
*/
void sapp_pkt_dump_by_raw_pkt(int tid, const void *pkt, int pkt_len, int has_layer2_hdr, unsigned short eth_pro_host_order, enum _pkt_classify class_val)
{
	raw_pkt_t raw_pkt;
	char temp_dump_buff[MTU_MAX];
	const void *to_tcpdump_buff;
	int to_tcpdump_len;
	struct mesa_ethernet_hdr *ehdr;
	static const unsigned char uknown_mac_acsii[6] = {0x75, 0x6b, 0x6e, 0x6f, 0x77, 0x6e};

	if(0 == G_PKT_DUMP_SW){
		return;
	}	

	if(0 == has_layer2_hdr){
		if(pkt_len + sizeof(struct mesa_ethernet_hdr) > MTU_MAX){
			sapp_runtime_log(RLOG_LV_INFO, "inject packet length too long:%d, can't send to tcpdump_mesa!", pkt_len);
			return;
		}
	}else{
		if(pkt_len > MTU_MAX){
			sapp_runtime_log(RLOG_LV_INFO, "inject packet length too long:%d, can't send to tcpdump_mesa!", pkt_len);
			return;
		}
	}

	if(0 == has_layer2_hdr){
		ehdr = (struct mesa_ethernet_hdr *)temp_dump_buff;
		memcpy(ehdr->ether_shost, uknown_mac_acsii, ETH_ALEN);
		memcpy(ehdr->ether_dhost, uknown_mac_acsii, ETH_ALEN);
		ehdr->ether_type = htons(eth_pro_host_order);
		memcpy(temp_dump_buff + sizeof(struct mesa_ethernet_hdr), pkt, pkt_len);
		to_tcpdump_buff = temp_dump_buff;
		to_tcpdump_len = pkt_len + sizeof(struct mesa_ethernet_hdr);
	}else{
		to_tcpdump_buff = pkt;
		to_tcpdump_len = pkt_len;
	}

	//memset(&raw_pkt, 0, sizeof(raw_pkt_t));
	//raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	raw_pkt.low_layer_type = ADDR_TYPE_MAC;
	raw_pkt.raw_pkt_data = to_tcpdump_buff;
	raw_pkt.raw_pkt_len = to_tcpdump_len;
	//raw_pkt.__lib_raw_pkt_data = to_tcpdump_buff;
	//raw_pkt.__lib_raw_pkt_len = to_tcpdump_len;

	cycle_pkt_dump_by_classify(tid, &raw_pkt, class_val);

	return;
}


static int packet_io_send_by_sys_routev4(MESA_send_handle *send_handle,int datalen,int dir,
									char *feedback_buf, int *feedback_buf_len)
{
	int ret, offset = 0;
	struct sockaddr_in sock_addr_v4;
	char *actual_data_ptr;
	struct mesa_ip4_hdr *ip4_hdr;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[send_handle->threadnum]->sys_stat;

    offset = packet_io_calc_ethernet_offset_to_ip(send_handle->send_buf);
    if(offset < 0){
			return -1;
    }

	/* 使用系统路由时, MAC地址由协议栈填充, 指针和长度要减去ETH头部 */
#if 0
	actual_data_ptr = (char *)send_handle->send_buf + sizeof(mesa_ethernet_hdr);
	datalen -= sizeof(mesa_ethernet_hdr);
#else
	actual_data_ptr = (char *)send_handle->send_buf + offset;
	datalen -= offset;

#endif

	ip4_hdr = (struct mesa_ip4_hdr *)actual_data_ptr;

	memset(&sock_addr_v4, 0, sizeof(struct sockaddr_in));
	sock_addr_v4.sin_family = AF_INET;
	/* build_ipv4时已经按dir方向构造好地址, 此处直接使用ip_dst即可 */
	sock_addr_v4.sin_addr.s_addr = ip4_hdr->ip_dst.s_addr;

	//if(sapp_global_single.send_fake_pkt_mode != 0){
	//	return packet_io_send_fake_pkt_by_gdev(send_handle, ADDR_TYPE_IPV4,
	//						actual_data_ptr+VXLAN_HDR_RESERVED_LEN, datalen, dir,
	//						feedback_buf, feedback_buf_len);
	//}
	
retry:
	ret = sendto(send_handle->raw_ipv4_fd, actual_data_ptr, datalen, 0,
				(struct sockaddr *)&sock_addr_v4, sizeof(struct sockaddr));
	if(ret < 0){
		if(EINTR == errno){
			goto retry; /* 被信号中断的IO调用需要重试 */
		}else{
			local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
			sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: sendto error, %s\n", __FILE__,__LINE__,strerror(errno));
			return ret;
		}
	}

	sapp_pkt_dump_by_raw_pkt(send_handle->threadnum, actual_data_ptr, datalen, 0, ETH_P_IP, PKT_CLASSIFY_INJECT);

	/* 是否需要将Inject包回馈给调用者 */
	if(feedback_buf != KILL_TCP_PHONY_POINTER){
		if(*feedback_buf_len < ret + (int)sizeof(struct mesa_ethernet_hdr)){
			return -2;
		}

		memcpy(feedback_buf, phony_feedback_eth_hdr_ip4, ETHERNET_HDR_LEN);

		memcpy(feedback_buf + sizeof(struct mesa_ethernet_hdr), actual_data_ptr, datalen);
		
		*feedback_buf_len = datalen + sizeof(struct mesa_ethernet_hdr);
	}

	return ret;
}

static int packet_io_send_by_sys_routev6(MESA_send_handle *send_handle,int datalen,int dir,
							char *feedback_buf, int *feedback_buf_len)
{
	int ret;
	struct sockaddr_in6 sock_addr_v6;
	char *actual_data_ptr;
	struct mesa_ip6_hdr *ip6_hdr;
	int offset;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[send_handle->threadnum]->sys_stat;
	
	if(0 == g_ipv6_send_packet_enabled){
		//printf("IPv6 module is not support! Please check 'sapp.toml->ipv6_send_packet_enabled'.\n");
		sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: IPv6 module is not support! Please check 'sapp.toml->ipv6_send_packet_enabled'.\n", __FILE__, __LINE__);		
		return -1;
	}

	offset = packet_io_calc_ethernet_offset_to_ip(send_handle->send_buf);
    if(offset < 0){
			return -1;
    }	

	/* 使用系统路由时, MAC地址由协议栈填充, 指针和长度要减去ETH头部 */
#if 0	
	actual_data_ptr = (char *)send_handle->send_buf + sizeof(struct mesa_ethernet_hdr);
	datalen -= sizeof(struct mesa_ethernet_hdr);
#else
	/* 2018-09-13 lijia modify, adjust MAC_IN_MAC header */
	actual_data_ptr = (char *)send_handle->send_buf + offset;
	datalen -= offset;	
#endif

	ip6_hdr = (struct mesa_ip6_hdr *)actual_data_ptr;
	
	memset(&sock_addr_v6, 0, sizeof(struct sockaddr_in6));
	sock_addr_v6.sin6_family = AF_INET6;
	memcpy(sock_addr_v6.sin6_addr.s6_addr, ip6_hdr->ip6_dst.s6_addr, IPV6_ADDR_LEN);

retry:	
	ret = sendto(send_handle->raw_ipv6_fd, actual_data_ptr, datalen, 0,
				(struct sockaddr *)&sock_addr_v6, sizeof(struct sockaddr_in6));
	if(ret < 0){
		if(EINTR == errno){
			goto retry; /* 被信号中断的IO调用需要重试 */
		}else{
			local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
			sapp_runtime_log(RLOG_LV_FATAL,"%s:%d: packet_io_send_by_sys_routev6() sendto error, %s\n", __FILE__,__LINE__,strerror(errno));
			return ret;
		}
	}

	sapp_pkt_dump_by_raw_pkt(send_handle->threadnum,actual_data_ptr, datalen, 0, ETH_P_IPV6,PKT_CLASSIFY_INJECT);

	if(feedback_buf != KILL_TCP_PHONY_POINTER){
		if(*feedback_buf_len < ret + (int)sizeof(struct mesa_ethernet_hdr)){
			return -2;
		}

		memcpy(feedback_buf, phony_feedback_eth_hdr_ip6, ETHERNET_HDR_LEN);
		
		memcpy(feedback_buf + sizeof(struct mesa_ethernet_hdr), actual_data_ptr, datalen);
		*feedback_buf_len = datalen + sizeof(struct mesa_ethernet_hdr);
	}
	
	return ret;
}

static int packet_io_get_sendroute_mac(char dev_id, char link_id, unsigned char *out_mac_addr)
{
    char *p_mac_addr = (char *)&g_send_gateway_mac_table[dev_id][link_id][0];
    if(G_SND_ROUTE_INFO_NUM <= 0 || strlen(p_mac_addr) <= 0){
    	return -1;
    }else{
		if(MESA_mac_pton(p_mac_addr, ':', (char *)out_mac_addr) < 0){
			sapp_runtime_log(20, "error, src mac:%s is not correct, for example:00:11:22:33:44:55\n", p_mac_addr);
			return -1;
		}
    }
    return 0;
}

static int packet_io_send_by_manual_conf(MESA_send_handle *send_handle,int datalen,
										int dir, UINT16 ether_type)
{
	int ret;
	
	/* to do:
		获取网关ip, mac 信息, 
		根据手工配置, 
		或根据分析/proc/net/route, /proc/net/arp自动获取!

		get_gateway_info_by_manual();
		get_gateway_info_aotu();
		
	*/	

	const struct streaminfo_private *pstrem_pr =  (const struct streaminfo_private *)send_handle->user_arg;
	const struct streaminfo *pstream = (const struct streaminfo *)send_handle->user_arg;
	const struct streaminfo *tmpstream = pstream;
	struct vxlan_info mim_mem_hdr;
	int opt_len = sizeof(mim_mem_hdr);
	ret = MESA_get_stream_opt(tmpstream, MSO_STREAM_VXLAN_INFO, &mim_mem_hdr, &opt_len);
	if(ret < 0){
		sapp_runtime_log(20, "packet_io_send_by_manual_conf(): get vxlan info error!\n");
		return -1;
	}
    unsigned char send_route_mac[MAC_ADDR_LEN] = "";
	unsigned char *p_dst_mac;

	if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_STACK_2_LAYER_MUTI_ROUTE )
    {
        ret = packet_io_get_sendroute_mac(mim_mem_hdr.dev_id, mim_mem_hdr.link_id, send_route_mac);
        if(ret < 0){
            sapp_runtime_log(20, "packet_io_send_by_manual_conf(): get sendroute_mac info using %d:%d error!\n", mim_mem_hdr.dev_id, mim_mem_hdr.link_id);
            return -1;
        }
        p_dst_mac = send_route_mac;
    }
    else
    {
        p_dst_mac = (unsigned char *)sapp_global_val->config.packet_io.inject_mode_single_gateway_dst_mac;
    }
    sendpacket_build_ethernet(p_dst_mac, sapp_global_val->config.packet_io.inject_mode_single_gateway_src_mac, ether_type, NULL, 0, send_handle->send_buf);


send_again:
	ret = sendto(send_handle->raw_eth_fd, send_handle->send_buf, datalen, 0, 
				(struct sockaddr *)&send_handle->saddr_raw_eth, sizeof(struct sockaddr));
	if(ret < 0){
		if((EAGAIN == errno) || (EINTR == errno) ){
			goto send_again;
		}else{
			return -1;
		}
	}	

	sapp_pkt_dump_by_raw_pkt(send_handle->threadnum, send_handle->send_buf, datalen, 1, 0, PKT_CLASSIFY_INJECT);
	
	return ret;
}

int packet_io_send_fake_pkt(MESA_send_handle *send_handle,int datalen,int send_type, 
					int low_layer_type, int dir,int thread_num,
					char *feedback_buf, int *feedback_buf_len, const raw_pkt_t *raw_pkt)
{
	int ret;
	UINT16 low_layer_ether_hproto;
	const struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)send_handle->send_buf;
	
	if(g_topology_mode & __NET_CONN_PARALLEL)
	{
		
		low_layer_ether_hproto = ntohs(ehdr->ether_type);
		
		if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_GDEV)
		{
			ret = packet_io_send_fake_pkt_by_gdev(send_handle, (enum addr_type_t)low_layer_type,
												  (char *)send_handle->send_buf, datalen, dir, feedback_buf, feedback_buf_len);
		}
		else if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_STACK_2_LAYER_1_ROUTE 
		     || sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_STACK_2_LAYER_MUTI_ROUTE)
        {
            ret = packet_io_send_by_manual_conf(send_handle, datalen, dir, low_layer_ether_hproto);
        }
		else
		{
			switch (low_layer_type)
			{
				case __ADDR_TYPE_IP_PAIR_V4:
				case ADDR_TYPE_IPV4:
					ret = packet_io_send_by_sys_routev4(send_handle, datalen, dir, feedback_buf, feedback_buf_len);
					break;

				case __ADDR_TYPE_IP_PAIR_V6:
				case ADDR_TYPE_IPV6:
					ret = packet_io_send_by_sys_routev6(send_handle, datalen, dir, feedback_buf, feedback_buf_len);
					break;

				default:
					/* 并联模式下的非IP协议, 不能使用系统路由发送, 必须使用raw_eth_fd通过指定网卡发送 */
					ret = packet_io_send_by_manual_conf(send_handle, datalen, dir, low_layer_ether_hproto);
					break;
			}
		}
	}
	else
	{
		if(NULL == raw_pkt){
			raw_pkt = sapp_global_val->mthread_volatile[thread_num]->raw_pkt;
		}
	
		ret = dl_io_fun_list.dl_io_low_level_send(send_handle->low_level_send_handle, 
										(UINT8 *)send_handle->send_buf,
										datalen,
										low_layer_type,
										dir,
										thread_num,
										raw_pkt);
		if(ret < 0){
			sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		}										
	}

	return ret;
}

/*
	send_type:发包类型, RST, 日志, 回传数据等;
	low_layer_type:除MAC层之外, 最底层协议类型, 如IPv4, ipv6, VLAN等.
	datalen		:上层APP总长, 但不含MAC层的14字节.
*/
int packet_io_send(MESA_send_handle *send_handle,int datalen,int send_type, 
					int low_layer_type, int dir,int thread_num,
					char *feedback_buf, int *feedback_buf_len, const raw_pkt_t *raw_pkt)
{
	int ret = -1;

	switch(send_type){
		case SEND_TYPE_LINK_INJECT:
			ret = packet_io_send_fake_pkt(send_handle, datalen, send_type, low_layer_type, 
									dir, thread_num, feedback_buf, feedback_buf_len, raw_pkt);
		break;

		case SEND_TYPE_LOG:
			/* to do */
			ret = -1;
		break;

		case SEND_TYPE_REDIRECT:
			/* to do, 水浒原始报文转发 */
			ret = -1;
		break;

		default:
			break;
	}	
	
	return ret;
}



send_raw_pkt_info_t *get_raw_pkt_conf_by_id(unsigned int target_id)
{
	int i;

	for(i = 0; i < G_SND_RAW_PKT_INFO_NUM; i++){
		if(target_id == G_SND_RAW_PKT_INFO[i].target_id){
			return &(G_SND_RAW_PKT_INFO[i]);
		}
	}

	//printf("Send raw pkt error! Not found target_id:%u\n", target_id);

	return NULL;
}

int parse_send_gdev_ip_conf(const char *profile_path)
{
    FILE *fp;
    char conf_buf[1024] = "";
    int dev_id = 0;
    char ip_addr[32] = "";
    int ret = 0;
    fp = fopen(profile_path, "r");
    if(NULL == fp){
        printf("open send_gdev config file: %s error!\n", profile_path);
        return -1;
    }

    memset(g_send_gdev_ip_table, 0, sizeof(g_send_gdev_ip_table));
    G_SND_GDEV_INFO_NUM = 0;

    while(fgets(conf_buf, 1024, fp)){
        if('#' == conf_buf[0] || ' ' == conf_buf[0] || '\r' == conf_buf[0] || '\n' == conf_buf[0]){
            continue;
        }

        //del_last_rn(conf_buf, 1024);

        ret = sscanf(conf_buf, "%d\t%s", &dev_id, ip_addr);

        if(ret != 2 || dev_id >= 64 || strlen(ip_addr) >= 32)
        {
            printf("read %s error, line:%s!\n", profile_path, conf_buf);
            G_SND_GDEV_INFO_NUM = 0;
            break;
        }

        memcpy(g_send_gdev_ip_table[dev_id], ip_addr, strlen(ip_addr));

        G_SND_GDEV_INFO_NUM++;
        memset(conf_buf, 0, sizeof(conf_buf));
    }
    fclose(fp);
    return 0;
}

int parse_send_route_conf(const char *profile_path)
{
	FILE *fp;
	char conf_buf[1024] = "";
	//const char *delim = "\t ";
	int dev_id = 0, link_id = 0;
	char mac_addr[18] = "";
	int ret = 0;
	fp = fopen(profile_path, "r");
	if(NULL == fp){
		printf("open send route config file: %s error!\n", profile_path);
		return -1;
	}

	memset(g_send_gateway_mac_table, 0, sizeof(g_send_gateway_mac_table));
    G_SND_ROUTE_INFO_NUM = 0;

    while(fgets(conf_buf, 1024, fp)){
		if('#' == conf_buf[0] || ' ' == conf_buf[0] || '\r' == conf_buf[0] || '\n' == conf_buf[0]){
			continue;
		}

		//del_last_rn(conf_buf, 1024);

		ret = sscanf(conf_buf, "%d\t%d\t%s", &dev_id, &link_id, mac_addr);

		if(ret != 3 || dev_id >= 64 || link_id >= 16 || strlen(mac_addr) >= 18)
		{
			printf("read %s error, line:%s!\n", profile_path, conf_buf);
			G_SND_ROUTE_INFO_NUM = 0;
			break;
		}

		memcpy(g_send_gateway_mac_table[dev_id][link_id], mac_addr, strlen(mac_addr));

		G_SND_ROUTE_INFO_NUM++;
		memset(conf_buf, 0, sizeof(conf_buf));
	}
	fclose(fp);
	return 0;
}


int packet_io_send_raw(int thread_num, char *data, int datalen,unsigned int target_id)
{
	MESA_send_handle *snd_handle;
	int ret;

	snd_handle = packet_io_get_send_handle(thread_num);
	if(NULL == snd_handle){
		return -1;
	}

	/* 
	  在polling模式下, 借用全局变量暂存的"当前包raw_pkt"已经不对了, 因为当前包跟从polling entry收到的包可能完全是两个流的数据包 
	*/
	ret = dl_io_fun_list.dl_io_raw_pkt_send(snd_handle->low_level_send_handle,
									(unsigned char *)data,
									datalen,
									g_packet_device_alias[target_id].dl_io_param,
									thread_num,
									0, /* 此处是直接构造全部包头, 并指定发包网卡, 发包方向无意义 */
									NULL);
	if(ret < 0){
		sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
	}
									
	return ret;
}



void packet_io_clean_thread_context(int thread_seq)
{
	free_thread_stream(thread_seq);

	ipv4_frag_per_thread_exit(thread_seq);
	ipv6_frag_per_thread_exit(thread_seq);
	pptp_per_thread_exit(thread_seq);
}

void packet_io_lib_destroy(void)
{
	if(dl_io_fun_list.dl_io_destroy){
		dl_io_fun_list.dl_io_destroy();
	}
}

int packet_io_init(int argc, char *argv[])
{
	int i, ret;

	if(sapp_global_val->config.stream.tcp.inject.remedy_kill_tcp_by_inline_device != 0){
		ret = gdev_block_init();
		if(ret < 0){
			printf("\n\033[33m[Error]gdev_block_init error!\033[0m\n");
			return -1;
		}
	}
		
	if(0 == use_custom_pkt_cb){
		packet_io_register_cb(mesa_default_pkt_cb);	
	}

	if(NULL == dl_io_fun_list.dl_io_init){
		printf("Error, packet io library must support 'dl_io_init' !\n");
		exit(0);
	}
	
	if(dl_io_fun_list.dl_io_init(argc, argv) < 0){
		return -1;
	}

	for(i = 0; i < MAX_THREAD_NUM; i++){
		g_send_buf_pool[i] = (UINT8 *)malloc(SENDPACKET_BUF_LEN);
	}

	if(sendpacket_init_new(g_packet_io_thread_num) < 0){
		printf("Error, sendpacket_init_new error !\n");
		return -1;
	}

#if 0 /* 20161117 lijia move to send_handle_init() */
	for(i = 0; i < g_packet_io_thread_num; i++){
		g_packet_dl_send_handle[i] = dl_io_fun_list.dl_io_get_send_handle(i);
	}
#endif

	if(CAP_MODEL_PCAP_DUMPFILE == g_packet_io_cap_mode){
		dl_io_fun_list.dl_io_register_exit_cb(libsapp_destroy_env);
	}

	if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_GDEV){
    	parse_send_gdev_ip_conf("conf/send_gdev.conf");
    }

	if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_STACK_2_LAYER_MUTI_ROUTE){
		parse_send_route_conf("conf/send_route.conf");
	}
	
	packet_io_device_alias_init();

	packet_io_status_init();

	if(packet_io_under_ddos_init() < 0){
		return -1;
	}

	return 0;
}


void packet_io_exit(void)
{
	/* 读包模式下, 给其他非IO线程一些时间, 处理未完成数据, 比如异步发送日志, field_stat刷新统计数据等等. */
	sapp_set_current_state(SAPP_STATE_READY_TO_EXIT);
	sleep(sapp_global_val->config.packet_io.dumpfile_sleep_time_before_exit);

	sysinfo_output(); /* 最后一次写统计信息, 关闭标志位, 因为流表将被清空, 再写就没意义了 */
	update_packet_io_status_sw = 0;
		
	plugctrl_destroy_all_plug();
	sendpacket_destroy(g_packet_io_thread_num);
	packet_io_lib_destroy();


	sapp_log_handle_destroy();
	sapp_fs2_destroy();
	packet_io_under_ddos_destroy();

	sapp_timer_destroy(sapp_global_val->individual_fixed.sapp_standalone_timer);
	
	sapp_gval_destroy();

	exit(0);
	
	return;
}


#ifdef __cplusplus
}
#endif


