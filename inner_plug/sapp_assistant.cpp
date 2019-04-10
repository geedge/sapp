/*
	此文件非平台核心功能和函数,
	是提供给其他业务插件的接口, 如sapp_get_platform_opt等, 做为一个.so文件挂载到平台,
	便于更新部署.
*/
#include "stream_internal.h"
#include "stream_manage.h"
#include "sysinfo.h"
#include "packet_io.h"
#include "packet_io_internal.h"
#include "project_requirement.h"
#include "project_internal.h"
#include "dictator.h"
#include "MESA_handle_logger.h"
#include "field_stat2.h"
#include "MESA_prof_load.h"
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/types.h>
#include <linux/version.h>
#include <dlfcn.h>
#if IOMODE_MARSIO
#include "marsio.h"
#include "mrtunnat.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

int sapp_assistant_version_VERSION=20180722;

extern time_t g_CurrentTime;//add by lqy 20070606
extern time_t g_sapp_start_time;
extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];
extern volatile unsigned long long sysinfo_new[COUNTER_NUM];
extern int g_packet_io_thread_num;
extern int g_packet_io_cap_mode;
extern int g_iThreadNum;
static void *sapp_fs_handle;
static pthread_mutex_t g_plug_Independent_thread_mutex;
static pthread_t g_plug_Independent_thread_pid[NON_PKT_THREAD_SEND_QUEUE];

typedef struct{
	int sapp_tot_pkt_fs_id;
	int sapp_tot_bytes_fs_id;
	int sapp_active_send_fs_id;
}sapp_fs_id_t;

//static sapp_fs_id_t g_sapp_fs_id;
static const unsigned char G_BROADCAST_ADDR[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


void * (*dl_marsio_buff_ctrlzone)(void *m, uint8_t id);


static int sapp_identify_broad_multicast_init(void)
{
#if IOMODE_MARSIO
	void *io_lib_handle;
	
	if(CAP_MODEL_MARSIOV4 == g_packet_io_cap_mode){
#if LINK_MODE_DYNAMIC	
		io_lib_handle = dlopen("./platform_lib/packet_io_marsio.so", RTLD_NOW | RTLD_GLOBAL);
		if(NULL == io_lib_handle){
			printf("\033[1;31;40m[Error]dlopen %s error, %s!\033[0m\n", "./platform_lib/packet_io_marsio.so", dlerror());
			return -1;
		}	
		dl_marsio_buff_ctrlzone = (void * (*)(void *m, uint8_t id))dlsym(io_lib_handle, "marsio_buff_ctrlzone");
		if(NULL == dl_marsio_buff_ctrlzone){
			printf("\033[1;31;40m[Error]dlsym %s error, %s!\033[0m\n", "marsio_buff_ctrlzone", dlerror());
			return -1;
		}

		/* 此处不要用dlclose(), 因为后续还要用dlopen打开packet_io_marsio.so,  */
#else
	dl_marsio_buff_ctrlzone = (void * (*)(void *m, uint8_t id))marsio_buff_ctrlzone;
#endif
	}
#endif

	return 0;
}

/* 识别是否隧道内部数据包           , 隧道内的包应该无条件转发/回注        */
int sapp_identify_tunnel_inner_pkt(const raw_pkt_t *raw_pkt)
{
#if IOMODE_MARSIO
	if(CAP_MODEL_MARSIOV4 == g_packet_io_cap_mode){
		const struct mr_tunnat_ctrlzone *mr_ctzone;
		if(dl_marsio_buff_ctrlzone){
			mr_ctzone = (const struct mr_tunnat_ctrlzone *)((*dl_marsio_buff_ctrlzone)((void *)raw_pkt->io_lib_pkt_reference, 0));
			if(mr_ctzone->action & TUNNAT_CZ_ACTION_FORWARD){
				return 1;
			}
		}
	}
#endif

	return 0;
}

int sapp_identify_broad_multicast_pkt(const void *this_layer_data, const raw_pkt_t *raw_pkt)
{
	const struct mesa_ethernet_hdr *p_eth_hdr = (const struct mesa_ethernet_hdr *)this_layer_data;
	unsigned short eth_type = p_eth_hdr->ether_type; /* 使用网络序直接判断, 避免每次都调用ntohs() */

	if(sapp_identify_tunnel_inner_pkt(raw_pkt) != 0){
		return 0;
	}

	if(memcmp(G_BROADCAST_ADDR, p_eth_hdr->ether_dhost, 6) == 0){
		/* G串联模式下，非ARP协议的广播包，直接丢弃! 防止再回注到网络中, 造成广播风暴等网络问题 */
		if(eth_type != ETH_P_ARP_NET){
			return 1;
		}
	}else{
		/* 2017-10-10 lijia add, 组播MAC地址, 通常为局域网内控制类数据包, 如LLMNR, STP等协议, 一般无需处理 */
		if((p_eth_hdr->ether_dhost[0] & 0x01) == 0x01){
			return 1;
		}
	}

	return 0;
}

/* 2017-09-04 lijia add, for 网管需求, 插件获取平台内部参数 */
int sapp_get_platform_opt(enum sapp_platform_opt opt, void *opt_val, int *opt_val_len)
{
	int i, ret = 0;
	unsigned long long tmp_long;

	if((NULL == opt_val) || (opt_val_len <= 0)){
		return -1;
	}

	switch((int)opt){
		case SPO_TOTAL_RCV_PKT:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			tmp_long = 0;
			for(i = 0; i < g_packet_io_thread_num; i++){
				tmp_long += g_SysInputInfo[i][PKT_ETHERNET];
			}
			*tot_pkt = tmp_long;
		}
		break;

		case SPO_TOTAL_RCV_BYTE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			tmp_long = 0;
			for(i = 0; i < g_packet_io_thread_num; i++){
				tmp_long += g_SysInputInfo[i][PKT_ETHERNET_LEN];
			}
			*tot_byte = tmp_long;
		}
		break;

		case SPO_THREAD_COUNT:
		{
			if(*opt_val_len != sizeof(int)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}

			int *tcnt = (int *)opt_val;
			*tcnt = g_packet_io_thread_num;
		}
		break;

		case SPO_CURTIME_TIMET:
		{
			if(*opt_val_len != sizeof(time_t)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			time_t *curtime = (time_t *)opt_val;
			*curtime = g_CurrentTime;
		}
		break;

		case SPO_CURTIME_STRING:
		{
			if(*opt_val_len <= (int)strlen("1970-01-01 11:11:11")){

				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;			
			}
			time_t cur_time = g_CurrentTime;
			struct tm date_loc;
			int ret;
			
			localtime_r(&cur_time, &date_loc);
			ret = snprintf((char *)opt_val, *opt_val_len, "%04d-%02d-%02d %02d:%02d:%02d", 
					date_loc.tm_year+1900, date_loc.tm_mon+1,date_loc.tm_mday, 
					date_loc.tm_hour, date_loc.tm_min, date_loc.tm_sec);
			*opt_val_len = ret;
		}
		break;
		
		case SPO_START_TIME:
		{
			if(*opt_val_len != sizeof(time_t)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			time_t *stime = (time_t *)opt_val;
			*stime = g_sapp_start_time;
		}
		break;

		case SPO_RUN_TIME:
		{
			if(*opt_val_len != sizeof(time_t)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			time_t *runtime = (time_t *)opt_val;
			*runtime = g_CurrentTime - g_sapp_start_time;
		}
		break;

		/* 外部插件频繁调用rand等函数比较消耗CPU, 使用CPU当前的时钟周期数, 和当前平台处理的包数拼成一个随机数 */
		case SPO_RAND_NUMBER:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}

			long long *rnum = (long long *)opt_val;

			*rnum = ((sapp_get_cpu_cycle() & 0xFFFF) << 48)
			         | ((g_SysInputInfo[0][PKT_TCPLEN] & 0xFFFF) << 32)
			         | ((g_SysInputInfo[0][PKT_IPLEN] & 0xFFFF) << 16)
			         | ((g_SysInputInfo[0][PKT_ETHERNET_LEN] & 0xFFFF));
		}
		break;

		case SPO_FIELD_STAT_HANDLE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			void **out_handle = (void **)opt_val;
			*out_handle = sapp_fs_handle;
		}
		break;

		case SPO_INDEPENDENT_THREAD_ID:
		{
			int id_index = -1;
			int *opt_int = (int *)opt_val;
			int i;
			pthread_t this_pid = pthread_self(); /* 获取当前线程id */
			
			pthread_mutex_lock(&g_plug_Independent_thread_mutex);

			/* 为避免一个线程多次调用此接口, 先查找之前是否保存过 */
			for(i = 0; i < NON_PKT_THREAD_SEND_QUEUE; i++){
				if(g_plug_Independent_thread_pid[i] == this_pid){
					id_index = i;
					break;
				}
			}

			if(-1 == id_index){ /* 当前线程第一次创建, 没找到 */
				for(i = 0; i < NON_PKT_THREAD_SEND_QUEUE; i++){
					if(0 == g_plug_Independent_thread_pid[i]){
						g_plug_Independent_thread_pid[i] = this_pid;
						break;
					}
				}
				if((i+ g_iThreadNum >= NON_PKT_THREAD_SEND_QUEUE )  /* 发包线程最大64个 */
				|| (i >= NON_PKT_THREAD_SEND_QUEUE)){
					sapp_runtime_log(RLOG_LV_FATAL, "Independent_thread num over limit, only support max %d!\n", NON_PKT_THREAD_SEND_QUEUE);
					*opt_int = -1;
					ret = -1;
				}else{
					*opt_int = g_iThreadNum + i; 
				}
			}else{
				*opt_int = g_iThreadNum + id_index;
			}
			
			pthread_mutex_unlock(&g_plug_Independent_thread_mutex);
		}
		break;
		
		default:
			sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_type:%d not support!\n", (int)opt);
			ret = -1;
	}

	return ret;
}

#if 0
int sapp_fileld_stat_init(void)
{
	int opt;
	char cfg_server_ip[16];
	int cfg_server_port_host; 
	
	sapp_fs_handle = FS_create_handle();

	FS_set_para(sapp_fs_handle, OUTPUT_DEVICE, "./log/sapp_field_stat.log", strlen("./log/sapp_field_stat.log"));
	
	opt = 1;
	FS_set_para(sapp_fs_handle, PRINT_MODE, &opt, sizeof(int));

	opt = 1;
	FS_set_para(sapp_fs_handle, CREATE_THREAD, &opt, sizeof(int));

	opt = 1;
	FS_set_para(sapp_fs_handle, STAT_CYCLE, &opt, sizeof(int));

	FS_set_para(sapp_fs_handle, APP_NAME, "sapp", strlen("sapp") + 1);

	MESA_load_profile_string_def("conf/sapp_assistant.conf", "field_stat", "remote_server_ip", cfg_server_ip, 16, "");
	if('\0' == cfg_server_ip[0]){
		printf("\033[41msapp_fileld_stat_init()->remote_server_ip error!\033[0m\n");
		return -1;
	}
	FS_set_para(sapp_fs_handle, STATS_SERVER_IP, cfg_server_ip, strlen(cfg_server_ip) + 1);

	MESA_load_profile_int_def("conf/sapp_assistant.conf", "field_stat", "remote_server_port", &cfg_server_port_host, 0);
	if(0 == cfg_server_port_host || cfg_server_port_host > 65535){
		printf("\033[41msapp_fileld_stat_init()->remote_server_port error!\033[0m\n");
		return -1;
	}
	FS_set_para(sapp_fs_handle, STATS_SERVER_PORT, &cfg_server_port_host, sizeof(cfg_server_port_host));

	g_sapp_fs_id.sapp_tot_pkt_fs_id = FS_register(sapp_fs_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ethernet_tot_pkt");
	if(g_sapp_fs_id.sapp_tot_pkt_fs_id < 0){
		printf("\033[41msapp_fileld_stat_init()->FS_register %s error!\033[0m\n", "Ethernet_tot_pkt");
		return -1;
	}
	g_sapp_fs_id.sapp_tot_bytes_fs_id = FS_register(sapp_fs_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ethernet_tot_len");
	if(g_sapp_fs_id.sapp_tot_bytes_fs_id < 0){
		printf("\033[41msapp_fileld_stat_init()->FS_register %s error!\033[0m\n", "Ethernet_tot_len");
		return -1;
	}
	
	return 0;
}
#endif

/*
	因为sapp_fs_handle句柄初始化后, 可能还有其他插件需要使用FS_register注册新的字段,
	此时不能先调用FS_start(sapp_fs_handle),
	但做为平台层插件, 无法得知什么时候平台和其他插件已经全部初始化完, 可以运行了.

	使用一个小技巧, 平台开始收包后, 肯定就是开始运行了.
	然后再调用FS_start(sapp_fs_handle);
*/

#if 0
static void *sapp_delay_start(void *arg)
{
	//time_t last_time;
	
	while(0 == g_SysInputInfo[0][PKT_IP]){
		usleep(100);
	}

	if(sapp_global_single.fs2_handle != NULL){
		FS_start(sapp_fs_handle);
	}

	//last_time = time(NULL);
	while(1){
		usleep(1000);
	}

	return NULL;
}
#endif

void sapp_fs2_update(int field_index, unsigned  long long value)
{
	if(sapp_global_single.fs2_handle != NULL){
		FS_operate(sapp_global_single.fs2_handle, sapp_global_single.fs2_filed_id_array[field_index], 0, FS_OP_SET,  (long long)value);
	}
}

static int sapp_fs2_init(void)
{
	int module_switch;
	char cfg_ip_str[32];
	int cfg_port;
	int fs2_opt;
	int cycle;

	MESA_load_profile_int_def("conf/main.conf", "ShowStatInfo", "FS_switch", &module_switch, 0);
	if(0 == module_switch){
		sapp_global_single.fs2_handle = NULL;
		return 0;
	}

	sapp_global_single.fs2_handle = FS_create_handle();
	if(NULL == sapp_global_single.fs2_handle){
		sapp_runtime_log(RLOG_LV_FATAL, "FS_create_handle() error: %s!\n", strerror(errno));
		return -1;
	}

	MESA_load_profile_string_def("conf/main.conf", "ShowStatInfo", "FS_server_ip", cfg_ip_str,32, "#");
	if('#' == cfg_ip_str[0]){
		sapp_runtime_log(RLOG_LV_FATAL, "FS_switch is enable, but not found FS_server_ip config\n");
		return -1;
	}

	sapp_global_single.fs2_server_ip = strdup(cfg_ip_str);

	MESA_load_profile_int_def("conf/main.conf", "ShowStatInfo", "FS_server_port", &cfg_port, -1);
	if(cfg_port <= 0 || cfg_port > 65535){
		sapp_runtime_log(RLOG_LV_FATAL, "FS_server_port %d invalid!\n", cfg_port);
		return -1;
	}

    MESA_load_profile_int_def("conf/main.conf", "ShowStatInfo", "FS_cycle", &cycle, 3);

    sapp_global_single.fs2_server_port_host = (unsigned short)cfg_port;

	fs2_opt = 1;
	FS_set_para(sapp_global_single.fs2_handle, STAT_CYCLE, &fs2_opt, sizeof(int));

	fs2_opt = 1; /* 1:Rewrite ,2: Append.  */
	FS_set_para(sapp_global_single.fs2_handle, PRINT_MODE, &fs2_opt, sizeof(int));

	MESA_load_profile_int_def("conf/main.conf", "ShowStatInfo", "FS_print_switch", &fs2_opt, 0);	
	FS_set_para(sapp_global_single.fs2_handle, PRINT_TRIGGER, &fs2_opt, sizeof(int));

	FS_set_para(sapp_global_single.fs2_handle, OUTPUT_DEVICE, "fs2_sysinfo.log", strlen("fs2_sysinfo.log")+1);

	FS_set_para(sapp_global_single.fs2_handle, APP_NAME, "sapp", strlen("sapp")+1);

	FS_set_para(sapp_global_single.fs2_handle, STATS_SERVER_IP, (void *)sapp_global_single.fs2_server_ip, strlen(sapp_global_single.fs2_server_ip)+1);

	FS_set_para(sapp_global_single.fs2_handle, STATS_SERVER_PORT, &sapp_global_single.fs2_server_port_host, sizeof(short));

	sapp_global_single.fs2_filed_id_array[PKT_ETHERNET] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ethernet_pps");
	sapp_global_single.fs2_filed_id_array[PKT_ETHERNET_LEN] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ethernet_bps");

	sapp_global_single.fs2_filed_id_array[PKT_IP] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "IPv4_pps");
	sapp_global_single.fs2_filed_id_array[PKT_IPLEN] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "IPv4_bps");

	sapp_global_single.fs2_filed_id_array[PKT_IPV6] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "IPv6_pps");
	sapp_global_single.fs2_filed_id_array[PKT_IPV6LEN] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "IPv6_bps");

	sapp_global_single.fs2_filed_id_array[PKT_TCP] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "TCP_pps");
	sapp_global_single.fs2_filed_id_array[PKT_TCPLEN] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "TCP_bps");

	sapp_global_single.fs2_filed_id_array[PKT_UDP] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "UDP_pps");
	sapp_global_single.fs2_filed_id_array[PKT_UDPLEN] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "UDP_bps");

	sapp_global_single.fs2_filed_id_array[SYS_TCP_LINK_NEW] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "TCP_LINK_NEW");
	sapp_global_single.fs2_filed_id_array[SYS_TCP_LINK_DEL] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "TCP_LINK_DEL");
	sapp_global_single.fs2_filed_id_array[SYS_TCP_LINK_DATA] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "TCP_CONCURRENT");

    sapp_global_single.fs2_filed_id_array[LINK_DOUBLE] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD,
            FS_CALC_CURRENT, "TCP_LINK_DOUBLE");
    sapp_global_single.fs2_filed_id_array[LINK_SINGLE_C2S] = FS_register(sapp_global_single.fs2_handle,
            FS_STYLE_FIELD, FS_CALC_CURRENT, "TCP_LINK_C2S");
    sapp_global_single.fs2_filed_id_array[LINK_SINGLE_S2C] = FS_register(sapp_global_single.fs2_handle,
            FS_STYLE_FIELD, FS_CALC_CURRENT, "TCP_LINK_S2C");


    sapp_global_single.fs2_filed_id_array[SEND_TCP_RST] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "SEND_TCP_RST");
	sapp_global_single.fs2_filed_id_array[SEND_TCP_SYN_ACK] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "SEND_TCP_S/A");
	sapp_global_single.fs2_filed_id_array[SEND_UDP_PKT] = FS_register(sapp_global_single.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "SEND_UDP");

	for(int i = 0; i < g_packet_io_thread_num; i++)
	{
		char histogram_name[16];
		sprintf(histogram_name, "tid_%d(ns)", i);
		sapp_global_single.fs2_latency_id_array[i] = FS_register_histogram(sapp_global_single.fs2_handle,  //Field Stat句柄
							  FS_CALC_SPEED,    //输出累计值或瞬时值
							  histogram_name,     //统计项名称，字符串
							  1,                  //可追踪的最小值
							  100000000,            //可追踪的最大值
							  2);                 //精度，即小数点后几位，范围1~4

	}
	FS_start(sapp_global_single.fs2_handle);
	
	return 0;
}

void sapp_fs2_set_latency(int thead_seq, long long time_cost)
{
	if(sapp_global_single.fs2_handle != NULL){
		FS_operate(sapp_global_single.fs2_handle, sapp_global_single.fs2_latency_id_array[thead_seq], 0, FS_OP_SET, time_cost);
	}
}

int sapp_assistant_init(void)
{
	///pthread_t pid;
	
	if(sapp_fs2_init() < 0){
		return -1;
	}

	sapp_identify_broad_multicast_init();

	pthread_mutex_init(&g_plug_Independent_thread_mutex, NULL);

	///pthread_create(&pid, NULL, sapp_delay_start, NULL);
	///pthread_detach(pid);
	
	return 1;
}

#ifdef __cplusplus
}
#endif

