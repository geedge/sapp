#ifndef _SAPP_GLOBAL_VAL_H_
#define _SAPP_GLOBAL_VAL_H_ 1

#include <pthread.h>
#include <netinet/in.h>
#include <limits.h>
#include "sapp_pkt_stat.h"
#include "sapp_limits.h"
#include "sapp_mem.h"
#include "stream_inc/stream_base.h"
#include "packet_io.h"
#include "sapp_cla_private.h"

enum pkt_dump_mode{
	PKT_DUMP_LOCAL_FILE		=	1, 
	PKT_DUMP_UDP_SOCKET		=	2, 
};


/*
	vxlan和vlan_flipping是可以共存的,
	vxlan用于在线流量,
	vlan_flipping用于本机自检流量,
*/
enum overlay_mode_config{
	OVERLAY_MODE_NONE			= 0,
	OVERLAY_MODE_VXLAN			= 1,
	OVERLAY_MODE_NF			= 2,
};

typedef struct{
	int layer_type_index[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];
}embed_layer_t;


typedef struct{
	int is_asymmetric_layer;
	embed_layer_t under_layer;
	embed_layer_t upper_layer;
}asymmetric_presence_layer_t;


typedef struct{
	int worker_threads;
	int send_only_threads_max_num; /* 纯发包线程最大数量, 是插件动态创建的, sapp可能无法预知, 只能设个最大值 */
	int bind_mask_array_num;
	long bind_mask_array[SAPP_MAX_THREADS];
	long bind_mask; /* bind_mask_array中的每个变量做为bit_index转成的整数值 */
}sapp_config_cpu_t;


typedef struct{
	char instance_name[NAME_MAX];
}sapp_config_system_t;



typedef struct{
	int  enabled;
	char mode_str[NAME_MAX];  /* storage/udp_socket */
	int mode_bin;
	unsigned int command_port; /* integer, host order, user should truncate to short */
	unsigned int file_size_max_per_thread; /* MB */
	char *bpf_filter;
	char *storge_path;
	int dump_all_thread_enabled;
	int dump_thread_id_array_num;
	int dump_thread_id_array[SAPP_MAX_THREADS]; /* 用户配置文件原始数组, 格式: [0,1,2,3], 表示第0,1,2,3号线程启用捕包 */
	unsigned char dump_thread_id_mask[SAPP_MAX_THREADS]; /* 根据原始数组解析后的掩码数组, 用线程id做为下标, 值不为0表示当前线程开启捕包, 值:{1,1,1,1} */
	int pkt_dump_ratio; /* capture one packet every 'pkt_dump_ratio' packets */
}sapp_config_tools_pktdump_t;

typedef struct{
	int signal;
}sapp_config_tools_signal_handler_t;

typedef struct{
	sapp_config_tools_pktdump_t pkt_dump;
	sapp_config_tools_signal_handler_t signal_handler;
}sapp_config_tools_t;


typedef struct{
	int auto_remedy; /* 平台全局配置, 对于每个流, 可以设置auto_remedy_flag, 优先级高于全局auto_remedy */
	int rst_signature_enable;
	int rst_num;
	int rst_signature_seed1;
	int rst_signature_seed2;
	int link_mss;
	int remedy_kill_tcp_by_inline_device; /* 并联FD不生效时, 借助inline device下发DROP规则 */
}sapp_config_stream_tcp_inject_t;


typedef struct{
	int max;  /* max stream number per thread */
	int timeout;
	int reorder_pkt_max;
	int syn_mandatory;
	int analyse_option_enabled;
	int tuple4_reuse_time_interval;
	int meaningful_statistics_minimum_pkt;
	int meaningful_statistics_minimum_byte;
	sapp_config_stream_tcp_inject_t inject;
	unsigned short *well_known_ports_array; /* 用于按data建连接确定server端 */
	int well_known_ports_array_num;
	int closing_timeout;
	int opening_timeout;
}sapp_config_stream_tcp_t;


typedef struct{
	int max;  /* max stream number per thread */
	int timeout;
	int meaningful_statistics_minimum_pkt;
	int meaningful_statistics_minimum_byte;	
	unsigned short *well_known_ports_array; /* 用于新建连接确定server端, 比如4001->8000, 实际上是OICQ的C2S方向数据包,之前的版本会被误识别为S2C方向的 */
	int well_known_ports_array_num;	
}sapp_config_stream_udp_t;


typedef struct{
	char stream_id_base_time_str[32];
	unsigned int stream_id_base_time_t;
	sapp_config_stream_tcp_t tcp;
	sapp_config_stream_udp_t udp;
}sapp_config_stream_t;


typedef struct{
	char sapp_log_category[NAME_MAX];
	char sapp_plugin_log_category[NAME_MAX];
}sapp_config_profiling_log_t;


typedef struct{
	int enabled;
	int  prometheus_service_port;
	char  prometheus_service_uri[NAME_MAX];
	char local_file[NAME_MAX];
	char app_name[NAME_MAX];
	int refresh_interval_s;
}sapp_config_profiling_metric_t;

typedef struct{
	sapp_config_profiling_log_t log;
	sapp_config_profiling_metric_t fs2;
	sapp_config_profiling_metric_t fs3;

	//process_latency and sanity_check
	char process_latency_log_category[NAME_MAX];
	int histogram_enabled;
	int process_latency_threshold_in_ms; /* nanosecond, 配置文件里单位是microsecond, 需要乘以1000 */
	/* 精确模式开启后, fs2自身统计也非常耗CPU, 每个包都要调用FS_operate(),
	   如果停用精确模式, 输入fs2的是保留最近一段时间的最大值, 最小值和这一段时间的平均值, 仅调用FS_operate()三次,
	   精确度降低了一些, 但大大减少了调用FS_operate()的次数.
		开启pkt_latency_accurate_enable后平均值基本是对的, 但标准差就不准了.
	   */
	//int process_latency_accurate_enable; 
	
	int sanity_check_raw_pkt_broken_enabled;
	int sanity_check_symbol_conflict_enabled;
}sapp_config_profiling_t;

typedef struct{
	char type_str[NAME_MAX]; /* pag,pcap,marsio */
	char name[NAME_MAX];
	enum cap_mode_t type_bin; /* 由字符串type转换为二进制数值 */
}sapp_config_packet_io_interface_t;


typedef struct{
	sapp_config_packet_io_interface_t interface;
	unsigned char format_type; /* vxlan, ddp, k18mac, 327, etc.. */
}sapp_config_packet_io_dev_t;


enum __sapp_config_packet_io_depolyment_mode{
	SAPP_CFG_PKT_IO_DEPOLY_MODE_MIRROR,
	SAPP_CFG_PKT_IO_DEPOLY_MODE_INLINE,
	SAPP_CFG_PKT_IO_DEPOLY_MODE_TRANSPARENT,
};

#define MAX_VLAN_FLIPPING_MAP_NUM	(4096) /* vlan_id最大范围是0~4095, 数组长度是4096 */

typedef struct{
	unsigned short couple_vlan_id; /* vlan flipping是成对存在, 数组下标表示一个vlanid, 元素的值是另一个vlanid, host order */
	unsigned char this_vlan_route_location; // 'C' or 'I'
	unsigned char mac_flipping_enable;
}sapp_vlan_flipping_map_t;


typedef struct{
	char overlay_mode_string[NAME_MAX];
	enum overlay_mode_config overlay_mode_bin;
	int l2_l3_tunnel_support;
	int vlan_flipping_map_num;
	sapp_vlan_flipping_map_t vlan_flipping_map_array[MAX_VLAN_FLIPPING_MAP_NUM];
}sapp_config_packet_io_tunnel_t;


typedef struct{
	//int dup_pkt_distinguish_enable;
	int dup_pkt_distinguish_all_inject;
	int dup_pkt_distinguish_ipv4_tcp;
	int dup_pkt_distinguish_ipv4_udp;
 	int bloom_capacity;
	double bloom_error_rate;
	int bloom_timeout;
}sapp_dup_pkt_t;

typedef struct{
	int enabled;
	int get_cpu_usage_interval; //单位:毫秒, milliseconds(ms)
	int smooth_avg_window; //用最近N次的平均值代替实时值, 避免抖动
	double bypass_trigger_cpu_usage;
	double factor_decrease_ratio;
	double factor_increase_ratio;
	int recovery_observe_time; //单位:秒, second(s)
}sapp_under_ddos_config_t;

typedef struct{
	sapp_config_packet_io_tunnel_t packet_io_tunnel;
	const char *input_bpf_filter;
	char depolyment_mode_str[NAME_MAX]; /* [mirror, inline, transparent, dumpfile] */
	enum sapp_deploment_mode_t depolyment_mode_bin; /* 方便程序内处理, 转成数值形式, 如1:mirror; 2:transparent; 3:inline等, 详见: enum sapp_deploment_mode_t */
	sapp_config_packet_io_dev_t internal;
	sapp_config_packet_io_dev_t external;
	char pcap_dumpfile_name[NAME_MAX];
	int polling_enabled;
	int polling_priority; /* call sapp_recv_pkt every call polling_entry times, 调用多少次polling后调用一次recv pkt, 1表示两者优先级相同 */
	int work_percent;
	int without_usleep; /* 性能测试模式, 不会调用usleep, CPU会100% */
	int inbound_route_dir; /* 表示入境, I2C方向的值是0还是1 */
	char pcap_capture_direction[NAME_MAX]; /* in, out, inout */
	char inject_pkt_mode_string[NAME_MAX];
	int inject_pkt_mode; /* 包注入方式二进制值, 详见: enum send_fake_packet_mode */
	unsigned short inject_mode_inline_device_sport; /* udp socket绑定的本端源端口, host order, 主机序 */
	char inject_mode_single_gateway_device[NAME_MAX];
	char inject_mode_single_gateway_src_mac_string[20];
	char inject_mode_single_gateway_dst_mac_string[20];
	char inject_mode_single_gateway_dst_mac[6]; /* gateway的MAC */
	char inject_mode_single_gateway_src_mac[6]; /* inject_mode_single_gateway_device网卡的MAC */
	int monitor_thread_enabled; /* 读包模式退出之前, 为了某些线程能还写日志, 异步发送数据等操作, 再sleep一会 */
	sapp_dup_pkt_t dup_pkt_para; /* 重复流量识别 */

	char extract_linkdir_from_mac_sntax_raw_string[32];
	char extract_linkdir_from_mac_enabled;
	unsigned char extract_linkdir_from_mac_byte_index; /* 从mac地址的第几个字节获取链路方向, 从0开始到11结束, 总计12字节 */
	unsigned char extract_linkdir_from_mac_bit_value; /* 从某个字节获取链路方向的bit值, 而不是index, 可以直接进行&运算 */

	sapp_under_ddos_config_t under_ddos_config;
	short not_exit_for_dumpfile_mode; /* 读包结束后不退出进程, 方便插件自测试, 多次循环读取多个包 */
	short infinite_loop_enabled;
	short destroy_all_plug_enabled;
}sapp_config_packet_io_t;



typedef struct{
	const char *cfg_files_root_dir;
	
	const char *cfg_main_entry_relative; /* 主配置文件, 固定是sapp.toml, 路径可以靠-c参数指定 */
	const char *cfg_main_entry_absolute; /* /home/project_xxx/sapp/sapp.toml */

	const char *cfg_sapp_log_relative;
	const char *cfg_sapp_log_absolute;

	const char *cfg_plug_list_relative;
	const char *cfg_plug_list_absolute;
	
	const char *cfg_project_list_relative;
	const char *cfg_project_list_absolute;
	
	const char *cfg_entry_list_relative;
	const char *cfg_entry_list_absolute;

	const char *cfg_file_send_raw_pkt_relative;
	const char *cfg_file_send_raw_pkt_absolute;
	
	const char *cfg_file_vxlan_sport_map_relative;
	const char *cfg_file_vxlan_sport_map_absolute;

	const char *cfg_file_inline_dev_relative;
	const char *cfg_file_inline_dev_absolute;

	const char *cfg_file_necessary_plug_relative;  /* 必要插件列表, 如果加载失败sapp就退出 */
	const char *cfg_file_necessary_plug_absolute;

	const char *cfg_file_stream_compare_layer_relative;
	const char *cfg_file_stream_compare_layer_absolute;	

	const char *cfg_file_vlan_flipping_relative;
	const char *cfg_file_vlan_flipping_absolute;		

	const char *cfg_file_asymmetric_addr_layer_relative;
	const char *cfg_file_asymmetric_addr_layer_absolute;		

	const char *cfg_file_well_known_port_relative;
	const char *cfg_file_well_known_port_absolute;		
}sapp_config_file_link_t;


typedef struct{
	const char *data_files_root_dir;
	
	const char *data_sapp_sysinfo_log_relative;
	const char *data_sapp_sysinfo_log_absolute;

	const char *data_sapp_fs2_log_relative;
	const char *data_sapp_fs2_log_absolute;

	const char *data_sapp_fs3_log_relative;
	const char *data_sapp_fs3_log_absolute;

	const char *data_inline_keepalive_log_relative;
	const char *data_inline_keepalive_log_absolute;	

	const char *data_load_plugin_stat_log_relative;
	const char *data_load_plugin_stat_log_absolute;		

	const char *data_under_ddos_stat_log_relative;
	const char *data_under_ddos_stat_log_absolute;	

	const char *data_memory_stat_log_relative;
	const char *data_memory_stat_log_absolute;		
}sapp_data_file_link_t;

typedef struct{
	const char *libmarsio_file_path; /* libmarsio.so是动态dlopen的, 但sapp事先不一定知道在哪个路径, 从配置文件获取 */
}sapp_library_file_link_t;

typedef struct{
	int ipv6_decapsulation_enabled; /* 是否解析ipv6数据包 */
	int ipv6_send_packet_enabled; /* 是否支持发送ipv6数据包, 此项依赖系统ipv6内核模块是否加载 */
	int tcp_drop_pure_ack_pkt; /* 丢弃没有负载的纯ack包, 可以节约一次流表查询, 根据业务需求设置 */
	int tcp_syn_option_parse_enabled; /* 是否解析tcp syn包头部选项 */
	int skip_not_ip_layer_over_eth; /* 跳过非ip层, 保证在并联模式下, 可以通过系统路由发送rst包 */
	int reverse_ethernet_addr_enabled;  /* smac地址中包含特殊信息时无需翻转 */
	int skip_gtp_S_PN_E_field_for_inject; /* GTP隧道注入数据包时忽略扩展字段:sequence,N-PDU, extension */
}sapp_protocol_feature_t;


typedef struct{
	sapp_config_cpu_t cpu;
	sapp_config_tools_t tools;
	sapp_config_system_t system;
	sapp_config_stream_t stream;
	sapp_config_profiling_t profiling;
	sapp_config_packet_io_t packet_io;
	sapp_protocol_feature_t protocol_feature;
	sapp_config_file_link_t cfg_file_path;
	sapp_data_file_link_t data_file_path;
	sapp_library_file_link_t library_file_path;
}sapp_config_t;


typedef struct{
	void *fs_metric_handle; 
	int fs_id_count_array[SAPP_STAT_NUM_MAX];
	int fs_id_length_array[SAPP_STAT_NUM_MAX];
	int fs_latency_id_array[SAPP_MAX_THREADS];
	int fs_latency_plug_entrg_id_array[SAPP_MAX_PLUG_ENTRY_NUM];
	int fs_work_percent_id_array[SAPP_MAX_THREADS];
}sapp_gval_individual_fixed_fs2_t; 



#define TRAFFIC_METRICS_MAX 3
#define FLOW_METRICS_MAX 6
typedef struct{
	struct fieldstat_instance *fs_metric_handle;
	int metrics_ids[2][SAPP_STAT_NUM_MAX];
}sapp_gval_individual_fixed_fs3_t; 

typedef struct{
	void *log_handle; /* runtime.log */
	void *plugin_log_handle; /* runtime.log */
	void *process_latency_log_handle;
	void *sapp_timer_handle[SAPP_MAX_THREADS];
	void *sapp_standalone_timer;
	time_t sapp_start_time;
	int depolyment_mode_private; /* 根据配置sapp_global_val->config.packet_io.depolyment_mode_bin转换得到的内部值,例如:NET_CONN_PARALLEL  */
	unsigned char create_stream_mode; /* 兼容原来的逻辑, 值从配置stream.tcp.syn_mandatory转换得到 */
	int packet_io_cap_level; 

	sapp_gval_individual_fixed_fs2_t fs2_runtime;
	sapp_gval_individual_fixed_fs3_t fs3_runtime;

	pthread_t thread_obtain_id[SAPP_MAX_THREADS]; /* pthread_create返回的id */
	pid_t thread_tid[SAPP_MAX_THREADS]; /* gdb 或 top 查看的id */
	pthread_t thread_timer_event_id;
	int cpu_bind_core_id_per_thread[SAPP_MAX_THREADS]; /* 如果设置了bind_mask, 记录每个IO工作线程绑定的cpu core id */
	void *breakpad;
	char overlay_layer_def[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX]; /* 表示在原始报文基础上封装的隧道, 如vxlan, 这些层不应该调用插件, 回注时需要特殊处理 */
	char prune_layer_def[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];   /* 表示注入包时需要跳过的层, 用于代替最早的配置文件: skip_not_iop_layer, 比如vlan, mpls等, 用于mirror模式下, 接入点和注入点不一样的网络环境 */

	void *under_ddos_handle;
	pthread_t gdev_keepalive_log_thread_id;
}sapp_gval_individual_fixed_t;

typedef struct{
	unsigned long long count[SAPP_STAT_NUM_MAX];  /* 计数类, 如包数, 新建链接数, 并发链接数等 */
	unsigned long long length[SAPP_STAT_NUM_MAX]; /* 长度类, 如数据包总字节数 */
	unsigned long long count_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];
	unsigned long long length_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];
	unsigned long long count_project_in_use[PROJECT_REQ_MAX_PLUG_NUM];
	unsigned long long count_bridge_in_use[STREAM_BRIDGE_MAX_NUM];
}sapp_gval_mthread_sys_stat_t;


typedef struct{
	int stat_count; /* 一段时间内, 记录的数据包延时总数, time_cost_sum/stat_count即平均延时 */
	int min_time_cost;
	int max_time_cost;
	long long time_cost_sum;
}sapp_fuzzy_latency_stat_t;

typedef struct{
	long long mem_used_block[__SAPP_MEM_TYPE_MAX];
	long long mem_used_bytes[__SAPP_MEM_TYPE_MAX];
}sapp_mem_used_stat_t;

struct __sapp_gval_mthread{
	sapp_gval_mthread_sys_stat_t sys_stat;
	unsigned short stream_seq_per_thread; /* 用于计算全局流ID */
	sapp_fuzzy_latency_stat_t fuzzy_pkt_latency_stat_per_thread;
	sapp_fuzzy_latency_stat_t fuzzy_pkt_latency_stat_per_entry_per_thread[SAPP_MAX_PLUG_ENTRY_NUM];
	const raw_pkt_t *raw_pkt; /* 因为MESA_fakepacket_send_xxx系列函数没有raw_pkt参数, 也没有stream_info, 为了向前兼容, 不好修改接口, 增加全局变量用于存储当前包 */
	void *dup_pkt_distinguish_handle; /* 三个流量入口开关, inject, ipv4_tcp, ipv4_udp, 共同使用一个bloom句柄 */
	volatile int destory_env_done; //0:do nothing; 1:doing; 2:done
	sapp_mem_used_stat_t mem_used_stat;
}__attribute__ ((aligned (64))); /* for multi-thread, must 64byte alignment */
typedef struct __sapp_gval_mthread sapp_gval_mthread_t; 


struct __sapp_gval_individual_volatile{
	volatile int current_state; /* refer to enum sapp_state_t  */
	volatile int recv_signal_SIGTERM; /* 收到SIGTERM信号, 优雅的退出 */
	sapp_mem_used_stat_t mem_used_stat; /* 全局变量或初始化就不变的内存 */
}__attribute__ ((aligned (64)));
typedef struct __sapp_gval_individual_volatile sapp_gval_individual_volatile_t;


typedef struct{
	sapp_cmd_args_val_t **cmd_args_array;
	int cmd_args_num;
	char **dumpfie_list_array; /* 参数--dumpfile-list命令执行后, 得到的文件列表, 字符串指针数组 */
	int slient_mode; /* 静默模式, 前台不输出任何信息 */
}sapp_cla_t;


typedef struct{
	sapp_cla_t cla;
	sapp_config_t config;
	sapp_gval_individual_fixed_t individual_fixed; /* 初始化后不再改变的变量 */
	sapp_gval_individual_volatile_t *individual_volatile; /* 程序启动后会实时更新的独立变量 */
	sapp_gval_mthread_t *mthread_volatile[SAPP_MAX_THREADS]; /* 程序启动后会实时更新的多线程变量 */
}sapp_global_t;

extern embed_layer_t g_stream_compare_layer_set; 
extern embed_layer_t g_asymmetric_addr_layer_set; 
extern asymmetric_presence_layer_t g_asymmetric_presence_layer_set[__ADDR_TYPE_MAX];   

#endif

