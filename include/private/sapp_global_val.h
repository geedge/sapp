#ifndef _SAPP_GLOBAL_VAL_H_
#define _SAPP_GLOBAL_VAL_H_ 1

#include <pthread.h>
#include <netinet/in.h>
#include "sapp_pkt_stat.h"
#include "sapp_limits.h"
#include "stream_inc/stream_base.h"


enum pkt_dump_mode{
	PKT_DUMP_LOCAL_FILE		=	1, 
	PKT_DUMP_UDP_SOCKET		=	2, 
};

enum depolyment_mode_config{
	DEPOLYMENT_MODE_MIRROR		= 1,
	DEPOLYMENT_MODE_TRANSPARENT	= 2,
	DEPOLYMENT_MODE_INLINE		= 3,
};

/*
	vxlan和vlan_flipping是可以共存的,
	vxlan用于在线流量,
	vlan_flipping用于本机自检流量,
*/
enum overlay_mode_config{
	OVERLAY_MODE_NONE			= 0,
	OVERLAY_MODE_VXLAN			= 1,
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
	int dictator_enable;
}sapp_config_mem_t;


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
}sapp_config_stream_tcp_t;


typedef struct{
	int max;  /* max stream number per thread */
	int timeout;
	int meaningful_statistics_minimum_pkt;
	int meaningful_statistics_minimum_byte;	
}sapp_config_stream_udp_t;


typedef struct{
	char stream_id_base_time_str[32];
	unsigned int stream_id_base_time_t;
	sapp_config_stream_tcp_t tcp;
	sapp_config_stream_udp_t udp;
}sapp_config_stream_t;


typedef struct{
	int enabled;
	int file_truncate_enabled; /* append or truncate */
	char log_file_name[PATH_MAX];
	char log_conf_name[PATH_MAX];
}sapp_config_profiling_log_local_t;


typedef struct{
	int metrics_type; 
	char app_name[NAME_MAX];
}sapp_config_profiling_log_remote_field_stat2_t;


typedef struct{
	char name[NAME_MAX];
	char value[NAME_MAX];
}log_line_protocol_tag_t;

typedef struct{
	int sock_fd;
	struct sockaddr_in sock_addr;
	time_t last_send_metrics_time;
	unsigned long long history_count[SAPP_STAT_NUM_MAX];
	unsigned long long history_length[SAPP_STAT_NUM_MAX];	
}log_line_protocol_handle_t;


#define LINE_PROTOCOL_TAG_NUM_MAX	16
typedef struct{
	log_line_protocol_tag_t tags[LINE_PROTOCOL_TAG_NUM_MAX];
}sapp_config_profiling_log_remote_line_protocol_t;



typedef struct{
	int enabled;
	char log_app_name[NAME_MAX];
	char server_ip[INET_ADDRSTRLEN]; /* string */
	unsigned int server_port; /* integer(4 byte), host order, user should truncate to short before use it */
	char remote_send_out_type[NAME_MAX]; /* field_stat2 */
	sapp_config_profiling_log_remote_field_stat2_t field_stat2;
}sapp_config_profiling_log_remote_t;

typedef struct{
	int enabled;
	int port; /* host order */
	char url_path[NAME_MAX];
}sapp_config_profiling_log_prometheus_t;



typedef struct{
	int level;
	int interval;
	sapp_config_profiling_log_local_t local;
	sapp_config_profiling_log_remote_t remote;
	sapp_config_profiling_log_prometheus_t prometheus;
}sapp_config_profiling_log_t;


typedef struct{
	sapp_config_profiling_log_t log;
	unsigned char pkt_latency_enabled;
	unsigned char sanity_check_raw_pkt_broken_enabled;
	unsigned char sanity_check_symbol_conflict_enabled;
	unsigned int pkt_latency_threshold_in_us; /* microsecond */
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
	char vlan_flipping_cfg_file[PATH_MAX];
	char asymmetric_addr_layer_cfg_file[PATH_MAX];
	char asymmetric_presence_layer_cfg_file[PATH_MAX];
	char prune_inject_layer_cfg_file[PATH_MAX];
	char stream_compare_layer_cfg_file[PATH_MAX];
	int l2_l3_tunnel_support;
	int vlan_flipping_map_num;
	sapp_vlan_flipping_map_t vlan_flipping_map_array[MAX_VLAN_FLIPPING_MAP_NUM];
}sapp_config_packet_io_tunnel_t;


typedef struct{
	sapp_config_packet_io_tunnel_t packet_io_tunnel;
	const char *input_bpf_filter;
	char depolyment_mode_str[NAME_MAX]; /* [mirror, inline, transparent, dumpfile] */
	enum depolyment_mode_config depolyment_mode_bin; /* 方便程序内处理, 转成数值形式, 如1:mirror; 2:transparent; 3:inline等, 详见: enum depolyment_mode_config */
	sapp_config_packet_io_dev_t internal;
	sapp_config_packet_io_dev_t external;
	char pcap_dumpfile_name[NAME_MAX];
	int polling_enabled;
	int polling_priority; /* call sapp_recv_pkt every call polling_entry times, 调用多少次polling后调用一次recv pkt, 1表示两者优先级相同 */
	int without_usleep; /* 性能测试模式, 不会调用usleep, CPU会100% */
	int inbound_route_dir; /* 表示入境, I2C方向的值是0还是1 */
	char pcap_capture_direction[NAME_MAX]; /* in, out, inout */
	//int create_mpls_anyway;
	char inject_pkt_mode_string[NAME_MAX];
	int inject_pkt_mode; /* 包注入方式二进制值, 详见: enum send_fake_packet_mode */
	unsigned short inject_mode_inline_device_sport; /* udp socket绑定的本端源端口, host order, 主机序 */
	char inject_mode_single_gateway_device[NAME_MAX];
	char inject_mode_single_gateway_src_mac_string[20];
	char inject_mode_single_gateway_dst_mac_string[20];
	char inject_mode_single_gateway_dst_mac[6]; /* gateway的MAC */
	char inject_mode_single_gateway_src_mac[6]; /* inject_mode_single_gateway_device网卡的MAC */
	int dumpfile_sleep_time_before_exit; /* 读包模式退出之前, 为了某些线程能还写日志, 异步发送数据等操作, 再sleep一会 */
}sapp_config_packet_io_t;

typedef struct{
	const char *project_list_path;
	const char *plugin_path;
	const char *entrylist_path;
	const char *send_raw_pkt_path;
	const char *vxlan_sport_service_map_path;
	const char *necessary_plug_list_path; /* 必要插件列表, 如果加载失败sapp就退出 */
}sapp_config_special_link_t;

typedef struct{
	int ipv6_decapsulation_enabled; /* 是否解析ipv6数据包 */
	int ipv6_send_packet_enabled; /* 是否支持发送ipv6数据包, 此项依赖系统ipv6内核模块是否加载 */
	int tcp_drop_pure_ack_pkt; /* 丢弃没有负载的纯ack包, 可以节约一次流表查询, 根据业务需求设置 */
	int tcp_syn_option_parse_enabled; /* 是否解析tcp syn包头部选项 */
	int skip_not_ip_layer_over_eth; /* 跳过非ip层, 保证在并联模式下, 可以通过系统路由发送rst包 */
	int reverse_ethernet_addr_enabled;  /* smac地址中包含特殊信息时无需翻转 */
}sapp_protocol_feature_t;


typedef struct{
	sapp_config_cpu_t cpu;
	sapp_config_mem_t mem;
	sapp_config_tools_t tools;
	sapp_config_system_t system;
	sapp_config_stream_t stream;
	sapp_config_profiling_t profiling;
	sapp_config_packet_io_t packet_io;
	sapp_protocol_feature_t protocol_feature;
	sapp_config_special_link_t special_conf_link;
}sapp_config_t;


typedef struct{
	void *field_stat2_handle; /* equal to profiling_log_remote_handle if log.enabled=1 and remote_send_out_type=field_stat2 */
	int fs_id_count_array[SAPP_STAT_NUM_MAX];
	int fs_id_length_array[SAPP_STAT_NUM_MAX];
	int fs_latency_id_array[SAPP_MAX_THREADS];
}sapp_gval_individual_fixed_fs_t; /* field stat info */

typedef struct{
	void *log_handle; /* runtime.log */
	void *profiling_log_remote_handle; /* metric, field_stat2 or line_protocol */
	void *sapp_timer_handle[SAPP_MAX_THREADS];
	void *sapp_standalone_timer;
	time_t sapp_start_time;
	int depolyment_mode_private; /* 根据配置sapp_global_val->config.packet_io.depolyment_mode_bin转换得到的内部值,例如:NET_CONN_PARALLEL  */
	unsigned char create_stream_mode; /* 兼容原来的逻辑, 值从配置stream.tcp.syn_mandatory转换得到 */
	int packet_io_cap_level; 
	sapp_gval_individual_fixed_fs_t field_stat2_para;
	pthread_t pkt_process_tid[SAPP_MAX_THREADS];
	void *breakpad;

	char overlay_layer_def[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX]; /* 表示在原始报文基础上封装的隧道, 如vxlan, 这些层不应该调用插件, 回注时需要特殊处理 */
	char prune_layer_def[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];   /* 表示注入包时需要跳过的层, 用于代替最早的配置文件: skip_not_iop_layer, 比如vlan, mpls等, 用于mirror模式下, 接入点和注入点不一样的网络环境 */
}sapp_gval_individual_fixed_t;

typedef struct{
	unsigned long long count[SAPP_STAT_NUM_MAX];  /* 计数类, 如包数, 新建链接数, 并发链接数等 */
	unsigned long long length[SAPP_STAT_NUM_MAX]; /* 长度类, 如数据包总字节数 */
	unsigned long long count_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];
	unsigned long long length_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];
}sapp_gval_mthread_sys_stat_t;



struct __sapp_gval_mthread{
	sapp_gval_mthread_sys_stat_t sys_stat;
	unsigned short stream_seq_per_thread; /* 用于计算全局流ID */
	const raw_pkt_t *raw_pkt; /* 因为MESA_fakepacket_send_xxx系列函数没有raw_pkt参数, 也没有stream_info, 为了向前兼容, 不好修改接口, 增加全局变量用于存储当前包 */
}__attribute__ ((aligned (64))); /* for multi-thread, must 64byte alignment */
typedef struct __sapp_gval_mthread sapp_gval_mthread_t; 


struct __sapp_gval_individual_volatile{
	volatile time_t current_time;
	volatile long long current_time_ms;
	volatile int current_state;
}__attribute__ ((aligned (64)));
typedef struct __sapp_gval_individual_volatile sapp_gval_individual_volatile_t;


typedef struct{
	sapp_cmd_args_val_t **cmd_args_array;
	int cmd_args_num;
	char **dumpfie_list_array; /* 参数--dumpfile-list命令执行后, 得到的文件列表, 字符串指针数组 */
}sapp_cla_t;


typedef struct{
	sapp_cla_t cla;
	sapp_config_t config;
	sapp_gval_individual_fixed_t individual_fixed; /* 初始化后不再改变的变量 */
	sapp_gval_individual_volatile_t *individual_volatile; /* 程序运行时会实时更新的变量 */
	sapp_gval_mthread_t *mthread_volatile[SAPP_MAX_THREADS];
}sapp_global_t;

extern embed_layer_t g_stream_compare_layer_set; 
extern embed_layer_t g_asymmetric_addr_layer_set; 
extern asymmetric_presence_layer_t g_asymmetric_presence_layer_set[__ADDR_TYPE_MAX];   

#endif

