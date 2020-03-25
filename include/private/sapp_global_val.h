#ifndef _SAPP_GLOBAL_VAL_H_
#define _SAPP_GLOBAL_VAL_H_ 1

#include <pthread.h>
#include <netinet/in.h>
#include "sapp_pkt_stat.h"

typedef struct{
	int worker_threads;
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
	sapp_config_tools_pktdump_t pkt_dump;
}sapp_config_tools_t;


typedef struct{
	int auto_remedy; /* 平台全局配置, 对于每个流, 可以设置auto_remedy_flag, 优先级高于全局auto_remedy */
	int rst_signature_enable;
	int rst_num;
	int rst_signature_seed1;
	int rst_signature_seed2;
	int link_mss;
}sapp_config_stream_tcp_inject_t;


typedef struct{
	int max;  /* max stream number per thread */
	int timeout;
	int reorder_pkt_max;
	int syn_mandatory;
	int analyse_option_enabled;
	sapp_config_stream_tcp_inject_t inject;
}sapp_config_stream_tcp_t;


typedef struct{
	int max;  /* max stream number per thread */
	int timeout;
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
	int level;
	int interval;
	sapp_config_profiling_log_local_t local;
	sapp_config_profiling_log_remote_t remote;
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

typedef struct{
	const char *input_bpf_filter;
	char depolyment_mode_str[NAME_MAX]; /* [mirror, inline, transparent, dumpfile] */
	int depolyment_mode_bin; /* 方便程序内处理, 转成数值形式, 如1:mirror; 2:transparent; 3:inline等 */
	sapp_config_packet_io_dev_t internal;
	sapp_config_packet_io_dev_t external;
	char pcap_dumpfile_name[NAME_MAX];
	int polling_enabled;
	int polling_priority; /* call sapp_recv_pkt every call polling_entry times, 调用多少次polling后调用一次recv pkt, 1表示两者优先级相同 */
	int inbound_route_dir; /* 表示入境, I2C方向的值是0还是1 */
	char pcap_capture_direction[NAME_MAX]; /* in, out, inout */
}sapp_config_packet_io_t;

typedef struct{
	const char *project_list_path;
	const char *plugin_path;
	const char *entrylist_path;
	const char *send_raw_pkt_path;
	const char *vxlan_sport_service_map_path;
}sapp_config_special_link_t;

typedef struct{
	int ipv6_decapsulation_enabled; /* 是否解析ipv6数据包 */
	int ipv6_send_packet_enabled; /* 是否支持发送ipv6数据包, 此项依赖系统ipv6内核模块是否加载 */
	int tcp_drop_pure_ack_pkt; /* 丢弃没有负载的纯ack包, 可以节约一次流表查询, 根据业务需求设置 */
	int tcp_syn_option_parse_enabled; /* 是否解析tcp syn包头部选项 */
	int skip_not_ip_layer_over_eth; /* 跳过非ip层, 保证在并联模式下, 可以通过系统路由发送rst包 */
}sapp_protocol_feature_t;


typedef struct{
	sapp_config_cpu_t cpu;
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
}sapp_gval_individual_fixed_t;

typedef struct{
	unsigned long long count[SAPP_STAT_NUM_MAX];  /* 计数类, 如包数, 新建链接数, 并发链接数等 */
	unsigned long long length[SAPP_STAT_NUM_MAX]; /* 长度类, 如数据包总字节数 */
}sapp_gval_mthread_sys_stat_t;



typedef struct{
	sapp_gval_mthread_sys_stat_t sys_stat;
	unsigned short stream_seq_per_thread;
	char __padding[12];
}sapp_gval_mthread_t; /*   for multi-thread, must 64byte alignment */


typedef struct{
	volatile time_t current_time;
	volatile long long current_time_ms;
	volatile int current_state;
	char __padding[44];
}sapp_gval_individual_volatile_t;


typedef struct{
	sapp_cmd_args_val_t **cmd_args_array;
	int cmd_args_num;
}sapp_cla_t;


typedef struct{
	sapp_cla_t cla;
	sapp_config_t config;
	sapp_gval_individual_fixed_t individual_fixed; /* 初始化后不再改变的变量 */
	sapp_gval_individual_volatile_t *individual_volatile; /* 程序运行时会实时更新的变量 */
	sapp_gval_mthread_t *mthread_volatile[SAPP_MAX_THREADS];
}sapp_global_t;


#endif

