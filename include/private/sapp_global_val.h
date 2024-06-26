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
	vxlan��vlan_flipping�ǿ��Թ����?,
	vxlan������������,
	vlan_flipping���ڱ����Լ�����,
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
	int send_only_threads_max_num; /* �������߳��������?, �ǲ����̬������?, sapp�����޷�Ԥ֪, ֻ��������ֵ */
	int bind_mask_array_num;
	long bind_mask_array[SAPP_MAX_THREADS];
	long bind_mask; /* bind_mask_array�е�ÿ��������Ϊbit_indexת�ɵ�����ֵ */
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
	int dump_thread_id_array[SAPP_MAX_THREADS]; /* �û������ļ�ԭʼ����, ��ʽ: [0,1,2,3], ��ʾ��0,1,2,3���߳����ò��� */
	unsigned char dump_thread_id_mask[SAPP_MAX_THREADS]; /* ����ԭʼ������������������, ���߳�id��Ϊ�±�, ֵ��Ϊ0��ʾ��ǰ�߳̿�������, ֵ:{1,1,1,1} */
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
	int auto_remedy; /* ƽ̨ȫ������, ����ÿ����, ��������auto_remedy_flag, ���ȼ�����ȫ��auto_remedy */
	int rst_signature_enable;
	int rst_num;
	int rst_signature_seed1;
	int rst_signature_seed2;
	int link_mss;
	int remedy_kill_tcp_by_inline_device; /* ����FD����Чʱ, ����inline device�·�DROP���� */
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
	int well_known_ports_array_num;
	unsigned short *well_known_ports_array; /* ���ڰ�data������ȷ��server�� */
	int closing_timeout;
	int opening_timeout;
	int max_timeouts_per_sec;
	int max_opening_per_sec;
	int reorder_on_closing;
	int fast_close_nouse;
}sapp_config_stream_tcp_t;


typedef struct{
	int max;  /* max stream number per thread */
	int timeout;
	int meaningful_statistics_minimum_pkt;
	int meaningful_statistics_minimum_byte;	
	unsigned short *well_known_ports_array; /* �����½�����ȷ��server��, ����4001->8000, ʵ������OICQ��C2S�������ݰ�,֮ǰ�İ汾�ᱻ��ʶ��ΪS2C�����? */
	int well_known_ports_array_num;	
	int max_timeouts_per_sec;
	int max_opening_per_sec;
	int max_opening;
	int max_pair;
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
	char process_latency_local_file[NAME_MAX];
	int process_latency_refresh_interval_s;
	int process_latency_threshold_in_us; /* �����ļ��ﵥλ��microsecond, ��Ҫ����1000 */
	/* ��ȷģʽ������, fs2����ͳ��Ҳ�ǳ���CPU, ÿ������Ҫ����FS_operate(),
	   ���ͣ�þ�ȷģ�?, ����fs2���Ǳ������һ��ʱ�������?, ��Сֵ����һ��ʱ���ƽ���?, ������FS_operate()����,
	   ��ȷ�Ƚ�����һЩ, ���������˵���FS_operate()�Ĵ���.
		����pkt_latency_accurate_enable��ƽ��ֵ�����ǶԵ�, ����׼��Ͳ�׼��?.
	   */
	int process_latency_clock_id; 
	
	int sanity_check_raw_pkt_broken_enabled;
	int sanity_check_symbol_conflict_enabled;
	int memory_used_stat_interval_s;
}sapp_config_profiling_t;

typedef struct{
	char type_str[NAME_MAX]; /* pag,pcap,marsio */
	char name[NAME_MAX];
	enum cap_mode_t type_bin; /* ���ַ���typeת��Ϊ��������ֵ */
}sapp_config_packet_io_interface_t;


typedef struct{
	sapp_config_packet_io_interface_t interface;
	unsigned char format_type; /* vxlan, ddp, k18mac, 327, etc.. */
}sapp_config_packet_io_dev_t;


enum __sapp_config_packet_io_deployment_mode{
	SAPP_CFG_PKT_IO_DEPOLY_MODE_MIRROR,
	SAPP_CFG_PKT_IO_DEPOLY_MODE_INLINE,
	SAPP_CFG_PKT_IO_DEPOLY_MODE_TRANSPARENT,
};

#define MAX_VLAN_FLIPPING_MAP_NUM	(4096) /* vlan_id���Χ��?0~4095, ���鳤����4096 */

typedef struct{
	unsigned short couple_vlan_id; /* vlan flipping�ǳɶԴ���, �����±��ʾһ��vlanid, Ԫ�ص�ֵ����һ��vlanid, host order */
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


enum bloom_library{
	BLOOM_LIBRARY_NONE=0,
	BLOOM_LIBRARY_DABLOOM,
	BLOOM_LIBRARY_APBLOOM,
};

typedef struct{
	int kickout_udp_stream_enabled;
	int dup_pkt_distinguish_all_inject;
	int dup_pkt_distinguish_ipv4_tcp;
	int dup_pkt_distinguish_ipv4_udp;
 	int bloom_capacity;
	int bloom_slice_num;
	long bloom_timeout_ms;
	enum bloom_library bloom_library;
	int bloom_partition_num;
	long transition_time_ms;
	double bloom_error_rate;
	int first_packets;
}sapp_dup_pkt_t;

typedef struct{
	int enabled;
	int get_cpu_usage_interval; //��λ:����, milliseconds(ms)
	int smooth_avg_window; //�����N�ε�ƽ��ֵ����ʵʱֵ, ���ⶶ��
	double bypass_trigger_cpu_usage;
	double factor_decrease_ratio;
	double factor_increase_ratio;
	int recovery_observe_time; //��λ:��, second(s)
}sapp_under_ddos_config_t;

typedef struct{
	sapp_config_packet_io_tunnel_t packet_io_tunnel;
	const char *input_bpf_filter;
	char deployment_mode_str[NAME_MAX]; /* [mirror, inline, transparent, dumpfile] */
	enum sapp_deploment_mode_t deployment_mode_bin; /* ��������ڴ���?, ת����ֵ��ʽ, ��1:mirror; 2:transparent; 3:inline��, ���?: enum sapp_deploment_mode_t */
	sapp_config_packet_io_dev_t internal;
	sapp_config_packet_io_dev_t external;
	char pcap_dumpfile_name[NAME_MAX];
	int polling_priority; /* call sapp_recv_pkt every call polling_entry times, ���ö��ٴ�polling�����һ��recv pkt, 1��ʾ�������ȼ���ͬ */
	int work_percent;
	int without_usleep; /* ���ܲ���ģʽ, �������usleep, CPU��100% */
	int inbound_route_dir; /* ��ʾ�뾳, I2C�����ֵ��?0����1 */
	char pcap_capture_direction[NAME_MAX]; /* in, out, inout */
	char inject_pkt_mode_string[NAME_MAX];
	int inject_pkt_mode; /* ��ע�뷽ʽ������ֵ, ���?: enum send_fake_packet_mode */
	int inject_pkt_prepend_segment_id;
	unsigned short inject_mode_inline_device_sport; /* udp socket�󶨵ı���Դ�˿�, host order, ������ */
	char inject_mode_single_gateway_device[NAME_MAX];
	char inject_mode_single_gateway_src_mac_string[20];
	char inject_mode_single_gateway_dst_mac_string[20];
	char inject_mode_single_gateway_dst_mac[6]; /* gateway��MAC */
	char inject_mode_single_gateway_src_mac[6]; /* inject_mode_single_gateway_device������MAC */
	int monitor_thread_enabled; /* ����ģʽ�˳�֮ǰ, Ϊ��ĳЩ�߳��ܻ�д��־, �첽�������ݵȲ���, ��sleepһ�� */
	sapp_dup_pkt_t dup_pkt_para; /* �ظ�����ʶ�� */

	char extract_linkdir_from_mac_sntax_raw_string[32];
	char extract_linkdir_from_mac_enabled;
	unsigned char extract_linkdir_from_mac_byte_index; /* ��mac��ַ�ĵڼ����ֽڻ�ȡ��·����, ��0��ʼ��11����, �ܼ�12�ֽ� */
	unsigned char extract_linkdir_from_mac_bit_value; /* ��ĳ���ֽڻ�ȡ��·�����bitֵ, ������index, ����ֱ�ӽ���&���� */

	sapp_under_ddos_config_t under_ddos_config;
	short not_exit_for_dumpfile_mode; /* �����������˳�����, �������Բ���, ���ѭ����ȡ����� */
	short infinite_loop_enabled;
	short destroy_all_plug_enabled;
	short dlclose_all_plug_enabled;
	int dumpfile_sleep_time_before_exit;
	int watchdog_enabled;
}sapp_config_packet_io_t;



typedef struct{
	const char *cfg_files_root_dir;
	
	const char *cfg_main_entry_relative; /* �������ļ�, �̶���sapp.toml, ·�����Կ�-c����ָ�� */
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

	const char *cfg_file_necessary_plug_relative;  /* ��Ҫ����б�?, �������ʧ��sapp���˳� */
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

	const char *data_sapp_fs2_process_latency_relative;
	const char *data_sapp_fs2_process_latency_absolute;

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
	const char *libmarsio_file_path; /* libmarsio.so�Ƕ�̬dlopen��, ��sapp���Ȳ�һ��֪�����ĸ�·��, �������ļ���ȡ */
}sapp_library_file_link_t;

typedef struct{
	int ipv6_decapsulation_enabled; /* �Ƿ����ipv6���ݰ� */
	int ipv6_send_packet_enabled; /* �Ƿ�֧�ַ���ipv6���ݰ�, ��������ϵͳipv6�ں�ģ���Ƿ����? */
	int tcp_drop_pure_ack_pkt; /* ����û�и��صĴ�ack��, ���Խ�Լһ��������ѯ, ����ҵ���������� */
	int tcp_syn_option_parse_enabled; /* �Ƿ����tcp syn��ͷ��ѡ�� */
	int skip_not_ip_layer_over_eth; /* ������ip��, ��֤�ڲ���ģʽ��, ����ͨ��ϵͳ·�ɷ���rst�� */
	int reverse_ethernet_addr_enabled;  /* smac��ַ�а���������Ϣʱ���跭ת */
	int skip_gtp_S_PN_E_field_for_inject; /* GTP����ע�����ݰ�ʱ������չ�ֶ�:sequence,N-PDU, extension */
	int ipv4_reassembly_enabled; 
	int ipv6_reassembly_enabled; 
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

	void *fs_process_lantency_handle; 
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
	int deployment_mode_private; /* ��������sapp_global_val->config.packet_io.deployment_mode_binת���õ����ڲ�ֵ,����:NET_CONN_PARALLEL  */
	unsigned char create_stream_mode; /* ����ԭ�����߼�, ֵ������stream.tcp.syn_mandatoryת���õ� */
	int packet_io_cap_level; 

	sapp_gval_individual_fixed_fs2_t fs2_runtime;
	sapp_gval_individual_fixed_fs3_t fs3_runtime;

	pthread_t thread_obtain_id[SAPP_MAX_THREADS]; /* pthread_create���ص�id */
	pid_t thread_tid[SAPP_MAX_THREADS]; /* gdb �� top �鿴��id */
	pthread_t thread_timer_event_id;
	pthread_t thread_timer_loop_id;
	int cpu_bind_core_id_per_thread[SAPP_MAX_THREADS]; /* ���������bind_mask, ��¼ÿ��IO�����̰߳󶨵�cpu core id */
	void *breakpad;
	char overlay_layer_def[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX]; /* ��ʾ��ԭʼ���Ļ����Ϸ�װ������, ��vxlan, ��Щ�㲻Ӧ�õ��ò��?, ��עʱ��Ҫ���⴦�� */
	char prune_layer_def[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];   /* ��ʾע���ʱ��Ҫ�����Ĳ�?, ���ڴ�������������ļ�?: skip_not_iop_layer, ����vlan, mpls��, ����mirrorģʽ��, ������ע��㲻һ�������绷��? */

	void *under_ddos_handle;
	pthread_t gdev_keepalive_log_thread_id;
}sapp_gval_individual_fixed_t;

typedef struct{
	unsigned long long count[SAPP_STAT_NUM_MAX];  /* ������, �����?, �½�������, ������������ */
	unsigned long long length[SAPP_STAT_NUM_MAX]; /* ������, �����ݰ����ֽ��� */
	unsigned long long count_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];
	unsigned long long length_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];
	unsigned long long count_project_in_use[PROJECT_REQ_MAX_PLUG_NUM];
	unsigned long long count_bridge_in_use[STREAM_BRIDGE_MAX_NUM];
}sapp_gval_mthread_sys_stat_t;


typedef struct{
	int stat_count; /* һ��ʱ����, ��¼�����ݰ���ʱ����, time_cost_sum/stat_count��ƽ����ʱ */
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
	unsigned short stream_seq_per_thread; /* ���ڼ���ȫ����ID */
	sapp_fuzzy_latency_stat_t fuzzy_pkt_latency_stat_per_thread;
	sapp_fuzzy_latency_stat_t fuzzy_pkt_latency_stat_per_entry_per_thread[SAPP_MAX_PLUG_ENTRY_NUM];
	const raw_pkt_t *raw_pkt; /* ��ΪMESA_fakepacket_send_xxxϵ�к���û��raw_pkt����, Ҳû��stream_info, Ϊ����ǰ����, �����޸Ľӿ�, ����ȫ�ֱ������ڴ洢��ǰ�� */
	void *dup_pkt_distinguish_handle; /* ����������ڿ���?, inject, ipv4_tcp, ipv4_udp, ��ͬʹ��һ��bloom���? */
	volatile int destory_env_done; //0:do nothing; 1:doing; 2:done
	sapp_mem_used_stat_t mem_used_stat;
}__attribute__ ((aligned (64))); /* for multi-thread, must 64byte alignment */
typedef struct __sapp_gval_mthread sapp_gval_mthread_t; 


struct __sapp_gval_individual_volatile{
	volatile int current_state; /* refer to enum sapp_state_t  */
	volatile int recv_signal_SIGTERM; /* �յ�SIGTERM�ź�, ���ŵ��˳� */
	sapp_mem_used_stat_t mem_used_stat; /* ȫ�ֱ������ʼ���Ͳ�����ڴ� */
}__attribute__ ((aligned (64)));
typedef struct __sapp_gval_individual_volatile sapp_gval_individual_volatile_t;


typedef struct{
	sapp_cmd_args_val_t **cmd_args_array;
	int cmd_args_num;
	char **dumpfie_list_array; /* ����--dumpfile-list����ִ�к�, �õ����ļ��б�, �ַ���ָ������ */
	int slient_mode; /* ��Ĭģʽ, ǰ̨������κ����? */
}sapp_cla_t;


typedef struct{
	sapp_cla_t cla;
	sapp_config_t config;
	sapp_gval_individual_fixed_t individual_fixed; /* ��ʼ�����ٸı�ı���? */
	sapp_gval_individual_volatile_t *individual_volatile; /* �����������ʵʱ���µĶ�������? */
	sapp_gval_mthread_t *mthread_volatile[SAPP_MAX_THREADS]; /* �����������ʵʱ���µĶ��̱߳���? */
}sapp_global_t;

extern embed_layer_t g_stream_compare_layer_set; 
extern embed_layer_t g_asymmetric_addr_layer_set; 
extern asymmetric_presence_layer_t g_asymmetric_presence_layer_set[__ADDR_TYPE_MAX];   

#endif

